import ghidra.app.script.GhidraScript;
import ghidra.app.cmd.disassemble.ArmDisassembleCommand;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.symbol.ExternalLocation;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.lang.RegisterValue;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.SymbolIterator;
import java.io.File;
import java.io.FileWriter;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * ExtractIR v3.1: exports functions + P-Code IR + strings + imports + XREFs as JSON.
 * Streams output (no big in-memory buffers) so it stays safe under a 512M heap.
 * Caps: 5000 P-Code ops per function, 10000 strings (both flagged when hit).
 *
 * v3 adds VALUE EXPORT on MMIO accesses: every MMIO LOAD/STORE entry now
 * carries "value" (exact stored/loaded value, or null), "value_known_ones"
 * and "value_known_zeroes" (bit masks of provably-set / provably-clear bits).
 * Why masks, not just exact values: bare-metal code uses read-modify-write
 * (e.g. GPIOA_ODR |= (1<<5)), so the stored value depends on runtime
 * register state and is NOT statically exact -- but the bit effect IS:
 * bit 5 forced to 1 (LED ON) or forced to 0 (LED OFF). The known-bit masks
 * capture exactly that. Ops folded: COPY, LOAD (program memory only),
 * INT_ADD/SUB/MULT (exact-only), INT_AND/OR/XOR/NOT (mask algebra, exact
 * even on partial knowledge), INT_LEFT/RIGHT, INT_2COMP (arithmetic
 * negation), INT_NEGATE (bitwise NOT -- NOT arithmetic negation; ARM BIC
 * sleigh proves it: "Rd = rn&(~shift1)"), INT_ZEXT/SEXT, SUBPIECE.
 * Everything else yields unknown bits (ones=0, zeroes=0).
 *
 * v3.1 replaces the v3 LINEAR scan (last definition wins) with a CFG
 * FIXPOINT scan, because the linear scan was PROVEN to hallucinate:
 * Black Magic Probe renesas_uid recorded a LOAD at 0x4136544A, but the
 * literal-pool words show the list-order definition gave 0x41365432
 * (+0x18 = 0x4136544A) while the definition on the path that actually
 * reaches the LOAD gives 0x41365431 (+0x18 = 0x41365449). The linear
 * scan took another branch's value. The fixpoint is a must-analysis:
 * states flow along CFG edges (fallthrough + branch targets); at joins,
 * conflicting exact values become UNKNOWN and known-bit masks are
 * AND-merged (a bit is claimed only if it holds on EVERY incoming path).
 * Two more soundness rules: (1) unique-space varnodes are temporaries
 * LOCAL to one instruction, so their values are stripped whenever control
 * crosses an instruction boundary; (2) CALL/CALLIND clobber the AAPCS
 * caller-saved registers r0-r3, r12 (Ghidra ARM offsets 32, 36, 40, 44,
 * 80 -- confirmed empirically: the epilogue pop targets 0x30/0x34/0x38/
 * 0x3c/0x5c decode as r4/r5/r6/r7/pc under rN = 0x20 + 4N, sp = 0x54,
 * lr = 0x58, pc = 0x5c). Callee-saved r4-r11 and sp are preserved; lr
 * is NOT clobbered because Ghidra's own P-Code models the link value.
 * CBRANCH fallthrough is the NEXT OP (not the next instruction): ARM
 * predicated instructions model as [condition, CBRANCH, guarded ops]
 * inside one instruction, and skipping to the next instruction would
 * wrongly make the guarded ops unreachable (caught Oct 26: the first
 * v3.1 build did exactly that and produced a phantom exact 0xFFFF in
 * jtagtap_tdi_seq).
 *
 * v3.2 adds MAY-analysis alongside the must-analysis: a second fixpoint
 * over the same CFG whose join is UNION (finite value sets, capped at
 * 16; anything bigger or argument-dependent is TOP). A LOAD/STORE the
 * must-analysis drops (path-dependent address) is recorded as a
 * MAY-access with the full set of possible MMIO addresses, so an audit
 * sees what a driver COULD touch. Jump-table blocks stay unreachable
 * (BRANCHIND has no successors) -- recovering those needs table
 * recovery, a separate step.
 *
 * v3.3 adds TBB/TBH jump-table recovery: the successor computation
 * recognises Ghidra's ARM TBB/TBH P-Code shape (table LOAD + ZEXT +
 * x2 + table base -> pc -> BRANCHIND), reads the table entries from
 * program memory, and adds every entry's target that is a real
 * instruction start in the same function as a CFG successor (both
 * fixpoints share the recovered map). The table read stops when the
 * next entry address reaches the smallest target seen so far (the
 * table ends where the first case block begins), when it leaves the
 * function's address range, or at 64 entries. Non-matching
 * BRANCHINDs (pointer tables, bx reg) keep no successors: pointer
 * targets are other functions, not successors here -- call-graph
 * recovery is a separate step.
 *
 * v3.4 adds call-graph recovery for pointer-table dispatch: a backward
 * slice from each CALLIND/BRANCHIND destination recognises a single
 * constant target (one COPY hop allowed) or a constant-base table of
 * 4-byte pointers (index*4, optional Thumb-bit AND); table entries
 * are kept while each pointer (& ~1) is a real function entry, and
 * the read stops at the first pointer that is not (or an unreadable
 * address), capped at 64. TBB/TBH BRANCHINDs are skipped here (they
 * are CFG successors, not calls). Argument-dependent dispatch (vtable
 * via object pointer) has no constant base and is left for points-to
 * analysis. Every reported target is a real function entry by
 * construction -- this recovers edges, never invents them.
 * FIXED Oct 26 (same v3.4, before landing): the first build found 0
 * edges because the table base can sit in a register (`adr` -> COPY
 * const -> reg), not only as a direct constant -- the slice now
 * follows one COPY hop for the base. The same fix revealed that
 * `remote_packet_process`'s pointer table points INSIDE its own
 * function (computed goto, not calls), so pointer-table entries that
 * are real instruction starts in the same function now become CFG
 * successors (BRANCHIND only), while function-entry entries become
 * call-graph edges.
 *
 * v3.5 adds points-to recovery for the CALLINDs v3.4 could not
 * resolve (BMP: 161 of 178 are LOAD [struct + const offset] --
 * vtable-style dispatch). Each CALLIND's pointer load is resolved
 * through its backward def chain (COPY / INT_ADD / LOAD of a
 * resolvable address, depth 4), where a varnode in a memory space
 * reads as the word at that address (ARM literal-pool pattern).
 * A chain ending in flash yields the static word; a chain ending
 * in RAM (BMP's probe structs live in .bss, filled at runtime)
 * is matched against the whole-program store map, which records
 * every runtime store of a resolvable function address keyed by
 * exact address or field offset. When the chain does not resolve,
 * the fallbacks are a scaled call-table read and the offset map.
 * Only single-constant destinations stay CERTAIN (indirect_calls,
 * with the Thumb-AND unwrap v3.4 missed -- which in BMP resolves
 * to const 0x16, not a function, so certain stays 0).
 * Parameter-passed struct pointers (no def in the 40-op window),
 * [reg + reg] indexing, and longer chains stay unresolved and
 * are counted, never guessed.
 *
 * v3.6 adds two evidence-backed recoveries from the Oct 26, 2026
 * source cross-check (singletons 44/44 exact, field truth 99/116):
 * (1) TAIL-CALL recovery: reset/halt dispatch compiles to BRANCHIND
 * (a tail jump), not CALLIND, so v3.5 could not see it at all.
 * recoverTailCalls runs the same points-to tiers on BRANCHINDs
 * whose destination is a struct-field LOAD, and classifies the rest:
 * a constant destination inside the current function is a goto
 * (skipped, not unresolved), a destination of lr is a return
 * (skipped), and only the remainder counts as unresolved tail calls.
 * BRANCHINDs already resolved by v3.4 (constant destinations,
 * pointer-table successors) are never double-counted.
 * (2) WHOLE-IMAGE LITERAL SCAN: some function-pointer stores live
 * outside Ghidra's recognized function pcodes (their literals are
 * in the image, but no function LOADs them). The scan reads every
 * word of initialized program memory; a word equal to a function
 * entry (Thumb bit masked) is a stored pointer. Pointers already
 * in the store map need nothing; the rest are attributed to a
 * field by name (longest field-name suffix wins, e.g.
 * lpc43x0_attach -> attach, adiv5_swd_write_no_check ->
 * write_no_check) and merged into the offset map before pass 2,
 * so CALLIND may-sets gain them. Names matching no field are
 * listed as unattributed, never guessed. Command handlers
 * (cmd_*, exec_*, target_cmd_*, *_cmd_*) are excluded from
 * attribution by rule: they live in command tables, never in ops
 * structs, but their names end in field words. A second fix found
 * during v3.6 verification: stores are now recorded BOTH by exact
 * address and by field offset (dual recording) -- previously a
 * store whose address resolved went only to the exact map, hiding
 * DP init stores from every parameter-based site.
 * v3.7 (may false-positive fix): may-state values now carry
 * provenance (the ops that materialized their bits; pure
 * computation preserves it), and may-access recording drops a
 * value only when a feasibility-aware taint BFS proves no path
 * carries it to the use: taint flows where provenance flows
 * (COPY, value-preserving arithmetic), dies at LOADs, comparison
 * results and CALL-clobbered registers, and paths requiring the
 * same branch condition both ways (the correlated if/else-assign
 * pattern behind the rcc USART1 flag) are pruned. A value copied
 * to another varnode before its original is redefined survives
 * (the platform_init GPIOB case). Any doubt keeps the value, so
 * no true may-address is lost.
 * If the fixpoint does not converge within 100 rounds, every state is
 * reset to fully unknown (sound: fewer accesses recorded, never false
 * ones) and "fixpoint_converged" reports false for that function.
 * Remaining limits: path-INSENSITIVE (merge loses precision where paths
 * disagree -- a true access may be missed, never invented); no
 * inter-procedural analysis (callees are opaque beyond the clobber);
 * no RAM model (loads from RAM other than program memory read unknown);
 * indirect branches (BRANCHIND) have recovered TBB/TBH successors
 * (v3.3); other indirect branches still have no successors (sound
 * under-approximation: paths through them may be missed).
 *
 * Step 1 (ISA abstraction, behavior unchanged): all ARM-specific
 * knowledge now lives behind the IsaAdapter interface (ArmIsa):
 * caller-saved clobber set, register offsets (incl. lr), Thumb-bit
 * tagging, pointer size and pointer reads, jump-table recovery
 * (TBB/TBH), code-address formatting, and the MMIO window. The
 * fixpoints, may-analysis, points-to and tail-call logic operate
 * on P-Code through the interface only, so a future RiscVIsa can
 * plug in without touching them. The interface deliberately avoids
 * ARM-only concepts as requirements: no condition flags, no fixed
 * instruction size, no literal pools -- a RISC-V adapter returns
 * identity for the tag helpers and its own jump-table recovery.
 *
 * v3.15 adds BOUNDS evidence: a CFG must-fixpoint provenance scan per function
 * that records computed-pointer copy sites (memcpy/memmove where a
 * pointer argument is ADD(struct-field, function-argument offset)),
 * the unsound-check shape (an unsigned comparison of offset+size
 * against the same struct's size field), and sound-guard evidence
 * (signed offset-vs-0 check, wide ZEXT/SEXT check, or guard-call).
 * Emitted per function as "copy_sites" and top-level as "copy_sites"
 * + "copy_site_total" + "bounds_flagged_total"; the Lean verifier
 * gains a bounds verdict line in generic mode.
 * v3.16 extends the site set to cache-range transfers (address
 * argument = computed pointer) and adds the loop-rooted offset
 * form (ROOT: ARG plus loop accumulation, produced only by the
 * must-join of ARG with an ADD-chain rooted in it), plus a
 * per-kind pointer-form census ("transfer_call_forms"). See
 * ~/workspace/v24-bounds/design.md for semantics and limits.
 * Version bump v3.14 -> v3.15 because report JSON gains fields.
 */
public class ExtractIR extends GhidraScript {

    private static final int MAX_PCODE_PER_FUNCTION = 5000;
    private static final int MAX_STRINGS = 10000;
    private static final int MAX_FIXPOINT_ROUNDS = 100;

    // ---------------- Step 1: ISA abstraction ----------------
    // All ISA-specific knowledge lives behind IsaAdapter; the rest
    // of ExtractIR operates on P-Code through this interface only.
    // A future RiscVIsa plugs in here: it returns identity for the
    // tag helpers (no Thumb bit), its own caller-saved set and
    // return register (ra), its pointer size, and its own
    // jump-table recovery (auipc+addi+jalr chains). Nothing in this
    // interface requires condition flags, a fixed instruction size,
    // or literal pools.
    private interface IsaAdapter {
        /** Short name, e.g. "ARM". */
        String name();
        /** Ghidra register-space name ("register" on ARM). */
        String registerSpaceName();
        /** Register offsets clobbered by CALL/CALLIND (caller-saved). */
        long[] callerSavedRegisterOffsets();
        /** Offset of the return-address register (ARM lr). */
        long returnAddressRegisterOffset();
        /** True when this varnode is the return-address register. */
        boolean isReturnAddressRegister(Varnode v);
        /** Strip instruction-address tagging (ARM Thumb bit). */
        long stripInstructionTag(long addr);
        /** True when a constant masks off instruction tagging (ARM &~1). */
        boolean isInstructionTagMask(long constValue);
        /** Size of a code/data pointer in bytes (ARM: 4). */
        int pointerSize();
        /** Shift for pointer-index scaling (ARM: 2, since 2^2 == 4). */
        int pointerIndexShift();
        /** Read one pointer-sized word from program memory. */
        long readPointer(Memory mem, Address addr) throws Exception;
        /** Format a code address the way instruction addresses print. */
        String formatCodeAddress(long addr);
        /** True when an address is in the ISA's peripheral/MMIO window. */
        boolean isMmioAddress(long addr);
        /** Window kinds (Phase 4, vendor-neutral): a window is a
            declared band the lens records, with a role, not
            hardcoded per-device logic. Two kinds exist: the
            peripheral window (device MMIO) and the
            INTERNAL-PERIPHERAL window (core-private config space
            such as ARM's Private Peripheral Bus). The ARM PPB band
            below is the FIRST instantiation of the internal kind;
            other ISAs instantiate it only when they have such a
            band. The band is a LENS window only: PPB accesses are
            judged by the boundary property's configurator/PPB rule,
            not by the generic window rule. */
        /** The ISA's peripheral/MMIO bands as [start, end) pairs,
            in the same order isMmioAddress tests them (ARM: the
            Cortex-M window plus the internal-peripheral PPB band;
            RISC-V/MIPS: the configured band list).
            Emitted into the report as "mmio_windows" so the Lean
            verifier can check the trace against the platform's bands
            instead of a hardcoded ARM window. */
        List<long[]> mmioWindows();
        /** Recover jump-table successors for BRANCHINDs (ARM: TBB/TBH). */
        Map<Integer, List<Integer>> recoverJumpTableTargets(
            List<OpRec> ops, Memory mem);
        /** Fallthrough successor op index for a CBRANCH/CALL op
            (default: the next op). MIPS overrides this to skip the
            delay-slot instruction's standalone ops: Ghidra embeds the
            delay slot's P-Code in the branch/call P-Code already, so
            the standalone copy must not be re-executed on the
            fallthrough path (it would double-apply delay-slot writes
            and resurrect caller-saved registers after calls). Returns
            -1 when there is no fallthrough successor. */
        int fallthroughIndex(List<OpRec> ops, int i);
        /** Unwrap ISA-specific wrappers around an indirect-branch
            target before def-chain walks (MIPS: the pc COPY +
            AND-~1 from jr/jalr P-Code). ARM/RISC-V return the input
            def unchanged. Never returns -1 for a valid input def. */
        int unwrapIndirectDef(List<OpRec> ops, int brIdx, int cur);
        /** True when this ISA has overlapping register views (x86:
            al/ax/eax/rax share storage, so a write to one view must
            invalidate the others). ARM/RISC-V/MIPS return false. */
        boolean hasOverlappingRegisters();
        /** Caller-saved register offsets for a callee whose Ghidra
            calling-convention name is conv (null = unknown callee:
            the conservative union). Single-convention adapters ignore
            conv and return callerSavedRegisterOffsets(); x86 maps
            the name to its ABI set (System V / Windows) and falls back
            to the binary default for unknown names. */
        long[] clobberForConvention(String conv);
        /** Argument register offsets for a callee whose Ghidra
            calling-convention name is conv (v2 item #2:
            inter-procedural constant propagation). Returns null
            when the argument registers cannot be determined
            (x86-64 unknown convention): such a call site is
            UNMODELLED and poisons the callee's entry -- never a
            guess. (The clobber union is sound for KILLING but
            unsound for READING arguments: e.g. RCX is arg0 under
            Windows but arg3 under System V, so a union read
            would mix conventions and corrupt must-facts.)
            Returns an empty array when arguments are not passed
            in registers at all (x86-32: stack args) -- propagation
            is then a no-op for that callee. Single-convention
            adapters ignore conv. */
        long[] argumentRegisterOffsets(String conv);
        /** Offset of the register a callee's return value is left
            in (v8 retprop): ARM r0, RISC-V a0 (x10), MIPS v0 ($2),
            x86 RAX/EAX. Always a pointer-size register, so a
            return summary is a single Bits at pointer size. */
        long returnRegisterOffset();
    }

    // Selected in run() from the program's processor (default ARM:
    // the pre-step-1 behaviour). RISC-V programs get a RiscVIsa,
    // MIPS programs a MipsIsa, x86 programs an X86Isa.
    private IsaAdapter isa = new ArmIsa();

    /** Memory-propagation stack registers (set in run() before any
        fixpoint runs; -1 = that leg disabled). The stack pointer
        (RSP/SP) is never a general register on any supported ISA;
        the frame pointer leg is enabled only for unambiguous names
        (RBP/FP) -- R11/S0 double as general registers, so they are
        deliberately NOT used as frame pointers here. A store whose
        address def-chain reaches SP/FP is a stack store and can
        never alias a global (same assumption as Prov's rbpSlotOf:
        RBP is the frame pointer, stable after the prologue). */
    private long memSpOff = -1L;
    private long memFpOff = -1L;
    /** Program endianness (for memState byte slicing on loads
        whose size differs from the stored size). */
    private boolean memBigEndian = false;

    /** Per-callee Ghidra calling-convention names, keyed by
        function entry-point offset (ram space only). Built in
        run() before the function loop. A missing entry means
        "unknown callee" and falls back to the conservative union
        via clobberForConvention(null), never a guess. For
        single-convention adapters the name is ignored, so the
        map is semantically inert for ARM/RISC-V/MIPS. */
    private Map<Long, String> callConvMap =
        new HashMap<Long, String>();

    /** v8 retprop: return summaries by callee entry key (dual-keyed
        with the stripped entry key, like funcByEntry, so the CALL
        branch can apply a summary from the raw call target alone).
        Empty during Phase B; set by Phase R before Phase P/M, so
        Phase M's re-runs apply the final summaries too. A summary
        is a single Bits at pointer size: an exact constant, or a
        BAR/BASE symbol. CALLIND never consults this map. */
    private Map<Long, Bits> retSummaries =
        new HashMap<Long, Bits>();

    /** v8 retprop (Prov): interface return summaries by callee
        entry key (dual-keyed like retSummaries). Empty outside
        Phase P2 (x86-64 only); set by Phase P2 before emission,
        so member-call resolution in callers sees interfaces
        returned by helpers. Only IFACE summaries exist (see
        extractProvSummaries). */
    private Map<Long, Prov> provSummaries =
        new HashMap<Long, Prov>();

    /** v9 struct: field summaries by callee entry key (dual-keyed
        like retSummaries). Each value maps "delta:size" -> Bits:
        the field values the callee stored into the object it
        returns, agreed on ALL its RETURN ops (see
        extractStructSummaries). Empty outside Phase S; set by
        Phase S before Phase M, so Phase M's re-runs apply the
        final summaries automatically (same instance field) and
        the callers' field loads resolve. */
    private Map<Long, Map<String, Bits>> structSummaries =
        new HashMap<Long, Map<String, Bits>>();

    /** v9 struct (Prov): struct-layout summaries by callee entry
        key (dual-keyed like provSummaries). Each value is the
        STRUCT provenance the callee returns, agreed on ALL its
        RETURN ops (see extractStructProvSummaries). Empty outside
        Phase S-Prov; set by Phase S-Prov before emission, so
        member-call resolution in callers sees interfaces stored
        into fields of structs returned by helpers. */
    private Map<Long, Prov> structProvSummaries =
        new HashMap<Long, Prov>();

    /** Caller-saved set for a CALL/CALLIND op: for direct CALLs
        to a known function, the per-callee Ghidra convention
        (signature-driven, x86); otherwise the conservative union
        (clobberForConvention(null)). For ARM/RISC-V/MIPS this
        is behaviour-identical to callerSavedRegisterOffsets(). */
    private long[] clobberForCall(OpRec op) {
        if (op.mnem.equals("CALL") && op.ins.length >= 1) {
            Varnode t = op.ins[0];
            if (t != null && t.getAddress() != null &&
                "ram".equals(t.getAddress().getAddressSpace().
                    getName())) {
                String conv = callConvMap.get(t.getOffset());
                if (conv != null) {
                    return isa.clobberForConvention(conv);
                }
            }
        }
        return isa.clobberForConvention(null);
    }

    // ---------------- v13 clobber refinement ----------------
    // Until v12, every CALL killed the whole caller-saved set,
    // even when the callee never touches most of it. That killed
    // real values: QemuVideoDxe's generic helper (per-site clones
    // for CF8/CFC) lost its config address in RCX across an inner
    // CALL, so its IN stayed unknown. This slice refines the kill
    // to what the callee provably may write.
    //
    // MECHANISM (i): per-callee may-write sets. For each function,
    // the union of its own register-writing op outputs, plus the
    // may-write sets of its direct-call and resolved tail-call
    // targets, iterated to a fixpoint over the call graph. A
    // caller-saved register is preserved across a direct CALL iff
    // NO written interval overlaps the register's whole interval
    // [c, c+pointerSize): a partial (sub-register) write still
    // clobbers the whole register -- preserving a partially
    // written register would keep stale bytes, so the rule is
    // whole-register or nothing. (A future sub-view refinement
    // could preserve untouched bytes; not this slice.)
    //
    // SOUNDNESS: the may-write set is a may-analysis (union over
    // all ops, all paths). If a register is absent from it, NO
    // path through the callee writes it, so the caller's value
    // provably survives. Anything unknown TAINTS the function
    // (may write everything): external/empty callees, CALLIND
    // inside, direct calls to unknown addresses, unresolved tail
    // calls, ambiguous tail-target names. Taint propagates along
    // call edges. Indirect calls at the CALL site itself stay
    // fully conservative (no callee, no refinement).
    //
    // MECHANISM (ii) (callee-saved preservation) is NOT built
    // here: the convention sets already exclude callee-saved
    // registers, so they already survive calls. What is NOT
    // modeled: balanced push/pop of a CALLER-saved register
    // inside the callee -- the pop IS a write, so the register
    // still counts as may-written and stays clobbered. That is a
    // documented completeness loss (sound direction), not a bug:
    // a future save/restore analysis could recover it.
    //
    // SCOPE: must transfer only (applyTransfer). The may and
    // taint transfers keep the full conservative kill: growing
    // may sets could break Lean may-confinement verdicts, and
    // that interaction needs its own slice. Per-site clones use
    // the same applyTransfer, so refinement composes with
    // per-site automatically (the QemuVideo case IS a clone's
    // value surviving an inner CALL). The stack pointer, return
    // address, config latch and memState are untouched by this
    // slice: a callee may still reprogram config space and store
    // globals, so those die at calls exactly as before.
    //
    // RESIDUAL (same honesty policy as the rest of the engine):
    // refinement trusts Ghidra's lift completeness -- an
    // instruction Ghidra fails to lift contributes no output to
    // the may-write set. That trust is shared by every other
    // analysis in this file.
    private static class ClobberRef {
        // Callee address (dual-keyed raw + stripped entry offset,
        // like retSummaries) -> written register intervals, each
        // encoded as (off << 32) | (size & 0xffffffffL).
        Map<Long, Set<Long>> writes = new HashMap<Long, Set<Long>>();
        // Callee addresses that may write anything.
        Set<Long> tainted = new HashSet<Long>();
    }
    private ClobberRef clobberRef = null;

    /** v13: refined caller-saved set for a CALL op: the convention
        set minus registers the callee provably never writes (no
        written interval overlaps the register's whole interval).
        CALLIND, unknown callees, tainted callees, and a null map
        all fall back to the full conservative set. */
    private long[] refinedClobberForCall(OpRec op) {
        long[] base = clobberForCall(op);
        if (clobberRef == null) return base;
        if (!op.mnem.equals("CALL") || op.ins.length < 1) return base;
        Varnode t = op.ins[0];
        if (t == null || t.getAddress() == null ||
            !"ram".equals(t.getAddress().getAddressSpace().
                getName())) {
            return base;
        }
        Set<Long> w = clobberRef.writes.get(t.getOffset());
        if (w == null) {
            w = clobberRef.writes.get(
                isa.stripInstructionTag(t.getOffset()));
        }
        if (w == null || clobberRef.tainted.contains(t.getOffset()) ||
            clobberRef.tainted.contains(
                isa.stripInstructionTag(t.getOffset()))) {
            return base;
        }
        int ps = isa.pointerSize();
        List<Long> kept = new ArrayList<Long>();
        for (long c : base) {
            boolean hit = false;
            for (Long enc : w) {
                long o = enc.longValue() >>> 32;
                long s = enc.longValue() & 0xffffffffL;
                if (o < c + ps && c < o + s) { hit = true; break; }
            }
            if (hit) kept.add(c);
        }
        long[] r = new long[kept.size()];
        for (int i = 0; i < kept.size(); i++) r[i] = kept.get(i);
        return r;
    }

    /** v13: true when a BRANCHIND is a return through the ISA's
        return-address register (directly, or through one COPY
        hop), mirroring recoverTailCalls' isReturn classification.
        Other BRANCHIND shapes fall through to the taint rule in
        computeClobberRef (sound: an unclassified branch may leave
        the function). */
    private boolean isReturnBranch(OpRec op, List<OpRec> pops,
        int opIdx) {
        if (op.ins.length < 1) return false;
        Varnode dest = op.ins[0];
        if (isa.isReturnAddressRegister(dest)) return true;
        int def = findDef(pops, vkey(dest), opIdx);
        if (def >= 0) {
            OpRec dd = pops.get(def);
            if (dd.mnem.equals("COPY") && dd.ins.length == 1 &&
                isa.isReturnAddressRegister(dd.ins[0])) return true;
        }
        return false;
    }

    /** v13: parse a function's TailCallResult.sites JSON strings
        into instr-string -> target-name lists. Unparseable sites
        are absent from the map (callers treat absence as
        unresolvable, i.e. taint). An empty target list also
        counts as unresolvable at the use site. */
    private static Map<String, List<String>> parseTailSites(
        TailCallResult tc) {
        Map<String, List<String>> m =
            new HashMap<String, List<String>>();
        if (tc == null || tc.sites == null) return m;
        for (String s : tc.sites) {
            try {
                int ii = s.indexOf("\"instr\": \"");
                if (ii < 0) continue;
                int a = ii + 10;
                int b = s.indexOf("\"", a);
                if (b < 0) continue;
                String instr = s.substring(a, b);
                int ti = s.indexOf("\"targets\": [", b);
                if (ti < 0) continue;
                List<String> names = new ArrayList<String>();
                int p = ti + 12;
                while (true) {
                    int cb = s.indexOf("]", p);
                    int q1 = s.indexOf("\"", p);
                    if (q1 < 0 || (cb >= 0 && cb < q1)) break;
                    int q2 = s.indexOf("\"", q1 + 1);
                    if (q2 < 0) break;
                    names.add(s.substring(q1 + 1, q2).
                        replace("\\\"", "\"").
                        replace("\\\\", "\\"));
                    p = q2 + 1;
                }
                m.put(instr, names);
            } catch (Exception e) {
                // Absent from the map -> taint. Sound.
            }
        }
        return m;
    }

    /** v13: compute per-callee may-write register sets over the
        whole program. Direct writes come from raw op outputs
        (complete w.r.t. lifted P-Code, not w.r.t. modeled
        transfers); edges come from direct CALLs and resolved
        tail calls; taint covers everything unknown. The result
        is stored in the instance field before Phase B, so every
        fixpoint (merged and per-site clones alike) refines its
        CALL kills through refinedClobberForCall. */
    private ClobberRef computeClobberRef(List<FuncRec> funcRecs,
        Map<Long, FuncRec> funcByEntry) {
        ClobberRef ref = new ClobberRef();
        String space = isa.registerSpaceName();
        Map<String, FuncRec> byName = new HashMap<String, FuncRec>();
        Set<String> ambiguousNames = new HashSet<String>();
        for (FuncRec rec : funcRecs) {
            String n;
            try { n = rec.f.getName(); } catch (Exception e) {
                continue;
            }
            if (byName.containsKey(n)) ambiguousNames.add(n);
            else byName.put(n, rec);
        }
        Map<Long, Set<Long>> direct = new HashMap<Long, Set<Long>>();
        Map<Long, Set<Long>> edges = new HashMap<Long, Set<Long>>();
        Set<Long> tainted = new HashSet<Long>();
        for (FuncRec rec : funcRecs) {
            long ek = rec.entryKey;
            List<OpRec> pops = rec.or.ops;
            Set<Long> dw = new HashSet<Long>();
            Set<Long> ed = new HashSet<Long>();
            boolean taint = false;
            try {
                if (rec.f.isExternal()) taint = true;
            } catch (Exception e) {
                taint = true;
            }
            if (pops == null || pops.isEmpty()) taint = true;
            Map<String, List<String>> tailSites =
                parseTailSites(rec.tc);
            for (int i = 0; pops != null && i < pops.size(); i++) {
                OpRec op = pops.get(i);
                if (op.out != null && op.out.getAddress() != null &&
                    space.equals(op.out.getAddress().
                        getAddressSpace().getName())) {
                    dw.add((op.out.getOffset() << 32) |
                        (op.out.getSize() & 0xffffffffL));
                }
                if (op.mnem.equals("CALL")) {
                    if (op.ins.length < 1) { taint = true; continue; }
                    Varnode tt = op.ins[0];
                    if (tt == null || tt.getAddress() == null ||
                        !"ram".equals(tt.getAddress().
                            getAddressSpace().getName())) {
                        taint = true; continue;
                    }
                    FuncRec callee = funcByEntry.get(tt.getOffset());
                    if (callee == null) {
                        callee = funcByEntry.get(
                            isa.stripInstructionTag(tt.getOffset()));
                    }
                    if (callee == null) taint = true;
                    else ed.add(callee.entryKey);
                } else if (op.mnem.equals("CALLIND")) {
                    taint = true;
                } else if (op.mnem.equals("BRANCHIND")) {
                    if (rec.ind != null &&
                        rec.ind.resolvedBranchInds != null &&
                        rec.ind.resolvedBranchInds.contains(i)) {
                        continue;
                    }
                    if (rec.branchTargets != null &&
                        rec.branchTargets.containsKey(i)) {
                        continue;
                    }
                    if (isReturnBranch(op, pops, i)) continue;
                    List<String> names =
                        tailSites.get(op.instrAddr.toString());
                    if (names == null || names.isEmpty()) {
                        taint = true; continue;
                    }
                    boolean ok = true;
                    for (String nm : names) {
                        if (ambiguousNames.contains(nm)) {
                            ok = false; break;
                        }
                        FuncRec g = byName.get(nm);
                        if (g == null) { ok = false; break; }
                        ed.add(g.entryKey);
                    }
                    if (!ok) taint = true;
                }
            }
            direct.put(ek, dw);
            edges.put(ek, ed);
            if (taint) tainted.add(ek);
        }
        Map<Long, Set<Long>> writes = new HashMap<Long, Set<Long>>();
        for (Long ek : direct.keySet()) {
            writes.put(ek, new HashSet<Long>(direct.get(ek)));
        }
        boolean changed = true;
        int rounds = 0;
        while (changed && rounds < 1000) {
            changed = false;
            rounds++;
            for (Long ek : direct.keySet()) {
                Set<Long> w = writes.get(ek);
                for (Long g : edges.get(ek)) {
                    if (tainted.contains(g) &&
                        !tainted.contains(ek)) {
                        tainted.add(ek);
                        changed = true;
                    }
                    if (w.addAll(writes.get(g))) changed = true;
                }
            }
        }
        if (rounds >= 1000) {
            // Safety fallback, should never trigger: taint all.
            for (Long ek : direct.keySet()) tainted.add(ek);
        }
        for (Long ek : direct.keySet()) {
            ref.writes.put(ek, writes.get(ek));
            long st = isa.stripInstructionTag(ek.longValue());
            if (st != ek.longValue()) ref.writes.put(st, writes.get(ek));
            if (tainted.contains(ek)) {
                ref.tainted.add(ek);
                if (st != ek.longValue()) ref.tainted.add(st);
            }
        }
        // Publish before counting: the count itself refines calls.
        clobberRef = ref;
        int refinedCalls = 0;
        int totalCalls = 0;
        for (FuncRec rec : funcRecs) {
            List<OpRec> pops = rec.or.ops;
            if (pops == null) continue;
            for (OpRec op : pops) {
                if (!op.mnem.equals("CALL")) continue;
                totalCalls++;
                long[] b = clobberForCall(op);
                long[] r = refinedClobberForCall(op);
                if (r.length < b.length) refinedCalls++;
            }
        }
        println("[*] clobber: funcs=" + direct.size() +
            " tainted=" + tainted.size() +
            " direct-calls=" + totalCalls +
            " refined-calls=" + refinedCalls);
        return ref;
    }

    /** ARM (Cortex-M, Thumb) adapter: holds every ARM-specific fact. */
    private class ArmIsa implements IsaAdapter {
        public String name() { return "ARM"; }
        public String registerSpaceName() { return "register"; }
        public long[] callerSavedRegisterOffsets() {
            // AAPCS caller-saved registers. Ghidra ARM offsets
            // (rN = 0x20 + 4N): r0=32, r1=36, r2=40, r3=44, r12=80.
            // Callee-saved r4-r11 and sp are preserved; lr is NOT
            // clobbered: Ghidra's own P-Code models it.
            return new long[] {32L, 36L, 40L, 44L, 80L};
        }
        public long returnAddressRegisterOffset() { return 0x58L; }
        public boolean isReturnAddressRegister(Varnode v) {
            return v != null && v.getAddress() != null &&
                registerSpaceName().equals(
                    v.getAddress().getAddressSpace().getName()) &&
                v.getOffset() == returnAddressRegisterOffset();
        }
        public long stripInstructionTag(long addr) { return addr & ~1L; }
        public boolean isInstructionTagMask(long constValue) {
            return (constValue & 0xFFFFFFFFL) == 0xFFFFFFFEL;
        }
        public int pointerSize() { return 4; }
        public int pointerIndexShift() { return 2; }
        public long readPointer(Memory mem, Address addr) throws Exception {
            return mem.getInt(addr) & 0xffffffffL;
        }
        public String formatCodeAddress(long addr) {
            return String.format("%08x", addr);
        }
        public boolean isMmioAddress(long addr) {
            // ARM Cortex-M peripheral region, plus the two
            // RP2040 blocks that live outside it (Phase 3
            // item 6, profile bounds from the RP2040 SVD
            // profile: SIO 0xD0000000-0xD0000180, SSI
            // 0x18000000-0x180000FC). A window extension is
            // sound in the must direction (it can only ADD
            // recordings for addresses the code provably
            // touches); the regression measures whether any
            // non-RP2040 ARM target touches these ranges.
            // Phase 4 adds the PPB band (see
            // internalPeripheralWindow, the generic
            // internal-peripheral-window kind's first
            // instantiation); PPB accesses are judged by the
            // boundary property, not the generic window rule.
            return (addr >= 0x40000000L && addr < 0x60000000L) ||
                (addr >= 0xD0000000L && addr < 0xD0000180L) ||
                (addr >= 0x18000000L && addr < 0x18000100L) ||
                (addr >= 0xE0000000L && addr < 0xE0100000L);
        }
        /** Phase 4 (PPB BAND FIRST): the ARM Private Peripheral
            Bus band, the first instantiation of the generic
            internal-peripheral-window kind. SAU/MPU/NVIC/SCB
            registers live here (0xE0000000-0xE00FFFFF); without
            this band the lens records NONE of them, so
            config-register writes are invisible by construction
            (the design's PPB gap). Sound in the must direction
            (it can only ADD recordings); the Phase 4 regression
            measures and explains every new recording. */
        public static long[] internalPeripheralWindow() {
            return new long[] {0xE0000000L, 0xE0100000L};
        }
        public List<long[]> mmioWindows() {
            List<long[]> wins = new ArrayList<long[]>();
            wins.add(new long[] {0x40000000L, 0x60000000L});
            wins.add(new long[] {0xD0000000L, 0xD0000180L});
            wins.add(new long[] {0x18000000L, 0x18000100L});
            wins.add(internalPeripheralWindow());
            return wins;
        }
        public int fallthroughIndex(List<OpRec> ops, int i) {
            return i + 1 < ops.size() ? i + 1 : -1;
        }
        public int unwrapIndirectDef(List<OpRec> ops, int brIdx, int cur) {
            return cur;
        }
        public boolean hasOverlappingRegisters() { return false; }
        public long[] clobberForConvention(String conv) {
            return callerSavedRegisterOffsets();
        }
        public long[] argumentRegisterOffsets(String conv) {
            // AAPCS r0-r3 (Ghidra ARM offsets rN = 0x20 + 4N,
            // verified by probe: r0=32, r1=36, r2=40, r3=44).
            return new long[] {32L, 36L, 40L, 44L};
        }
        public long returnRegisterOffset() {
            // AAPCS return register is r0.
            return 32L;
        }
        /** ARM TBB/TBH jump-table recovery (v3.3), implementing
        IsaAdapter.recoverJumpTableTargets.
            Pattern (Ghidra ARM P-Code, verified on BMP):
              COPY index -> U1
              INT_ADD [const BASE, U1] -> U1
              LOAD [ram, U1] -> U2            (output size 1 = TBB, 2 = TBH)
              INT_ZEXT [U2] -> U1
              INT_MULT [U1, const 2] -> U3
              INT_ADD [const BASE, U3] -> pc
              BRANCHIND [pc]
            Targets = BASE + 2*entry for each table entry. Returns a map
            from BRANCHIND op index to successor op indices (empty for
            non-matching BRANCHINDs). */
        public Map<Integer, List<Integer>> recoverJumpTableTargets(
            List<OpRec> ops, Memory mem) {
            Map<Integer, List<Integer>> result =
                new HashMap<Integer, List<Integer>>();
            if (ops.isEmpty()) return result;
            Map<String, Integer> firstAt = new HashMap<String, Integer>();
            long maxAddr = 0;
            for (int i = 0; i < ops.size(); i++) {
                String a = ops.get(i).instrAddr.toString();
                if (!firstAt.containsKey(a)) firstAt.put(a, i);
                try {
                    long v = Long.parseLong(a, 16);
                    if (v > maxAddr) maxAddr = v;
                } catch (Exception e) {
                    // Ignore unparseable addresses.
                }
            }
            for (int i = 0; i < ops.size(); i++) {
                OpRec br = ops.get(i);
                if (!br.mnem.equals("BRANCHIND") || br.ins.length < 1) continue;
                int defPc = findDef(ops, vkey(br.ins[0]), i);
                if (defPc < 0) continue;
                OpRec addFinal = ops.get(defPc);
                if (!addFinal.mnem.equals("INT_ADD") ||
                    addFinal.ins.length != 2) continue;
                Long base = null;
                String prodKey = null;
                for (int s = 0; s < 2; s++) {
                    Varnode v = addFinal.ins[s];
                    if (v.isConstant()) {
                        base = v.getOffset();
                    } else {
                        prodKey = vkey(v);
                    }
                }
                if (base == null || prodKey == null) continue;
                int defProd = findDef(ops, prodKey, defPc);
                if (defProd < 0) continue;
                OpRec mult = ops.get(defProd);
                if (!mult.mnem.equals("INT_MULT") || mult.ins.length != 2) continue;
                String entryKey = null;
                boolean timesTwo = false;
                for (int s = 0; s < 2; s++) {
                    Varnode v = mult.ins[s];
                    if (v.isConstant() && v.getOffset() == 2L) {
                        timesTwo = true;
                    } else {
                        entryKey = vkey(v);
                    }
                }
                if (!timesTwo || entryKey == null) continue;
                int defEntry = findDef(ops, entryKey, defProd);
                if (defEntry < 0) continue;
                OpRec zext = ops.get(defEntry);
                if (!zext.mnem.equals("INT_ZEXT") || zext.ins.length != 1) continue;
                int defLoad = findDef(ops, vkey(zext.ins[0]), defEntry);
                if (defLoad < 0) continue;
                OpRec load = ops.get(defLoad);
                if (!load.mnem.equals("LOAD") || load.ins.length < 2 ||
                    load.out == null) continue;
                int entrySize = load.out.getSize();
                if (entrySize != 1 && entrySize != 2) continue;
                int defLoadAddr = findDef(ops, vkey(load.ins[1]), defLoad);
                if (defLoadAddr < 0) continue;
                OpRec addLoad = ops.get(defLoadAddr);
                if (!addLoad.mnem.equals("INT_ADD") ||
                    addLoad.ins.length != 2) continue;
                Long base2 = null;
                for (int s = 0; s < 2; s++) {
                    Varnode v = addLoad.ins[s];
                    if (v.isConstant()) base2 = v.getOffset();
                }
                if (base2 == null ||
                    base2.longValue() != base.longValue()) continue;
                // Pattern matched: read the table.
                List<Integer> targets = new ArrayList<Integer>();
                long minTarget = Long.MAX_VALUE;
                for (int k = 0; k < 64; k++) {
                    long entryAddr = base.longValue() + (long) k * entrySize;
                    if (k > 0 && entryAddr >= minTarget) break;
                    if (entryAddr > maxAddr) break;
                    long entry;
                    try {
                        Address ad = toAddr(entryAddr);
                        if (entrySize == 1) {
                            entry = mem.getByte(ad) & 0xffL;
                        } else {
                            entry = mem.getShort(ad) & 0xffffL;
                        }
                    } catch (Exception e) {
                        break;
                    }
                    long target = base.longValue() + 2L * entry;
                    if (target < minTarget) minTarget = target;
                    Integer j = firstAt.get(formatCodeAddress(target));
                    if (j == null) {
                        j = firstAt.get(formatCodeAddress(stripInstructionTag(target)));
                    }
                    if (j != null && !targets.contains(j)) targets.add(j);
                }
                if (!targets.isEmpty()) result.put(i, targets);
            }
            return result;
        }
    }

    /** RISC-V adapter (RV32 first; RV64 via the width flag, structural
        only -- untested, see below). All facts are EMPIRICAL
        (Ghidra 11.4.2 RISCV sleigh + probe runs on a real RV32IMC
        binary), not from memory:
        - Language auto-detected on import: RISCV:LE:32:RV32IMC.
        - Register space "register", base 0x2000, stride XLEN:
          x0 zero 0x2000, x1 ra, x2 sp, x3 gp, x4 tp, x5-x7 t0-t2,
          x8-x9 s0-s1, x10-x17 a0-a7, x18-x27 s2-s11, x28-x31 t3-t6.
        - Caller-saved per the RISC-V ABI: t0-t6, a0-a7. ra is
          EXCLUDED: Ghidra's jal P-Code COPYs the return address into
          ra before the CALL op (verified in the probe dump), exactly
          like ARM's lr handling -- clobbering it would lose the known
          return address and break return detection.
        - No instruction-address tagging (no Thumb bit); compressed
          instructions lift to ordinary P-Code, so nothing special.
        - Constant materialization: lui = INT_LEFT [imm, 12] (+ COPY);
          auipc = INT_LEFT [imm, 12] + INT_ADD [that, PC-const];
          addi = INT_ADD. All constant-foldable (see constFold).
        - Jump tables hold ABSOLUTE pointers (non-PIC) or base-relative
          OFFSETS (PIC: target = base + loaded). Same-function entries
          become CFG successors here; cross-function entries are left
          for recoverIndirect (pointer-table edges). RV64 note: the
          width flag sets stride/pointer/shift, but RV64 offset tables
          (32-bit offsets via lw) do not match the pointer-sized LOAD
          check -- RV64 jump-table recovery is untested. */
    private class RiscVIsa implements IsaAdapter {
        private final int stride;       // 4 (RV32) or 8 (RV64)
        private final int ptrSize;      // 4 or 8
        private final int ptrShift;     // 2 or 3
        private final long addrMask;    // 0xffffffffL or -1L
        private final List<long[]> mmioWindows;

        RiscVIsa(boolean is64, List<long[]> windows) {
            stride = is64 ? 8 : 4;
            ptrSize = is64 ? 8 : 4;
            ptrShift = is64 ? 3 : 2;
            addrMask = is64 ? -1L : 0xffffffffL;
            mmioWindows = windows;
        }

        private long reg(int n) { return 0x2000L + (long) stride * n; }

        public String name() { return "RISCV"; }
        public String registerSpaceName() { return "register"; }
        public long[] callerSavedRegisterOffsets() {
            // t0-t2 (x5-x7), a0-a7 (x10-x17), t3-t6 (x28-x31).
            int[] nums = {5, 6, 7, 10, 11, 12, 13, 14, 15, 16, 17,
                28, 29, 30, 31};
            long[] offs = new long[nums.length];
            for (int i = 0; i < nums.length; i++) offs[i] = reg(nums[i]);
            return offs;
        }
        public long returnAddressRegisterOffset() { return reg(1); }
        public boolean isReturnAddressRegister(Varnode v) {
            return v != null && v.getAddress() != null &&
                registerSpaceName().equals(
                    v.getAddress().getAddressSpace().getName()) &&
                v.getOffset() == returnAddressRegisterOffset();
        }
        public long stripInstructionTag(long addr) { return addr; }
        public boolean isInstructionTagMask(long constValue) { return false; }
        public int pointerSize() { return ptrSize; }
        public int pointerIndexShift() { return ptrShift; }
        public long readPointer(Memory mem, Address addr) throws Exception {
            if (ptrSize == 8) return mem.getLong(addr);
            return mem.getInt(addr) & 0xffffffffL;
        }
        public String formatCodeAddress(long addr) {
            return String.format("%08x", addr);
        }
        public boolean isMmioAddress(long addr) {
            // RISC-V has no fixed peripheral window (unlike ARM
            // Cortex-M): the map is platform-specific. These default
            // bands cover the common families without overlapping
            // their flash/RAM (see defaultRiscvMmioWindows); a caller
            // may override them with the mmio= script argument, and
            // the SVD-profile classifier remains the authority on
            // known-vs-suspect peripherals.
            for (long[] w : mmioWindows) {
                if (addr >= w[0] && addr < w[1]) return true;
            }
            return false;
        }
        public List<long[]> mmioWindows() {
            return mmioWindows;
        }
        public int fallthroughIndex(List<OpRec> ops, int i) {
            return i + 1 < ops.size() ? i + 1 : -1;
        }
        public int unwrapIndirectDef(List<OpRec> ops, int brIdx, int cur) {
            return cur;
        }
        public boolean hasOverlappingRegisters() { return false; }
        public long[] clobberForConvention(String conv) {
            return callerSavedRegisterOffsets();
        }
        public long[] argumentRegisterOffsets(String conv) {
            // RISC-V calling convention: a0-a7 = x10-x17
            // (probe-verified: a0 = 0x2000 + stride*10).
            long[] offs = new long[8];
            for (int i = 0; i < 8; i++) offs[i] = reg(10 + i);
            return offs;
        }
        public long returnRegisterOffset() {
            // Return register is a0 = x10.
            return reg(10);
        }
        public Map<Integer, List<Integer>> recoverJumpTableTargets(
            List<OpRec> ops, Memory mem) {
            Map<Integer, List<Integer>> result =
                new HashMap<Integer, List<Integer>>();
            if (ops.isEmpty()) return result;
            Map<String, Integer> firstAt = new HashMap<String, Integer>();
            for (int i = 0; i < ops.size(); i++) {
                String a = ops.get(i).instrAddr.toString();
                if (!firstAt.containsKey(a)) firstAt.put(a, i);
            }
            for (int i = 0; i < ops.size(); i++) {
                OpRec br = ops.get(i);
                if (!br.mnem.equals("BRANCHIND") || br.ins.length < 1) continue;
                TableMatch m = matchBranchTable(ops, i, ptrSize, ptrShift,
                    addrMask);
                if (m == null) continue;
                List<Integer> targets = new ArrayList<Integer>();
                for (int k = 0; k < 64; k++) {
                    long entryAddr = m.base + (long) ptrSize * k;
                    long entry;
                    try {
                        entry = readPointer(mem, toAddr(entryAddr));
                    } catch (Exception e) {
                        break;
                    }
                    long t;
                    if (m.offset) {
                        t = (m.base + (int) entry) & addrMask;
                    } else {
                        t = stripInstructionTag(entry);
                    }
                    Integer j = firstAt.get(formatCodeAddress(t));
                    if (j == null) break;
                    if (!targets.contains(j)) targets.add(j);
                }
                if (!targets.isEmpty()) result.put(i, targets);
            }
            return result;
        }
    }

    /** MIPS32 adapter (MIPS64 structural via the width flag, untested).
        All facts are EMPIRICAL (Ghidra 11.4.2 MIPS sleigh + probe runs
        on a real MIPS32BE binary), not from memory:
        - Language auto-detected on import: MIPS:BE:32:default.
        - Register space "register", $n at 4n: $zero 0x0, $at 0x4,
          $v0-$v1 0x8-0xc, $a0-$a3 0x10-0x1c, $t0-$t7 0x20-0x3c,
          $s0-$s7 0x40-0x5c, $t8-$t9 0x60-0x64, $k0-$k1 0x68-0x6c,
          $gp 0x70, $sp 0x74, $s8/$fp 0x78, $ra 0x7c, $pc 0x80.
        - Caller-saved per the o32 ABI: $at, $v0-$v1, $a0-$a3,
          $t0-$t7, $t8-$t9. $ra is EXCLUDED: Ghidra's jal/jalr P-Code
          COPYs the return address into ra before the CALL/CALLIND op
          (verified in the probe dump), exactly like ARM/RISC-V.
          $zero is never clobbered (constant 0); $s0-$s7, $gp, $sp,
          $fp, $k0-$k1 are callee-saved / reserved.
        - No instruction-address tagging (no Thumb bit); the bit-0
          clearing in jr/jalr P-Code (INT_2COMP(2) AND) is unwrapped
          in table matching, not a tag on addresses.
        - Constant materialization: lui = INT_LEFT [imm, 16],
          addiu/ori = INT_ADD/INT_OR. All constant-foldable.
        - DELAY SLOTS (the subtle part): Ghidra embeds the delay-slot
          instruction's P-Code in the branch/call instruction's P-Code
          AND lists the delay slot as its own instruction. The
          standalone copy must NOT be re-executed: fallthroughIndex
          skips it (CBRANCH/CALL fallthrough goes to the instruction
          after the delay slot). Unconditional BRANCH/BRANCHIND keep
          their current successors (the embedded copy already carries
          the delay-slot effects). See fallthroughIndex.
        - Jump tables hold ABSOLUTE pointers (non-PIC: lui + addiu
          base, sll index, addu, lw, jr). The BRANCHIND input chain
          runs through a pc COPY + AND-~1 (jr bit-0 clear), which is
          unwrapped before table matching. */
    private class MipsIsa implements IsaAdapter {
        private final int stride;       // 4 (MIPS32) or 8 (MIPS64)
        private final int ptrSize;      // 4 or 8
        private final int ptrShift;     // 2 or 3
        private final long addrMask;    // 0xffffffffL or -1L
        private final List<long[]> mmioWindows;

        MipsIsa(boolean is64, List<long[]> windows) {
            stride = is64 ? 8 : 4;
            ptrSize = is64 ? 8 : 4;
            ptrShift = is64 ? 3 : 2;
            addrMask = is64 ? -1L : 0xffffffffL;
            mmioWindows = windows;
        }

        private long reg(int n) { return (long) stride * n; }

        public String name() { return "MIPS"; }
        public String registerSpaceName() { return "register"; }
        public long[] callerSavedRegisterOffsets() {
            // $at(1), $v0-$v1(2-3), $a0-$a3(4-7), $t0-$t7(8-15),
            // $t8-$t9(24-25). $ra(31) excluded (see class comment).
            int[] nums = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13,
                14, 15, 24, 25};
            long[] offs = new long[nums.length];
            for (int i = 0; i < nums.length; i++) offs[i] = reg(nums[i]);
            return offs;
        }
        public long returnAddressRegisterOffset() { return reg(31); }
        public boolean isReturnAddressRegister(Varnode v) {
            return v != null && v.getAddress() != null &&
                registerSpaceName().equals(
                    v.getAddress().getAddressSpace().getName()) &&
                v.getOffset() == returnAddressRegisterOffset();
        }
        public long stripInstructionTag(long addr) { return addr; }
        public boolean isInstructionTagMask(long constValue) {
            return (constValue & 0xFFFFFFFFL) == 0xFFFFFFFEL;
        }
        public int pointerSize() { return ptrSize; }
        public int pointerIndexShift() { return ptrShift; }
        public long readPointer(Memory mem, Address addr) throws Exception {
            if (ptrSize == 8) return mem.getLong(addr);
            return mem.getInt(addr) & 0xffffffffL;
        }
        public String formatCodeAddress(long addr) {
            return String.format("%08x", addr);
        }
        public boolean isMmioAddress(long addr) {
            // MIPS has no fixed peripheral window (unlike ARM
            // Cortex-M): the map is platform-specific. These default
            // bands cover the common firmware families (see
            // defaultMipsMmioWindows); a caller may override them with
            // the mmio= script argument, and the SVD-profile classifier
            // remains the authority on known-vs-suspect peripherals.
            for (long[] w : mmioWindows) {
                if (addr >= w[0] && addr < w[1]) return true;
            }
            return false;
        }
        public List<long[]> mmioWindows() {
            return mmioWindows;
        }
        public int fallthroughIndex(List<OpRec> ops, int i) {
            // Skip the delay-slot instruction's standalone ops: the
            // branch/call instruction's own P-Code already embeds
            // them (verified in the probe dump), so falling through
            // to them would double-apply delay-slot writes and
            // resurrect caller-saved registers after calls. MIPS32
            // instructions are 4 bytes, so the delay slot sits at
            // branchAddr + 4; a nop delay slot has no ops, in which
            // case the next op already is next-after-delay.
            int n = ops.size();
            if (i + 1 >= n) return -1;
            long b;
            try {
                b = Long.parseLong(ops.get(i).instrAddr.toString(), 16);
            } catch (Exception e) {
                return i + 1;
            }
            int j = i + 1;
            while (j < n &&
                ops.get(j).instrAddr.toString().equals(
                    ops.get(i).instrAddr.toString())) j++;
            if (j >= n) return -1;
            long d;
            try {
                d = Long.parseLong(ops.get(j).instrAddr.toString(), 16);
            } catch (Exception e) {
                return j;
            }
            if (d != b + 4L) return j; // nop delay slot: j is next-after-delay
            int k = j;
            while (k < n) {
                long a;
                try {
                    a = Long.parseLong(ops.get(k).instrAddr.toString(), 16);
                } catch (Exception e) {
                    break;
                }
                if (a != d) break;
                k++;
            }
            return k < n ? k : -1;
        }
        /** Fold a varnode to a constant, including INT_2COMP /
            INT_NEGATE of a constant (constFold does not handle those;
            the jr/jalr bit-0 clear is INT_2COMP(2) AND). Null when
            the value is not a known constant. */
        private Long maskConst(List<OpRec> ops, Varnode v, int beforeIdx) {
            Long c = constFold(ops, vkey(v), beforeIdx, 16, addrMask);
            if (c != null) return c;
            int def = findDef(ops, vkey(v), beforeIdx);
            if (def < 0) return null;
            OpRec d = ops.get(def);
            if (d.ins.length == 1 && d.ins[0].isConstant()) {
                if (d.mnem.equals("INT_2COMP")) {
                    return (-d.ins[0].getOffset()) & addrMask;
                }
                if (d.mnem.equals("INT_NEGATE")) {
                    return (~d.ins[0].getOffset()) & addrMask;
                }
            }
            return null;
        }
        /** Unwrap the jr/jalr input chain (pc COPY + INT_AND(~1,
            value)) to the def index of the unwrapped value. Returns
            the input def when the chain does not match, and never
            -1 for a valid input def. Shared by table matching and
            unwrapIndirectDef. */
        private int unwrapJrChain(List<OpRec> ops, int brIdx, int cur) {
            for (int hop = 0; hop < 6; hop++) {
                if (cur < 0) break;
                OpRec d = ops.get(cur);
                if (d.mnem.equals("COPY") && d.ins.length == 1 &&
                    !d.ins[0].isConstant()) {
                    int nxt = findDef(ops, vkey(d.ins[0]), cur);
                    if (nxt < 0) break;
                    cur = nxt;
                    continue;
                }
                if (d.mnem.equals("INT_AND") && d.ins.length == 2) {
                    boolean unwrapped = false;
                    for (int s = 0; s < 2; s++) {
                        Long mv = maskConst(ops, d.ins[s], cur);
                        if (mv != null &&
                            mv.longValue() == 0xFFFFFFFEL) {
                            int nxt = findDef(ops, vkey(d.ins[1 - s]),
                                cur);
                            if (nxt >= 0) {
                                cur = nxt;
                                unwrapped = true;
                            }
                            break;
                        }
                    }
                    if (unwrapped) continue;
                }
                break;
            }
            return cur;
        }
        public int unwrapIndirectDef(List<OpRec> ops, int brIdx, int cur) {
            return unwrapJrChain(ops, brIdx, cur);
        }
        public boolean hasOverlappingRegisters() { return false; }
        public long[] clobberForConvention(String conv) {
            return callerSavedRegisterOffsets();
        }
        public long[] argumentRegisterOffsets(String conv) {
            // MIPS o32 calling convention: a0-a3 = $4-$7
            // (probe-verified: a0 = stride*4).
            long[] offs = new long[4];
            for (int i = 0; i < 4; i++) offs[i] = reg(4 + i);
            return offs;
        }
        public long returnRegisterOffset() {
            // Return register is v0 = $2.
            return reg(2);
        }
        public Map<Integer, List<Integer>> recoverJumpTableTargets(
            List<OpRec> ops, Memory mem) {
            Map<Integer, List<Integer>> result =
                new HashMap<Integer, List<Integer>>();
            if (ops.isEmpty()) return result;
            Map<String, Integer> firstAt = new HashMap<String, Integer>();
            for (int i = 0; i < ops.size(); i++) {
                String a = ops.get(i).instrAddr.toString();
                if (!firstAt.containsKey(a)) firstAt.put(a, i);
            }
            for (int i = 0; i < ops.size(); i++) {
                OpRec br = ops.get(i);
                if (!br.mnem.equals("BRANCHIND") || br.ins.length < 1) continue;
                // Unwrap the jr chain: BRANCHIND <- pc COPY <-
                // INT_AND(~1, value) <- value. The AND's mask side is
                // INT_2COMP(2), not a direct constant.
                int cur = unwrapJrChain(ops, i,
                    findDef(ops, vkey(br.ins[0]), i));
                if (cur < 0) continue;
                TableMatch m = matchBranchTableFrom(ops, i, cur,
                    ptrSize, ptrShift, addrMask);
                if (m == null) continue;
                List<Integer> targets = new ArrayList<Integer>();
                for (int k = 0; k < 64; k++) {
                    long entryAddr = m.base + (long) ptrSize * k;
                    long entry;
                    try {
                        entry = readPointer(mem, toAddr(entryAddr));
                    } catch (Exception e) {
                        break;
                    }
                    long t;
                    if (m.offset) {
                        t = (m.base + (int) entry) & addrMask;
                    } else {
                        t = stripInstructionTag(entry);
                    }
                    Integer j = firstAt.get(formatCodeAddress(t));
                    if (j == null) break;
                    if (!targets.contains(j)) targets.add(j);
                }
                if (!targets.isEmpty()) result.put(i, targets);
            }
            return result;
        }
    }

    /** x86 adapter (v3.8, 64-bit first; 32-bit structural only,
        untested): holds every x86-specific fact. Register offsets
        are from the empirical Ghidra 11.4.2 probe
        (~/workspace/x86-probe/probe_x86.log, language
        x86:LE:64:default): rax 0x0, rcx 0x8, rdx 0x10, rbx 0x18,
        rsp 0x20, rbp 0x28, rsi 0x30, rdi 0x38, r8 0x80, r9 0x88,
        r10 0x90, r11 0x98, r12 0xa0, r13 0xa8, r14 0xb0, r15 0xb8.
        Sub-registers share the parent offset (eax/ax/al 0x0, ah
        0x1, ...), which is why hasOverlappingRegisters() is true.
        32-bit uses the same base offsets with width 4 (the legacy
        registers live in the same register space); the 32-bit
        layout is NOT probe-verified, so 32-bit results are
        best-effort until a 32-bit test binary exists. */
    private class X86Isa implements IsaAdapter {
        private final boolean is64;
        private final int ptrSize;
        private final int ptrShift;
        private final long addrMask;
        private final List<long[]> windows;
        private final boolean windowsDefault;

        X86Isa(boolean is64, List<long[]> windows,
            boolean windowsDefault) {
            this.is64 = is64;
            this.ptrSize = is64 ? 8 : 4;
            this.ptrShift = is64 ? 3 : 2;
            this.addrMask = is64 ? -1L : 0xffffffffL;
            this.windows = windows;
            this.windowsDefault = windowsDefault;
        }

        public String name() { return "X86"; }
        public String registerSpaceName() { return "register"; }

        /** System V AMD64 volatile set (default for ELF). */
        private long[] sysvClobber() {
            return new long[] {0x0L, 0x8L, 0x10L, 0x30L, 0x38L,
                0x80L, 0x88L, 0x90L, 0x98L};
        }

        /** Windows x64 volatile set (default for PE). */
        private long[] windowsClobber() {
            return new long[] {0x0L, 0x8L, 0x10L,
                0x80L, 0x88L, 0x90L, 0x98L};
        }

        /** 32-bit volatile set. All 32-bit conventions share it:
            they differ in stack cleanup, not register volatility. */
        private long[] x86_32Clobber() {
            return new long[] {0x0L, 0x8L, 0x10L};
        }

        public long[] callerSavedRegisterOffsets() {
            if (!is64) return x86_32Clobber();
            return windowsDefault ? windowsClobber() : sysvClobber();
        }

        /** Signature-driven clobbers (locked decision, v1). The
            convention name comes from Ghidra's per-function
            signature (see callConvMap in run()); null = unknown
            callee (CALLIND, thunk, missing entry) -> the
            conservative union, which for 64-bit IS the System V
            set (SysV volatile superset of Windows volatile), so
            the fallback is sound and simple. A name mentioning
            "win" maps to the Windows set; any other known name
            falls back to the binary default (PE -> Windows,
            ELF -> System V, abi= overrides). Vector registers
            (xmm) are out of scope for v1 and ignored, not
            crashed on. */
        public long[] clobberForConvention(String conv) {
            if (!is64) return x86_32Clobber();
            if (conv == null) return sysvClobber();
            String c = conv.toLowerCase();
            if (c.contains("win")) return windowsClobber();
            return windowsDefault ? windowsClobber() : sysvClobber();
        }
        public long[] argumentRegisterOffsets(String conv) {
            // x86-32: stack args -- no register propagation (no-op).
            if (!is64) return new long[0];
            // Unknown convention: UNMODELLED (null), never the union
            // (see the interface contract: the clobber union is
            // sound for killing but unsound for reading arguments).
            if (conv == null) return null;
            String c = conv.toLowerCase();
            // Windows x64: RCX, RDX, R8, R9 (probe-verified offsets).
            if (c.contains("win") || windowsDefault) {
                return new long[] {0x8L, 0x10L, 0x80L, 0x88L};
            }
            // System V AMD64: RDI, RSI, RDX, RCX, R8, R9.
            return new long[] {0x38L, 0x30L, 0x10L, 0x8L, 0x80L,
                0x88L};
        }
        public long returnRegisterOffset() {
            // Return register is RAX (64-bit) / EAX (32-bit),
            // offset 0 in both cases (probe-verified: helpers
            // leave their value in register:0x0, and RETURN's own
            // input is the return ADDRESS, not the value).
            return 0L;
        }

        /** x86 has NO link register: CALL pushes the return
            address on the stack (ram space) and RET pops it. The
            -1 sentinel is never compared against a real register
            offset; isReturnAddressRegister() is false for every
            varnode, so the tail-call classification that uses it
            simply does not apply to x86. */
        public long returnAddressRegisterOffset() { return -1L; }
        public boolean isReturnAddressRegister(Varnode v) {
            return false;
        }
        public long stripInstructionTag(long addr) { return addr; }
        public boolean isInstructionTagMask(long constValue) {
            return false;
        }
        public int pointerSize() { return ptrSize; }
        public int pointerIndexShift() { return ptrShift; }
        public long readPointer(Memory mem, Address addr)
            throws Exception {
            if (ptrSize == 8) return mem.getLong(addr);
            return mem.getInt(addr) & 0xffffffffL;
        }
        public String formatCodeAddress(long addr) {
            return String.format("%08x", addr);
        }
        public boolean isMmioAddress(long addr) {
            for (long[] w : windows) {
                if (addr >= w[0] && addr < w[1]) return true;
            }
            return false;
        }
        public List<long[]> mmioWindows() { return windows; }
        public int fallthroughIndex(List<OpRec> ops, int i) {
            return i + 1 < ops.size() ? i + 1 : -1;
        }
        public int unwrapIndirectDef(List<OpRec> ops, int brIdx,
            int cur) {
            return cur;
        }
        public boolean hasOverlappingRegisters() { return true; }

        /** Follow a COPY / INT_SEXT / INT_ZEXT chain to the
            underlying LOAD def index, or -1. The x86 switch shape
            puts an INT_SEXT between the ADD and the 4-byte LOAD
            (MOVSXD), which the shared matchBranchTableFrom does
            not handle (it requires the LOAD to be a direct ADD
            input with size == pointerSize). */
        private int unwrapLoadThroughExt(List<OpRec> ops, Varnode v,
            int beforeIdx) {
            int cur = findDef(ops, vkey(v), beforeIdx);
            for (int hop = 0; hop < 8 && cur >= 0; hop++) {
                OpRec d = ops.get(cur);
                if (d.mnem.equals("LOAD") && d.ins.length >= 2) {
                    return cur;
                }
                if ((d.mnem.equals("COPY") ||
                    d.mnem.equals("INT_SEXT") ||
                    d.mnem.equals("INT_ZEXT")) && d.ins.length == 1 &&
                    !d.ins[0].isConstant()) {
                    cur = findDef(ops, vkey(d.ins[0]), cur);
                    continue;
                }
                return -1;
            }
            return -1;
        }

        /** x86-64 relative-offset jump-table recovery ONLY.
            Shape (probe-verified, dispatch_switch): LEA base (Ghidra
            folds RIP-relative LEA to a constant) + index*4 +
            LOAD 4 bytes + INT_SEXT + INT_ADD(base, sext) +
            BRANCHIND. Entries are 4-byte SIGNED offsets; target =
            base + sext32(entry). Absolute pointer-table BRANCHINDs
            (call_via_ptr: LOAD 8 bytes, no ADD) are DELIBERATELY
            not claimed here: recoverIndirect already handles them
            (function entries -> edges, same-function starts ->
            successors), and claiming them here would LOSE the
            led_on/led_off edges (jump-table application only adds
            same-function instruction starts). 4-byte absolute
            switch tables are a 32-bit idiom, out of v1. */
        public Map<Integer, List<Integer>> recoverJumpTableTargets(
            List<OpRec> ops, Memory mem) {
            Map<Integer, List<Integer>> result =
                new HashMap<Integer, List<Integer>>();
            if (ops.isEmpty()) return result;
            Map<String, Integer> firstAt = new HashMap<String, Integer>();
            for (int i = 0; i < ops.size(); i++) {
                String a = ops.get(i).instrAddr.toString();
                if (!firstAt.containsKey(a)) firstAt.put(a, i);
            }
            for (int i = 0; i < ops.size(); i++) {
                OpRec br = ops.get(i);
                if (!br.mnem.equals("BRANCHIND") || br.ins.length < 1) {
                    continue;
                }
                int cur = findDef(ops, vkey(br.ins[0]), i);
                for (int hop = 0; hop < 8 && cur >= 0; hop++) {
                    OpRec d = ops.get(cur);
                    if (d.mnem.equals("COPY") && d.ins.length == 1 &&
                        !d.ins[0].isConstant()) {
                        cur = findDef(ops, vkey(d.ins[0]), cur);
                        continue;
                    }
                    break;
                }
                if (cur < 0) continue;
                OpRec d = ops.get(cur);
                if (!d.mnem.equals("INT_ADD") || d.ins.length != 2) {
                    continue;
                }
                Long base = null;
                for (int s = 0; s < 2; s++) {
                    int ldIdx = unwrapLoadThroughExt(ops, d.ins[s],
                        cur);
                    if (ldIdx < 0) continue;
                    OpRec ld = ops.get(ldIdx);
                    if (ld.out == null || ld.out.getSize() != 4) {
                        continue;
                    }
                    Long b = matchAddr(ops, vkey(ld.ins[1]), ldIdx,
                        0L, 8, addrMask, 4, 2);
                    if (b == null) continue;
                    Long side = constFold(ops, vkey(d.ins[1 - s]),
                        cur, 16, addrMask);
                    if (side != null &&
                        side.longValue() == b.longValue()) {
                        base = b;
                        break;
                    }
                }
                if (base == null) continue;
                List<Integer> targets = new ArrayList<Integer>();
                for (int k = 0; k < 64; k++) {
                    long entryAddr = base.longValue() + 4L * k;
                    int entry;
                    try {
                        entry = mem.getInt(toAddr(entryAddr));
                    } catch (Exception e) {
                        break;
                    }
                    long t = (base.longValue() + (long) entry) &
                        addrMask;
                    Integer j = firstAt.get(formatCodeAddress(t));
                    if (j == null) break;
                    if (!targets.contains(j)) targets.add(j);
                }
                if (!targets.isEmpty()) result.put(i, targets);
            }
            return result;
        }
    }

    private static String esc(String s) {
        if (s == null) return "";
        StringBuilder b = new StringBuilder(s.length() + 16);
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '"': b.append("\\\""); break;
                case '\\': b.append("\\\\"); break;
                case '\n': b.append("\\n"); break;
                case '\r': b.append("\\r"); break;
                case '\t': b.append("\\t"); break;
                default:
                    if (c < 0x20) {
                        b.append(String.format("\\u%04x", (int) c));
                    } else {
                        b.append(c);
                    }
            }
        }
        return b.toString();
    }

    private static String varnodeJson(Varnode v) {
        if (v == null) return "null";
        String space = v.getAddress().getAddressSpace().getName();
        return "{\"space\": \"" + esc(space) + "\", \"offset\": \"0x" +
            Long.toHexString(v.getOffset()) + "\", \"size\": " + v.getSize() +
            ", \"constant\": " + v.isConstant() + "}";
    }

    private static String vkey(Varnode v) {
        return v.getAddress().getAddressSpace().getName() + ":" +
            v.getOffset() + ":" + v.getSize();
    }

    /** Known-bit value: bits known 1 (ones) and bits known 0 (zeroes).
        Unknown = both zero. Exact when ones|zeroes covers the full mask. */
    private static class Bits {
        final long ones;
        final long zeroes;
        // v7 cfgspace: optional symbolic value. A Bits with sym != null
        // ALWAYS has ones == 0 && zeroes == 0 (never exact), so a symbol
        // can never masquerade as a constant: exactValue() returns null
        // for it, and isMmioAddress() never fires on it. Forms:
        //   "BAR:bus:dev:fn:idx:off"  raw BAR register value (unmasked)
        //   "BASE:bus:dev:fn:idx:off" masked BAR base (flags cleared)
        // Only BASE symbols yield findings; raw BAR symbols never do.
        final String sym;
        // v7 cfgspace: width (in bytes) at which the symbol value is
        // fully contained. Deriving a narrower view of a symbol
        // value is sound ONLY for a view that starts at the value's
        // base and covers at least symW bytes (e.g. EAX from a
        // ZEXT-widened RAX: the low 4 bytes ARE the 32-bit BAR
        // value). Deriving a view narrower than symW, or not
        // starting at the base, must drop the symbol (e.g. EAX from
        // a 64-bit BAR+offset address is just address bits, not the
        // BAR symbol). 0 means "no symbol".
        final int symW;
        Bits(long ones, long zeroes) {
            this(ones, zeroes, null, 0);
        }
        Bits(long ones, long zeroes, String sym, int symW) {
            this.ones = ones;
            this.zeroes = zeroes;
            this.sym = sym;
            this.symW = symW;
        }
        static Bits symBits(String sym, int symW) {
            return new Bits(0, 0, sym, symW);
        }
        static String barSym(long bus, long dev, long fn, long bar,
            long off) {
            return "BAR:" + bus + ":" + dev + ":" + fn + ":" + bar +
                ":" + off;
        }
        static String baseSym(long bus, long dev, long fn, long bar,
            long off) {
            return "BASE:" + bus + ":" + dev + ":" + fn + ":" + bar +
                ":" + off;
        }
        // Parses a BAR/BASE symbol. Returns [kind, bus, dev, fn, bar,
        // off] with kind 0 = BAR, 1 = BASE, or null if malformed.
        static long[] parseBarSym(String sym) {
            if (sym == null) return null;
            String[] p = sym.split(":");
            if (p.length != 6) return null;
            int kind;
            if (p[0].equals("BAR")) kind = 0;
            else if (p[0].equals("BASE")) kind = 1;
            else return null;
            try {
                return new long[] { kind, Long.parseLong(p[1]),
                    Long.parseLong(p[2]), Long.parseLong(p[3]),
                    Long.parseLong(p[4]), Long.parseLong(p[5]) };
            } catch (NumberFormatException e) {
                return null;
            }
        }
        // Same symbol with its offset shifted by delta, or null.
        static String adjustBarSym(String sym, long delta) {
            long[] p = parseBarSym(sym);
            if (p == null) return null;
            String kind = p[0] == 0 ? "BAR" : "BASE";
            return kind + ":" + p[1] + ":" + p[2] + ":" + p[3] + ":" +
                p[4] + ":" + (p[5] + delta);
        }
        // v9 struct: abstract-object symbols. "OBJ:<callAddr>:<delta>"
        // denotes a pointer value produced by the call at program
        // address callAddr, plus delta bytes (pointer arithmetic
        // folds into delta, exactly like BAR offsets). The call
        // address is program-unique, so it identifies the object:
        // two different call sites never share an id, and one call
        // site denotes one abstract object -- EXCEPT a call site
        // inside a CFG loop, which may produce many objects (the
        // transfer never creates an OBJ symbol there; see the CALL
        // branch). Like every symbol, an OBJ symbol has ones == 0
        // && zeroes == 0, so exactValue() is null and it can never
        // masquerade as a constant or an MMIO address. It is also
        // disjoint from every real address by construction: field
        // cells keyed by it never overlap mem:/gmem: cells.
        static String objSym(long callAddr, long delta) {
            return "OBJ:" + callAddr + ":" + delta;
        }
        // Parses an OBJ symbol. Returns [callAddr, delta], or null.
        static long[] parseObjSym(String sym) {
            if (sym == null) return null;
            String[] p = sym.split(":");
            if (p.length != 3 || !p[0].equals("OBJ")) return null;
            try {
                return new long[] { Long.parseLong(p[1]),
                    Long.parseLong(p[2]) };
            } catch (NumberFormatException e) {
                return null;
            }
        }
        // Same OBJ symbol with its delta shifted, or null.
        static String adjustObjSym(String sym, long delta) {
            long[] p = parseObjSym(sym);
            if (p == null) return null;
            return objSym(p[0], p[1] + delta);
        }
        // Symbol adjustment for any symbol kind (BAR/BASE/OBJ), or
        // null when the symbol is of no adjustable kind.
        static String adjustSym(String sym, long delta) {
            if (sym == null) return null;
            if (sym.startsWith("BAR:") || sym.startsWith("BASE:")) {
                return adjustBarSym(sym, delta);
            }
            if (sym.startsWith("OBJ:")) {
                return adjustObjSym(sym, delta);
            }
            if (sym.startsWith("SP:")) {
                long[] p = parseSpSym(sym);
                if (p == null) return null;
                return spSym(p[0], p[1] + delta);
            }
            return null;
        }
        // v14 stack slots: abstract stack-pointer symbols.
        // "SP:<funcEntry>:<delta>" denotes the stack pointer of
        // the function entered at funcEntry, plus delta bytes
        // (pointer arithmetic folds into delta, exactly like OBJ
        // deltas). The entry address makes the symbol unique per
        // function: a slot address from one activation can never
        // collide with another function's slots, and stk: cells
        // are never copied across functions (entries carry only
        // argument registers + gmem: seeds). Like every symbol,
        // an SP symbol has ones == 0 && zeroes == 0, so
        // exactValue() is null and it can never masquerade as a
        // constant address -- in particular it can never fire
        // isMmioAddress() or resolve as an MMIO base.
        static String spSym(long funcEntry, long delta) {
            return "SP:" + funcEntry + ":" + delta;
        }
        static long[] parseSpSym(String sym) {
            if (sym == null) return null;
            String[] p = sym.split(":");
            if (p.length != 3 || !p[0].equals("SP")) return null;
            try {
                return new long[] { Long.parseLong(p[1]),
                    Long.parseLong(p[2]) };
            } catch (NumberFormatException e) {
                return null;
            }
        }
        static Bits unknown() {
            return new Bits(0, 0);
        }
        static Bits exact(long v, long mask) {
            return new Bits(v & mask, (~v) & mask);
        }
        /** Exact value if every bit is known, else null. */
        Long exactValue(long mask) {
            if (((ones | zeroes) & mask) == mask) return ones & mask;
            return null;
        }
    }

    private static long sizeMask(int size) {
        if (size >= 8) return -1L;
        if (size <= 0) return 0xffffffffL;
        return (1L << (size * 8)) - 1;
    }

    private static Bits resolveBits(Varnode v, Map<String, Bits> bvals) {
        if (v == null) return Bits.unknown();
        if (v.isConstant()) {
            return Bits.exact(v.getOffset(), sizeMask(v.getSize()));
        }
        Bits b = bvals.get(vkey(v));
        // v7: a symbol entry must return directly. Without this, the
        // old 0/0 skip falls through to the slicing path, which builds
        // fresh Bits without sym and the symbol is lost at every COPY.
        if (b != null && (b.ones != 0 || b.zeroes != 0 ||
            b.sym != null)) return b;
        // Sub-register view of a wider known value (x86: reading
        // EAX after RAX was written, or DX after RDX). Writes only
        // create the written view, so the narrower view's exact key
        // is often missing; slice the smallest containing register
        // key. Sound: known bits of the wider value imply known
        // bits of the slice. Restricted to the register space:
        // ARM/RISC-V/MIPS never have overlapping register keys, so
        // this is a no-op for them (no containing key exists), and
        // unique-space temporaries are never sliced (their offsets
        // are not views of one another).
        if (v.getAddress() == null) return Bits.unknown();
        String space = v.getAddress().getAddressSpace().getName();
        if (!space.equals("register")) return Bits.unknown();
        long off = v.getOffset();
        int sz = v.getSize();
        Bits best = null;
        int bestSize = Integer.MAX_VALUE;
        for (Map.Entry<String, Bits> e : bvals.entrySet()) {
            String k = e.getKey();
            if (!k.startsWith(space + ":")) continue;
            String[] p = k.split(":");
            if (p.length != 3) continue;
            try {
                long o = Long.parseLong(p[1]);
                int s = Integer.parseInt(p[2]);
                if (o <= off && off + sz <= o + s && s < bestSize) {
                    int sh = (int) (off - o) * 8;
                    long m = sizeMask(sz);
                    Bits sl = new Bits((e.getValue().ones >>> sh) & m,
                        (e.getValue().zeroes >>> sh) & m);
                    best = sl;
                    bestSize = s;
                }
            } catch (Exception ex) {
                // Non-numeric key: not a register view, skip it.
            }
        }
        return best != null ? best : Bits.unknown();
    }

    /** State keys in a register space whose [offset, offset+size)
        range intersects [off, off+size), except keepKey. Used only
        when the adapter has overlapping registers (x86): a write
        to al must invalidate the eax/rax keys, and a CALL clobber
        of rax must invalidate eax/ax/al/ah keys. Returns the keys
        to drop; the caller removes them (so the same helper serves
        must maps, may maps, and the taint key set). */
    private static List<String> overlappingKeys(
        java.util.Collection<String> keys, String space, long off,
        int size, String keepKey) {
        List<String> drop = new ArrayList<String>();
        for (String k : keys) {
            if (keepKey != null && k.equals(keepKey)) continue;
            if (!k.startsWith(space + ":")) continue;
            String[] p = k.split(":");
            if (p.length != 3) continue;
            try {
                long o = Long.parseLong(p[1]);
                int s = Integer.parseInt(p[2]);
                if (o < off + size && off < o + s) drop.add(k);
            } catch (Exception e) {
                // Non-numeric key: not a register view, keep it.
            }
        }
        return drop;
    }

    /** Port/MSR recording's sub-register resolver. resolveBits now
        does exact-key + register-space slicing itself, so this
        just delegates (kept as a named entry point so the
        recording code reads as "sub-register aware"). */
    private static Bits resolveBitsSlice(Varnode v,
        Map<String, Bits> bvals) {
        return resolveBits(v, bvals);
    }

    private static Long resolveExactSlice(Varnode v,
        Map<String, Bits> bvals) {
        Bits b = resolveBitsSlice(v, bvals);
        return b.exactValue(sizeMask(v.getSize()));
    }

    private static Long resolveExact(Varnode v, Map<String, Bits> bvals) {
        if (v == null) return null;
        Bits b = resolveBits(v, bvals);
        return b.exactValue(sizeMask(v.getSize()));
    }

    // ---------------- v10 u32: sound sign-extension truncation ----
    // A 32-bit address held in a u32 (bit 31 set) is widened to 64
    // bits through a SIGNED int on x86-64, so Ghidra lifts an
    // INT_SEXT and the address becomes 0xFFFFFFFFFED00000 --
    // outside every MMIO band, so the access was missed (and a
    // STORE even polluted memState at the bogus address). The
    // memprop fixtures had to use u64 globals to dodge this.
    //
    // Predicate (ones/zeroes reasoning): a Bits value is provably
    // the sign-extension of a 32-bit value iff bit 31 is KNOWN and
    // bits 63..32 are all KNOWN copies of bit 31: bit 31 known 1
    // requires every upper bit a known 1; bit 31 known 0 requires
    // every upper bit a known 0. A symbol never satisfies it
    // (ones == 0 && zeroes == 0, so bit 31 is unknown), a value
    // with unknown upper bits never does, and a genuine 64-bit
    // pointer with meaningful upper bits (e.g. 0x00007F00FED00000:
    // upper 0x00007F00, not all copies of bit 31) never does.
    // The residual, stated honestly: a genuine 64-bit address whose
    // upper 32 bits HAPPEN to be all sign copies (e.g. a kernel
    // address 0xFFFFFFFFFED00000 used as a real pointer) is
    // indistinguishable from a sign-extended 32-bit address at the
    // Bits level, and is read as the 32-bit address. In the
    // analyzed domain (x86-64 firmware/UEFI, where addresses are
    // 32-bit values) that reading is the programmer's intent.
    //
    // Band gate (why truncation is band-checked, not blanket): a
    // truncated value whose low 32 bits are NOT in any band keeps
    // today's exact behaviour (same key, same non-MMIO verdict), so
    // the fix changes NOTHING except MMIO-band recoveries. A
    // blanket truncation would re-key non-band memState cells and
    // break currently-working absolute-address connections.
    private static boolean isSext32(Bits b) {
        if (b == null || b.sym != null) return false;
        final long UPPER = 0xFFFFFFFF00000000L;
        final long SIGN = 0x80000000L;
        if ((b.ones & SIGN) != 0) return (b.ones & UPPER) == UPPER;
        if ((b.zeroes & SIGN) != 0) return (b.zeroes & UPPER) == UPPER;
        return false;
    }

    /** Exact-long version of the sext32 shape test, for values
        (may-address sets, constant ram addresses) that carry no
        Bits: true iff a is exactly the sign-extension of its low
        32 bits. Note a plain 32-bit-range constant (e.g.
        0xFED00000 as a long) is NOT sext-shaped -- its
        sign-extension is 0xFFFFFFFFFED00000, a different value --
        so band addresses already in 32-bit form are untouched. */
    private static boolean isSext32Value(long a) {
        return a == (long)(int)a;
    }

    /** Address resolution for MEMORY addresses (band-gated
        truncation): the exact value when known; when the Bits
        provably represent a sign-extended 32-bit value AND the low
        32 bits fall in an MMIO band, the low 32 bits (the true
        address). Otherwise exactly today's resolveExact result
        (including null for unknown/symbolic values). Callers still
        apply their own band check to the result; a truncated value
        outside every band is never returned here, so it can never
        be band-shopped into a finding. */
    private Long resolveAddressExact(Varnode v,
        Map<String, Bits> bvals) {
        if (v == null) return null;
        Bits b = resolveBits(v, bvals);
        if (b.sym != null) return null;
        Long ex = b.exactValue(sizeMask(v.getSize()));
        if (ex != null) {
            if (isSext32(b)) {
                long low = ex.longValue() & 0xFFFFFFFFL;
                if (isa.isMmioAddress(low)) return low;
            }
            return ex;
        }
        if (isSext32(b)) {
            Long low = b.exactValue(0xFFFFFFFFL);
            if (low != null && isa.isMmioAddress(low.longValue())) {
                return low;
            }
        }
        return null;
    }

    /** Constant-address version of the band-gated rule, for
        COPY-to-ram addresses (which never pass through Bits): a
        sext-shaped constant whose low 32 bits are in a band reads
        as the low 32 bits; anything else is unchanged. */
    private long canonicalizeBandAddr(long a) {
        if (isSext32Value(a)) {
            long low = a & 0xFFFFFFFFL;
            if (isa.isMmioAddress(low)) return low;
        }
        return a;
    }

    /** MSR-index resolution (NOT band-gated: MSR indices are
        architecturally 32-bit -- WRMSR/RDMSR take ECX -- so a
        sext-shaped 64-bit index IS the 32-bit index; there is no
        band to gate on and no genuine-64-bit index domain). */
    private static Long resolveMsrIndexExact(Varnode v,
        Map<String, Bits> bvals) {
        if (v == null) return null;
        Bits b = resolveBits(v, bvals);
        if (b.sym != null) return null;
        Long ex = b.exactValue(sizeMask(v.getSize()));
        if (ex != null) {
            if (isSext32(b)) return ex.longValue() & 0xFFFFFFFFL;
            return ex;
        }
        if (isSext32(b)) return b.exactValue(0xFFFFFFFFL);
        return null;
    }

    // v10 u32: instance method (was static) because the size-correct
    // image read now consults memLookup, which needs the instance's
    // memBigEndian. All callers are in instance methods.
    private Bits copyBits(Varnode in, Memory mem, Map<String, Bits> bvals,
        IsaAdapter isa) {
        if (in.isConstant()) {
            return Bits.exact(in.getOffset(), sizeMask(in.getSize()));
        }
        if (in.getAddress() != null &&
            "ram".equals(in.getAddress().getAddressSpace().getName())) {
            // v10 u32: read EXACTLY the load's size, not a pointer.
            // readPointer reads 8 bytes even for a 4-byte (or
            // 1-byte) load, and throws when the variable sits at
            // the end of its memory block -- proven by the u32
            // fixture: a 4-byte global as the last word of .data
            // (getLong crossing into unreadable .bss) made every
            // 4-byte global load yield unknown. Size-correct reads
            // mirror loadBits. MMIO addresses stay unknown
            // (hardware state, never image bytes); a memState entry
            // wins over image bytes, exactly as in the COPY-from-ram
            // branch and loadBits.
            long a = in.getAddress().getOffset();
            if (isa.isMmioAddress(a)) return Bits.unknown();
            Bits m = memLookup(bvals, a, in.getSize());
            if (m != null) return m;
            try {
                int sz = in.getSize();
                long val;
                if (sz == 8) val = mem.getLong(in.getAddress());
                else if (sz == 4) val = mem.getInt(in.getAddress()) & 0xffffffffL;
                else if (sz == 2) val = mem.getShort(in.getAddress()) & 0xffffL;
                else if (sz == 1) val = mem.getByte(in.getAddress()) & 0xffL;
                else return Bits.unknown();
                return Bits.exact(val, sizeMask(sz));
            } catch (Exception e) {
                return Bits.unknown();
            }
        }
        return resolveBits(in, bvals);
    }

    /** Value loaded by a LOAD op: exact only when the address is known and
        points into program memory (e.g. a literal pool); MMIO and other
        unmapped addresses yield unknown bits (hardware state). */
    private Bits loadBits(Varnode[] ins, Varnode out, Map<String, Bits> bvals,
        Memory mem) {
        if (ins.length < 2 || out == null) return Bits.unknown();
        // v9 struct: a load through an abstract object reads the
        // object's field cells, never image bytes (an abstract
        // object has no image address). No covering cell -> unknown
        // (exactly today's behaviour for an unknown address).
        Bits ab = resolveBits(ins[1], bvals);
        if (ab.sym != null &&
            Bits.parseObjSym(ab.sym) != null) {
            // fldLookup returns null for "no covering cell";
            // loadBits never returns null (the LOAD branch
            // passes the result straight to putKnown).
            Bits r = fldLookup(bvals, ab.sym, out.getSize());
            return r != null ? r : Bits.unknown();
        }
        // v14 stack slots: a load through an SP symbol reads the
        // function's stk: cells, never image bytes (a stack slot
        // has no image address, and uninitialized slots must read
        // unknown, not a stale value). No covering cell ->
        // unknown (exactly today's behaviour for a stack load,
        // since the address was never exact).
        if (ab.sym != null) {
            long[] sp = Bits.parseSpSym(ab.sym);
            if (sp != null) {
                Bits r = stkLookup(bvals, sp[0], sp[1],
                    out.getSize());
                return r != null ? r : Bits.unknown();
            }
        }
        Long addr = resolveAddressExact(ins[1], bvals);
        if (addr == null) return Bits.unknown();
        // Memory propagation: a memState entry covering the load
        // range wins over image bytes (the entry proves a
        // dominating store wrote this range on every path, so the
        // image bytes are stale there). No covering entry ->
        // exactly today's behaviour (image bytes). MMIO loads
        // never consult memState (hardware state, not a value).
        if (!isa.isMmioAddress(addr.longValue())) {
            Bits m = memLookup(bvals, addr.longValue(), out.getSize());
            if (m != null) return m;
        }
        try {
            Address a = toAddr(addr.longValue());
            int sz = out.getSize();
            long val;
            if (sz == 8) val = mem.getLong(a);
            else if (sz == 4) val = mem.getInt(a) & 0xffffffffL;
            else if (sz == 2) val = mem.getShort(a) & 0xffffL;
            else if (sz == 1) val = mem.getByte(a) & 0xffL;
            else return Bits.unknown();
            return Bits.exact(val, sizeMask(sz));
        } catch (Exception e) {
            return Bits.unknown();
        }
    }

    // ---------------- v3.1 CFG fixpoint machinery ----------------

    /** One collected P-Code op, kept so the fixpoint can run before
        anything is streamed out. */
    private static class OpRec {
        final Address instrAddr;
        final String instrAsm;
        final String mnem;
        final Varnode[] ins;
        final Varnode out;
        /** Memory-propagation: true when a LOAD/STORE address is
            provably stack-derived (def-chain to SP/FP), computed
            once in buildOps. Stack stores can never alias globals. */
        boolean addrIsStack = false;
        OpRec(Address a, String asm, String mnem, Varnode[] ins, Varnode out) {
            this.instrAddr = a;
            this.instrAsm = asm;
            this.mnem = mnem;
            this.ins = ins;
            this.out = out;
        }
    }

    private static class FixResult {
        final Map<String, Bits>[] inStates;
        final boolean converged;
        FixResult(Map<String, Bits>[] inStates, boolean converged) {
            this.inStates = inStates;
            this.converged = converged;
        }
    }

    /** Put a value canonically: unknown entries are dropped (missing key
        already means unknown), which keeps states comparable. */
    private static void putKnown(Map<String, Bits> m, String key, Bits b) {
        // v7: a symbol entry (ones == 0, zeroes == 0, sym != null) is
        // kept, not dropped: dropping it would erase the BAR symbol.
        if (b.ones == 0 && b.zeroes == 0 && b.sym == null) {
            m.remove(key);
        } else {
            m.put(key, b);
        }
    }

    /** The transfer function: the v3 op-folding algebra, applied to a
        COPY of the incoming state. No MMIO recording here -- that happens
        once, after convergence, from the final states. */
    private void applyTransfer(Map<String, Bits> bvals, OpRec op, Memory mem,
        int opIdx, Set<Integer> loopCallOps) {
        String mnem = op.mnem;
        Varnode[] ins = op.ins;
        Varnode out = op.out;
        if ((mnem.equals("INT_XOR") || mnem.equals("INT_SUB")) &&
            ins.length == 2 && out != null &&
            vkey(ins[0]).equals(vkey(ins[1]))) {
            // Zeroing idiom (x86 xor eax,eax / sub eax,eax; ARM
            // eor rX,rX): x^x and x-x are 0 for EVERY x, even
            // when x is unknown. The generic formulas treat the
            // two inputs as independent values and lose this,
            // which dropped real x86 MSR values (EDX zeroed via
            // xor esi,esi, then moved to EDX, then shifted into
            // the WRMSR value). Taint deliberately keeps the
            // conservative behaviour here (keeping taint is sound).
            putKnown(bvals, vkey(out),
                Bits.exact(0, sizeMask(out.getSize())));
        } else if (mnem.equals("COPY") && ins.length == 1) {
            if (out != null) {
                if (isRamSpace(out)) {
                    // COPY-to-ram: Ghidra's x86-64 form of an
                    // absolute store (RIP-relative globals and
                    // absolute MMIO addresses do NOT become STORE
                    // ops on x86-64; they become COPY ops with a
                    // ram destination). Without this branch the
                    // globals slice would be vacuous on x86-64
                    // -- including OVMF, whose globals are all
                    // RIP-relative. Same store rule as STORE:
                    // MMIO never enters memState; overlapping
                    // cells drop; the cell is set only when the
                    // value has known bits. Deliberately NOT
                    // putKnown into bvals: a ram key there would
                    // survive CALLs (the CALL branch drops only
                    // registers + mem: keys), a latent staleness
                    // hole that must not be left live. Any stale
                    // ram key from an earlier path is purged.
                    bvals.remove(vkey(out));
                    // v10 u32: band-gated canonicalization of a
                    // sext-shaped constant address (movabs to
                    // 0xFFFFFFFFFED00020 reads as 0xFED00020, so
                    // the MMIO store skips memState instead of
                    // polluting it at the bogus address).
                    long a = canonicalizeBandAddr(out.getOffset());
                    if (!isa.isMmioAddress(a)) {
                        dropMemRange(bvals, a, out.getSize(), true);
                        Bits vb = resolveBits(ins[0], bvals);
                        // v14 stack slots: an absolute store of a
                        // stack address escapes it (same rule as
                        // the STORE branch below).
                        if (vb.sym != null &&
                            Bits.parseSpSym(vb.sym) != null) {
                            dropAllStk(bvals);
                        }
                        if (vb.ones != 0 || vb.zeroes != 0) {
                            // v7 cfgspace: strip symbols (see STORE).
                            bvals.put(memKey(a, out.getSize()),
                                new Bits(vb.ones, vb.zeroes));
                        }
                    }
                } else if (isRamSpace(ins[0]) &&
                    !isa.isMmioAddress(ins[0].getOffset())) {
                    // COPY-from-ram: a global load. memState
                    // wins when it covers the range (a dominating
                    // store wrote it on every path); otherwise
                    // exactly today's behaviour (image bytes via
                    // copyBits). MMIO loads keep today's behaviour
                    // unconditionally (hardware, not a stored
                    // value).
                    Bits m = memLookup(bvals, ins[0].getOffset(),
                        ins[0].getSize());
                    putKnown(bvals, vkey(out), m != null ? m :
                        copyBits(ins[0], mem, bvals, isa));
                } else {
                    putKnown(bvals, vkey(out),
                        copyBits(ins[0], mem, bvals, isa));
                }
            }
        } else if (mnem.equals("INT_AND") || mnem.equals("INT_OR") ||
            mnem.equals("INT_XOR")) {
            if (ins.length == 2 && out != null) {
                Bits a = resolveBits(ins[0], bvals);
                Bits bb = resolveBits(ins[1], bvals);
                long mask = sizeMask(out.getSize());
                Bits r;
                if (mnem.equals("INT_AND")) {
                    r = new Bits((a.ones & bb.ones) & mask,
                        (a.zeroes | bb.zeroes) & mask);
                    // v7 cfgspace: memory-BAR flag masking. A raw BAR
                    // ANDed with the flag mask (0xFFFFFFF0 for 32-bit,
                    // 0xFFFFFFFFFFFFFFF0 for 64-bit) becomes a BASE
                    // symbol. Any other mask, an already-masked
                    // symbol, or a nonzero offset is dropped
                    // (conservative): masking an offset symbol is not
                    // in general equal to BASE + offset.
                    Bits s0 = resolveBits(ins[0], bvals);
                    Bits s1 = resolveBits(ins[1], bvals);
                    Long m0 = resolveExact(ins[0], bvals);
                    Long m1 = resolveExact(ins[1], bvals);
                    String raw = null;
                    long maskVal = 0;
                    if (s0.sym != null && s0.sym.startsWith("BAR:") &&
                        m1 != null) {
                        raw = s0.sym;
                        maskVal = m1;
                    } else if (s1.sym != null &&
                        s1.sym.startsWith("BAR:") && m0 != null) {
                        raw = s1.sym;
                        maskVal = m0;
                    }
                    if (raw != null && (maskVal == 0xFFFFFFF0L ||
                        maskVal == 0xFFFFFFFFFFFFFFF0L)) {
                        long[] p = Bits.parseBarSym(raw);
                        if (p != null && p[5] == 0) {
                            r = Bits.symBits(Bits.baseSym(p[1], p[2], p[3],
                                p[4], 0), out.getSize());
                        }
                    }
                } else if (mnem.equals("INT_OR")) {
                    r = new Bits((a.ones | bb.ones) & mask,
                        (a.zeroes & bb.zeroes) & mask);
                } else {
                    r = new Bits(((a.ones & bb.zeroes) |
                        (a.zeroes & bb.ones)) & mask,
                        ((a.ones & bb.ones) |
                        (a.zeroes & bb.zeroes)) & mask);
                }
                putKnown(bvals, vkey(out), r);
            }
        } else if (mnem.equals("INT_ADD") || mnem.equals("INT_SUB") ||
            mnem.equals("INT_MULT")) {
            if (ins.length == 2 && out != null) {
                Long a = resolveExact(ins[0], bvals);
                Long b = resolveExact(ins[1], bvals);
                long mask = sizeMask(out.getSize());
                if (a != null && b != null) {
                    long r = 0;
                    if (mnem.equals("INT_ADD")) r = a + b;
                    else if (mnem.equals("INT_SUB")) r = a - b;
                    else r = a * b;
                    putKnown(bvals, vkey(out), Bits.exact(r, mask));
                } else if (mnem.equals("INT_ADD") ||
                    mnem.equals("INT_SUB")) {
                    // v7 cfgspace: symbol + exact constant adjusts the
                    // offset (either operand order for ADD; only the
                    // minuend for SUB). Symbol + non-exact, or
                    // constant - symbol, or any MULT, is unknown.
                    // v9 struct: the same rule carries OBJ deltas
                    // (a field address is the object symbol plus
                    // its field offset).
                    Bits s0 = resolveBits(ins[0], bvals);
                    Bits s1 = resolveBits(ins[1], bvals);
                    Long e0 = resolveExact(ins[0], bvals);
                    Long e1 = resolveExact(ins[1], bvals);
                    String adj = null;
                    if (s0.sym != null && e1 != null) {
                        adj = Bits.adjustSym(s0.sym, mnem.equals("INT_ADD")
                            ? e1 : -e1);
                    } else if (mnem.equals("INT_ADD") &&
                        s1.sym != null && e0 != null) {
                        adj = Bits.adjustSym(s1.sym, e0);
                    }
                    if (adj != null) {
                        putKnown(bvals, vkey(out),
                            Bits.symBits(adj, out.getSize()));
                    } else {
                        putKnown(bvals, vkey(out), Bits.unknown());
                    }
                } else {
                    putKnown(bvals, vkey(out), Bits.unknown());
                }
            }
        } else if ((mnem.equals("INT_NOT") || mnem.equals("INT_NEGATE")) &&
            ins.length == 1 && out != null) {
            // CAREFUL: Ghidra's INT_NEGATE is bitwise NOT (~),
            // NOT arithmetic negation. Proof: the ARM sleigh
            // defines BIC as "Rd = rn&(~shift1)" and it
            // compiles to INT_NEGATE + INT_AND. (Arithmetic
            // negation is INT_2COMP.)
            Bits a = resolveBits(ins[0], bvals);
            long mask = sizeMask(out.getSize());
            putKnown(bvals, vkey(out),
                new Bits(a.zeroes & mask, a.ones & mask));
        } else if (mnem.equals("INT_2COMP") &&
            ins.length == 1 && out != null) {
            Long a = resolveExact(ins[0], bvals);
            long mask = sizeMask(out.getSize());
            if (a != null) {
                putKnown(bvals, vkey(out), Bits.exact(-a, mask));
            } else {
                putKnown(bvals, vkey(out), Bits.unknown());
            }
        } else if ((mnem.equals("INT_LEFT") || mnem.equals("INT_RIGHT")) &&
            ins.length == 2 && out != null) {
            Bits a = resolveBits(ins[0], bvals);
            Long n = resolveExact(ins[1], bvals);
            long mask = sizeMask(out.getSize());
            int width = out.getSize() * 8;
            if (n != null && n.longValue() >= 0) {
                int sh = (int) Math.min(n.longValue(), 1000000L);
                Bits r;
                if (sh >= width) {
                    r = new Bits(0, mask);
                } else if (mnem.equals("INT_LEFT")) {
                    long low = (sh == 0) ? 0 : ((1L << sh) - 1);
                    r = new Bits((a.ones << sh) & mask,
                        ((a.zeroes << sh) | low) & mask);
                } else {
                    long high = (sh == 0) ? 0 :
                        (~((1L << (width - sh)) - 1) & mask);
                    r = new Bits((a.ones >>> sh) & mask,
                        ((a.zeroes >>> sh) | high) & mask);
                }
                putKnown(bvals, vkey(out), r);
            } else {
                putKnown(bvals, vkey(out), Bits.unknown());
            }
        } else if (mnem.equals("INT_SRIGHT") && ins.length == 2 && out != null) {
            Long a = resolveExact(ins[0], bvals);
            Long n = resolveExact(ins[1], bvals);
            long mask = sizeMask(out.getSize());
            int width = out.getSize() * 8;
            if (a != null && n != null && n.longValue() >= 0 &&
                n.longValue() < 64) {
                long sa = a.longValue();
                if ((sa & (1L << (width - 1))) != 0) sa |= ~mask;
                putKnown(bvals, vkey(out),
                    Bits.exact(sa >> n.intValue(), mask));
            } else {
                putKnown(bvals, vkey(out), Bits.unknown());
            }
        } else if (mnem.equals("INT_ZEXT") && ins.length == 1 && out != null) {
            // v10 u32: a direct ram input (Ghidra folds a global
            // load into the extension, e.g. movslq mem -> SEXT)
            // resolves from image bytes like COPY-from-ram; the
            // plain resolveBits path returns unknown for ram keys
            // (ram keys never live in bvals). Without this, every
            // SEXT/ZEXT of a global was unknown before it began.
            Bits a = isRamSpace(ins[0]) ?
                copyBits(ins[0], mem, bvals, isa) :
                resolveBits(ins[0], bvals);
            long outMask = sizeMask(out.getSize());
            long inMask = sizeMask(ins[0].getSize());
            // v7 cfgspace: zero-extension preserves the value, so it
            // preserves the symbol. (Critical: Ghidra emits INT_ZEXT
            // to the full register after every 32-bit write.)
            if (a.sym != null) {
                putKnown(bvals, vkey(out), Bits.symBits(a.sym, a.symW));
            } else {
                putKnown(bvals, vkey(out), new Bits(a.ones & outMask,
                    (a.zeroes | ~inMask) & outMask));
            }
        } else if (mnem.equals("INT_SEXT") && ins.length == 1 && out != null) {
            // v10 u32: same ram-input resolution as INT_ZEXT
            // (movslq of a u32 global folds the load into SEXT).
            Bits a = isRamSpace(ins[0]) ?
                copyBits(ins[0], mem, bvals, isa) :
                resolveBits(ins[0], bvals);
            long outMask = sizeMask(out.getSize());
            long inMask = sizeMask(ins[0].getSize());
            long signBit = 1L << (ins[0].getSize() * 8 - 1);
            Bits r;
            if ((a.ones & signBit) != 0) {
                r = new Bits((a.ones | ~inMask) & outMask, a.zeroes & outMask);
            } else if ((a.zeroes & signBit) != 0) {
                r = new Bits(a.ones & outMask, (a.zeroes | ~inMask) & outMask);
            } else {
                r = Bits.unknown();
            }
            putKnown(bvals, vkey(out), r);
        } else if (mnem.equals("SUBPIECE") && ins.length == 2 && out != null) {
            Bits a = resolveBits(ins[0], bvals);
            Long off = resolveExact(ins[1], bvals);
            long mask = sizeMask(out.getSize());
            if (off != null && off.longValue() >= 0) {
                int sh = off.intValue() * 8;
                putKnown(bvals, vkey(out), new Bits((a.ones >>> sh) & mask,
                    (a.zeroes >>> sh) & mask));
            } else {
                putKnown(bvals, vkey(out), Bits.unknown());
            }
        } else if (mnem.equals("LOAD") && out != null) {
            putKnown(bvals, vkey(out), loadBits(ins, out, bvals, mem));
        } else if (mnem.equals("STORE") && ins.length >= 3) {
            // v9 struct: a store through an abstract object writes
            // the object's field cell (full Bits, symbols included:
            // a BAR base stored into a field must survive as a
            // symbol, unlike memState which strips symbols). The
            // store ALSO clears memState, exactly as today's
            // unknown-address store does: the object is abstract,
            // so memState behaviour is preserved bit-for-bit and
            // no existing memState result can change. Stack stores
            // never carry OBJ symbols (stack addresses are
            // SP/FP-derived, never call-produced), so the stack
            // gate below is unaffected.
            Bits ab0 = resolveBits(ins[1], bvals);
            if (ab0.sym != null &&
                Bits.parseObjSym(ab0.sym) != null) {
                Bits vb0 = resolveBits(ins[2], bvals);
                fldStore(bvals, ab0.sym, ins[2].getSize(), vb0);
                dropAllMem(bvals);
            } else if (ab0.sym != null &&
                Bits.parseSpSym(ab0.sym) != null) {
                // v14 stack slots: a store through an SP symbol
                // records the value in the function's stk: cells
                // (full Bits, symbols included, like fld: cells:
                // a spilled BAR base or object pointer must
                // survive as that symbol when reloaded). Stack
                // stores never touch mem:/gmem: (today's rule,
                // unchanged: a stack address cannot alias a
                // global). Overlapping cells drop first, exactly
                // like dropMemRange; a value with no known bits
                // and no symbol creates no cell (putKnown drops
                // it), so a stale cell never survives a
                // clobbering store.
                long[] sps = Bits.parseSpSym(ab0.sym);
                int sz = ins[2].getSize();
                if (sz > 0 && sz <= 8) {
                    dropStkRange(bvals, sps[0], sps[1], sz);
                    putKnown(bvals, stkKey(sps[0], sps[1], sz),
                        resolveBits(ins[2], bvals));
                    stkStoreCount++;
                }
            } else
            // Memory propagation, stage 1 (intra-procedural):
            // a store to a known non-MMIO address records the
            // value in memState ("mem:" keys in this same map, so
            // the must-meet's agree-or-drop discipline applies to
            // cells exactly as it does to registers: a cell
            // survives a join only when every incoming path agrees
            // on it). A store to an unknown non-stack address
            // clears all of memState (it may alias any global).
            // Stack stores are ignored entirely: they can never
            // alias a global (proven-stack via def-chain to SP/FP).
            // MMIO stores are hardware state, never memState: a
            // later load from the same MMIO address does NOT
            // return the stored value.
            if (!op.addrIsStack) {
                Long addr = resolveAddressExact(ins[1], bvals);
                if (addr != null &&
                    !isa.isMmioAddress(addr.longValue())) {
                    int sz = ins[2].getSize();
                    dropMemRange(bvals, addr.longValue(), sz, true);
                    Bits vb = resolveBits(ins[2], bvals);
                    if (vb.ones != 0 || vb.zeroes != 0) {
                        // v7 cfgspace: symbols never enter memState
                        // (defense in depth; the invariant already
                        // excludes them since recording requires
                        // known bits). BARs never flow through
                        // memory in this slice.
                        bvals.put(memKey(addr.longValue(), sz),
                            new Bits(vb.ones, vb.zeroes));
                    }
                } else if (addr == null) {
                    dropAllMem(bvals);
                }
                // v14 stack slots: storing a stack address into
                // non-stack memory escapes it (a later call may
                // read that global and write through the
                // pointer), so all stk: cells die now. Dropping
                // at escape time is over-conservative (a later
                // load in this same function, before any call,
                // also loses) but sound, and it keeps the CALL
                // rule below simple.
                Bits svb = resolveBits(ins[2], bvals);
                if (svb.sym != null &&
                    Bits.parseSpSym(svb.sym) != null) {
                    dropAllStk(bvals);
                }
            }
        } else if (mnem.equals("CALL") || mnem.equals("CALLIND")) {
            // Caller-saved registers are dead after the call, except
            // registers the callee provably never writes (v13
            // refinedClobberForCall; must transfer only -- the may
            // and taint transfers keep the full conservative kill).
            // The base set comes from clobberForCall: the per-callee
            // Ghidra signature for x86, the adapter's single set
            // otherwise.
            long[] clobber = refinedClobberForCall(op);
            Set<String> drop = new HashSet<String>();
            for (long off : clobber) {
                if (isa.hasOverlappingRegisters()) {
                    drop.addAll(overlappingKeys(bvals.keySet(),
                        isa.registerSpaceName(), off,
                        isa.pointerSize(), null));
                } else {
                    for (String k : bvals.keySet()) {
                        if (k.startsWith(isa.registerSpaceName() +
                            ":" + off + ":")) {
                            drop.add(k);
                        }
                    }
                }
            }
            for (String k : drop) bvals.remove(k);
            // A callee may store to any global: intra-procedural
            // memState dies at the call. Seeded globals ("gmem:"
            // keys, Phase M) survive: the seed rule guarantees
            // every store program-wide agrees on their value, so
            // no callee can change one to a different value.
            dropAllMem(bvals);
            // v14 stack slots: stk: cells survive a direct CALL
            // to a known, untainted callee -- the callee's own
            // frame is disjoint from the caller's slots, and the
            // SP register itself survives calls (callee-saved
            // by convention, so the slot keys stay valid). They
            // die when the callee is unknown, indirect, or
            // tainted (it may store anywhere), and when a stack
            // address escapes as a call argument (the callee
            // then holds a pointer to the caller's slot).
            // DOCUMENTED RESIDUAL: a callee writing its
            // incoming stack-argument area could stale a caller
            // outgoing-arg slot reloaded after the call;
            // compilers do not reload outgoing-arg slots as
            // locals (locals live above the outgoing area), so
            // this does not fire on compiler-generated code,
            // but it is an assumption, stated here, not a
            // proof. Same honesty class as the balanced
            // push/pop residual in the clobber slice.
            boolean dropStk = true;
            if (mnem.equals("CALL") && op.ins.length >= 1) {
                Varnode t = op.ins[0];
                if (t != null && t.getAddress() != null &&
                    "ram".equals(t.getAddress().getAddressSpace()
                        .getName()) && clobberRef != null) {
                    long to = t.getOffset();
                    long ts = isa.stripInstructionTag(to);
                    Set<Long> w = clobberRef.writes.get(to);
                    if (w == null) w = clobberRef.writes.get(ts);
                    boolean tainted =
                        clobberRef.tainted.contains(to) ||
                        clobberRef.tainted.contains(ts);
                    if (w != null && !tainted) {
                        dropStk = false;
                        long[] argRegs = null;
                        try {
                            argRegs = isa.argumentRegisterOffsets(
                                callConvMap.get(to));
                            if (argRegs == null) argRegs =
                                isa.argumentRegisterOffsets(
                                    callConvMap.get(ts));
                        } catch (Exception e) {
                            argRegs = null;
                        }
                        if (argRegs != null) {
                            int ps = isa.pointerSize();
                            for (long off : argRegs) {
                                Varnode vn = regVarnode(off, ps);
                                if (vn == null) continue;
                                Bits ab = resolveBits(vn, bvals);
                                if (ab.sym != null &&
                                    Bits.parseSpSym(ab.sym) != null) {
                                    dropStk = true;
                                    break;
                                }
                            }
                        } else {
                            dropStk = true;
                        }
                    }
                }
            }
            if (dropStk) dropAllStk(bvals);
            // v7 cfgspace: a callee may reprogram config space, so
            // the latched CF8 address dies at the call. (A memory
            // store does NOT kill it: the latch is CPU state, not
            // memory. Seeded "gmem:" keys survive, as before.)
            bvals.remove("cfg:addr");
            // v8 retprop: a direct CALL to a summarized callee
            // restores the return register to the summary value.
            // The summary holds on ALL paths through the callee
            // (see Phase R), and any argument dependence is covered
            // by the constprop agree discipline: a callee whose
            // entry arguments are not agreed computes an unknown
            // (or argument-independent) return, so the summary is
            // valid at every direct site. CALLIND gets nothing (the
            // clobber above already killed the register); the
            // summary is applied AFTER the clobber, never before.
            boolean scalarApplied = false;
            if (mnem.equals("CALL") && op.ins.length >= 1) {
                Varnode t = op.ins[0];
                if (t != null && t.getAddress() != null &&
                    "ram".equals(t.getAddress().getAddressSpace()
                        .getName())) {
                    Bits sum = retSummaries.get(t.getOffset());
                    if (sum == null) {
                        sum = retSummaries.get(
                            isa.stripInstructionTag(t.getOffset()));
                    }
                    if (sum != null) {
                        putKnown(bvals, isa.registerSpaceName() +
                            ":" + isa.returnRegisterOffset() + ":" +
                            isa.pointerSize(), sum);
                        scalarApplied = true;
                    }
                }
            }
            // v9 struct: the value returned by this call is a fresh
            // abstract object, identified by this call site -- UNLESS
            // a scalar summary already claimed the register (a
            // scalar return is not a pointer), or this call site
            // lies in a CFG loop (one site, many objects: no sound
            // single identity exists, so the value stays unknown,
            // exactly as before). A direct CALL to a struct-
            // summarized callee additionally installs the callee's
            // field cells under this call site's id, so later field
            // loads through the returned pointer resolve. CALLIND
            // gets a fresh object but never a summary (no static
            // callee). Field cells survive later CALLs (a callee
            // cannot touch this object: it never receives the
            // pointer -- object ids do not cross function
            // boundaries except through these summaries).
            // DOCUMENTED RESIDUAL (same honesty policy as v2 item
            // #2's address-taken hole): if a callee actually
            // returns a global address that is not exact in its own
            // fixpoint, the caller models it as a fresh object; an
            // intervening call mutating that global's field through
            // its real address would leave a stale field cell. Exact
            // returns take the scalar path above, so the hole needs
            // a computed (non-exact) global address plus a
            // cross-path mutation to bite.
            if (!scalarApplied && (mnem.equals("CALL") ||
                mnem.equals("CALLIND"))) {
                boolean inLoop = loopCallOps != null &&
                    loopCallOps.contains(opIdx);
                if (!inLoop) {
                    String oid = Bits.objSym(
                        op.instrAddr.getOffset(), 0);
                    putKnown(bvals, isa.registerSpaceName() +
                        ":" + isa.returnRegisterOffset() + ":" +
                        isa.pointerSize(),
                        Bits.symBits(oid, isa.pointerSize()));
                    if (mnem.equals("CALL") && op.ins.length >= 1) {
                        Varnode t = op.ins[0];
                        if (t != null && t.getAddress() != null &&
                            "ram".equals(t.getAddress().getAddressSpace()
                                .getName())) {
                            Map<String, Bits> fields =
                                structSummaries.get(t.getOffset());
                            if (fields == null) {
                                fields = structSummaries.get(
                                    isa.stripInstructionTag(
                                        t.getOffset()));
                            }
                            if (fields != null) {
                                for (Map.Entry<String, Bits> fe :
                                    fields.entrySet()) {
                                    String[] fp =
                                        fe.getKey().split(":");
                                    if (fp.length != 2) continue;
                                    try {
                                        long fo = Long.parseLong(fp[0]);
                                        int fs = Integer.parseInt(fp[1]);
                                        bvals.put("fld:" +
                                            Bits.objSym(
                                                op.instrAddr.getOffset(),
                                                fo) + ":" + fs,
                                            fe.getValue());
                                    } catch (Exception ex) {
                                        // Malformed summary key:
                                        // skip that field, never
                                        // trust it.
                                    }
                                }
                            }
                        }
                    }
                }
            }
            if (out != null) putKnown(bvals, vkey(out), Bits.unknown());
        } else if (mnem.equals("CALLOTHER")) {
            // v7 cfgspace: CF8/CFC config-space tracking. The
            // "cfg:addr" cell holds the last OUT 0xCF8 value. Only a
            // constant config address can yield a BAR symbol; only
            // BAR registers (0x10..0x24) yield symbols; a CFC write
            // dirties the latch (BAR sizing read-backs return a size
            // mask, never a BAR base); an unknown port may be a CFC
            // write, so it dirties the latch too. A config WRITE
            // never creates a symbol. All other config reads stay
            // unknown. RDMSR/WRMSR fall through to unknown out.
            String am = op.instrAsm == null ? "" : op.instrAsm;
            if (am.equalsIgnoreCase("OUT") && ins.length >= 3) {
                Long port = resolveAddressExact(ins[1], bvals);
                if (port != null && port == 0xCF8L) {
                    Bits val = resolveBits(ins[2], bvals);
                    // Unknown value removes the cell (putKnown
                    // drops 0/0 without sym), so a variable address
                    // yields nothing downstream.
                    putKnown(bvals, "cfg:addr", val);
                } else if (port != null && port == 0xCFCL) {
                    bvals.remove("cfg:addr");
                } else if (port == null) {
                    bvals.remove("cfg:addr");
                }
                // OUT to any other exact port: latch untouched.
            } else if (am.equalsIgnoreCase("IN") && ins.length >= 2 &&
                out != null) {
                Long port = resolveAddressExact(ins[1], bvals);
                Bits cfg = bvals.get("cfg:addr");
                Long cfgVal = cfg == null ? null :
                    cfg.exactValue(0xFFFFFFFFL);
                boolean made = false;
                if (port != null && port == 0xCFCL &&
                    cfgVal != null) {
                    long v = cfgVal;
                    // Bit 31 = enable; dword-aligned; BAR register.
                    if ((v & 0x80000000L) != 0 && (v & 0x3L) == 0) {
                        long reg = v & 0xFCL;
                        if (reg >= 0x10 && reg <= 0x24) {
                            long idx = (reg - 0x10) / 4;
                            long bus = (v >>> 16) & 0xFFL;
                            long dev = (v >>> 11) & 0x1FL;
                            long fn = (v >>> 8) & 0x7L;
                            putKnown(bvals, vkey(out),
                                Bits.symBits(Bits.barSym(bus, dev, fn,
                                    idx, 0), out.getSize()));
                            made = true;
                        }
                    }
                }
                if (!made) {
                    putKnown(bvals, vkey(out), Bits.unknown());
                }
            } else if (out != null) {
                putKnown(bvals, vkey(out), Bits.unknown());
            }
        } else {
            if (out != null) putKnown(bvals, vkey(out), Bits.unknown());
        }
        // Overlapping-register invalidation (x86 only; a no-op
        // gate for ARM/RISC-V/MIPS). x86 register views are
        // nested (al ⊂ ax ⊂ eax ⊂ rax, ah ⊂ ax ⊂ ...), so a
        // write to view V has two cases: views that CONTAIN V
        // hold partly-stale values -> delete them (a stale wider
        // value surviving a sub-register write, e.g. SETZ AL
        // leaving a stale EAX, would corrupt must-analysis);
        // views CONTAINED in V are fully determined by V's new
        // value -> slice it into them (deleting them would break
        // real chains: WRMSR reads EDX after a ZEXT wrote RDX).
        // If V's new value is unknown, contained views are
        // dropped too (unknown sliced is unknown). The
        // may-transfer keeps the simpler delete-all (sound there:
        // a missing may key means TOP).
        if (isa.hasOverlappingRegisters() && out != null &&
            out.getAddress() != null &&
            isa.registerSpaceName().equals(out.getAddress().
                getAddressSpace().getName())) {
            String outKey = vkey(out);
            Bits outBits = bvals.get(outKey);
            long outOff = out.getOffset();
            int outSize = out.getSize();
            List<String> drop = new ArrayList<String>();
            Map<String, Bits> derive = new HashMap<String, Bits>();
            for (String k : bvals.keySet()) {
                if (k.equals(outKey)) continue;
                if (!k.startsWith(isa.registerSpaceName() + ":")) {
                    continue;
                }
                String[] p = k.split(":");
                if (p.length != 3) continue;
                try {
                    long o = Long.parseLong(p[1]);
                    int s = Integer.parseInt(p[2]);
                    if (o < outOff + outSize && outOff < o + s) {
                        if (outBits != null && o >= outOff &&
                            o + s <= outOff + outSize) {
                            int sh = (int) (o - outOff) * 8;
                            long m = sizeMask(s);
                            // v7 cfgspace: a derived view keeps the
                            // symbol ONLY if it starts at the value
                            // base and covers the symbol's full
                            // width (see symW). Otherwise the view
                            // is partial bits, not the symbol.
                            String dsym = null;
                            int dw = 0;
                            if (outBits.sym != null && o == outOff &&
                                s >= outBits.symW) {
                                dsym = outBits.sym;
                                dw = outBits.symW;
                            }
                            derive.put(k, new Bits(
                                (outBits.ones >>> sh) & m,
                                (outBits.zeroes >>> sh) & m, dsym, dw));
                        } else {
                            drop.add(k);
                        }
                    }
                } catch (Exception e) {
                    // Non-numeric key: not a register view.
                }
            }
            for (String k : drop) bvals.remove(k);
            for (Map.Entry<String, Bits> e : derive.entrySet()) {
                bvals.put(e.getKey(), e.getValue());
            }
        }
    }

    /** Must-meet of two states: null means "unreached" (identity). A bit
        survives only if it agrees on every incoming path. */
    private static Map<String, Bits> meet(Map<String, Bits> a,
        Map<String, Bits> b) {
        if (a == null) return b;
        if (b == null) return a;
        Map<String, Bits> r = new HashMap<String, Bits>();
        Set<String> keys = new HashSet<String>();
        keys.addAll(a.keySet());
        keys.addAll(b.keySet());
        for (String k : keys) {
            Bits x = a.get(k);
            Bits y = b.get(k);
            long ones = (x == null ? 0 : x.ones) & (y == null ? 0 : y.ones);
            long zeroes = (x == null ? 0 : x.zeroes) &
                (y == null ? 0 : y.zeroes);
            // v7 cfgspace: a symbol survives the meet only if both
            // sides carry the identical symbol (agree-or-drop, same
            // rule as exact bits). A symbol on one side only dies.
            String sym = null;
            int symW = 0;
            if (x != null && y != null && x.sym != null &&
                x.sym.equals(y.sym) && x.symW == y.symW) {
                sym = x.sym;
                symW = x.symW;
            }
            if (ones != 0 || zeroes != 0 || sym != null) {
                r.put(k, new Bits(ones, zeroes, sym, symW));
            }
        }
        return r;
    }

    private static boolean sameState(Map<String, Bits> a,
        Map<String, Bits> b) {
        if (a == null || b == null) return a == b;
        if (a.size() != b.size()) return false;
        for (Map.Entry<String, Bits> e : a.entrySet()) {
            Bits o = b.get(e.getKey());
            if (o == null || o.ones != e.getValue().ones ||
                o.zeroes != e.getValue().zeroes) {
                return false;
            }
            // v7 cfgspace: a symbol change is a state change, or the
            // fixpoint could stop while symbols still differ.
            String s1 = e.getValue().sym;
            String s2 = o.sym;
            if (s1 == null ? s2 != null : !s1.equals(s2)) {
                return false;
            }
            if (e.getValue().symW != o.symW) {
                return false;
            }
        }
        return true;
    }

    /** Strip instruction-local temporaries: unique-space varnodes never
        carry values across an instruction boundary. */
    private static Map<String, Bits> stripUniques(Map<String, Bits> m) {
        Map<String, Bits> r = new HashMap<String, Bits>();
        for (Map.Entry<String, Bits> e : m.entrySet()) {
            if (!e.getKey().startsWith("unique:")) {
                r.put(e.getKey(), e.getValue());
            }
        }
        return r;
    }

    @SuppressWarnings("unchecked")
    private FixResult runFixpoint(List<OpRec> ops, Memory mem,
        Map<Integer, List<Integer>> branchTargets,
        Map<String, Bits> entry, Set<Integer> loopCallOps) {
        int n = ops.size();
        Map<String, Bits>[] in = new Map[n];
        if (n == 0) return new FixResult(in, true);
        // v2 item #2: inter-procedural entry state (argument
        // registers bound by the caller meet, or empty = all
        // unknown, the pre-v2 behaviour). A loop back to op 0
        // meets into this state, which is correct: an entry
        // constant survives only if no loop-back path redefines it.
        in[0] = (entry == null) ? new HashMap<String, Bits>()
            : new HashMap<String, Bits>(entry);
        // v14 stack slots: seed the stack pointer with its
        // function-unique SP symbol. Entry maps never carry it
        // (they hold only argument registers + gmem: seeds), so
        // this cannot leak a caller's SP into a callee; and the
        // symbol is what makes SP-derived addresses computable
        // through COPY/INT_ADD chains (exact-only arithmetic
        // could never fold SP + const). A loop back to op 0
        // meets into this seed: a balanced loop keeps the
        // symbol, an unbalanced one drops it (sound).
        if (memSpOff >= 0 && !ops.isEmpty()) {
            String spKey = isa.registerSpaceName() + ":" +
                memSpOff + ":" + isa.pointerSize();
            if (!in[0].containsKey(spKey)) {
                long entryAddr = isa.stripInstructionTag(
                    ops.get(0).instrAddr.getOffset());
                in[0].put(spKey, Bits.symBits(
                    Bits.spSym(entryAddr, 0),
                    isa.pointerSize()));
            }
        }

        // First op index per instruction address (for branch targets).
        Map<String, Integer> firstAt = new HashMap<String, Integer>();
        for (int i = 0; i < n; i++) {
            String a = ops.get(i).instrAddr.toString();
            if (!firstAt.containsKey(a)) firstAt.put(a, i);
        }
        // Successor lists.
        List<List<Integer>> succ = new ArrayList<List<Integer>>(n);
        for (int i = 0; i < n; i++) succ.add(new ArrayList<Integer>());
        for (int i = 0; i < n; i++) {
            OpRec op = ops.get(i);
            String mnem = op.mnem;
            if (mnem.equals("BRANCH") || mnem.equals("CBRANCH")) {
                if (op.ins.length >= 1) {
                    long t = op.ins[0].getOffset();
                    Integer j = firstAt.get(isa.formatCodeAddress(t));
                    if (j == null) {
                        j = firstAt.get(isa.formatCodeAddress(isa.stripInstructionTag(t)));
                    }
                    if (j != null) succ.get(i).add(j);
                    else if (mnem.equals("BRANCH") &&
                        op.ins[0].isConstant()) {
                        // Intra-instruction sleigh label (x86 CPUID
                        // cascade): the BRANCH target is a P-Code
                        // label constant, not a code address, so no
                        // firstAt entry exists. The instruction
                        // completes and execution continues at the
                        // next op; without this, an unresolvable
                        // BRANCH kills the whole rest of the
                        // function (276 ops lost in PciHostBridgeDxe,
                        // including its RDMSR). CBRANCH already
                        // falls through below, so only plain BRANCH
                        // needs this. ARM/RISC-V/MIPS never emit
                        // constant-target BRANCHes, so this is a
                        // no-op for them. KEEP IN SYNC between
                        // runFixpoint and buildSucc.
                        int f = isa.fallthroughIndex(ops, i);
                        if (f >= 0) succ.get(i).add(f);
                    }
                }
                if (mnem.equals("CBRANCH")) {
                    // Fallthrough is the NEXT OP, not the next instruction:
                    // ARM predicated instructions (mov.gt/mov.le/it-blocks)
                    // model as [condition, CBRANCH -> next instruction,
                    // guarded ops...] inside ONE instruction. Skipping to
                    // the next instruction would wrongly make the guarded
                    // ops unreachable (caught Oct 26: jtagtap_tdi_seq got
                    // a phantom exact 0xFFFF because its predicated
                    // mov.gt/mov.le copies were skipped).
                    // Fallthrough goes through the ISA adapter: MIPS
                    // skips the delay-slot instruction's standalone ops
                    // (their effects are already embedded in the branch
                    // P-Code by Ghidra); ARM/RISC-V return i+1 unchanged.
                    int f = isa.fallthroughIndex(ops, i);
                    if (f >= 0) succ.get(i).add(f);
                }
            } else if (mnem.equals("RETURN")) {
                // No successors: RETURN ends the function.
            } else if (mnem.equals("BRANCHIND")) {
                // Jump-table targets recovered by the ISA adapter; anything else
                // (pointer tables, bx reg) keeps no successors.
                List<Integer> bt = branchTargets.get(i);
                if (bt != null) succ.get(i).addAll(bt);
            } else if (mnem.equals("CALL") || mnem.equals("CALLIND")) {
                // Fallthrough goes through the ISA adapter (MIPS skips
                // the delay-slot instruction's standalone ops).
                int f = isa.fallthroughIndex(ops, i);
                if (f >= 0) succ.get(i).add(f);
            } else {
                if (i + 1 < n) succ.get(i).add(i + 1);
            }
        }

        boolean converged = false;
        for (int round = 0; round < MAX_FIXPOINT_ROUNDS && !converged; round++) {
            boolean changed = false;
            for (int i = 0; i < n; i++) {
                if (in[i] == null) continue;
                Map<String, Bits> out = new HashMap<String, Bits>(in[i]);
                applyTransfer(out, ops.get(i), mem, i, loopCallOps);
                for (int j : succ.get(i)) {
                    Map<String, Bits> prop = out;
                    if (!ops.get(j).instrAddr.equals(ops.get(i).instrAddr)) {
                        prop = stripUniques(out);
                    }
                    Map<String, Bits> merged = meet(in[j], prop);
                    if (!sameState(in[j], merged)) {
                        in[j] = merged;
                        changed = true;
                    }
                }
            }
            if (!changed) converged = true;
        }
        if (!converged) {
            // Sound fallback: claim nothing rather than a stale value.
            for (int i = 0; i < n; i++) {
                in[i] = new HashMap<String, Bits>();
            }
        }
        return new FixResult(in, converged);
    }

    // ---------------- v3.2 MAY-analysis ----------------
    // Same CFG as the must-fixpoint, but the join is UNION: the state
    // maps each varnode to the FINITE SET of values it may hold (at most
    // 16 elements; anything bigger, or a value from an unconstrained
    // source such as a function argument, becomes TOP, represented by a
    // missing key). A LOAD/STORE whose must-address is unknown but whose
    // may-set is a finite set of MMIO addresses is recorded as a
    // MAY-access: an audit must know what a driver COULD touch, not
    // only what it must touch. This recovers predicated-move merges
    // (e.g. aux_serial's USART choice) and branch-selected addresses.
    // Jump-table blocks stay unreachable (BRANCHIND has no successors),
    // so MAY does not recover those -- that needs table recovery.
    // Successor computation is intentionally duplicated from
    // runFixpoint: the two fixpoints MUST share the same CFG, or the
    // must/may path sets diverge. KEEP IN SYNC.
    private static final int MAX_MAY_SET_SIZE = 16;

    /** v3.7: may-state values carry provenance -- each value maps to
        the op indices that materialized its bits (COPY from a
        literal, LOAD from memory; pure computation preserves the
        inputs' provenance, constants carry the empty set). The
        recording step uses provenance to drop values whose
        definition is provably dead at the use (see isKilledDef). */
    private static class MayResult {
        final Map<String, Map<Long, Set<Integer>>>[] inStates;
        final boolean converged;
        MayResult(Map<String, Map<Long, Set<Integer>>>[] inStates,
            boolean converged) {
            this.inStates = inStates;
            this.converged = converged;
        }
    }

    /** May-resolution: constant -> singleton with empty provenance
        (a constant is always a possible value); otherwise the map
        entry (missing key = TOP = unconstrained, e.g. an argument). */
    private static Map<Long, Set<Integer>> mayResolve(Varnode v,
        Map<String, Map<Long, Set<Integer>>> m) {
        if (v == null) return null;
        if (v.isConstant()) {
            Map<Long, Set<Integer>> s = new HashMap<Long, Set<Integer>>();
            s.put(v.getOffset() & sizeMask(v.getSize()),
                new HashSet<Integer>());
            return s;
        }
        return m.get(vkey(v));
    }

    /** COPY source resolution: like mayResolve, but a const or a ram
        varnode is materialized by this COPY op (provenance = the
        COPY itself), mirroring copyBits. */
    private static Map<Long, Set<Integer>> mayCopyBits(Varnode v,
        Map<String, Map<Long, Set<Integer>>> m, Memory mem, int curOp,
        IsaAdapter isa) {
        if (v == null) return null;
        if (v.isConstant()) {
            Map<Long, Set<Integer>> s = new HashMap<Long, Set<Integer>>();
            Set<Integer> p = new HashSet<Integer>();
            p.add(curOp);
            s.put(v.getOffset() & sizeMask(v.getSize()), p);
            return s;
        }
        if (v.getAddress() != null &&
            "ram".equals(v.getAddress().getAddressSpace().getName())) {
            try {
                long val = isa.readPointer(mem, v.getAddress());
                Map<Long, Set<Integer>> s =
                    new HashMap<Long, Set<Integer>>();
                Set<Integer> p = new HashSet<Integer>();
                p.add(curOp);
                s.put(val, p);
                return s;
            } catch (Exception e) {
                return null;
            }
        }
        return m.get(vkey(v));
    }

    private static void mayPut(Map<String, Map<Long, Set<Integer>>> m,
        String key, Map<Long, Set<Integer>> s) {
        if (s == null || s.size() > MAX_MAY_SET_SIZE) {
            m.remove(key);
        } else {
            m.put(key, s);
        }
    }

    /** Provenance union for one computed value: the union of the
        inputs' defining ops (empty = pure constant, never killed). */
    private static Set<Integer> unionProv(Set<Integer> a, Set<Integer> b) {
        Set<Integer> u = new HashSet<Integer>();
        if (a != null) u.addAll(a);
        if (b != null) u.addAll(b);
        return u;
    }

    private static Map<Long, Set<Integer>> mayCombine(
        Map<Long, Set<Integer>> a, Map<Long, Set<Integer>> b,
        java.util.function.BiFunction<Long, Long, Long> f, long mask) {
        if (a == null || b == null) return null;
        if ((long) a.size() * (long) b.size() > MAX_MAY_SET_SIZE) return null;
        Map<Long, Set<Integer>> r = new HashMap<Long, Set<Integer>>();
        for (Map.Entry<Long, Set<Integer>> e : a.entrySet()) {
            for (Map.Entry<Long, Set<Integer>> e2 : b.entrySet()) {
                long v = f.apply(e.getKey(), e2.getKey()) & mask;
                Set<Integer> prev = r.get(v);
                Set<Integer> u = unionProv(e.getValue(), e2.getValue());
                if (prev == null) r.put(v, u);
                else prev.addAll(u);
            }
        }
        return r.size() > MAX_MAY_SET_SIZE ? null : r;
    }

    private static Map<Long, Set<Integer>> mayMap(
        Map<Long, Set<Integer>> a,
        java.util.function.Function<Long, Long> f, long mask) {
        if (a == null) return null;
        Map<Long, Set<Integer>> r = new HashMap<Long, Set<Integer>>();
        for (Map.Entry<Long, Set<Integer>> e : a.entrySet()) {
            long v = f.apply(e.getKey()) & mask;
            Set<Integer> prev = r.get(v);
            Set<Integer> u = unionProv(e.getValue(), null);
            if (prev == null) r.put(v, u);
            else prev.addAll(u);
        }
        return r.size() > MAX_MAY_SET_SIZE ? null : r;
    }

    /** The may transfer function: the v3 op-folding algebra over
        value->provenance maps. Inner maps are never mutated after
        creation (mayPut/mayMeet always build fresh ones), so sharing
        a map between two varnodes (COPY passthrough) is safe. */
    private void applyMayTransfer(
        Map<String, Map<Long, Set<Integer>>> m, OpRec op,
        Memory mem, int curOp) {
        String mnem = op.mnem;
        Varnode[] ins = op.ins;
        Varnode out = op.out;
        if ((mnem.equals("INT_XOR") || mnem.equals("INT_SUB")) &&
            ins.length == 2 && out != null &&
            vkey(ins[0]).equals(vkey(ins[1]))) {
            // Zeroing idiom, as in applyTransfer: the result is
            // exactly 0 with empty (unconditional) provenance.
            Map<Long, Set<Integer>> r =
                new HashMap<Long, Set<Integer>>();
            r.put(0L, new HashSet<Integer>());
            mayPut(m, vkey(out), r);
        } else if (mnem.equals("COPY") && ins.length == 1) {
            if (out != null) {
                mayPut(m, vkey(out), mayCopyBits(ins[0], m, mem, curOp, isa));
            }
        } else if (mnem.equals("INT_AND") || mnem.equals("INT_OR") ||
            mnem.equals("INT_XOR")) {
            if (ins.length == 2 && out != null) {
                Map<Long, Set<Integer>> a = mayResolve(ins[0], m);
                Map<Long, Set<Integer>> b = mayResolve(ins[1], m);
                long mask = sizeMask(out.getSize());
                Map<Long, Set<Integer>> r = null;
                if (mnem.equals("INT_AND")) {
                    r = mayCombine(a, b, (x, y) -> x & y, mask);
                } else if (mnem.equals("INT_OR")) {
                    r = mayCombine(a, b, (x, y) -> x | y, mask);
                } else {
                    r = mayCombine(a, b, (x, y) -> x ^ y, mask);
                }
                mayPut(m, vkey(out), r);
            }
        } else if (mnem.equals("INT_ADD") || mnem.equals("INT_SUB") ||
            mnem.equals("INT_MULT")) {
            if (ins.length == 2 && out != null) {
                Map<Long, Set<Integer>> a = mayResolve(ins[0], m);
                Map<Long, Set<Integer>> b = mayResolve(ins[1], m);
                long mask = sizeMask(out.getSize());
                Map<Long, Set<Integer>> r = null;
                if (mnem.equals("INT_ADD")) {
                    r = mayCombine(a, b, (x, y) -> x + y, mask);
                } else if (mnem.equals("INT_SUB")) {
                    r = mayCombine(a, b, (x, y) -> x - y, mask);
                } else {
                    r = mayCombine(a, b, (x, y) -> x * y, mask);
                }
                mayPut(m, vkey(out), r);
            }
        } else if ((mnem.equals("INT_NOT") || mnem.equals("INT_NEGATE")) &&
            ins.length == 1 && out != null) {
            mayPut(m, vkey(out), mayMap(mayResolve(ins[0], m),
                x -> ~x, sizeMask(out.getSize())));
        } else if (mnem.equals("INT_2COMP") &&
            ins.length == 1 && out != null) {
            mayPut(m, vkey(out), mayMap(mayResolve(ins[0], m),
                x -> -x, sizeMask(out.getSize())));
        } else if ((mnem.equals("INT_LEFT") || mnem.equals("INT_RIGHT") ||
            mnem.equals("INT_SRIGHT")) && ins.length == 2 && out != null) {
            Map<Long, Set<Integer>> a = mayResolve(ins[0], m);
            Map<Long, Set<Integer>> n = mayResolve(ins[1], m);
            long mask = sizeMask(out.getSize());
            Map<Long, Set<Integer>> r = null;
            if (a != null && n != null && n.size() == 1) {
                long sh = n.keySet().iterator().next();
                Set<Integer> nProv = n.values().iterator().next();
                if (sh >= 0 && sh < 64) {
                    r = new HashMap<Long, Set<Integer>>();
                    int width = out.getSize() * 8;
                    for (Map.Entry<Long, Set<Integer>> e : a.entrySet()) {
                        long x = e.getKey();
                        long v;
                        if (mnem.equals("INT_LEFT")) {
                            v = x << sh;
                        } else if (mnem.equals("INT_RIGHT")) {
                            v = x >>> sh;
                        } else {
                            long sx = x;
                            if (width > 0 && width <= 64 &&
                                (sx & (1L << (width - 1))) != 0) sx |= ~mask;
                            v = sx >> sh;
                        }
                        long k = v & mask;
                        Set<Integer> prev = r.get(k);
                        Set<Integer> u = unionProv(e.getValue(), nProv);
                        if (prev == null) r.put(k, u);
                        else prev.addAll(u);
                    }
                    if (r.size() > MAX_MAY_SET_SIZE) r = null;
                }
            }
            mayPut(m, vkey(out), r);
        } else if (mnem.equals("INT_ZEXT") && ins.length == 1 && out != null) {
            // Zero-extension keeps the numeric value.
            mayPut(m, vkey(out), mayResolve(ins[0], m));
        } else if (mnem.equals("INT_SEXT") && ins.length == 1 && out != null) {
            Map<Long, Set<Integer>> a = mayResolve(ins[0], m);
            long outMask = sizeMask(out.getSize());
            long inMask = sizeMask(ins[0].getSize());
            long signBit = 1L << (ins[0].getSize() * 8 - 1);
            Map<Long, Set<Integer>> r = null;
            if (a != null) {
                r = new HashMap<Long, Set<Integer>>();
                for (Map.Entry<Long, Set<Integer>> e : a.entrySet()) {
                    long x = e.getKey();
                    long v = ((x & signBit) != 0) ? ((x | ~inMask) & outMask)
                        : (x & outMask);
                    Set<Integer> prev = r.get(v);
                    Set<Integer> u = unionProv(e.getValue(), null);
                    if (prev == null) r.put(v, u);
                    else prev.addAll(u);
                }
                if (r.size() > MAX_MAY_SET_SIZE) r = null;
            }
            mayPut(m, vkey(out), r);
        } else if (mnem.equals("SUBPIECE") && ins.length == 2 && out != null) {
            Map<Long, Set<Integer>> a = mayResolve(ins[0], m);
            Map<Long, Set<Integer>> off = mayResolve(ins[1], m);
            long mask = sizeMask(out.getSize());
            Map<Long, Set<Integer>> r = null;
            if (a != null && off != null && off.size() == 1) {
                long sh = off.keySet().iterator().next() * 8;
                Set<Integer> offProv = off.values().iterator().next();
                if (sh >= 0 && sh < 64) {
                    r = new HashMap<Long, Set<Integer>>();
                    for (Map.Entry<Long, Set<Integer>> e : a.entrySet()) {
                        long k = (e.getKey() >>> sh) & mask;
                        Set<Integer> prev = r.get(k);
                        Set<Integer> u = unionProv(e.getValue(), offProv);
                        if (prev == null) r.put(k, u);
                        else prev.addAll(u);
                    }
                    if (r.size() > MAX_MAY_SET_SIZE) r = null;
                }
            }
            mayPut(m, vkey(out), r);
        } else if (mnem.equals("LOAD") && out != null) {
            Map<Long, Set<Integer>> r = null;
            if (ins.length >= 2) {
                Map<Long, Set<Integer>> addrs = mayResolve(ins[1], m);
                if (addrs != null) {
                    r = new HashMap<Long, Set<Integer>>();
                    boolean ok = true;
                    for (long a : addrs.keySet()) {
                        try {
                            Address ad = toAddr(a);
                            int sz = out.getSize();
                            long val;
                            if (sz == 4) val = mem.getInt(ad) & 0xffffffffL;
                            else if (sz == 2) val = mem.getShort(ad) & 0xffffL;
                            else if (sz == 1) val = mem.getByte(ad) & 0xffL;
                            else { ok = false; break; }
                            // The loaded value is materialized by
                            // this LOAD (its origin is memory).
                            Set<Integer> p = new HashSet<Integer>();
                            p.add(curOp);
                            r.put(val, p);
                        } catch (Exception e) {
                            ok = false;
                            break;
                        }
                    }
                    if (!ok || r.size() > MAX_MAY_SET_SIZE) r = null;
                }
            }
            mayPut(m, vkey(out), r);
        } else if (mnem.equals("CALL") || mnem.equals("CALLIND")) {
            long[] clobber = clobberForCall(op);
            Set<String> drop = new HashSet<String>();
            for (long off : clobber) {
                if (isa.hasOverlappingRegisters()) {
                    drop.addAll(overlappingKeys(m.keySet(),
                        isa.registerSpaceName(), off,
                        isa.pointerSize(), null));
                } else {
                    for (String k : m.keySet()) {
                        if (k.startsWith(isa.registerSpaceName() +
                            ":" + off + ":")) {
                            drop.add(k);
                        }
                    }
                }
            }
            for (String k : drop) m.remove(k);
            if (out != null) mayPut(m, vkey(out), null);
        } else {
            if (out != null) mayPut(m, vkey(out), null);
        }
        // Overlapping-register invalidation, as in applyTransfer
        // (x86 only). Stale may values are sound (a superset) but
        // would cause false may entries, so invalidate them too.
        if (isa.hasOverlappingRegisters() && out != null &&
            out.getAddress() != null &&
            isa.registerSpaceName().equals(out.getAddress().
                getAddressSpace().getName())) {
            for (String k : overlappingKeys(m.keySet(),
                isa.registerSpaceName(), out.getOffset(),
                out.getSize(), vkey(out))) {
                m.remove(k);
            }
        }
    }

    /** May-join: a varnode keeps a finite set only if EVERY incoming
        path has a finite set for it; the set is the union, with
        provenance unioned per value. A missing key on any path
        means TOP (unconstrained) on that path, which poisons the
        join to TOP. */
    private static Map<String, Map<Long, Set<Integer>>> mayMeet(
        Map<String, Map<Long, Set<Integer>>> a,
        Map<String, Map<Long, Set<Integer>>> b) {
        if (a == null) return b;
        if (b == null) return a;
        Map<String, Map<Long, Set<Integer>>> r =
            new HashMap<String, Map<Long, Set<Integer>>>();
        for (Map.Entry<String, Map<Long, Set<Integer>>> e : a.entrySet()) {
            Map<Long, Set<Integer>> y = b.get(e.getKey());
            if (y == null) continue;
            Map<Long, Set<Integer>> u = new HashMap<Long, Set<Integer>>();
            for (Map.Entry<Long, Set<Integer>> ve : e.getValue().entrySet()) {
                Set<Integer> s = new HashSet<Integer>(ve.getValue());
                Set<Integer> yv = y.get(ve.getKey());
                if (yv != null) s.addAll(yv);
                u.put(ve.getKey(), s);
            }
            for (Map.Entry<Long, Set<Integer>> ve : y.entrySet()) {
                if (!u.containsKey(ve.getKey())) {
                    u.put(ve.getKey(), new HashSet<Integer>(ve.getValue()));
                }
            }
            if (u.size() <= MAX_MAY_SET_SIZE) r.put(e.getKey(), u);
        }
        return r;
    }

    private static boolean maySameState(
        Map<String, Map<Long, Set<Integer>>> a,
        Map<String, Map<Long, Set<Integer>>> b) {
        if (a == null || b == null) return a == b;
        if (a.size() != b.size()) return false;
        for (Map.Entry<String, Map<Long, Set<Integer>>> e : a.entrySet()) {
            Map<Long, Set<Integer>> o = b.get(e.getKey());
            if (o == null || !o.equals(e.getValue())) return false;
        }
        return true;
    }

    private static Map<String, Map<Long, Set<Integer>>> stripMayUniques(
        Map<String, Map<Long, Set<Integer>>> m) {
        Map<String, Map<Long, Set<Integer>>> r =
            new HashMap<String, Map<Long, Set<Integer>>>();
        for (Map.Entry<String, Map<Long, Set<Integer>>> e : m.entrySet()) {
            if (!e.getKey().startsWith("unique:")) {
                r.put(e.getKey(), e.getValue());
            }
        }
        return r;
    }

    /** CFG successors for one function, shared by the may fixpoint
        and the recording-time feasibility check (KEEP IN SYNC with
        runFixpoint's successor rules for BRANCH/CBRANCH/RETURN/
        BRANCHIND/CALL). */
    private List<List<Integer>> buildSucc(List<OpRec> ops,
        Map<Integer, List<Integer>> branchTargets) {
        int n = ops.size();
        Map<String, Integer> firstAt = new HashMap<String, Integer>();
        for (int i = 0; i < n; i++) {
            String a = ops.get(i).instrAddr.toString();
            if (!firstAt.containsKey(a)) firstAt.put(a, i);
        }
        List<List<Integer>> succ = new ArrayList<List<Integer>>(n);
        for (int i = 0; i < n; i++) succ.add(new ArrayList<Integer>());
        for (int i = 0; i < n; i++) {
            OpRec op = ops.get(i);
            String mnem = op.mnem;
            if (mnem.equals("BRANCH") || mnem.equals("CBRANCH")) {
                if (op.ins.length >= 1) {
                    long t = op.ins[0].getOffset();
                    Integer j = firstAt.get(isa.formatCodeAddress(t));
                    if (j == null) {
                        j = firstAt.get(isa.formatCodeAddress(isa.stripInstructionTag(t)));
                    }
                    if (j != null) succ.get(i).add(j);
                    else if (mnem.equals("BRANCH") &&
                        op.ins[0].isConstant()) {
                        // Intra-instruction sleigh label (x86 CPUID
                        // cascade): see runFixpoint. KEEP IN SYNC.
                        int f = isa.fallthroughIndex(ops, i);
                        if (f >= 0) succ.get(i).add(f);
                    }
                }
                if (mnem.equals("CBRANCH")) {
                    // Fallthrough goes through the ISA adapter (see
                    // runFixpoint: MIPS skips the delay-slot
                    // instruction's standalone ops).
                    int f = isa.fallthroughIndex(ops, i);
                    if (f >= 0) succ.get(i).add(f);
                }
            } else if (mnem.equals("RETURN")) {
                // No successors: RETURN ends the function.
            } else if (mnem.equals("BRANCHIND")) {
                // Jump-table targets recovered by the ISA adapter; anything else
                // (pointer tables, bx reg) keeps no successors.
                List<Integer> bt = branchTargets.get(i);
                if (bt != null) succ.get(i).addAll(bt);
            } else if (mnem.equals("CALL") || mnem.equals("CALLIND")) {
                // Fallthrough goes through the ISA adapter (MIPS skips
                // the delay-slot instruction's standalone ops).
                int f = isa.fallthroughIndex(ops, i);
                if (f >= 0) succ.get(i).add(f);
            } else {
                if (i + 1 < n) succ.get(i).add(i + 1);
            }
        }
        return succ;
    }

    /** v9 struct: the set of CALL/CALLIND op indices that lie on a
        CFG cycle (the op can reach itself through successors, so
        the site may execute more than once per function
        invocation). Computed from buildSucc, which shares
        runFixpoint's successor rules exactly (KEEP IN SYNC).
        Cost is one DFS per call op; call ops are few per
        function. A missed cycle would be unsound (two objects
        sharing one id), so the check is reachability, not a
        syntactic loop heuristic. */
    private Set<Integer> loopCallOpsFor(List<OpRec> ops,
        Map<Integer, List<Integer>> branchTargets) {
        Set<Integer> out = new HashSet<Integer>();
        List<List<Integer>> succ = buildSucc(ops, branchTargets);
        for (int i = 0; i < ops.size(); i++) {
            String m = ops.get(i).mnem;
            if (!m.equals("CALL") && !m.equals("CALLIND")) continue;
            java.util.ArrayDeque<Integer> stack =
                new java.util.ArrayDeque<Integer>();
            Set<Integer> seen = new HashSet<Integer>();
            for (int s : succ.get(i)) stack.push(s);
            boolean back = false;
            while (!stack.isEmpty()) {
                int j = stack.pop();
                if (j == i) {
                    back = true;
                    break;
                }
                if (!seen.add(j)) continue;
                for (int s : succ.get(j)) stack.push(s);
            }
            if (back) out.add(i);
        }
        return out;
    }

    /** Resolve a CBRANCH condition to (root varnode key, takenMeansZero
        as "1"/"0") by walking the def chain through COPY, BOOL_NEGATE
        and INT_EQUAL/INT_NOTEQUAL-against-0. Returns null when the
        chain cannot be resolved (then the edge is unconstrained --
        conservative). */
    private String[] resolveCond(Varnode v, List<OpRec> ops, int beforeIdx) {
        if (v == null || v.isConstant()) return null;
        Varnode cur = v;
        Varnode root = null;
        boolean takenZero = false;
        int flips = 0;
        for (int step = 0; step < 8; step++) {
            int def = findDef(ops, vkey(cur), beforeIdx);
            if (def < 0) {
                root = cur;
                takenZero = (flips % 2 == 1);
                break;
            }
            OpRec dd = ops.get(def);
            if (dd.mnem.equals("COPY") && dd.ins.length == 1 &&
                !dd.ins[0].isConstant()) {
                cur = dd.ins[0];
                continue;
            }
            if (dd.mnem.equals("BOOL_NEGATE") && dd.ins.length == 1) {
                flips++;
                cur = dd.ins[0];
                continue;
            }
            if ((dd.mnem.equals("INT_EQUAL") ||
                dd.mnem.equals("INT_NOTEQUAL")) &&
                dd.ins.length == 2 && dd.ins[1].isConstant() &&
                dd.ins[1].getOffset() == 0) {
                if (dd.ins[0].isConstant()) return null;
                root = dd.ins[0];
                takenZero = dd.mnem.equals("INT_EQUAL")
                    ? (flips % 2 == 0) : (flips % 2 == 1);
                break;
            }
            root = cur;
            takenZero = (flips % 2 == 1);
            break;
        }
        if (root == null || root.isConstant()) return null;
        // Full backward search for the root's defining op: two
        // branches are correlated ONLY if they test the same value,
        // and a root redefined between branches (the ARM flag temps
        // 0x60-0x69 are redefined at nearly every instruction) must
        // never count as the same condition.
        int rootDef = -1;
        for (int j = beforeIdx - 1; j >= 0; j--) {
            Varnode o = ops.get(j).out;
            if (o != null && vkey(o).equals(vkey(root))) {
                rootDef = j;
                break;
            }
        }
        String key = vkey(root) + "@" +
            (rootDef >= 0 ? Integer.toString(rootDef) : "entry");
        return new String[]{key, takenZero ? "1" : "0"};
    }

    /** v3.7: is the value defined by defOp dead at useOp? Dead means
        no FEASIBLE path carries it to the use varnode. This is a
        taint BFS, not a redefinition check: a value survives a
        redefinition of its original varnode if it was copied to
        another varnode first (the platform_init GPIOB case), and it
        dies on paths whose branch outcomes contradict each other
        (the correlated if/else-assign pattern behind the rcc
        false positive). Taint flows exactly where may-provenance
        flows (COPY and value-preserving arithmetic); LOAD results,
        comparison results and CALL-clobbered registers lose it.
        Any doubt (unresolvable condition, search cap) returns
        false -- the value is kept. Sound: only provably-dead
        values are dropped, never true ones. */
    private boolean isKilledDef(int defOp, int useOp, String useKey,
        List<OpRec> ops, List<List<Integer>> succ) {
        if (defOp < 0 || defOp >= ops.size()) return false;
        OpRec d = ops.get(defOp);
        if (d.out == null) return false;
        String defKey = vkey(d.out);
        Map<String, Integer> firstAt = new HashMap<String, Integer>();
        for (int i = 0; i < ops.size(); i++) {
            String a = ops.get(i).instrAddr.toString();
            if (!firstAt.containsKey(a)) firstAt.put(a, i);
        }
        java.util.ArrayDeque<Object[]> q = new java.util.ArrayDeque<Object[]>();
        java.util.Set<String> seen = new java.util.HashSet<String>();
        java.util.Set<String> t0 = new java.util.HashSet<String>();
        t0.add(defKey);
        for (int s : succ.get(defOp)) {
            q.add(new Object[]{s, t0, new HashMap<String, Boolean>()});
        }
        int steps = 0;
        while (!q.isEmpty()) {
            Object[] cur = q.remove();
            int j = (Integer) cur[0];
            @SuppressWarnings("unchecked")
            java.util.Set<String> taint = (java.util.Set<String>) cur[1];
            @SuppressWarnings("unchecked")
            Map<String, Boolean> asm = (Map<String, Boolean>) cur[2];
            if (j == useOp) {
                if (taint.contains(useKey)) return false;
                continue;
            }
            java.util.List<String> sortedTaint =
                new java.util.ArrayList<String>(taint);
            java.util.Collections.sort(sortedTaint);
            String sig = j + "|" + sortedTaint.toString() + "|" +
                asm.toString();
            if (!seen.add(sig)) continue;
            if (++steps > 20000) return false;
            OpRec oj = ops.get(j);
            // Taint transfer for this op.
            java.util.Set<String> nt = new java.util.HashSet<String>(taint);
            String mn = oj.mnem;
            if (mn.equals("COPY") || mn.equals("INT_AND") ||
                mn.equals("INT_OR") || mn.equals("INT_XOR") ||
                mn.equals("INT_ADD") || mn.equals("INT_SUB") ||
                mn.equals("INT_MULT") || mn.equals("INT_NOT") ||
                mn.equals("INT_NEGATE") || mn.equals("INT_2COMP") ||
                mn.equals("INT_LEFT") || mn.equals("INT_RIGHT") ||
                mn.equals("INT_SRIGHT") || mn.equals("INT_ZEXT") ||
                mn.equals("INT_SEXT") || mn.equals("SUBPIECE")) {
                boolean anyIn = false;
                for (Varnode in : oj.ins) {
                    if (!in.isConstant() && taint.contains(vkey(in))) {
                        anyIn = true;
                        break;
                    }
                }
                if (oj.out != null) {
                    nt.remove(vkey(oj.out));
                    if (anyIn) nt.add(vkey(oj.out));
                }
            } else if (mn.equals("CALL") || mn.equals("CALLIND")) {
                // A call destroys the WHOLE clobbered register, so
                // all views go (x86: clobbering rax kills eax/ax/
                // al/ah taint too). This is the only overlap
                // invalidation taint gets: a partial write does NOT
                // kill taint on the wider register (the other bytes
                // still carry the old value), and taint removal is
                // a "proven dead" claim, so keeping it is the sound
                // direction there.
                long[] clobber = clobberForCall(oj);
                java.util.Set<String> drop = new java.util.HashSet<String>();
                for (long off : clobber) {
                    if (isa.hasOverlappingRegisters()) {
                        drop.addAll(overlappingKeys(nt,
                            isa.registerSpaceName(), off,
                            isa.pointerSize(), null));
                    } else {
                        for (String k : nt) {
                            if (k.startsWith(isa.registerSpaceName() +
                                ":" + off + ":")) {
                                drop.add(k);
                            }
                        }
                    }
                }
                nt.removeAll(drop);
                if (oj.out != null) nt.remove(vkey(oj.out));
            } else if (oj.out != null) {
                // LOAD, comparisons, BOOL ops: fresh result, no flow.
                nt.remove(vkey(oj.out));
            }
            if (mn.equals("CBRANCH") && oj.ins.length >= 2) {
                String[] cond = resolveCond(oj.ins[1], ops, j);
                Integer targetIdx = null;
                if (oj.ins.length >= 1) {
                    long t = oj.ins[0].getOffset();
                    targetIdx = firstAt.get(isa.formatCodeAddress(t));
                    if (targetIdx == null) {
                        targetIdx = firstAt.get(
                            isa.formatCodeAddress(isa.stripInstructionTag(t)));
                    }
                }
                for (int s : succ.get(j)) {
                    Map<String, Boolean> na =
                        new HashMap<String, Boolean>(asm);
                    if (cond != null && targetIdx != null) {
                        boolean takenZero = cond[1].equals("1");
                        Boolean req;
                        if (s == targetIdx.intValue()) {
                            req = takenZero;
                        } else if (s == j + 1) {
                            req = !takenZero;
                        } else {
                            req = null;
                        }
                        if (req != null) {
                            Boolean prev = na.get(cond[0]);
                            if (prev != null && !prev.equals(req)) continue;
                            na.put(cond[0], req);
                        }
                    }
                    q.add(new Object[]{s, nt, na});
                }
            } else {
                for (int s : succ.get(j)) {
                    q.add(new Object[]{s, nt, asm});
                }
            }
        }
        return true;
    }

    @SuppressWarnings("unchecked")
    private MayResult runMayFixpoint(List<OpRec> ops, Memory mem,
        Map<Integer, List<Integer>> branchTargets) {
        int n = ops.size();
        Map<String, Map<Long, Set<Integer>>>[] in = new Map[n];
        if (n == 0) return new MayResult(in, true);
        in[0] = new HashMap<String, Map<Long, Set<Integer>>>();

        List<List<Integer>> succ = buildSucc(ops, branchTargets);

        boolean converged = false;
        for (int round = 0; round < MAX_FIXPOINT_ROUNDS && !converged; round++) {
            boolean changed = false;
            for (int i = 0; i < n; i++) {
                if (in[i] == null) continue;
                Map<String, Map<Long, Set<Integer>>> out =
                    new HashMap<String, Map<Long, Set<Integer>>>(in[i]);
                applyMayTransfer(out, ops.get(i), mem, i);
                for (int j : succ.get(i)) {
                    Map<String, Map<Long, Set<Integer>>> prop = out;
                    if (!ops.get(j).instrAddr.equals(ops.get(i).instrAddr)) {
                        prop = stripMayUniques(out);
                    }
                    Map<String, Map<Long, Set<Integer>>> merged =
                        mayMeet(in[j], prop);
                    if (!maySameState(in[j], merged)) {
                        in[j] = merged;
                        changed = true;
                    }
                }
            }
            if (!changed) converged = true;
        }
        if (!converged) {
            // Sound fallback: claim nothing rather than a stale set.
            for (int i = 0; i < n; i++) {
                in[i] = new HashMap<String, Map<Long, Set<Integer>>>();
            }
        }
        return new MayResult(in, converged);
    }

    /** Most recent op before beforeIdx (exclusive) whose output
        varnode has the given key, searching back at most 40 ops.
        -1 if none. Used by the TBB/TBH backward slice. */
    private static int findDef(List<OpRec> ops, String key, int beforeIdx) {
        for (int j = beforeIdx - 1; j >= 0 && j >= beforeIdx - 40; j--) {
            Varnode out = ops.get(j).out;
            if (out != null && vkey(out).equals(key)) return j;
        }
        return -1;
    }

    /** v2 item #3, Prov-pass ONLY def lookup (window 200).
        x86-64 P-Code expands each instruction into many ops, so
        argument setup (e.g. an R9 GUID loaded 60+ ops before its
        call) falls outside findDef's 40-op window and silently
        fails to resolve. The wide window is deliberately NOT
        applied to constprop/points-to: widening findDef globally
        moved BMP may sets (step-3 precise resolution replacing
        step-4 coarse offset sets at 40+ sites, may targets
        1930 -> 1725) in ways not provably sound site-by-site, so
        existing analyses keep their exact v3.9 behaviour and only
        the new Prov pass uses the wide window. */
    private static int findDefWide(List<OpRec> ops, String key,
        int beforeIdx) {
        for (int j = beforeIdx - 1; j >= 0 && j >= beforeIdx - 200; j--) {
            Varnode out = ops.get(j).out;
            if (out != null && vkey(out).equals(key)) return j;
        }
        return -1;
    }

    private static class IndirectResult {
        final List<String> sites;
        final int edges;
        final Map<Integer, List<Integer>> successors;
        final Set<Integer> certainCalls;
        final Set<Integer> resolvedBranchInds;
        IndirectResult(List<String> sites, int edges,
            Map<Integer, List<Integer>> successors,
            Set<Integer> certainCalls) {
            this(sites, edges, successors, certainCalls,
                new HashSet<Integer>());
        }
        IndirectResult(List<String> sites, int edges,
            Map<Integer, List<Integer>> successors,
            Set<Integer> certainCalls, Set<Integer> resolvedBranchInds) {
            this.sites = sites;
            this.edges = edges;
            this.successors = successors;
            this.certainCalls = certainCalls;
            this.resolvedBranchInds = resolvedBranchInds;
        }
    }

    /** One pointer-table match: the table's base address and whether
        entries are base-relative offsets (PIC) or absolute pointers. */
    private static class TableMatch {
        final long base;
        final boolean offset;
        TableMatch(long base, boolean offset) {
            this.base = base;
            this.offset = offset;
        }
    }

    /** Constant-fold a varnode's def chain (COPY / INT_ADD / INT_SUB /
        INT_LEFT / INT_MULT / INT_AND / INT_OR / INT_XOR of constants,
        depth-capped). Follows lui (INT_LEFT by 12) and auipc
        (INT_LEFT + INT_ADD of a PC constant), so RISC-V table bases
        built by lui+addi or auipc+addi fold to one constant. Results
        are masked to the ISA's address width. Null when not constant
        (register/unique inputs without a constant def, depth out). */
    private static Long constFold(List<OpRec> ops, String key,
        int beforeIdx, int depth, long mask) {
        if (key.startsWith("const:")) {
            try {
                String[] parts = key.split(":");
                return Long.parseLong(parts[1]) & mask;
            } catch (Exception e) {
                return null;
            }
        }
        if (depth <= 0) return null;
        int def = findDef(ops, key, beforeIdx);
        if (def < 0) return null;
        OpRec d = ops.get(def);
        if (d.mnem.equals("COPY") && d.ins.length == 1) {
            return constFold(ops, vkey(d.ins[0]), def, depth - 1, mask);
        }
        if (d.ins.length == 2) {
            Long a = constFold(ops, vkey(d.ins[0]), def, depth - 1, mask);
            Long b = constFold(ops, vkey(d.ins[1]), def, depth - 1, mask);
            if (a == null || b == null) return null;
            if (d.mnem.equals("INT_ADD")) {
                return (a.longValue() + b.longValue()) & mask;
            }
            if (d.mnem.equals("INT_SUB")) {
                return (a.longValue() - b.longValue()) & mask;
            }
            if (d.mnem.equals("INT_MULT")) {
                return (a.longValue() * b.longValue()) & mask;
            }
            if (d.mnem.equals("INT_AND")) {
                return (a.longValue() & b.longValue()) & mask;
            }
            if (d.mnem.equals("INT_OR")) {
                return (a.longValue() | b.longValue()) & mask;
            }
            if (d.mnem.equals("INT_XOR")) {
                return (a.longValue() ^ b.longValue()) & mask;
            }
            if (d.mnem.equals("INT_LEFT")) {
                return (a.longValue() << b.longValue()) & mask;
            }
        }
        return null;
    }

    /** True when a varnode's def is a pointer-index scaling:
        INT_LEFT by pointerIndexShift, or INT_MULT by pointerSize
        (either side). The scale operand is constant-FOLDED, not
        required to be a direct constant: Ghidra lifts RISC-V
        `slli` as COPY const -> unique, then INT_LEFT [reg, unique],
        so a direct-constant check misses every RISC-V table. */
    private static boolean isScaledIndex(List<OpRec> ops, Varnode v,
        int beforeIdx, int pointerSize, int pointerShift, long mask) {
        int def = findDef(ops, vkey(v), beforeIdx);
        if (def < 0) return false;
        OpRec sc = ops.get(def);
        if (sc.mnem.equals("INT_LEFT") && sc.ins.length == 2) {
            Long sh = constFold(ops, vkey(sc.ins[1]), def, 16, mask);
            return sh != null && sh.longValue() == (long) pointerShift;
        }
        if (sc.mnem.equals("INT_MULT") && sc.ins.length == 2) {
            for (int t = 0; t < 2; t++) {
                Long c = constFold(ops, vkey(sc.ins[t]), def, 16, mask);
                if (c != null && c.longValue() == (long) pointerSize) {
                    return true;
                }
            }
        }
        return false;
    }

    /** Walk an address expression: INT_ADDs accumulating constants
        until one side is a scaled index and the other side folds to
        the table base. Returns the base, or null. Generalizes the
        old one-level findPtrTableBase match (const base + scaled
        index, or COPY-of-const base): RISC-V bases need two levels
        (an outer INT_ADD carrying the lw offset, around
        INT_ADD [scaled, lui+addi base]). */
    private static Long matchAddr(List<OpRec> ops, String key,
        int beforeIdx, long acc, int depth, long mask,
        int pointerSize, int pointerShift) {
        if (depth <= 0) return null;
        int def = findDef(ops, key, beforeIdx);
        if (def < 0) return null;
        OpRec d = ops.get(def);
        if (d.mnem.equals("COPY") && d.ins.length == 1) {
            Long c = constFold(ops, vkey(d.ins[0]), def, 16, mask);
            if (c != null) return null; // whole expr constant: not a table
            return matchAddr(ops, vkey(d.ins[0]), def, acc, depth - 1,
                mask, pointerSize, pointerShift);
        }
        if (!d.mnem.equals("INT_ADD") || d.ins.length != 2) return null;
        for (int s = 0; s < 2; s++) {
            Long c = constFold(ops, vkey(d.ins[s]), def, 16, mask);
            if (c == null) continue;
            if (isScaledIndex(ops, d.ins[1 - s], def,
                pointerSize, pointerShift, mask)) {
                return (acc + c.longValue()) & mask;
            }
            Long nested = matchAddr(ops, vkey(d.ins[1 - s]), def,
                (acc + c.longValue()) & mask, depth - 1, mask,
                pointerSize, pointerShift);
            if (nested != null) return nested;
        }
        return null;
    }

    /** Match a BRANCHIND's table: absolute-pointer tables (the
        BRANCHIND target's def is a pointer-sized LOAD) and
        base-relative offset tables (target's def is
        INT_ADD [loaded, base] with base equal to the table base).
        Returns null when no table matches. */
    private static TableMatch matchBranchTable(List<OpRec> ops, int brIdx,
        int pointerSize, int pointerShift, long mask) {
        OpRec br = ops.get(brIdx);
        if (br.ins.length < 1) return null;
        int cur = findDef(ops, vkey(br.ins[0]), brIdx);
        if (cur < 0) return null;
        return matchBranchTableFrom(ops, brIdx, cur,
            pointerSize, pointerShift, mask);
    }

    /** Table-match core, starting from an already-resolved def index
        (MIPS unwraps the pc COPY + AND-~1 chain first, then calls
        this; RISC-V calls matchBranchTable, which resolves cur the
        same way as before, so RISC-V behaviour is unchanged). */
    private static TableMatch matchBranchTableFrom(List<OpRec> ops,
        int brIdx, int cur, int pointerSize, int pointerShift,
        long mask) {
        OpRec d = ops.get(cur);
        if (d.mnem.equals("INT_ADD") && d.ins.length == 2) {
            // Offset table: one side loads the entry, the other side
            // must fold to the same base as the load's address chain.
            for (int s = 0; s < 2; s++) {
                int defLoad = findDef(ops, vkey(d.ins[s]), cur);
                if (defLoad < 0) continue;
                OpRec ld = ops.get(defLoad);
                if (!ld.mnem.equals("LOAD") || ld.ins.length < 2 ||
                    ld.out == null || ld.out.getSize() != pointerSize) continue;
                Long base = matchAddr(ops, vkey(ld.ins[1]), defLoad, 0L,
                    8, mask, pointerSize, pointerShift);
                if (base == null) continue;
                Long side = constFold(ops, vkey(d.ins[1 - s]), cur, 16, mask);
                if (side != null && side.longValue() == base.longValue()) {
                    return new TableMatch(base.longValue(), true);
                }
            }
            return null;
        }
        if (!d.mnem.equals("LOAD") || d.ins.length < 2 ||
            d.out == null || d.out.getSize() != pointerSize) return null;
        Long base = matchAddr(ops, vkey(d.ins[1]), cur, 0L, 8, mask,
            pointerSize, pointerShift);
        if (base == null) return null;
        return new TableMatch(base.longValue(), false);
    }

    /** Backward slice for pointer-table dispatch: from a CALLIND /
        BRANCHIND destination, unwrap an optional Thumb-bit AND and a
        pointer-sized LOAD, and return the table base. The LOAD
        address may be a nested INT_ADD chain (RISC-V lui+addi /
        auipc+addi bases with an lw offset level); the old one-level
        match (const base + scaled index, or COPY-of-const base via
        `adr`) is subsumed by matchAddr. Null if no match. */
    private Long findPtrTableBase(List<OpRec> ops, int brIdx) {
        OpRec br = ops.get(brIdx);
        if (br.ins.length < 1) return null;
        int cur = findDef(ops, vkey(br.ins[0]), brIdx);
        if (cur < 0) return null;
        cur = isa.unwrapIndirectDef(ops, brIdx, cur);
        if (cur < 0) return null;
        OpRec d = ops.get(cur);
        if (d.mnem.equals("INT_AND") && d.ins.length == 2) {
            boolean unwrapped = false;
            for (int s = 0; s < 2; s++) {
                Varnode v = d.ins[s];
                if (v.isConstant() &&
                    isa.isInstructionTagMask(v.getOffset())) {
                    cur = findDef(ops, vkey(d.ins[1 - s]), cur);
                    unwrapped = true;
                    break;
                }
            }
            if (!unwrapped || cur < 0) return null;
            d = ops.get(cur);
        }
        if (!d.mnem.equals("LOAD") || d.ins.length < 2 ||
            d.out == null || d.out.getSize() != isa.pointerSize()) return null;
        long mask = isa.pointerSize() == 4 ? 0xffffffffL : -1L;
        return matchAddr(ops, vkey(d.ins[1]), cur, 0L, 8, mask,
            isa.pointerSize(), isa.pointerIndexShift());
    }

    /** v3.4 (fixed): recover call-graph edges AND intra-function
        pointer-table successors. For each CALLIND/BRANCHIND (skipping
        jump-table ones, which are already CFG successors):
          - single constant destination -> function-entry edge;
          - pointer table (see findPtrTableBase): each entry (& ~1)
            that is a function entry becomes an edge; each entry that
            is a real instruction start in THIS function becomes a
            CFG successor (BRANCHIND only -- a computed goto, not a
            call); the read stops at the first entry that is neither,
            or an unreadable address, capped at 64.
        Argument-dependent dispatch (vtable via object pointer) has no
        constant base and is handled by v3.5's may-analysis below. Every
        reported edge target is a real function entry by construction. */
    private IndirectResult recoverIndirect(List<OpRec> ops, Memory mem,
        FunctionManager fm, Set<Integer> jumpTableBranchInds) {
        List<String> out = new ArrayList<String>();
        Map<Integer, List<Integer>> succ =
            new HashMap<Integer, List<Integer>>();
        Set<Integer> certainCalls = new HashSet<Integer>();
        Set<Integer> resolvedBranchInds = new HashSet<Integer>();
        int edges = 0;
        Map<String, Integer> firstAt = new HashMap<String, Integer>();
        for (int i = 0; i < ops.size(); i++) {
            String a = ops.get(i).instrAddr.toString();
            if (!firstAt.containsKey(a)) firstAt.put(a, i);
        }
        for (int i = 0; i < ops.size(); i++) {
            OpRec call = ops.get(i);
            if (!call.mnem.equals("CALLIND") &&
                !call.mnem.equals("BRANCHIND")) continue;
            if (call.mnem.equals("BRANCHIND") &&
                jumpTableBranchInds.contains(i)) continue;
            if (call.ins.length < 1) continue;
            List<String> targets = new ArrayList<String>();
            List<Integer> mySucc = new ArrayList<Integer>();
            int def = findDef(ops, vkey(call.ins[0]), i);
            if (def >= 0) {
                def = isa.unwrapIndirectDef(ops, i, def);
            }
            if (def >= 0) {
                OpRec dd = ops.get(def);
                // v3.5: CALLIND destinations go through a Thumb-bit
                // AND (all 178 BMP CALLINDs do) -- unwrap it before
                // looking for a constant destination.
                if (dd.mnem.equals("INT_AND") && dd.ins.length == 2) {
                    for (int s = 0; s < 2; s++) {
                        Varnode vv = dd.ins[s];
                        if (vv.isConstant() &&
                            isa.isInstructionTagMask(vv.getOffset())) {
                            int du = findDef(ops, vkey(dd.ins[1 - s]), def);
                            if (du >= 0) {
                                def = du;
                                dd = ops.get(def);
                            }
                            break;
                        }
                    }
                }
                if (dd.mnem.equals("COPY") && dd.ins.length == 1) {
                    Long c = null;
                    if (dd.ins[0].isConstant()) {
                        c = dd.ins[0].getOffset();
                    } else {
                        int def2 = findDef(ops, vkey(dd.ins[0]), def);
                        if (def2 >= 0) {
                            OpRec d2 = ops.get(def2);
                            if (d2.mnem.equals("COPY") && d2.ins.length == 1 &&
                                d2.ins[0].isConstant()) {
                                c = d2.ins[0].getOffset();
                            }
                        }
                    }
                    if (c != null) {
                        try {
                            Function fn = fm.getFunctionAt(toAddr(isa.stripInstructionTag(c)));
                            if (fn != null) targets.add(fn.getName());
                        } catch (Exception e) {
                            // Ignore unresolvable targets.
                        }
                    }
                }
            }
            if (targets.isEmpty() && mySucc.isEmpty()) {
                Long base = findPtrTableBase(ops, i);
                if (base != null) {
                    for (int k = 0; k < 64; k++) {
                        long entryAddr = base.longValue() + (long) isa.pointerSize() * k;
                        long ptr;
                        try {
                            ptr = isa.readPointer(mem, toAddr(entryAddr));
                        } catch (Exception e) {
                            break;
                        }
                        long t = isa.stripInstructionTag(ptr);
                        Function fn = null;
                        try {
                            fn = fm.getFunctionAt(toAddr(t));
                        } catch (Exception e) {
                            break;
                        }
                        if (fn != null) {
                            String nm = fn.getName();
                            if (!targets.contains(nm)) targets.add(nm);
                            continue;
                        }
                        if (call.mnem.equals("BRANCHIND")) {
                            Integer j = firstAt.get(
                                isa.formatCodeAddress(t));
                            if (j == null) {
                                j = firstAt.get(
                                    isa.formatCodeAddress(isa.stripInstructionTag(t)));
                            }
                            if (j != null) {
                                if (!mySucc.contains(j)) {
                                    mySucc.add(j);
                                }
                                continue;
                            }
                        }
                        break;
                    }
                }
            }
            if (!targets.isEmpty()) {
                StringBuilder tb = new StringBuilder();
                for (int k = 0; k < targets.size(); k++) {
                    if (k > 0) tb.append(", ");
                    tb.append("\"").append(esc(targets.get(k))).append("\"");
                }
                out.add("{\"instr\": \"" + ops.get(i).instrAddr +
                    "\", \"op\": \"" + call.mnem +
                    "\", \"targets\": [" + tb.toString() + "]}");
                edges += targets.size();
                if (call.mnem.equals("CALLIND")) certainCalls.add(i);
                if (call.mnem.equals("BRANCHIND")) {
                    resolvedBranchInds.add(i);
                }
            }
            if (!mySucc.isEmpty()) succ.put(i, mySucc);
        }
        return new IndirectResult(out, edges, succ, certainCalls,
            resolvedBranchInds);
    }

    private static class OpsResult {
        final List<OpRec> ops;
        final boolean truncated;
        OpsResult(List<OpRec> ops, boolean truncated) {
            this.ops = ops;
            this.truncated = truncated;
        }
    }

    /** Shared P-Code walk for one function (capped, best-effort). */
    private OpsResult buildOps(Function f) {
        List<OpRec> ops = new ArrayList<OpRec>();
        int opCount = 0;
        boolean truncated = false;
        try {
            InstructionIterator instrs =
                currentProgram.getListing().getInstructions(f.getBody(), true);
            while (instrs.hasNext() && !monitor.isCancelled()) {
                Instruction instr = instrs.next();
                PcodeOp[] pops = instr.getPcode();
                for (PcodeOp op : pops) {
                    if (opCount >= MAX_PCODE_PER_FUNCTION) {
                        truncated = true;
                        break;
                    }
                    ops.add(new OpRec(instr.getAddress(),
                        instr.getMnemonicString(), op.getMnemonic(),
                        op.getInputs(), op.getOutput()));
                    opCount++;
                }
                if (truncated) break;
            }
        } catch (Exception e) {
            // keep JSON valid even if P-Code walk fails for a function
        }
        // Memory-propagation: annotate stack-derived LOAD/STORE
        // addresses once here -- def-chain walks are too expensive
        // to repeat per fixpoint round, and the annotation is a
        // static property of the op (it never changes across
        // rounds). If the SP/FP legs were not resolved, every flag
        // stays false (sound: unknown stores clear memState).
        for (int i = 0; i < ops.size(); i++) {
            OpRec op = ops.get(i);
            if ((op.mnem.equals("LOAD") || op.mnem.equals("STORE")) &&
                op.ins.length >= 2) {
                op.addrIsStack = isStackAddr(ops, op.ins[1], i);
            }
        }
        return new OpsResult(ops, truncated);
    }

    private static void putStore(Map<Long, Set<String>> m, long key,
        String name) {
        Set<String> s = m.get(key);
        if (s == null) {
            s = new HashSet<String>();
            m.put(key, s);
        }
        s.add(name);
    }

    /** v3.5 pass 1: collect every runtime store of a function address,
        keyed by destination -- a resolved address, a constant
        address, or a [reg + const offset] field offset. The offset
        key deliberately merges different structs sharing one offset:
        the resulting may-set is a superset (safe for "could call"),
        never a claim of certainty. */
    private void collectFuncPtrStores(List<OpRec> ops, Memory mem,
        FunctionManager fm, Map<Long, Set<String>> byOffset,
        Map<Long, Set<String>> byAddr) {
        for (int i = 0; i < ops.size(); i++) {
            OpRec op = ops.get(i);
            if (!op.mnem.equals("STORE") || op.ins.length < 3) continue;
            // Value: any chain that resolves to a function entry
            // (const, COPY, LOAD from a flash table, ...).
            Long val = resolveValue(op.ins[2], ops, mem, i, 4);
            if (val == null) continue;
            long funcAddr = isa.stripInstructionTag(val.longValue());
            String funcName = null;
            try {
                Function fn = fm.getFunctionAt(toAddr(funcAddr));
                if (fn != null) funcName = fn.getName();
            } catch (Exception e) {
                continue;
            }
            if (funcName == null) continue;
            Varnode a = op.ins[1];
            if (a.isConstant()) {
                putStore(byAddr, a.getOffset(), funcName);
            } else {
                Long av = resolveValue(a, ops, mem, i, 4);
                if (av != null) {
                    // Guard against null-base artifacts (a base
                    // that resolved to ~0 plus a field offset).
                    if (av.longValue() >= 0x1000L) {
                        putStore(byAddr, av.longValue(), funcName);
                    }
                }
                // v3.6 dual recording: a store through INT_ADD
                // [base, const] is ALSO a field-offset store,
                // whatever the base resolves to. Previously a store
                // whose address resolved went ONLY to byAddr, so
                // parameter-based sites (which fall back to the
                // offset map) never saw it -- that hid the DP init
                // stores (write_no_check, dp_read, ...) from every
                // may-set even though the stores were recorded.
                int da = findDef(ops, vkey(a), i);
                if (da >= 0) {
                    OpRec ad = ops.get(da);
                    if (ad.mnem.equals("INT_ADD") &&
                        ad.ins.length == 2) {
                        for (int s = 0; s < 2; s++) {
                            if (ad.ins[s].isConstant()) {
                                putStore(byOffset,
                                    ad.ins[s].getOffset(), funcName);
                                break;
                            }
                        }
                    }
                }
            }
        }
    }

    private static class PointsToResult {
        final List<String> maySites;
        final int mayTargets;
        final int unresolved;
        PointsToResult(List<String> maySites, int mayTargets,
            int unresolved) {
            this.maySites = maySites;
            this.mayTargets = mayTargets;
            this.unresolved = unresolved;
        }
    }

    /** Resolve a varnode to a concrete address/value through its
        backward def chain (COPY, INT_ADD of resolvable sides, LOAD
        of a resolvable address read from program memory), capped
        at depth hops. Returns null for parameters, long chains,
        arithmetic that does not resolve, and unreadable memory --
        the caller counts those as unresolved, never guesses. */
    private Long resolveValue(Varnode v, List<OpRec> ops, Memory mem,
        int pos, int depth) {
        if (v.isConstant()) return v.getOffset();
        // A varnode in a memory space (e.g. "ram") is a memory
        // cell, not a computed value: its value is the word at
        // that address. This is the ARM literal-pool pattern
        // (ldr r3, [pc, #x] loads a global pointer from a pool
        // entry in flash). Register/unique/const spaces are
        // excluded: they are values, not cells.
        String spName = v.getAddress().getAddressSpace().getName();
        if (!spName.equals("register") && !spName.equals("unique") &&
            !spName.equals("const")) {
            try {
                return isa.readPointer(mem, v.getAddress());
            } catch (Exception e) {
                return null;
            }
        }
        if (depth <= 0) return null;
        int d = findDef(ops, vkey(v), pos);
        if (d < 0) return null;
        OpRec dd = ops.get(d);
        if (dd.mnem.equals("COPY") && dd.ins.length == 1) {
            return resolveValue(dd.ins[0], ops, mem, d, depth - 1);
        }
        if (dd.mnem.equals("INT_ADD") && dd.ins.length == 2) {
            Long a = resolveValue(dd.ins[0], ops, mem, d, depth - 1);
            Long b = resolveValue(dd.ins[1], ops, mem, d, depth - 1);
            if (a != null && b != null) {
                return a.longValue() + b.longValue();
            }
            return null;
        }
        if (dd.mnem.equals("LOAD") && dd.ins.length >= 2) {
            Long a = resolveValue(dd.ins[1], ops, mem, d, depth - 1);
            if (a == null) return null;
            try {
                return isa.readPointer(mem, toAddr(a.longValue()));
            } catch (Exception e) {
                return null;
            }
        }
        return null;
    }

    /** v2 item #3: Prov-pass ONLY value resolver. Identical to
        resolveValue except it uses findDefWide (see findDefWide):
        GUID and interface-argument chains in x86-64 span more
        than 40 P-Code ops. Existing analyses keep resolveValue. */
    private Long resolveValueWide(Varnode v, List<OpRec> ops,
        Memory mem, int pos, int depth) {
        if (v.isConstant()) return v.getOffset();
        String spName = v.getAddress().getAddressSpace().getName();
        if (!spName.equals("register") && !spName.equals("unique") &&
            !spName.equals("const")) {
            try {
                return isa.readPointer(mem, v.getAddress());
            } catch (Exception e) {
                return null;
            }
        }
        if (depth <= 0) return null;
        int d = findDefWide(ops, vkey(v), pos);
        if (d < 0) return null;
        OpRec dd = ops.get(d);
        if (dd.mnem.equals("COPY") && dd.ins.length == 1) {
            return resolveValueWide(dd.ins[0], ops, mem, d,
                depth - 1);
        }
        if (dd.mnem.equals("INT_ADD") && dd.ins.length == 2) {
            Long a = resolveValueWide(dd.ins[0], ops, mem, d,
                depth - 1);
            Long b = resolveValueWide(dd.ins[1], ops, mem, d,
                depth - 1);
            if (a != null && b != null) {
                return a.longValue() + b.longValue();
            }
            return null;
        }
        if (dd.mnem.equals("LOAD") && dd.ins.length >= 2) {
            Long a = resolveValueWide(dd.ins[1], ops, mem, d,
                depth - 1);
            if (a == null) return null;
            try {
                return isa.readPointer(mem, toAddr(a.longValue()));
            } catch (Exception e) {
                return null;
            }
        }
        return null;
    }

    /** v3.6: shared indirect-target resolution for one indirect site
        (CALLIND or BRANCHIND) at index i. Unwraps the Thumb-bit
        INT_AND; with unwrapCopy also unwraps COPY chains (tail-call
        destinations often pass through a move). If the destination
        def is a 4-byte LOAD, applies the v3.5 tiers: constant field
        address (static word + exact-address runtime stores),
        resolvable chain (same), else scaled call-table read or the
        field-offset store map. Returns the target set, empty when
        the site does not resolve (the caller counts it). */
    private Set<String> resolveIndirectSet(List<OpRec> ops, Memory mem,
        FunctionManager fm, Map<Long, Set<String>> byOffset,
        Map<Long, Set<String>> byAddr, int i, boolean unwrapCopy) {
        Set<String> tset = new HashSet<String>();
        OpRec call = ops.get(i);
        if (call.ins.length < 1) return tset;
        int def = findDef(ops, vkey(call.ins[0]), i);
        if (def >= 0) {
            def = isa.unwrapIndirectDef(ops, i, def);
        }
        if (def >= 0) {
            OpRec dd = ops.get(def);
            if (dd.mnem.equals("INT_AND") && dd.ins.length == 2) {
                for (int s = 0; s < 2; s++) {
                    Varnode vv = dd.ins[s];
                    if (vv.isConstant() &&
                        isa.isInstructionTagMask(vv.getOffset())) {
                        int du = findDef(ops, vkey(dd.ins[1 - s]), def);
                        if (du >= 0) {
                            def = du;
                            dd = ops.get(def);
                        }
                        break;
                    }
                }
            }
            if (unwrapCopy) {
                for (int hop = 0; hop < 2; hop++) {
                    if (!dd.mnem.equals("COPY") || dd.ins.length != 1 ||
                        dd.ins[0].isConstant()) break;
                    int du = findDef(ops, vkey(dd.ins[0]), def);
                    if (du < 0) break;
                    def = du;
                    dd = ops.get(def);
                }
            }
        }
        if (def < 0) return tset;
        OpRec d = ops.get(def);
        if (!d.mnem.equals("LOAD") || d.ins.length < 2 ||
            d.out == null || d.out.getSize() != isa.pointerSize()) {
            return tset;
        }
        Varnode addrV = d.ins[1];
        if (addrV.isConstant()) {
            addMemFunc(mem, fm, addrV.getOffset(), tset);
            Set<String> st = byAddr.get(addrV.getOffset());
            if (st != null) tset.addAll(st);
        } else {
            Long a = resolveValue(addrV, ops, mem, def, 4);
            if (a != null) {
                addMemFunc(mem, fm, a.longValue(), tset);
                Set<String> st = byAddr.get(a.longValue());
                if (st != null) tset.addAll(st);
            } else {
                int da = findDef(ops, vkey(addrV), def);
                if (da >= 0) {
                    OpRec ad = ops.get(da);
                    if (ad.mnem.equals("INT_ADD") &&
                        ad.ins.length == 2) {
                        int constSide = -1;
                        int regSide = -1;
                        for (int s = 0; s < 2; s++) {
                            if (ad.ins[s].isConstant()) {
                                constSide = s;
                            } else {
                                regSide = s;
                            }
                        }
                        if (constSide >= 0 && regSide >= 0) {
                            long cval = ad.ins[constSide].getOffset();
                            int dr = findDef(ops,
                                vkey(ad.ins[regSide]), da);
                            boolean scaled = false;
                            if (dr >= 0) {
                                OpRec rd = ops.get(dr);
                                if (rd.mnem.equals("INT_LEFT") &&
                                    rd.ins.length == 2 &&
                                    rd.ins[1].isConstant() &&
                                    rd.ins[1].getOffset() == (long) isa.pointerIndexShift()) {
                                    scaled = true;
                                } else if (rd.mnem.equals("INT_MULT") &&
                                    rd.ins.length == 2) {
                                    for (int t = 0; t < 2; t++) {
                                        if (rd.ins[t].isConstant() &&
                                            rd.ins[t].getOffset() == (long) isa.pointerSize()) {
                                            scaled = true;
                                        }
                                    }
                                }
                            }
                            if (scaled) {
                                for (int k = 0; k < 64; k++) {
                                    long ea = cval + (long) isa.pointerSize() * k;
                                    try {
                                        long ptr = isa.readPointer(mem, toAddr(ea));
                                        Function fn =
                                            fm.getFunctionAt(
                                                toAddr(
                                                    isa.stripInstructionTag(ptr)));
                                        if (fn == null) break;
                                        tset.add(fn.getName());
                                    } catch (Exception e) {
                                        break;
                                    }
                                }
                            } else {
                                Set<String> st =
                                    byOffset.get(cval);
                                if (st != null) {
                                    tset.addAll(st);
                                }
                            }
                        }
                    }
                }
            }
        }
        return tset;
    }

    /** v3.5 pass 2: resolve CALLINDs to may-call-edges. CALLINDs
        already certain via recoverIndirect are skipped (they are not
        unresolved). Tiers are resolveIndirectSet with unwrapCopy
        false, preserving v3.5 behaviour exactly. */
    private PointsToResult recoverPointsTo(List<OpRec> ops, Memory mem,
        FunctionManager fm, Map<Long, Set<String>> byOffset,
        Map<Long, Set<String>> byAddr, Set<Integer> certainCalls) {
        List<String> out = new ArrayList<String>();
        int targets = 0;
        int unresolved = 0;
        for (int i = 0; i < ops.size(); i++) {
            OpRec call = ops.get(i);
            if (!call.mnem.equals("CALLIND") || call.ins.length < 1) continue;
            if (certainCalls.contains(i)) continue;
            Set<String> tset = resolveIndirectSet(ops, mem, fm,
                byOffset, byAddr, i, false);
            if (tset.isEmpty()) {
                unresolved++;
            } else {
                List<String> sorted = new ArrayList<String>(tset);
                java.util.Collections.sort(sorted);
                StringBuilder tb = new StringBuilder();
                for (int k = 0; k < sorted.size(); k++) {
                    if (k > 0) tb.append(", ");
                    tb.append("\"").append(esc(sorted.get(k)))
                        .append("\"");
                }
                out.add("{\"instr\": \"" + ops.get(i).instrAddr +
                    "\", \"op\": \"CALLIND\"" +
                    ", \"targets\": [" + tb.toString() + "]}");
                targets += sorted.size();
            }
        }
        return new PointsToResult(out, targets, unresolved);
    }

    private static class TailCallResult {
        final List<String> sites;
        final int targets;
        final int unresolved;
        /** Target function names (v2 item #2: a tail-call target has
            an unmodelled caller, so its entry must stay unknown). */
        final Set<String> targetNames;
        TailCallResult(List<String> sites, int targets,
            int unresolved) {
            this(sites, targets, unresolved, new HashSet<String>());
        }
        TailCallResult(List<String> sites, int targets,
            int unresolved, Set<String> targetNames) {
            this.sites = sites;
            this.targets = targets;
            this.unresolved = unresolved;
            this.targetNames = targetNames;
        }
    }

    /** v3.6: resolve BRANCHIND tail calls. Skips BRANCHINDs already
        resolved by v3.4 (constant destinations) and jump-table
        successors (computed gotos). LOAD destinations run the same
        tiers as CALLINDs (with COPY unwrap). A constant destination
        inside this function is a goto (skipped, not unresolved); a
        constant destination at a function entry outside this
        function is a direct tail call; a destination of lr is a
        return (skipped). Everything else counts as unresolved. */
    private TailCallResult recoverTailCalls(List<OpRec> ops, Memory mem,
        FunctionManager fm, Map<Long, Set<String>> byOffset,
        Map<Long, Set<String>> byAddr, Set<Integer> resolvedBranchInds,
        Set<Integer> jumpTableBranchInds, long funcStart, long funcEnd) {
        List<String> out = new ArrayList<String>();
        Set<String> targetNames = new HashSet<String>();
        int targets = 0;
        int unresolved = 0;
        for (int i = 0; i < ops.size(); i++) {
            OpRec call = ops.get(i);
            if (!call.mnem.equals("BRANCHIND") ||
                call.ins.length < 1) continue;
            if (resolvedBranchInds.contains(i)) continue;
            if (jumpTableBranchInds.contains(i)) continue;
            Set<String> tset = resolveIndirectSet(ops, mem, fm,
                byOffset, byAddr, i, true);
            if (!tset.isEmpty()) {
                List<String> sorted = new ArrayList<String>(tset);
                java.util.Collections.sort(sorted);
                StringBuilder tb = new StringBuilder();
                for (int k = 0; k < sorted.size(); k++) {
                    if (k > 0) tb.append(", ");
                    tb.append("\"").append(esc(sorted.get(k)))
                        .append("\"");
                }
                out.add("{\"instr\": \"" + ops.get(i).instrAddr +
                    "\", \"op\": \"BRANCHIND\"" +
                    ", \"targets\": [" + tb.toString() + "]}");
                targets += sorted.size();
                targetNames.addAll(sorted);
                continue;
            }
            // Not a LOAD dispatch: classify instead of guessing.
            Varnode dest = call.ins[0];
            int def = findDef(ops, vkey(dest), i);
            if (def >= 0) {
                OpRec dd = ops.get(def);
                if (dd.mnem.equals("INT_AND") && dd.ins.length == 2) {
                    for (int s = 0; s < 2; s++) {
                        Varnode vv = dd.ins[s];
                        if (vv.isConstant() &&
                            isa.isInstructionTagMask(vv.getOffset())) {
                            int du = findDef(ops, vkey(dd.ins[1 - s]), def);
                            if (du >= 0) {
                                def = du;
                                dd = ops.get(def);
                            }
                            break;
                        }
                    }
                }
                if (dd.mnem.equals("LOAD")) {
                    // LOAD tiers failed: genuinely unresolved.
                    unresolved++;
                    continue;
                }
                for (int hop = 0; hop < 2; hop++) {
                    if (!dd.mnem.equals("COPY") || dd.ins.length != 1 ||
                        dd.ins[0].isConstant()) break;
                    int du = findDef(ops, vkey(dd.ins[0]), def);
                    if (du < 0) break;
                    def = du;
                    dd = ops.get(def);
                }
                if (dd.mnem.equals("LOAD")) {
                    unresolved++;
                    continue;
                }
            }
            // lr (ARM register offset 0x58) as the destination
            // varnode, directly or through the unwrapped chain.
            boolean isReturn = false;
            if (isa.isReturnAddressRegister(dest)) {
                isReturn = true;
            } else if (def >= 0) {
                OpRec dd = ops.get(def);
                if (dd.mnem.equals("COPY") && dd.ins.length == 1) {
                    Varnode v = dd.ins[0];
                    if (isa.isReturnAddressRegister(v)) {
                        isReturn = true;
                    }
                }
            }
            if (isReturn) continue;
            Long c = resolveValue(dest, ops, mem, i, 4);
            if (c != null) {
                long t = isa.stripInstructionTag(c.longValue());
                try {
                    Function fn = fm.getFunctionAt(toAddr(t));
                    if (fn != null && (t < funcStart || t >= funcEnd)) {
                        out.add("{\"instr\": \"" + ops.get(i).instrAddr +
                            "\", \"op\": \"BRANCHIND\"" +
                            ", \"targets\": [\"" + esc(fn.getName()) +
                            "\"]}");
                        targets += 1;
                        targetNames.add(fn.getName());
                        continue;
                    }
                    if (t >= funcStart && t < funcEnd) {
                        continue; // goto inside this function
                    }
                } catch (Exception e) {
                    // fall through to unresolved
                }
            }
            unresolved++;
        }
        return new TailCallResult(out, targets, unresolved, targetNames);
    }

    // ---------------- v2 item #3: protocol-aware points-to ----------------
    // UEFI protocol calls are indirect calls through a function-
    // pointer table inside an interface struct. The interface itself
    // is obtained via Boot Services (LocateProtocol / HandleProtocol
    // / OpenProtocol, identified by a GUID argument) or installed
    // (InstallProtocolInterface / InstallMultipleProtocolInterfaces).
    // This pass tracks INTERFACE PROVENANCE: for each value, what
    // protocol instance (if any) it certainly points to. A method
    // call resolves only when the interface identity AND the method
    // offset are both certain; anything ambiguous stays unknown
    // (never a guessed must-finding). See the design note above
    // runProvFixpoint.
    //
    // GUID byte order: EFI_GUID {UINT32, UINT16, UINT16, UINT8[8]}
    // is stored little-endian for the first three fields, then the
    // 8 Data4 bytes as written. Verified against the EDK2 headers
    // (MdePkg/Include/Protocol/PciIo.h, UEFI spec 2.9A §14).
    //
    // Hardware-effect attribution (Pci.Read/Write -> CF8/CFC) is
    // sound for THIS corpus because the platform host bridge driver
    // (PciHostBridgeDxe.pe) implements config access with MOV
    // ECX,0xcf8 + IN/OUT (verified in its disassembly). On an
    // ECAM-only platform the mechanism differs; the attribution
    // records the config cycle as the legacy CF8/CFC pair, which is
    // the mechanism this corpus uses. All other protocol methods
    // (BAR-relative Mem/Io, DMA Map/CopyMem, ...) have no fixed
    // hardware effect and are recorded as edges only, never as
    // fabricated port/MMIO accesses.
    private static class ProtoField {
        final String guid;
        final boolean embedded;
        ProtoField(String g, boolean e) { guid = g; embedded = e; }
        public boolean equals(Object o) {
            if (!(o instanceof ProtoField)) return false;
            ProtoField p = (ProtoField) o;
            return guid.equals(p.guid) && embedded == p.embedded;
        }
        public int hashCode() { return guid.hashCode() * 31 +
            (embedded ? 1 : 0); }
    }

    /** Provenance of one value. Kinds: 0 unknown, 1 Boot Services
        table pointer, 2 interface instance, 3 method function
        pointer, 4 struct pointer (layout: field offset -> field),
        5 method-slot pointer (address of a method slot), 6 pointer
        to an interface-pointer field (LOAD yields the interface).
        Only non-unknown values are stored in states (missing key
        already means unknown), mirroring the Bits convention. */
    private static class Prov {
        static final int UNKNOWN = 0;
        static final int BS = 1;
        static final int IFACE = 2;
        static final int METHOD = 3;
        static final int STRUCT = 4;
        static final int SLOT = 5;
        static final int FIELDPTR = 6;
        final int kind;
        final String guid;
        final long off;
        final Map<Long, ProtoField> layout;
        final Prov structProv;
        final long fieldOff;
        private Prov(int k, String g, long o,
            Map<Long, ProtoField> l, Prov s, long f) {
            kind = k; guid = g; off = o; layout = l; structProv = s;
            fieldOff = f;
        }
        static Prov unknown() { return new Prov(UNKNOWN, null, 0,
            null, null, 0); }
        static Prov bs() { return new Prov(BS, "BS", 0, null, null, 0); }
        static Prov iface(String g) { return new Prov(IFACE, g, 0,
            null, null, 0); }
        static Prov method(String g, long o) { return new Prov(METHOD,
            g, o, null, null, 0); }
        static Prov struct(Map<Long, ProtoField> l) { return new Prov(
            STRUCT, null, 0, l, null, 0); }
        static Prov slot(String g, long o) { return new Prov(SLOT,
            g, o, null, null, 0); }
        static Prov fieldPtr(Prov s, long f) { return new Prov(
            FIELDPTR, null, 0, null, s, f); }
        public boolean equals(Object o) {
            if (!(o instanceof Prov)) return false;
            Prov p = (Prov) o;
            if (kind != p.kind) return false;
            if (guid == null ? p.guid != null : !guid.equals(p.guid))
                return false;
            if (off != p.off || fieldOff != p.fieldOff) return false;
            if (layout == null ? p.layout != null :
                !layout.equals(p.layout)) return false;
            if (structProv == null ? p.structProv != null :
                !structProv.equals(p.structProv)) return false;
            return true;
        }
        public int hashCode() {
            int h = kind * 31 + (int) off + (int) fieldOff;
            if (guid != null) h = h * 31 + guid.hashCode();
            if (layout != null) h = h * 31 + layout.hashCode();
            if (structProv != null) h = h * 31 + structProv.hashCode();
            return h;
        }
        public String toString() {
            switch (kind) {
                case BS: return "BS";
                case IFACE: return "IFACE(" + guid + ")";
                case METHOD: return "METHOD(" + guid + ",0x" +
                    Long.toHexString(off) + ")";
                case STRUCT: return "STRUCT(" + layout + ")";
                case SLOT: return "SLOT(" + guid + ",0x" +
                    Long.toHexString(off) + ")";
                case FIELDPTR: return "FIELDPTR(" + structProv + "," +
                    fieldOff + ")";
                default: return "UNKNOWN";
            }
        }
    }

    /** One known protocol: GUID bytes + method offset -> name. */
    private static class ProtoInfo {
        final String name;
        final byte[] guidBytes;
        final Map<Long, String> methods;
        ProtoInfo(String n, byte[] g, String[][] m) {
            name = n; guidBytes = g;
            methods = new HashMap<Long, String>();
            for (String[] e : m) {
                methods.put(Long.parseLong(e[0], 16), e[1]);
            }
        }
    }

    private static byte[] guidBytes(long d1, int d2, int d3,
        int b0, int b1, int b2, int b3, int b4, int b5, int b6,
        int b7) {
        return new byte[] {
            (byte) d1, (byte) (d1 >>> 8), (byte) (d1 >>> 16),
            (byte) (d1 >>> 24), (byte) d2, (byte) (d2 >>> 8),
            (byte) d3, (byte) (d3 >>> 8),
            (byte) b0, (byte) b1, (byte) b2, (byte) b3,
            (byte) b4, (byte) b5, (byte) b6, (byte) b7 };
    }

    private static List<ProtoInfo> protoTable() {
        List<ProtoInfo> t = new ArrayList<ProtoInfo>();
        t.add(new ProtoInfo("PciIo",
            guidBytes(0x4cf5b200L, 0x68b8, 0x4ca5,
                0x9e, 0xec, 0xb2, 0x3e, 0x3f, 0x50, 0x02, 0x9a),
            new String[][] {
                {"0", "PollMem"}, {"8", "PollIo"},
                {"10", "Mem.Read"}, {"18", "Mem.Write"},
                {"20", "Io.Read"}, {"28", "Io.Write"},
                {"30", "Pci.Read"}, {"38", "Pci.Write"},
                {"40", "CopyMem"}, {"48", "Map"}, {"50", "Unmap"},
                {"58", "AllocateBuffer"}, {"60", "FreeBuffer"},
                {"68", "Flush"}, {"70", "GetLocation"},
                {"78", "Attributes"}, {"80", "GetBarAttributes"},
                {"88", "SetBarAttributes"}}));
        t.add(new ProtoInfo("PciRootBridgeIo",
            guidBytes(0x2f707ebbL, 0x4a1a, 0x11d4,
                0x9a, 0x38, 0x00, 0x90, 0x27, 0x3f, 0xc1, 0x4d),
            new String[][] {
                {"8", "PollMem"}, {"10", "PollIo"},
                {"18", "Mem.Read"}, {"20", "Mem.Write"},
                {"28", "Io.Read"}, {"30", "Io.Write"},
                {"38", "Pci.Read"}, {"40", "Pci.Write"},
                {"48", "CopyMem"}, {"50", "Map"}, {"58", "Unmap"},
                {"60", "AllocateBuffer"}, {"68", "FreeBuffer"},
                {"70", "Flush"}, {"78", "GetAttributes"},
                {"80", "SetAttributes"}, {"88", "Configuration"}}));
        return t;
    }

    /** EFI_BOOT_SERVICES method offsets (x86-64, 8-byte pointers,
        24-byte EFI_TABLE_HEADER first). Only the methods this pass
        reasons about are listed; anything else is "unknown BS
        method" (still a resolved edge, never a finding). */
    private static Map<Long, String> bsMethods() {
        Map<Long, String> m = new HashMap<Long, String>();
        m.put(0x18L, "RaiseTPL"); m.put(0x20L, "RestoreTPL");
        m.put(0x28L, "AllocatePages"); m.put(0x30L, "FreePages");
        m.put(0x38L, "GetMemoryMap"); m.put(0x40L, "AllocatePool");
        m.put(0x48L, "FreePool"); m.put(0x50L, "CreateEvent");
        m.put(0x58L, "SetTimer"); m.put(0x60L, "WaitForEvent");
        m.put(0x68L, "SignalEvent"); m.put(0x70L, "CloseEvent");
        m.put(0x78L, "CheckEvent");
        m.put(0x80L, "InstallProtocolInterface");
        m.put(0x88L, "ReinstallProtocolInterface");
        m.put(0x90L, "UninstallProtocolInterface");
        m.put(0x98L, "HandleProtocol");
        m.put(0xa8L, "RegisterProtocolNotify");
        m.put(0xb0L, "LocateHandle"); m.put(0xb8L, "LocateDevicePath");
        m.put(0xc0L, "InstallConfigurationTable");
        m.put(0xc8L, "LoadImage"); m.put(0xd0L, "StartImage");
        m.put(0xd8L, "Exit"); m.put(0xe0L, "UnloadImage");
        m.put(0xe8L, "ExitBootServices");
        m.put(0xf0L, "GetNextMonotonicCount"); m.put(0xf8L, "Stall");
        m.put(0x100L, "SetWatchdogTimer");
        m.put(0x108L, "ConnectController");
        m.put(0x110L, "DisconnectController");
        m.put(0x118L, "OpenProtocol"); m.put(0x120L, "CloseProtocol");
        m.put(0x128L, "OpenProtocolInformation");
        m.put(0x130L, "ProtocolsPerHandle");
        m.put(0x138L, "LocateHandleBuffer");
        m.put(0x140L, "LocateProtocol");
        m.put(0x148L, "InstallMultipleProtocolInterfaces");
        m.put(0x150L, "UninstallMultipleProtocolInterfaces");
        m.put(0x158L, "CalculateCrc32"); m.put(0x160L, "CopyMem");
        m.put(0x168L, "SetMem"); m.put(0x170L, "CreateEventEx");
        return m;
    }

    /** Read 16 bytes at a program address; null if unreadable. */
    private byte[] readGuidBytes(Memory mem, long addr) {
        try {
            Address a = toAddr(addr);
            byte[] b = new byte[16];
            for (int i = 0; i < 16; i++) {
                b[i] = mem.getByte(a.add(i));
            }
            return b;
        } catch (Exception e) {
            return null;
        }
    }

    private static boolean guidEquals(byte[] a, byte[] b) {
        if (a == null || b == null || a.length != 16 ||
            b.length != 16) return false;
        for (int i = 0; i < 16; i++) {
            if (a[i] != b[i]) return false;
        }
        return true;
    }

    /** Match 16 GUID bytes against the table; null if unknown. */
    private static String matchGuid(byte[] b, List<ProtoInfo> t) {
        if (b == null) return null;
        for (ProtoInfo p : t) {
            if (guidEquals(b, p.guidBytes)) return p.name;
        }
        return null;
    }

    private static ProtoInfo protoByName(String name,
        List<ProtoInfo> t) {
        for (ProtoInfo p : t) {
            if (p.name.equals(name)) return p;
        }
        return null;
    }

    /** One provenance state: varnode provenances, stack-slot
        provenances (RSP/RBP-relative locals), and function-local
        global assignments. Unknown = absent key (mirroring Bits).
        Slots and globals are memory: they survive across
        instructions, unlike unique varnodes (stripped by
        stripProvUniques on cross-instruction propagation). */
    private static class ProvState {
        final Map<String, Prov> varProv;
        final Map<String, Prov> slotProv;
        final Map<Long, Prov> globalProv;
        ProvState() {
            varProv = new HashMap<String, Prov>();
            slotProv = new HashMap<String, Prov>();
            globalProv = new HashMap<Long, Prov>();
        }
        ProvState(ProvState o) {
            varProv = new HashMap<String, Prov>(o.varProv);
            slotProv = new HashMap<String, Prov>(o.slotProv);
            globalProv = new HashMap<Long, Prov>(o.globalProv);
        }
        boolean sameAs(ProvState o) {
            if (o == null) return false;
            return varProv.equals(o.varProv) &&
                slotProv.equals(o.slotProv) &&
                globalProv.equals(o.globalProv);
        }
    }

    private static class ProvResult {
        final ProvState[] inStates;
        final boolean converged;
        ProvResult(ProvState[] s, boolean c) {
            inStates = s; converged = c;
        }
    }

    /** Context for the provenance fixpoint (per program run). */
    private static class ProvCtx {
        Memory mem;
        Set<Long> gbsAddrs;
        Map<Long, Prov> globalProvPre;
        List<ProtoInfo> protos;
        Map<Long, String> bsMethods;
        long rspOff;
        long rbpOff;
    }

    /** Meet of two provenances: equal stays, STRUCT layouts meet
        by field intersection, anything else becomes unknown
        (dropped). This is the certainty lattice: a value is a
        known interface only if EVERY path agrees. */
    private static Prov meetProv(Prov a, Prov b) {
        // Null here means "unknown on that path" (the state exists
        // but lacks the key), NOT "unreachable": a certain value
        // meeting unknown becomes unknown. State-level null
        // (unreachable) is handled by meetProvState, never here.
        if (a == null || b == null) return null;
        if (a.equals(b)) return a;
        if (a.kind == Prov.STRUCT && b.kind == Prov.STRUCT) {
            Map<Long, ProtoField> inter =
                new HashMap<Long, ProtoField>();
            for (Map.Entry<Long, ProtoField> e :
                a.layout.entrySet()) {
                ProtoField o = b.layout.get(e.getKey());
                if (o != null && o.equals(e.getValue())) {
                    inter.put(e.getKey(), e.getValue());
                }
            }
            return Prov.struct(inter);
        }
        return null;
    }

    private static ProvState meetProvState(ProvState a,
        ProvState b) {
        if (a == null) return b;
        if (b == null) return a;
        ProvState out = new ProvState();
        for (Map.Entry<String, Prov> e : a.varProv.entrySet()) {
            Prov m = meetProv(e.getValue(), b.varProv.get(e.getKey()));
            if (m != null) out.varProv.put(e.getKey(), m);
        }
        for (Map.Entry<String, Prov> e : a.slotProv.entrySet()) {
            Prov m = meetProv(e.getValue(), b.slotProv.get(e.getKey()));
            if (m != null) out.slotProv.put(e.getKey(), m);
        }
        for (Map.Entry<Long, Prov> e : a.globalProv.entrySet()) {
            Prov m = meetProv(e.getValue(), b.globalProv.get(e.getKey()));
            if (m != null) out.globalProv.put(e.getKey(), m);
        }
        return out;
    }

    private static ProvState stripProvUniques(ProvState s) {
        ProvState out = new ProvState();
        for (Map.Entry<String, Prov> e : s.varProv.entrySet()) {
            if (!e.getKey().startsWith("unique:")) {
                out.varProv.put(e.getKey(), e.getValue());
            }
        }
        out.slotProv.putAll(s.slotProv);
        out.globalProv.putAll(s.globalProv);
        return out;
    }

    /** Provenance fixpoint: mirrors runFixpoint's CFG and
        cross-instruction unique stripping, but over Prov states.
        Entry state binds the callee's argument registers (from
        inter-procedural parameter propagation); a loop back to op
        0 meets into it, so an entry provenance survives only if
        no loop path redefines it. Non-convergence falls back to
        all-unknown (sound: claim nothing). */
    private ProvResult runProvFixpoint(List<OpRec> ops,
        Map<Integer, List<Integer>> branchTargets,
        Map<String, Prov> entry, ProvCtx ctx) {
        int n = ops.size();
        ProvState[] in = new ProvState[n];
        if (n == 0) return new ProvResult(in, true);
        in[0] = new ProvState();
        if (entry != null) in[0].varProv.putAll(entry);
        List<List<Integer>> succ = buildSucc(ops, branchTargets);
        boolean converged = false;
        for (int round = 0; round < MAX_FIXPOINT_ROUNDS &&
            !converged; round++) {
            boolean changed = false;
            for (int i = 0; i < n; i++) {
                if (in[i] == null) continue;
                ProvState out = new ProvState(in[i]);
                applyProvTransfer(out, ops.get(i), ops, i, ctx);
                for (int j : succ.get(i)) {
                    ProvState prop = out;
                    if (!ops.get(j).instrAddr.equals(
                        ops.get(i).instrAddr)) {
                        prop = stripProvUniques(out);
                    }
                    ProvState merged = meetProvState(in[j], prop);
                    if (in[j] == null || !in[j].sameAs(merged)) {
                        in[j] = merged;
                        changed = true;
                    }
                }
            }
            if (!changed) converged = true;
        }
        if (!converged) {
            for (int i = 0; i < n; i++) in[i] = new ProvState();
        }
        return new ProvResult(in, converged);
    }

    /** Drop every provenance for one register offset (all sizes):
        any write to a register kills certainty for all its views
        (a narrow write still changes the full value). */
    private static void killReg(ProvState st, String space, long off) {
        String pfx = space + ":" + off + ":";
        List<String> dead = new ArrayList<String>();
        for (String k : st.varProv.keySet()) {
            if (k.startsWith(pfx)) dead.add(k);
        }
        for (String k : dead) st.varProv.remove(k);
    }

    private static void setProv(ProvState st, Varnode v, Prov p) {
        if (v == null) return;
        String space = v.getAddress().getAddressSpace().getName();
        if (!space.equals("unique")) {
            killReg(st, space, v.getOffset());
        }
        if (p == null || p.kind == Prov.UNKNOWN) {
            st.varProv.remove(vkey(v));
        } else {
            st.varProv.put(vkey(v), p);
        }
    }

    private static Prov getProv(ProvState st, Varnode v) {
        if (v == null) return null;
        return st.varProv.get(vkey(v));
    }

    /** Resolve an RBP-relative stack slot key for an address
        varnode, following COPY chains and INT_ADD(RBP, c). Only
        RBP slots are tracked: RSP moves with pushes/subs, so an
        RSP-relative offset does not identify a stable slot, and
        tracking it would alias distinct memory (unsound). RBP is
        the frame pointer, stable after the prologue; any direct
        RBP write clears all RBP slots (see applyProvTransfer). */
    private static String rbpSlotOf(Varnode v, List<OpRec> ops,
        int pos, ProvCtx ctx) {
        Varnode cur = v;
        for (int hop = 0; hop < 5; hop++) {
            if (cur == null) return null;
            String sp = cur.getAddress().getAddressSpace().getName();
            if (sp.equals("register") && cur.getOffset() == ctx.rbpOff) {
                return "rbp:0";
            }
            int d = findDefWide(ops, vkey(cur), pos);
            if (d < 0) return null;
            OpRec dd = ops.get(d);
            if (dd.mnem.equals("COPY") && dd.ins.length == 1) {
                cur = dd.ins[0];
                continue;
            }
            if (dd.mnem.equals("INT_ADD") && dd.ins.length == 2) {
                for (int s = 0; s < 2; s++) {
                    if (dd.ins[s].isConstant()) {
                        Varnode o = dd.ins[1 - s];
                        String osp = o.getAddress().getAddressSpace()
                            .getName();
                        if (osp.equals("register") &&
                            o.getOffset() == ctx.rbpOff) {
                            return "rbp:" + dd.ins[s].getOffset();
                        }
                        // One COPY hop to RBP.
                        int d2 = findDefWide(ops, vkey(o), d);
                        if (d2 >= 0) {
                            OpRec dd2 = ops.get(d2);
                            if (dd2.mnem.equals("COPY") &&
                                dd2.ins.length == 1) {
                                Varnode o2 = dd2.ins[0];
                                String o2sp = o2.getAddress()
                                    .getAddressSpace().getName();
                                if (o2sp.equals("register") && o2
                                    .getOffset() == ctx.rbpOff) {
                                    return "rbp:" +
                                        dd.ins[s].getOffset();
                                }
                            }
                        }
                    }
                }
            }
            return null;
        }
        return null;
    }

    /** Struct-field access for an address varnode: follows COPY
        chains to INT_ADD(structBase, constOff) where the base's
        provenance in the state is a STRUCT. Returns
        {baseKey, fieldOff, structProv} or null. */
    private static Object[] structFieldOf(Varnode v, List<OpRec> ops,
        int pos, ProvState st) {
        Varnode cur = v;
        for (int hop = 0; hop < 5; hop++) {
            if (cur == null) return null;
            int d = findDefWide(ops, vkey(cur), pos);
            if (d < 0) return null;
            OpRec dd = ops.get(d);
            if (dd.mnem.equals("COPY") && dd.ins.length == 1) {
                cur = dd.ins[0];
                continue;
            }
            if (dd.mnem.equals("INT_ADD") && dd.ins.length == 2) {
                for (int s = 0; s < 2; s++) {
                    if (dd.ins[s].isConstant()) {
                        Varnode o = dd.ins[1 - s];
                        Prov bp = getProv(st, o);
                        if (bp != null && bp.kind == Prov.STRUCT) {
                            return new Object[] {vkey(o),
                                dd.ins[s].getOffset(), bp};
                        }
                    }
                }
            }
            return null;
        }
        return null;
    }

    /** Resolve a GUID argument (a register holding a pointer to 16
        GUID bytes in the image) to a protocol name; null if the
        pointer does not resolve or the GUID is unknown. Uses the
        def-chain resolver (COPY / INT_ADD / LOAD), never a guess.
        Tries the full register width, then a 32-bit view (a small
        image address may be set with a 32-bit MOV, zero-extended). */
    private String resolveGuidArg(long regOff, List<OpRec> ops,
        Memory mem, int pos, ProvCtx ctx) {
        int[] sizes = new int[] {isa.pointerSize(), 4};
        for (int sz : sizes) {
            Varnode arg = regVarnode(regOff, sz);
            if (arg == null) continue;
            Long addr = resolveValueWide(arg, ops, mem, pos, 6);
            if (addr == null) continue;
            byte[] b = readGuidBytes(mem, addr.longValue());
            String g = matchGuid(b, ctx.protos);
            if (g != null) return g;
        }
        return null;
    }

    /** Resolve a GUID value varnode (a register or stack slot
        holding a GUID address) to a protocol name; null if the
        address does not resolve or the GUID is unknown. */
    private String resolveGuidValue(Varnode v, List<OpRec> ops,
        Memory mem, int pos, ProvCtx ctx) {
        if (v == null) return null;
        Long addr = resolveValueWide(v, ops, mem, pos, 6);
        if (addr == null) return null;
        byte[] b = readGuidBytes(mem, addr.longValue());
        return matchGuid(b, ctx.protos);
    }

    /** True when a STORE is a PUSH: address = RSP, and RSP's def
        is INT_SUB(RSP, 8). (Ghidra lifts x86 PUSH as SUB + STORE;
        the return-address push inside a CALL instruction is
        excluded by the caller skipping the call's own ops.) */
    private static boolean isPushStore(List<OpRec> ops, int sIdx,
        ProvCtx ctx) {
        OpRec op = ops.get(sIdx);
        if (!op.mnem.equals("STORE") || op.ins.length < 3) {
            return false;
        }
        Varnode av = op.ins[1];
        if (av == null || !av.isRegister() ||
            av.getOffset() != ctx.rspOff) return false;
        int d = findDefWide(ops, vkey(av), sIdx);
        if (d < 0) return false;
        OpRec dd = ops.get(d);
        if (!dd.mnem.equals("INT_SUB") || dd.ins.length != 2) {
            return false;
        }
        for (int s = 0; s < 2; s++) {
            if (dd.ins[s].isConstant() &&
                dd.ins[s].getOffset() == 8L) return true;
        }
        return false;
    }

    /** Stack argument values via the PUSH pattern, in order
        (stack0 first = most recent push). Skips the call's own
        P-Code (its return-address push). Stops at any CALL /
        BRANCH / RET (pushes beyond belong to another call) and
        at the scan window (200 ops). The InstallMultiple list is
        NULL-terminated, so prologue pushes beyond the terminator
        are never interpreted as pairs. */
    private static List<Varnode> readStackArgsPush(List<OpRec> ops,
        int pos, ProvCtx ctx) {
        List<Varnode> out = new ArrayList<Varnode>();
        Address callAddr = ops.get(pos).instrAddr;
        int i = pos - 1;
        while (i >= 0 && ops.get(i).instrAddr.equals(callAddr)) {
            i--;
        }
        for (; i >= Math.max(0, pos - 200) && out.size() < 16; i--) {
            OpRec op = ops.get(i);
            String m = op.mnem;
            if (m.equals("CALL") || m.equals("CALLIND") ||
                m.equals("BRANCH") || m.equals("BRANCHIND") ||
                m.equals("RETURN") || m.equals("RET")) {
                break;
            }
            if (m.equals("STORE") && isPushStore(ops, i, ctx)) {
                out.add(op.ins[2]);
            }
        }
        return out;
    }

    /** Stack argument values via the MOV pattern: stack arg k is
        the value most recently stored to [RSP + 0x20 + 8k] with no
        RSP write between that store and the call (the call's own
        P-Code excluded). Returns the longest valid prefix
        (stack0, stack1, ...); empty when slot 0 has no valid
        store. */
    private static List<Varnode> readStackArgsMov(List<OpRec> ops,
        int pos, ProvCtx ctx) {
        List<Varnode> out = new ArrayList<Varnode>();
        Address callAddr = ops.get(pos).instrAddr;
        for (int k = 0; k < 16; k++) {
            long want = 0x20L + 8L * k;
            int found = -1;
            for (int i = pos - 1; i >= Math.max(0, pos - 200); i--) {
                if (ops.get(i).instrAddr.equals(callAddr)) continue;
                OpRec op = ops.get(i);
                if (!op.mnem.equals("STORE") ||
                    op.ins.length < 3) continue;
                Varnode av = op.ins[1];
                int da = findDefWide(ops, vkey(av), i);
                if (da < 0) continue;
                OpRec ad = ops.get(da);
                if (!ad.mnem.equals("INT_ADD") ||
                    ad.ins.length != 2) continue;
                Long c = null;
                Varnode b = null;
                for (int s = 0; s < 2; s++) {
                    if (ad.ins[s].isConstant()) {
                        c = ad.ins[s].getOffset();
                        b = ad.ins[1 - s];
                    }
                }
                if (c == null || c.longValue() != want ||
                    b == null || !b.isRegister() ||
                    b.getOffset() != ctx.rspOff) continue;
                found = i;
                break;
            }
            if (found < 0) break;
            // No RSP write between the store and the call (call's
            // own P-Code excluded: its return-address SUB is not
            // an arg-setup change).
            boolean rspMoved = false;
            for (int j = found + 1; j < pos; j++) {
                if (ops.get(j).instrAddr.equals(callAddr)) continue;
                Varnode o = ops.get(j).out;
                if (o != null && o.isRegister() &&
                    o.getOffset() == ctx.rspOff) {
                    rspMoved = true;
                    break;
                }
            }
            if (rspMoved) break;
            out.add(ops.get(found).ins[2]);
        }
        return out;
    }

    /** Stack argument values (stack0, stack1, ...) for a call:
        PUSH pattern first (the common InstallMultiple shape),
        else MOV pattern. Empty when neither pattern yields a
        slot-0 value. */
    private static List<Varnode> readStackArgs(List<OpRec> ops,
        int pos, ProvCtx ctx) {
        List<Varnode> push = readStackArgsPush(ops, pos, ctx);
        if (!push.isEmpty()) return push;
        return readStackArgsMov(ops, pos, ctx);
    }

    /** True when register regV holds the same value as baseV at
        op pos: regV's COPY-chain reaches baseV, and baseV was not
        redefined between that COPY and pos. (Each link uses the
        most-recent def, so intermediate redefinitions are already
        excluded: a redefined intermediate would resolve to its
        newer def, breaking the chain.) This is the "parameter
        saved to a callee-saved register before learning" case:
        without it, a layout learned for RSI never reaches the
        R14 copy the function actually uses. */
    private static boolean isCopyAlias(List<OpRec> ops, int pos,
        Varnode regV, Varnode baseV) {
        String baseKey = vkey(baseV);
        Varnode cur = regV;
        int curPos = pos;
        for (int hop = 0; hop < 8; hop++) {
            if (cur == null) return false;
            int d = findDefWide(ops, vkey(cur), curPos);
            if (d < 0) return false;
            OpRec dd = ops.get(d);
            if (!dd.mnem.equals("COPY") || dd.ins.length != 1) {
                return false;
            }
            cur = dd.ins[0];
            curPos = d;
            if (vkey(cur).equals(baseKey)) {
                for (int j = d + 1; j < pos; j++) {
                    Varnode o = ops.get(j).out;
                    if (o != null && vkey(o).equals(baseKey)) {
                        return false;
                    }
                }
                return true;
            }
        }
        return false;
    }

    /** Learn an installed interface: interface arg = INT_ADD(base,
        F) (an embedded instance at base+F) or a bare register
        holding the instance pointer. Updates the base's STRUCT
        layout (or the register) in the post-call state. */
    /** Find the most recent STORE to an RBP slot before pos
        (scan window 200 ops); -1 if none. Used to follow an
        interface pointer that was staged through a stack slot
        (the InstallMultiple PUSH pattern). */
    private static int findSlotStore(List<OpRec> ops, String slot,
        int pos, ProvCtx ctx) {
        for (int i = pos - 1; i >= Math.max(0, pos - 200); i--) {
            OpRec op = ops.get(i);
            if (!op.mnem.equals("STORE") || op.ins.length < 3) {
                continue;
            }
            String s = rbpSlotOf(op.ins[1], ops, i, ctx);
            if (slot.equals(s)) return i;
        }
        return -1;
    }

    private void learnInstall(Varnode ifaceArg, String guid,
        List<OpRec> ops, int pos, ProvState st, ProvCtx ctx) {
        if (guid == null || ifaceArg == null) return;
        Varnode cur = ifaceArg;
        int curPos = pos;
        for (int hop = 0; hop < 8; hop++) {
            if (cur == null) return;
            int d = findDefWide(ops, vkey(cur), curPos);
            if (d < 0) break;
            OpRec dd = ops.get(d);
            if (dd.mnem.equals("COPY") && dd.ins.length == 1) {
                cur = dd.ins[0];
                curPos = d;
                continue;
            }
            // Interface staged through a stack slot (InstallMultiple
            // PUSH pattern): follow the slot's STORE to its value.
            if (dd.mnem.equals("LOAD") && dd.ins.length >= 2) {
                String slot = rbpSlotOf(dd.ins[1], ops, d, ctx);
                if (slot != null) {
                    int sIdx = findSlotStore(ops, slot, d, ctx);
                    if (sIdx >= 0) {
                        cur = ops.get(sIdx).ins[2];
                        curPos = sIdx;
                        continue;
                    }
                }
                break;
            }
            if (dd.mnem.equals("INT_ADD") && dd.ins.length == 2) {
                for (int s = 0; s < 2; s++) {
                    if (dd.ins[s].isConstant()) {
                        Varnode o = dd.ins[1 - s];
                        Prov bp = getProv(st, o);
                        if (bp != null && bp.kind != Prov.STRUCT) {
                            return;
                        }
                        Map<Long, ProtoField> nl =
                            new HashMap<Long, ProtoField>();
                        if (bp != null && bp.layout != null) {
                            nl.putAll(bp.layout);
                        }
                        nl.put(dd.ins[s].getOffset(),
                            new ProtoField(guid, true));
                        Prov learned = Prov.struct(nl);
                        setProv(st, o, learned);
                        // Alias update: registers holding the same
                        // value as the base (e.g. a parameter
                        // saved to a callee-saved register before
                        // this call) share the learned layout.
                        // RSP/RBP excluded defensively (frame).
                        long[] gprs = new long[] {0x0L, 0x8L, 0x10L,
                            0x18L, 0x30L, 0x38L, 0x80L, 0x88L, 0x90L,
                            0x98L, 0xa0L, 0xa8L, 0xb0L, 0xb8L};
                        for (long ro : gprs) {
                            Varnode rv = regVarnode(ro,
                                isa.pointerSize());
                            if (rv == null ||
                                vkey(rv).equals(vkey(o))) continue;
                            if (isCopyAlias(ops, pos, rv, o)) {
                                setProv(st, rv, learned);
                            }
                        }
                        return;
                    }
                }
            }
            break;
        }
        // Bare register holding the instance pointer.
        setProv(st, ifaceArg, Prov.iface(guid));
    }

    /** Bind an acquired interface (out-param of Locate / Handle /
        OpenProtocol) to its destination: an RBP stack slot, a
        struct field (pointer field), or a global. Anything else is
        left unbound (sound: no binding, no finding). */
    private void bindAcquisition(Varnode outArg, String guid,
        List<OpRec> ops, int pos, ProvState st, ProvCtx ctx) {
        if (guid == null || outArg == null) return;
        String slot = rbpSlotOf(outArg, ops, pos, ctx);
        if (slot != null) {
            st.slotProv.put(slot, Prov.iface(guid));
            return;
        }
        Object[] sf = structFieldOf(outArg, ops, pos, st);
        if (sf != null) {
            String baseKey = (String) sf[0];
            long f = (Long) sf[1];
            Prov bp = (Prov) sf[2];
            Map<Long, ProtoField> nl =
                new HashMap<Long, ProtoField>(bp.layout);
            nl.put(f, new ProtoField(guid, false));
            // Rewrite the base varnode's provenance: find the
            // varnode by key (space:offset:size) -- the key alone
            // is enough for the state map.
            st.varProv.put(baseKey, Prov.struct(nl));
            return;
        }
        Long addr = resolveValueWide(outArg, ops, ctx.mem, pos, 6);
        if (addr != null) {
            st.globalProv.put(addr.longValue(), Prov.iface(guid));
        }
    }

    /** The provenance transfer for one op. Mutates st (the
        out-state). BS acquisition/install side effects are applied
        here (post-clobber); method attribution itself happens at
        emission from the final in-states. */
    private void applyProvTransfer(ProvState st, OpRec op,
        List<OpRec> ops, int idx, ProvCtx ctx) {
        String mnem = op.mnem;
        // Any direct RBP write clears RBP slots (frame pointer
        // moved: old slot provenances no longer identify memory).
        if (op.out != null) {
            String osp = op.out.getAddress().getAddressSpace()
                .getName();
            if (osp.equals("register") &&
                op.out.getOffset() == ctx.rbpOff) {
                st.slotProv.clear();
            }
        }
        if (mnem.equals("COPY")) {
            if (op.ins.length >= 1) {
                Varnode src = op.ins[0];
                String ssp = src.getAddress().getAddressSpace()
                    .getName();
                // x86 absolute-address load: MOV reg, [addr] is a
                // COPY from a ram varnode, not a LOAD op. Treat it
                // as a global read (this is where gBS lives).
                if (!ssp.equals("register") &&
                    !ssp.equals("unique") &&
                    !ssp.equals("const")) {
                    Prov gp = st.globalProv.get(src.getOffset());
                    if (gp == null && ctx.globalProvPre != null) {
                        gp = ctx.globalProvPre.get(src.getOffset());
                    }
                    setProv(st, op.out, gp);
                } else {
                    Prov p = getProv(st, src);
                    setProv(st, op.out, p);
                }
            } else {
                setProv(st, op.out, null);
            }
            return;
        }
        if (mnem.equals("INT_ADD") && op.ins.length == 2) {
            for (int s = 0; s < 2; s++) {
                if (op.ins[s].isConstant()) {
                    Prov bp = getProv(st, op.ins[1 - s]);
                    long c = op.ins[s].getOffset();
                    if (bp == null) {
                        setProv(st, op.out, null);
                    } else if (bp.kind == Prov.IFACE) {
                        setProv(st, op.out, Prov.slot(bp.guid, c));
                    } else if (bp.kind == Prov.BS) {
                        setProv(st, op.out, Prov.slot("BS", c));
                    } else if (bp.kind == Prov.STRUCT) {
                        ProtoField fld = bp.layout.get(c);
                        if (fld == null) {
                            setProv(st, op.out, null);
                        } else if (fld.embedded) {
                            setProv(st, op.out,
                                Prov.iface(fld.guid));
                        } else {
                            setProv(st, op.out,
                                Prov.fieldPtr(bp, c));
                        }
                    } else {
                        setProv(st, op.out, null);
                    }
                    return;
                }
            }
            setProv(st, op.out, null);
            return;
        }
        if (mnem.equals("INT_SUB") && op.ins.length == 2) {
            // Container-record (CR) pattern: This - fieldOff =
            // the enclosing struct, whose fieldOff embeds the
            // interface. Bounded (small offsets only): a large
            // subtraction is buffer arithmetic, not CR.
            for (int s = 0; s < 2; s++) {
                if (op.ins[s].isConstant()) {
                    // Only base - const (not const - base).
                    if (s != 1) {
                        setProv(st, op.out, null);
                        return;
                    }
                    Prov bp = getProv(st, op.ins[0]);
                    long c = op.ins[1].getOffset();
                    if (bp != null && bp.kind == Prov.IFACE &&
                        c > 0 && c <= 0x1000L) {
                        Map<Long, ProtoField> nl =
                            new HashMap<Long, ProtoField>();
                        nl.put(c, new ProtoField(bp.guid, true));
                        setProv(st, op.out, Prov.struct(nl));
                    } else {
                        setProv(st, op.out, null);
                    }
                    return;
                }
            }
            setProv(st, op.out, null);
            return;
        }
        if (mnem.equals("LOAD")) {
            if (op.ins.length < 2) {
                setProv(st, op.out, null);
                return;
            }
            Varnode addrV = op.ins[1];
            if (addrV.isConstant()) {
                long a = addrV.getOffset();
                Prov p = st.globalProv.get(a);
                if (p == null) p = ctx.globalProvPre.get(a);
                setProv(st, op.out, p);
                return;
            }
            Prov ap = getProv(st, addrV);
            if (ap != null && ap.kind == Prov.SLOT) {
                setProv(st, op.out, Prov.method(ap.guid, ap.off));
                return;
            }
            if (ap != null && ap.kind == Prov.FIELDPTR) {
                Prov sp = ap.structProv;
                if (sp != null && sp.kind == Prov.STRUCT) {
                    ProtoField fld = sp.layout.get(ap.fieldOff);
                    if (fld != null && !fld.embedded) {
                        setProv(st, op.out, Prov.iface(fld.guid));
                        return;
                    }
                }
                setProv(st, op.out, null);
                return;
            }
            if (ap != null && ap.kind == Prov.IFACE) {
                setProv(st, op.out, Prov.method(ap.guid, 0L));
                return;
            }
            if (ap != null && ap.kind == Prov.BS) {
                setProv(st, op.out, Prov.method("BS", 0L));
                return;
            }
            String slot = rbpSlotOf(addrV, ops, idx, ctx);
            if (slot != null) {
                setProv(st, op.out, st.slotProv.get(slot));
                return;
            }
            // Embedded-method fallback: address = structBase +
            // (fieldOff + methodOff) for a UNIQUE embedded field
            // whose method table contains the residual offset.
            Object[] sf = structFieldOf(addrV, ops, idx, st);
            if (sf != null) {
                long c = (Long) sf[1];
                Prov bp = (Prov) sf[2];
                String foundGuid = null;
                long foundOff = 0;
                int matches = 0;
                for (Map.Entry<Long, ProtoField> e :
                    bp.layout.entrySet()) {
                    if (!e.getValue().embedded) continue;
                    long f = e.getKey();
                    if (c < f) continue;
                    long m = c - f;
                    ProtoInfo pi = protoByName(e.getValue().guid,
                        ctx.protos);
                    if (pi != null && pi.methods.containsKey(m)) {
                        foundGuid = e.getValue().guid;
                        foundOff = m;
                        matches++;
                    }
                }
                if (matches == 1) {
                    setProv(st, op.out,
                        Prov.method(foundGuid, foundOff));
                } else {
                    setProv(st, op.out, null);
                }
                return;
            }
            setProv(st, op.out, null);
            return;
        }
        if (mnem.equals("STORE")) {
            if (op.ins.length < 3) return;
            Varnode addrV = op.ins[1];
            Prov vp = getProv(st, op.ins[2]);
            String slot = rbpSlotOf(addrV, ops, idx, ctx);
            if (slot != null) {
                if (vp == null) st.slotProv.remove(slot);
                else st.slotProv.put(slot, vp);
                return;
            }
            if (addrV.isConstant()) {
                long a = addrV.getOffset();
                if (vp == null) st.globalProv.remove(a);
                else st.globalProv.put(a, vp);
                return;
            }
            Object[] sf = structFieldOf(addrV, ops, idx, st);
            if (sf != null) {
                String baseKey = (String) sf[0];
                long f = (Long) sf[1];
                Prov bp = (Prov) sf[2];
                Map<Long, ProtoField> nl =
                    new HashMap<Long, ProtoField>(bp.layout);
                if (vp != null && vp.kind == Prov.IFACE) {
                    nl.put(f, new ProtoField(vp.guid, false));
                } else {
                    nl.remove(f);
                }
                st.varProv.put(baseKey, Prov.struct(nl));
            }
            return;
        }
        if (mnem.equals("CALL") || mnem.equals("CALLIND")) {
            // Resolve a BS method call (target provenance) BEFORE
            // clobbering: the argument registers are pre-call.
            Prov tgt = null;
            if (mnem.equals("CALLIND") && op.ins.length >= 1) {
                tgt = getProv(st, op.ins[0]);
            }
            String bsMethod = null;
            long bsOff = 0;
            if (tgt != null && tgt.kind == Prov.METHOD &&
                "BS".equals(tgt.guid)) {
                bsMethod = ctx.bsMethods.get(tgt.off);
                bsOff = tgt.off;
            }
            // Argument values needed post-clobber: resolve GUIDs
            // and destinations from the PRE-call state.
            String acqGuid = null;
            Varnode acqOut = null;
            // Install pairs (guid, iface-value) in order. Pair 1
            // is (RDX, R8); InstallMultiple adds variadic pairs:
            // pair 2 = (R9, stack0), pair j>=3 = (stack[2j-5],
            // stack[2j-4]). Unknown GUIDs stay in the list as
            // (null, value) and are skipped at learning time, so
            // a later known pair (e.g. PciIo after DevicePath)
            // is still learned. A NULL GUID address terminates
            // the list.
            List<String> instGuids = new ArrayList<String>();
            List<Varnode> instIfaces = new ArrayList<Varnode>();
            if (bsMethod != null) {
                // MS ABI (EFIAPI) argument registers, x86-64:
                // RCX=0x8, RDX=0x10, R8=0x80. LocateProtocol takes
                // the GUID in arg0; Handle/Open/Install take it in
                // arg1; the Interface out-param / interface arg is
                // always arg2 (R8).
                if (bsOff == 0x140L) {
                    acqGuid = resolveGuidArg(0x8L, ops, ctx.mem, idx,
                        ctx);
                    acqOut = regVarnode(0x80L, isa.pointerSize());
                } else if (bsOff == 0x98L || bsOff == 0x118L) {
                    acqGuid = resolveGuidArg(0x10L, ops, ctx.mem, idx,
                        ctx);
                    acqOut = regVarnode(0x80L, isa.pointerSize());
                } else if (bsOff == 0x80L) {
                    instGuids.add(resolveGuidArg(0x10L, ops, ctx.mem,
                        idx, ctx));
                    instIfaces.add(regVarnode(0x80L,
                        isa.pointerSize()));
                } else if (bsOff == 0x148L) {
                    instGuids.add(resolveGuidArg(0x10L, ops, ctx.mem,
                        idx, ctx));
                    instIfaces.add(regVarnode(0x80L,
                        isa.pointerSize()));
                    // Variadic pairs: R9 + stack args.
                    Varnode r9 = regVarnode(0x88L,
                        isa.pointerSize());
                    Long g2addr = r9 == null ? null : resolveValueWide(
                        r9, ops, ctx.mem, idx, 6);
                    if (g2addr != null && g2addr.longValue() != 0L) {
                        List<Varnode> sargs = readStackArgs(ops, idx,
                            ctx);
                        instGuids.add(resolveGuidValue(r9, ops,
                            ctx.mem, idx, ctx));
                        instIfaces.add(sargs.isEmpty() ? null :
                            sargs.get(0));
                        // Pairs j>=3: (stack[2j-5], stack[2j-4]).
                        for (int j = 3; j <= 10; j++) {
                            int gi = 2 * j - 5;
                            int ii = 2 * j - 4;
                            if (gi >= sargs.size()) break;
                            Varnode gv = sargs.get(gi);
                            Long ga = resolveValueWide(gv, ops, ctx.mem,
                                idx, 6);
                            if (ga != null &&
                                ga.longValue() == 0L) break;
                            instGuids.add(resolveGuidValue(gv, ops,
                                ctx.mem, idx, ctx));
                            instIfaces.add(ii < sargs.size() ?
                                sargs.get(ii) : null);
                        }
                    }
                }
            }
            // Clobber caller-saved registers (union fallback: the
            // System V set, a superset of the Windows set, so this
            // is sound under either ABI).
            long[] clob = isa.clobberForConvention(null);
            if (clob != null) {
                for (long off : clob) {
                    killReg(st, isa.registerSpaceName(), off);
                }
            }
            // v8 retprop (Prov): a direct CALL to a summarized
            // callee restores the return register's provenance to
            // the summary interface (same all-RETURNs-agree rule as
            // Bits summaries, see Phase P2). Applied AFTER the
            // clobber, never before. CALLIND gets nothing; the
            // acquisition bindings below bind out-params (R8), not
            // the return register, so there is no conflict.
            if (mnem.equals("CALL") && op.ins.length >= 1) {
                Varnode t = op.ins[0];
                if (t != null && t.getAddress() != null &&
                    "ram".equals(t.getAddress().getAddressSpace()
                        .getName())) {
                    Prov ps = provSummaries.get(t.getOffset());
                    if (ps == null) {
                        ps = provSummaries.get(
                            isa.stripInstructionTag(t.getOffset()));
                    }
                    if (ps != null) {
                        Varnode rr = regVarnode(
                            isa.returnRegisterOffset(),
                            isa.pointerSize());
                        if (rr != null) setProv(st, rr, ps);
                    }
                }
            }
            // v9 struct (Prov): the value returned by this call is
            // a struct whose fields the caller may fill and read --
            // or, for a direct CALL to a struct-summarized callee,
            // the callee's layout. An IFACE summary above wins (a
            // callee returns either an interface or a struct, never
            // both); otherwise the return register becomes STRUCT:
            // the callee's summary layout, or an empty layout for
            // an untracked call (empty layouts resolve nothing --
            // INT_ADD on them yields null, exactly like unknown --
            // but field stores through the pointer accumulate a
            // layout via the existing STORE/structFieldOf rules, so
            // the callee's own summary can form). CALLIND gets an
            // empty struct too (AllocatePool is a CALLIND: this is
            // what lets UEFI callers track interface fields of
            // heap-allocated device structs). Layouts are
            // per-varnode snapshots, so loop-carried call sites
            // need no special case here (unlike Bits field cells,
            // which are shared keys): a saved copy keeps the
            // layout from its copy time, and meetProv intersects
            // layouts at joins.
            {
                Varnode rr = regVarnode(
                    isa.returnRegisterOffset(), isa.pointerSize());
                if (rr != null && getProv(st, rr) == null) {
                    Prov sp = null;
                    if (mnem.equals("CALL") && op.ins.length >= 1) {
                        Varnode t = op.ins[0];
                        if (t != null && t.getAddress() != null &&
                            "ram".equals(t.getAddress().getAddressSpace()
                                .getName())) {
                            sp = structProvSummaries.get(t.getOffset());
                            if (sp == null) {
                                sp = structProvSummaries.get(
                                    isa.stripInstructionTag(
                                        t.getOffset()));
                            }
                        }
                    }
                    if (sp == null) {
                        sp = Prov.struct(
                            new HashMap<Long, ProtoField>());
                    }
                    setProv(st, rr, sp);
                }
            }
            // Post-call bindings (memory effects of the call).
            if (acqGuid != null && acqOut != null) {
                bindAcquisition(acqOut, acqGuid, ops, idx, st, ctx);
            }
            for (int p = 0; p < instGuids.size(); p++) {
                if (instGuids.get(p) != null &&
                    instIfaces.get(p) != null) {
                    learnInstall(instIfaces.get(p), instGuids.get(p),
                        ops, idx, st, ctx);
                }
            }
            return;
        }
        // All other ops (arithmetic, logic, extension, CALLOTHER,
        // branches, returns): the output provenance is unknown.
        // CALLOTHER (IN/OUT/MSR userops) has no register effect
        // modelled here; its port/MSR recording is unchanged.
        if (op.out != null) {
            setProv(st, op.out, null);
        }
    }

    /** One resolved protocol/BS call at a CALLIND site. */
    private static class ProtoCall {
        final String guid;
        final String method;
        final long off;
        final boolean isBs;
        ProtoCall(String g, String m, long o, boolean b) {
            guid = g; method = m; off = o; isBs = b;
        }
    }

    /** Resolve a CALLIND to a protocol/BS method from the
        provenance in-state at that op. Returns null unless the
        target provenance is a METHOD whose (protocol, offset) is
        in the known tables. Unknown methods are NOT resolved
        (they stay on the existing may/unresolved path). */
    private static ProtoCall resolveProtoCall(OpRec op,
        ProvState st, ProvCtx ctx) {
        if (op == null || st == null || !op.mnem.equals("CALLIND") ||
            op.ins.length < 1) return null;
        Prov tgt = st.varProv.get(vkey(op.ins[0]));
        if (tgt == null || tgt.kind != Prov.METHOD) return null;
        if ("BS".equals(tgt.guid)) {
            String m = ctx.bsMethods.get(tgt.off);
            if (m == null) return null;
            return new ProtoCall("BS", m, tgt.off, true);
        }
        ProtoInfo pi = protoByName(tgt.guid, ctx.protos);
        if (pi == null) return null;
        String m = pi.methods.get(tgt.off);
        if (m == null) return null;
        return new ProtoCall(tgt.guid, m, tgt.off, false);
    }

    /** Known hardware effect of a protocol method, as port cycles
        (port, direction). Only PCI config Read/Write have a fixed
        effect (CF8 address + CFC data, verified against this
        corpus's host bridge driver). Everything else returns null
        (edge only, never a fabricated access). */
    /** v3.19 Phase 3 item 1: TDX tdcall-IO-read wrapper detection.
        A function G is a tdcall-IO-read wrapper of size s iff:
        (i) G contains NO CALLOTHER IN/OUT (a raw path would
        already be recorded -- this gate keeps the IoWrite16/32
        and IoRead32 helpers, which also call the tdcall
        trampoline with leaf 0x1e, from double-counting);
        (ii) G contains a direct CALL whose preceding constant
        assignment to the first Windows-x64 argument register
        (RCX, offset 0x8) is 0x1e (the TDX VP.VMCALL IO subleaf)
        and whose preceding constant assignment to the second
        argument register (RDX, offset 0x10) is s in {1,2,4};
        (iii) G forwards its first argument register to R9
        (offset 0x88) with a COPY before that CALL (the
        trampoline's port slot, cf. EDK2 TdVmCall IO);
        (iv) G returns a value loaded from memory after that
        CALL (a LOAD whose output is COPY'd to the return
        register, offset 0x0, with size s).
        Ghidra lifts `tdcall` to NO pcode ops, so the trampoline
        itself can never be recorded as a CALLOTHER IN/OUT --
        the wrapper shape is the only observable. Returns the
        size, or null when G is not such a wrapper. x86-64
        Windows convention only; anything else fails closed. */
    private static Integer tdcallReadSize(List<OpRec> ops) {
        for (int i = 0; i < ops.size(); i++) {
            OpRec op = ops.get(i);
            if (op.mnem.equals("CALLOTHER") &&
                (op.instrAsm.equalsIgnoreCase("IN") ||
                 op.instrAsm.equalsIgnoreCase("OUT"))) {
                return null;
            }
        }
        for (int ci = 0; ci < ops.size(); ci++) {
            OpRec call = ops.get(ci);
            if (!call.mnem.equals("CALL")) continue;
            Long leaf = tdcallLastConst(ops, ci, 0x8L);
            if (leaf == null || leaf.longValue() != 0x1eL) continue;
            Long sz = tdcallLastConst(ops, ci, 0x10L);
            if (sz == null || !(sz.longValue() == 1L ||
                sz.longValue() == 2L || sz.longValue() == 4L)) {
                continue;
            }
            boolean fwd = false;
            for (int j = 0; j < ci; j++) {
                OpRec o = ops.get(j);
                if (!o.mnem.equals("COPY") || o.ins.length != 1 ||
                    o.out == null) continue;
                if (tdcallIsReg(o.ins[0], 0x8L) &&
                    tdcallIsReg(o.out, 0x88L)) { fwd = true; break; }
            }
            if (!fwd) continue;
            boolean ret = false;
            for (int j = ci + 1; j < ops.size() && !ret; j++) {
                OpRec ld = ops.get(j);
                if (!ld.mnem.equals("LOAD") || ld.out == null) {
                    continue;
                }
                String lk = vkey(ld.out);
                for (int k = j + 1; k < ops.size(); k++) {
                    OpRec cp = ops.get(k);
                    if (!cp.mnem.equals("COPY") ||
                        cp.ins.length != 1 || cp.out == null) {
                        continue;
                    }
                    if (vkey(cp.ins[0]).equals(lk) &&
                        tdcallIsReg(cp.out, 0x0L) &&
                        cp.out.getSize() == sz.intValue()) {
                        ret = true; break;
                    }
                }
            }
            if (!ret) continue;
            return Integer.valueOf(sz.intValue());
        }
        return null;
    }

    /** Last constant COPY assignment to a register before op
        index `before` (exclusive), or null. Only plain COPYs
        count (mov reg, imm); XOR-zeroing and arithmetic
        definitions are not constant assignments here. */
    private static Long tdcallLastConst(List<OpRec> ops, int before,
        long regOff) {
        for (int j = before - 1; j >= 0; j--) {
            OpRec o = ops.get(j);
            if (o.out == null || !tdcallIsReg(o.out, regOff)) {
                continue;
            }
            if (o.mnem.equals("COPY") && o.ins.length == 1 &&
                o.ins[0].isConstant()) {
                return Long.valueOf(o.ins[0].getOffset());
            }
            return null;
        }
        return null;
    }

    private static boolean tdcallIsReg(Varnode v, long off) {
        if (v == null) return false;
        try {
            return "register".equals(
                v.getAddress().getAddressSpace().getName()) &&
                v.getOffset() == off;
        } catch (Exception e) {
            return false;
        }
    }

    private static String[][] protoHwEffect(ProtoCall pc) {
        if (pc == null || pc.isBs) return null;
        if (pc.method.equals("Pci.Read")) {
            return new String[][] {{"0xcf8", "OUT"},
                {"0xcfc", "IN"}};
        }
        if (pc.method.equals("Pci.Write")) {
            return new String[][] {{"0xcf8", "OUT"},
                {"0xcfc", "OUT"}};
        }
        return null;
    }

    /** Follow COPY chains to the first non-COPY defining op of a
        varnode; -1 if none (within 8 hops). x86 CALLIND targets
        and address computations routinely pass through COPYs
        (register moves, unique temps), so a single-def lookup
        misses them. */
    private static int followCopyTo(List<OpRec> ops, Varnode v,
        int pos) {
        Varnode cur = v;
        int curPos = pos;
        for (int hop = 0; hop < 8; hop++) {
            if (cur == null) return -1;
            int d = findDefWide(ops, vkey(cur), curPos);
            if (d < 0) return -1;
            OpRec dd = ops.get(d);
            if (dd.mnem.equals("COPY") && dd.ins.length == 1) {
                cur = dd.ins[0];
                curPos = d;
                continue;
            }
            return d;
        }
        return -1;
    }

    /** Resolve a base varnode to a global address: either a direct
        ram varnode (x86 absolute-address operand, e.g. MOV RAX,
        [0xa220] is COPY RAX <- ram:0xa220) reached through COPYs,
        or a LOAD from a constant address. Null otherwise (a
        parameter or computed base is not a global). */
    private static Long resolveGlobalBase(List<OpRec> ops, Varnode v,
        int pos) {
        Varnode cur = v;
        int curPos = pos;
        for (int hop = 0; hop < 8; hop++) {
            if (cur == null) return null;
            String sp = cur.getAddress().getAddressSpace().getName();
            if (sp.equals("ram")) return cur.getOffset();
            if (cur.isConstant()) return null;
            int d = findDefWide(ops, vkey(cur), curPos);
            if (d < 0) return null;
            OpRec dd = ops.get(d);
            if (dd.mnem.equals("COPY") && dd.ins.length == 1) {
                cur = dd.ins[0];
                curPos = d;
                continue;
            }
            if (dd.mnem.equals("LOAD") && dd.ins.length >= 2 &&
                dd.ins[1].isConstant()) {
                return dd.ins[1].getOffset();
            }
            return null;
        }
        return null;
    }

    /** Boot Services table fingerprint pre-pass: for each CALLIND
        whose target def (through COPYs) is LOAD [INT_ADD(base,
        constOff)] where base resolves to a global address, record
        constOff under that global. A global used with >= 2
        distinct BS method offsets including >= 1 protocol method
        (Handle/Open/LocateProtocol) IS the Boot Services table
        pointer: the offsets are UEFI ABI constants, not
        driver-specific addresses, so this identifies gBS without
        symbols. Returns the set of such globals (normally exactly
        one). */
    private static Set<Long> findGbsGlobals(List<FuncRec> funcRecs,
        Map<Long, String> bsMethods) {
        Map<Long, Set<Long>> offsByGlobal =
            new HashMap<Long, Set<Long>>();
        for (FuncRec rec : funcRecs) {
            List<OpRec> ops = rec.or.ops;
            for (int i = 0; i < ops.size(); i++) {
                OpRec op = ops.get(i);
                if (!op.mnem.equals("CALLIND") ||
                    op.ins.length < 1) continue;
                int def = followCopyTo(ops, op.ins[0], i);
                if (def < 0) continue;
                OpRec dd = ops.get(def);
                if (!dd.mnem.equals("LOAD") ||
                    dd.ins.length < 2) continue;
                Varnode addrV = dd.ins[1];
                int da = followCopyTo(ops, addrV, def);
                if (da < 0) continue;
                OpRec ad = ops.get(da);
                if (!ad.mnem.equals("INT_ADD") ||
                    ad.ins.length != 2) continue;
                Long constOff = null;
                Varnode baseV = null;
                for (int s = 0; s < 2; s++) {
                    if (ad.ins[s].isConstant()) {
                        constOff = ad.ins[s].getOffset();
                        baseV = ad.ins[1 - s];
                    }
                }
                if (constOff == null || baseV == null) continue;
                if (!bsMethods.containsKey(constOff)) continue;
                Long gaddr = resolveGlobalBase(ops, baseV, da);
                if (gaddr == null) continue;
                Set<Long> s = offsByGlobal.get(gaddr);
                if (s == null) {
                    s = new HashSet<Long>();
                    offsByGlobal.put(gaddr, s);
                }
                s.add(constOff);
            }
        }
        Set<Long> out = new HashSet<Long>();
        for (Map.Entry<Long, Set<Long>> e : offsByGlobal.entrySet()) {
            Set<Long> s = e.getValue();
            boolean hasProto = s.contains(0x98L) ||
                s.contains(0x118L) || s.contains(0x140L);
            if (s.size() >= 2 && hasProto) out.add(e.getKey());
        }
        return out;
    }

    /** Meet over ALL direct call sites of one callee, for
        provenance: a parameter register is bound only when every
        site has a provenance for it AND all sites agree (STRUCT
        layouts meet by field intersection). Anything else stays
        unknown. The register set is the x86-64 union (SysV +
        Windows args): entry states are just "what each register
        holds", which is ABI-independent, so propagating the union
        is sound (a register the callee never reads is harmless,
        and a register it does read holds exactly what the caller
        passed). */
    private Map<String, Prov> meetOverSitesProv(long calleeKey,
        Map<Long, List<CallSite>> sitesByCallee) {
        Map<String, Prov> out = new HashMap<String, Prov>();
        List<CallSite> sites = sitesByCallee.get(calleeKey);
        if (sites == null || sites.isEmpty()) return out;
        long[] regs = new long[] {0x38L, 0x30L, 0x10L, 0x8L,
            0x80L, 0x88L};
        int ptrSize = isa.pointerSize();
        for (long off : regs) {
            String key = isa.registerSpaceName() + ":" + off + ":" +
                ptrSize;
            Prov agreed = null;
            boolean allHave = true;
            for (CallSite s : sites) {
                FuncRec caller = s.caller;
                Prov v = null;
                if (caller.pv != null && caller.pv.inStates != null &&
                    s.opIdx < caller.pv.inStates.length &&
                    caller.pv.inStates[s.opIdx] != null) {
                    v = caller.pv.inStates[s.opIdx].varProv.get(key);
                }
                if (v == null) {
                    allHave = false;
                    break;
                }
                if (agreed == null) {
                    agreed = v;
                } else {
                    agreed = meetProv(agreed, v);
                    if (agreed == null) {
                        allHave = false;
                        break;
                    }
                }
            }
            if (allHave && agreed != null) out.put(key, agreed);
        }
        return out;
    }

    /** Entry-state equality for provenance maps (null = empty). */
    private static boolean provEntrySame(Map<String, Prov> a,
        Map<String, Prov> b) {
        if (a == null) a = new HashMap<String, Prov>();
        if (b == null) b = new HashMap<String, Prov>();
        if (a.size() != b.size()) return false;
        for (Map.Entry<String, Prov> e : a.entrySet()) {
            Prov o = b.get(e.getKey());
            if (o == null || !o.equals(e.getValue())) return false;
        }
        return true;
    }

    /** v3.6 field offsets per struct, from the v2.0.0 source layouts
        (target_internal.h, jtagtap.h, swd.h, adiv5_internal.h).
        A field present in two structs (mem_read/mem_write) lists
        both offsets: the literal scan adds to all of them, matching
        the existing offset-map semantics (sound superset). */
    private static long[] fieldOffsets(String field) {
        if (field.equals("attach")) return new long[] {4L};
        if (field.equals("detach")) return new long[] {8L};
        if (field.equals("check_error")) return new long[] {12L};
        if (field.equals("mem_read")) return new long[] {16L, 36L};
        if (field.equals("mem_write")) return new long[] {20L, 40L};
        if (field.equals("regs_description")) return new long[] {28L};
        if (field.equals("regs_read")) return new long[] {32L};
        if (field.equals("regs_write")) return new long[] {36L};
        if (field.equals("reg_read")) return new long[] {40L};
        if (field.equals("reg_write")) return new long[] {44L};
        if (field.equals("reset")) return new long[] {48L};
        if (field.equals("extended_reset")) return new long[] {52L};
        if (field.equals("halt_request")) return new long[] {56L};
        if (field.equals("halt_poll")) return new long[] {60L};
        if (field.equals("halt_resume")) return new long[] {64L};
        if (field.equals("breakwatch_set")) return new long[] {68L};
        if (field.equals("breakwatch_clear")) return new long[] {72L};
        if (field.equals("mass_erase")) return new long[] {80L};
        if (field.equals("enter_flash_mode")) return new long[] {84L};
        if (field.equals("exit_flash_mode")) return new long[] {88L};
        if (field.equals("jtagtap_reset")) return new long[] {0L};
        if (field.equals("jtagtap_next")) return new long[] {4L};
        if (field.equals("jtagtap_tms_seq")) return new long[] {8L};
        if (field.equals("jtagtap_tdi_tdo_seq")) return new long[] {12L};
        if (field.equals("jtagtap_tdi_seq")) return new long[] {16L};
        if (field.equals("jtagtap_cycle")) return new long[] {20L};
        if (field.equals("seq_in")) return new long[] {0L};
        if (field.equals("seq_in_parity")) return new long[] {4L};
        if (field.equals("seq_out")) return new long[] {8L};
        if (field.equals("seq_out_parity")) return new long[] {12L};
        if (field.equals("write_no_check")) return new long[] {4L};
        if (field.equals("read_no_check")) return new long[] {8L};
        if (field.equals("dp_read")) return new long[] {12L};
        if (field.equals("error")) return new long[] {16L};
        if (field.equals("low_access")) return new long[] {20L};
        if (field.equals("abort")) return new long[] {24L};
        if (field.equals("ap_read")) return new long[] {28L};
        if (field.equals("ap_write")) return new long[] {32L};
        return null;
    }

    private static final String[] SCAN_FIELDS = {
        "attach", "detach", "check_error", "mem_read", "mem_write",
        "regs_description", "regs_read", "regs_write", "reg_read",
        "reg_write", "reset", "extended_reset", "halt_request",
        "halt_poll", "halt_resume", "breakwatch_set", "breakwatch_clear",
        "mass_erase", "enter_flash_mode", "exit_flash_mode",
        "jtagtap_reset", "jtagtap_next", "jtagtap_tms_seq",
        "jtagtap_tdi_tdo_seq", "jtagtap_tdi_seq", "jtagtap_cycle",
        "seq_in", "seq_in_parity", "seq_out", "seq_out_parity",
        "write_no_check", "read_no_check", "dp_read", "error",
        "low_access", "abort", "ap_read", "ap_write"
    };

    private static class LiteralScanResult {
        final Map<String, Set<String>> attributions;
        final List<String> unattributed;
        final int literalCount;
        LiteralScanResult(Map<String, Set<String>> attributions,
            List<String> unattributed, int literalCount) {
            this.attributions = attributions;
            this.unattributed = unattributed;
            this.literalCount = literalCount;
        }
    }

    /** v3.6 whole-image literal scan. Reads every word of initialized
        program memory; a word equal to a function entry (Thumb bit
        masked) is a stored pointer. Pointers already in the store
        map need nothing. The rest are attributed to a field by name
        (exact field name, or longest field-name suffix: a name
        ending in _field, or containing _field_); ties and
        non-matches are listed as unattributed, never guessed.
        Attributions are merged into byOffset BEFORE pass 2, so
        CALLIND may-sets gain them. */
    private LiteralScanResult scanLiteralStores(Memory mem,
        FunctionManager fm, Map<Long, Set<String>> byOffset,
        Map<Long, Set<String>> byAddr) {
        Set<String> covered = new HashSet<String>();
        for (Set<String> s : byOffset.values()) covered.addAll(s);
        for (Set<String> s : byAddr.values()) covered.addAll(s);
        Set<String> seen = new HashSet<String>();
        Map<String, Set<String>> attributions =
            new HashMap<String, Set<String>>();
        List<String> unattributed = new ArrayList<String>();
        try {
            MemoryBlock[] blocks = mem.getBlocks();
            for (int b = 0; b < blocks.length; b++) {
                MemoryBlock block = blocks[b];
                if (!block.isInitialized()) continue;
                long start = block.getStart().getOffset();
                long end = block.getEnd().getOffset();
                if (end - start > 64L * 1024L * 1024L) continue;
                for (long a = start; a + (long) isa.pointerSize() <= end; a += (long) isa.pointerSize()) {
                    long w;
                    try {
                        w = isa.readPointer(mem, toAddr(a));
                    } catch (Exception e) {
                        continue;
                    }
                    Function fn;
                    try {
                        fn = fm.getFunctionAt(toAddr(isa.stripInstructionTag(w)));
                    } catch (Exception e) {
                        continue;
                    }
                    if (fn == null) continue;
                    String name = fn.getName();
                    if (covered.contains(name)) continue;
                    if (!seen.add(name)) continue;
                    // Command handlers (GDB monitor commands,
                    // remote-protocol handlers, target commands)
                    // are stored in command tables, never in ops
                    // structs -- but their names end in field words
                    // (cmd_reset, exec_v_attach), so the name rule
                    // below would mis-attribute them. They stay
                    // unattributed by rule, not by failed match.
                    if (name.startsWith("cmd_") ||
                        name.startsWith("exec_") ||
                        name.startsWith("target_cmd_") ||
                        name.contains("_cmd_")) {
                        unattributed.add(name);
                        continue;
                    }
                    String best = null;
                    boolean tie = false;
                    for (int k = 0; k < SCAN_FIELDS.length; k++) {
                        String f = SCAN_FIELDS[k];
                        if (name.equals(f) ||
                            name.endsWith("_" + f) ||
                            name.contains("_" + f + "_")) {
                            if (best == null ||
                                f.length() > best.length()) {
                                best = f;
                                tie = false;
                            } else if (f.length() == best.length()) {
                                tie = true;
                            }
                        }
                    }
                    if (best == null || tie) {
                        unattributed.add(name);
                    } else {
                        Set<String> s = attributions.get(best);
                        if (s == null) {
                            s = new HashSet<String>();
                            attributions.put(best, s);
                        }
                        s.add(name);
                        long[] offs = fieldOffsets(best);
                        if (offs != null) {
                            for (int q = 0; q < offs.length; q++) {
                                putStore(byOffset, offs[q], name);
                            }
                        }
                    }
                }
            }
        } catch (Exception e) {
            // best-effort; an empty scan only shrinks may-sets
        }
        java.util.Collections.sort(unattributed);
        return new LiteralScanResult(attributions, unattributed,
            seen.size());
    }

    /** Add the function entry stored at a program-memory address, if
        the word there is one. Best-effort: unreadable or non-function
        words add nothing. */
    private void addMemFunc(Memory mem, FunctionManager fm,
        long addr, Set<String> tset) {
        try {
            long ptr = isa.readPointer(mem, toAddr(addr));
            Function fn = fm.getFunctionAt(toAddr(isa.stripInstructionTag(ptr)));
            if (fn != null) tset.add(fn.getName());
        } catch (Exception e) {
            // Ignore unreadable or non-function words.
        }
    }

    /** Default RISC-V peripheral bands (see RiscVIsa.isMmioAddress).
        RISC-V has no fixed window: these bands cover the common
        families (CLINT, PLIC, FE310-style, GD32/STM32-like + K210,
        ESP32-like) without overlapping their flash/RAM. A caller may
        override them with the mmio= script argument; the
        SVD-profile classifier remains the authority on
        known-vs-suspect peripherals. Known caveat: ESP32-C3 XIP flash
        (0x42000000) falls inside the GD32 band, so flash-constant
        loads on ESP32-C3 would read as MMIO -- override with mmio=
        for that platform, or wait for profile-driven classification. */
    private static List<long[]> defaultRiscvMmioWindows() {
        List<long[]> w = new ArrayList<long[]>();
        w.add(new long[] {0x02000000L, 0x02010000L}); // CLINT
        w.add(new long[] {0x0C000000L, 0x10000000L}); // PLIC
        w.add(new long[] {0x10000000L, 0x20000000L}); // FE310-style
        w.add(new long[] {0x40000000L, 0x60000000L}); // GD32/K210
        w.add(new long[] {0x60000000L, 0x60100000L}); // ESP32-style
        return w;
    }

    /** Default MIPS peripheral bands (see MipsIsa.isMmioAddress).
        MIPS has no fixed window: these bands cover the common
        firmware families without overlapping their RAM or text
        (text typically lives at 0x80000000+, KSEG0/KSEG1 RAM mirrors
        at 0x80000000-0x9FFFFFFF / 0xA0000000-0xBFFFFFFF). A caller may
        override them with the mmio= script argument; the SVD-profile
        classifier remains the authority. Known caveat: Malta's
        0x1F000000 peripheral region is deliberately EXCLUDED because
        it collides with the Atheros SPI-flash window; Malta users
        should pass mmio= explicitly. */
    private static List<long[]> defaultMipsMmioWindows() {
        List<long[]> w = new ArrayList<long[]>();
        w.add(new long[] {0x10000000L, 0x10100000L}); // MediaTek/Ralink
        w.add(new long[] {0x18000000L, 0x1C000000L}); // Atheros/Broadcom
        w.add(new long[] {0x1F800000L, 0x1FC00000L}); // PIC32 physical
        w.add(new long[] {0xBF800000L, 0xBFC00000L}); // PIC32 KSEG1
        return w;
    }

    /** Default x86 platform bands (see X86Isa.isMmioAddress).
        x86 has no fixed peripheral window: PCI BAR space is
        platform-discovered (ACPI), so these bands cover only the
        architecturally fixed regions. BAR-discovered MMIO is NOT
        covered in v1: addresses there fail the generic window
        check until a profile-derived band or an mmio= override
        supplies them (OVMF drivers will hit this; that is an
        expected, documented limitation, not an extraction defect).
        The SVD-profile classifier remains the authority on
        known-vs-suspect. */
    private static List<long[]> defaultX86MmioWindows() {
        List<long[]> w = new ArrayList<long[]>();
        w.add(new long[] {0xA0000L, 0xC0000L}); // VGA
        w.add(new long[] {0xC0000L, 0x100000L}); // BIOS/option ROM
        w.add(new long[] {0xFEC00000L, 0xFED00000L}); // IOAPIC
        w.add(new long[] {0xFED00000L, 0xFEE00000L}); // HPET
        w.add(new long[] {0xFEE00000L, 0xFEF00000L}); // LAPIC
        return w;
    }

    /** Parse "start-end,start-end,..." (hex, optional 0x) into
        windows. Null on any parse failure. */
    private static List<long[]> parseMmioWindows(String spec) {
        try {
            List<long[]> w = new ArrayList<long[]>();
            for (String part : spec.split(",")) {
                String[] se = part.split("-");
                if (se.length != 2) return null;
                long s = parseHex(se[0].trim());
                long e = parseHex(se[1].trim());
                if (e <= s) return null;
                w.add(new long[] {s, e});
            }
            return w;
        } catch (Exception e) {
            return null;
        }
    }

    private static long parseHex(String s) {
        if (s.startsWith("0x") || s.startsWith("0X")) s = s.substring(2);
        return Long.parseLong(s, 16);
    }

    // ---------------- v2 item #4: ACPI-derived bands (MCFG only) ----------------
    // Bands affect CLASSIFICATION (known/suspect) and the Lean window
    // check; they do NOT create accesses. Real UEFI MMIO lives in
    // BAR-mapped regions, which the fixed x86 bands (legacy + APIC
    // ranges) do not cover; the MCFG table's ECAM window is the one
    // BAR-adjacent band with a fully specified, checkable format.
    //
    // WHY SIGNATURE-SCAN, NOT RSDP-CHASING: an RSDP points at
    // RSDT/XSDT by PHYSICAL address, and the physical-address to
    // file-offset translation of a flash image is platform
    // dependent (it depends on where the platform maps the ROM).
    // Chasing pointers would therefore bake in a mapping
    // assumption. Scanning the raw image bytes for a table that is
    // actually present, and validating it, tests presence without
    // any mapping assumption. DSDT/SSDT OperationRegions are NOT
    // attempted here: they need an AML parser (its own work), and
    // no DSDT/SSDT exists in the OVMF image at all (see the v4
    // survey: tables are QEMU runtime artifacts via fw_cfg).
    //
    // MCFG LAYOUT (ACPI spec): 36-byte standard header (signature
    // "MCFG" at 0, length LE u32 at 4, revision at 8, checksum at 9),
    // then an 8-byte reserved field (offsets 36..43), then N
    // 16-byte allocations starting at offset 44: base address LE
    // u64 at +0, segment group u16 at +8, start bus u8 at +10,
    // end bus u8 at +11, reserved u32 at +12. Length must equal
    // exactly 44 + 16*N. Per bus: 32 devices * 8 functions * 4KB
    // = 1MB, so one allocation covers [base, base + nBuses*1MB).
    //
    // VALIDATION (a band from a misparsed table is worse than no
    // band): signature, exact length arithmetic, table fits in the
    // image, ACPI checksum (sum of all length bytes mod 256 == 0),
    // every allocation non-zero base, startBus <= endBus, no
    // 64-bit wrap. A candidate failing ANY check is skipped, never
    // partially used (allocations from one table are collected in
    // a temp list and committed only if the whole table passes).
    // Never throws: any problem yields an empty list and the caller
    // falls back to the static bands. No QEMU default is ever
    // assumed: 0xB0000000 appears nowhere in this code; a band
    // exists only if a valid MCFG table was read from the image.
    private static List<long[]> findAcpiMcfgBands(byte[] img) {
        List<long[]> bands = new ArrayList<long[]>();
        if (img == null) return bands;
        for (int off = 0; off + 4 <= img.length; ) {
            int idx = -1;
            for (int i = off; i + 4 <= img.length; i++) {
                if (img[i] == 'M' && img[i + 1] == 'C' &&
                    img[i + 2] == 'F' && img[i + 3] == 'G') {
                    idx = i;
                    break;
                }
            }
            if (idx < 0) break;
            off = idx + 1;
            if (idx + 44 > img.length) continue;
            long len = (img[idx + 4] & 0xffL) |
                ((img[idx + 5] & 0xffL) << 8) |
                ((img[idx + 6] & 0xffL) << 16) |
                ((img[idx + 7] & 0xffL) << 24);
            if (len < 44 + 16 || (len - 44) % 16 != 0) continue;
            if (idx + len > img.length) continue;
            int sum = 0;
            for (long k = 0; k < len; k++) {
                sum += img[idx + (int) k] & 0xff;
            }
            if ((sum & 0xff) != 0) continue;
            int nAlloc = (int) ((len - 44) / 16);
            List<long[]> tableBands = new ArrayList<long[]>();
            boolean ok = true;
            for (int a = 0; a < nAlloc; a++) {
                int ao = idx + 44 + 16 * a;
                long base = 0;
                for (int b = 0; b < 8; b++) {
                    base |= (img[ao + b] & 0xffL) << (8 * b);
                }
                int startBus = img[ao + 10] & 0xff;
                int endBus = img[ao + 11] & 0xff;
                if (base <= 0 || startBus > endBus) {
                    ok = false;
                    break;
                }
                long size = (long) (endBus - startBus + 1) *
                    0x100000L;
                if (size <= 0 || base + size < base) {
                    ok = false;
                    break;
                }
                tableBands.add(new long[] {base, base + size});
            }
            if (ok) bands.addAll(tableBands);
        }
        return bands;
    }

    /** Union valid MCFG-derived ECAM bands from the input image
        into the x86 default band list (x86 branch only; other
        adapters never call this, so their outputs are structurally
        unchanged). Falls back silently to the static bands when
        the executable path is unavailable, the file is missing or
        over the 64MB scan cap, or no valid MCFG table is present.
        An explicit mmio= override suppresses augmentation: the
        override replaces all bands by user choice. */
    private void augmentX86WindowsWithAcpi(List<long[]> windows) {
        String exePath = null;
        try {
            exePath = currentProgram.getExecutablePath();
        } catch (Exception e) {
            exePath = null;
        }
        if (exePath == null || exePath.isEmpty()) {
            println("[*] acpi: no executable path; " +
                "static x86 bands only.");
            return;
        }
        try {
            java.io.File f = new java.io.File(exePath);
            if (!f.isFile() ||
                f.length() > 64L * 1024L * 1024L) {
                println("[*] acpi: input file unavailable or " +
                    ">64MB; static x86 bands only.");
                return;
            }
            byte[] img =
                java.nio.file.Files.readAllBytes(f.toPath());
            List<long[]> derived = findAcpiMcfgBands(img);
            if (derived.isEmpty()) {
                println("[*] acpi: no valid MCFG table in input " +
                    "image; static x86 bands only.");
                return;
            }
            for (long[] b : derived) {
                boolean dup = false;
                for (long[] w : windows) {
                    if (w[0] == b[0] && w[1] == b[1]) {
                        dup = true;
                        break;
                    }
                }
                if (!dup) windows.add(b);
                println("[*] acpi: MCFG ECAM band added [0x" +
                    Long.toHexString(b[0]) + ", 0x" +
                    Long.toHexString(b[1]) + ").");
            }
        } catch (Exception e) {
            println("[*] acpi: scan failed (" + e.getMessage() +
                "); static x86 bands only.");
        }
    }

    // ---------------- v2 item #2: inter-procedural constant propagation ----------------
    // SOUND SLICE, not a redesign: constants flow through DIRECT calls
    // with constant arguments, into callees whose EVERY call site is
    // modelled and agrees. The must-fixpoint of a callee starts from
    // an entry state binding its argument registers (all other
    // registers unknown, as before); propagated constants then
    // produce MORE entries in the existing mmio/port/msr classes --
    // no new JSON fields, no new flags, same one-command pipeline.
    //
    // SOUNDNESS (non-negotiable -- Lean trusts extractor JSON):
    // a propagated constant becomes a MUST-fact only when it holds
    // on ALL executions entering the callee. The entry for callee F
    // is the meet over ALL of F's direct call sites: one disagreeing
    // site (different constant, or an unknown value) drops that
    // argument to unknown. And F gets an entry ONLY when its caller
    // set is fully accounted for:
    //   (a) at least one direct call site, and
    //   (b) every Ghidra caller of F contains a direct CALL to F
    //       (a purely-indirect caller is unmodelled), and
    //   (c) F's address is never stored (not address-taken: a stored
    //       pointer could call F from anywhere), and
    //   (d) F is never a tail-call target (a jump to F passes
    //       arguments the direct-call meet cannot see), and
    //   (e) every direct site is modelled (x86-64: the callee's
    //       Ghidra convention must be known, so the argument
    //       registers are determined, never union-guessed), and
    //   (f) F is not external (no body to analyse).
    // Anything failing a guard keeps today's behaviour (all-unknown
    // entry). Functions with no callers (entry points, interrupt
    // handlers) also stay unknown. Return values are NOT propagated
    // (still unknown after CALL, as before); globals/memory are NOT
    // propagated (a BAR base stored to a global and reloaded in
    // another function is future work, as is context-sensitive
    // cloning for helpers called with varying constants -- merging
    // per-context findings into one per-function must-set would
    // violate the rule above, so it needs per-context attribution).
    // Residual risk, documented: an indirect call whose target
    // address is computed arithmetically (never stored, never a
    // literal) evades guard (c) -- the same hole as the v3.5
    // points-to recovery itself.
    //
    // CONVERGENCE: entries only gain precision across rounds
    // (intra-procedural transfer is monotone in input precision, and
    // a site value can only go unknown -> exact, never exact ->
    // different exact), so the worklist iteration terminates; the
    // round cap is a safety bound only, and the last iterate is
    // still sound (every iterate is justified by induction from the
    // all-unknown round-0 entries). A non-converged per-function
    // fixpoint keeps its previous converged result when one exists
    // (a converged result computed under a less-precise entry is a
    // sound under-approximation under a more-precise entry, by the
    // same monotonicity); otherwise it falls back to empty states,
    // as before.
    private static final int MAX_CONSTPROP_ROUNDS = 32;

    /** One function's Phase A record: everything the emission loop
        used to compute inline, plus the final must-fixpoint. */
    private static class FuncRec {
        Function f;
        OpsResult or;
        Map<Integer, List<Integer>> branchTargets;
        IndirectResult ind;
        TailCallResult tc;
        /** Canonical entry key: the function's raw entry offset. */
        long entryKey;
        /** v9 struct: op indices of CALL/CALLIND ops that can reach
            themselves through the CFG (loop-carried call sites).
            Computed once per function; the transfer never creates
            an OBJ symbol there, because one site may produce many
            distinct objects. */
        Set<Integer> loopCallOps;
        /** Final must-fixpoint (Phase B), never null after Phase B. */
        FixResult fx;
        /** Final provenance fixpoint (Phase P, v2 item #3); null
            when the provenance pass is skipped (non-x86-64) or
            failed for this function. */
        ProvResult pv;
    }

    /** One direct call site: the caller record + the CALL op index. */
    private static class CallSite {
        final FuncRec caller;
        final int opIdx;
        CallSite(FuncRec caller, int opIdx) {
            this.caller = caller;
            this.opIdx = opIdx;
        }
    }

    /** Synthetic register varnode for reading an argument register
        out of a fixpoint state. resolveExact slices containing
        views, so a full-width read after a narrow write correctly
        yields unknown unless the wider view itself is known. */
    private Varnode regVarnode(long off, int size) {
        try {
            AddressSpace rs = currentProgram.getAddressFactory()
                .getAddressSpace(isa.registerSpaceName());
            if (rs == null) return null;
            return new Varnode(rs.getAddress(off), size);
        } catch (Exception e) {
            return null;
        }
    }

    /** Entry-state equality with null treated as empty (absent entry
        and all-unknown entry are the same state). */
    private static boolean entrySame(Map<String, Bits> a,
        Map<String, Bits> b) {
        if (a == null) a = new HashMap<String, Bits>();
        if (b == null) b = new HashMap<String, Bits>();
        return sameState(a, b);
    }

    /** v8 retprop: equality of two Bits values, including symbols
        (Bits has no equals; compare the fields directly). */
    private static boolean sameBits(Bits a, Bits b) {
        if (a == b) return true;
        if (a == null || b == null) return false;
        if (a.ones != b.ones || a.zeroes != b.zeroes ||
            a.symW != b.symW) return false;
        if (a.sym == null) return b.sym == null;
        return a.sym.equals(b.sym);
    }

    /** v8 retprop: equality of two summary maps. */
    private static boolean sameRetSummaries(Map<Long, Bits> a,
        Map<Long, Bits> b) {
        if (a == b) return true;
        if (a == null || b == null) return false;
        if (a.size() != b.size()) return false;
        for (Map.Entry<Long, Bits> e : a.entrySet()) {
            if (!sameBits(e.getValue(), b.get(e.getKey()))) {
                return false;
            }
        }
        return true;
    }

    /** v8 retprop (Prov): equality of two interface-summary maps
        (Prov has equals; null treated as absent). */
    private static boolean sameProvSummaries(Map<Long, Prov> a,
        Map<Long, Prov> b) {
        if (a == b) return true;
        if (a == null || b == null) return false;
        if (a.size() != b.size()) return false;
        for (Map.Entry<Long, Prov> e : a.entrySet()) {
            Prov o = b.get(e.getKey());
            if (o == null || !e.getValue().equals(o)) return false;
        }
        return true;
    }

    /** v8 retprop (Prov): extract one interface return summary per
        callee from the current provenance fixpoints. The summary
        is the return register's provenance agreed on ALL RETURN
        ops, and only an interface (IFACE with a known GUID)
        qualifies: a helper that acquired an interface (a
        LocateProtocol out-param copied to the return register, or
        an interface parameter passed through) returns that
        interface to the caller with the same certainty. Any RETURN
        with a null inState, a non-IFACE provenance, or a
        disagreeing interface blocks the summary. Argument
        dependence needs no separate check: the fixpoint ran under
        the provEntries meet, so a value depending on a non-agreed
        argument is unknown here (or argument-independent, which is
        valid at every site). Dual-keyed like retSummaries. */
    private Map<Long, Prov> extractProvSummaries(
        List<FuncRec> funcRecs) {
        Map<Long, Prov> out = new HashMap<Long, Prov>();
        String retKey = isa.registerSpaceName() + ":" +
            isa.returnRegisterOffset() + ":" + isa.pointerSize();
        for (FuncRec rec : funcRecs) {
            if (rec.pv == null || !rec.pv.converged ||
                rec.pv.inStates == null) continue;
            Prov agree = null;
            boolean seen = false;
            boolean bad = false;
            List<OpRec> pops = rec.or.ops;
            for (int i = 0; i < pops.size(); i++) {
                if (!pops.get(i).mnem.equals("RETURN")) continue;
                if (i >= rec.pv.inStates.length) {
                    bad = true;
                    break;
                }
                ProvState st = rec.pv.inStates[i];
                if (st == null) {
                    bad = true;
                    break;
                }
                Prov p = st.varProv.get(retKey);
                if (p == null || p.kind != Prov.IFACE ||
                    p.guid == null) {
                    bad = true;
                    break;
                }
                if (!seen) {
                    agree = p;
                    seen = true;
                } else if (!agree.equals(p)) {
                    bad = true;
                    break;
                }
            }
            if (seen && !bad) {
                out.put(rec.entryKey, agree);
                long stripped =
                    isa.stripInstructionTag(rec.entryKey);
                if (stripped != rec.entryKey) {
                    out.put(stripped, agree);
                }
            }
        }
        return out;
    }

    /** v9 struct (Prov): extract one struct-layout summary per
        callee from the current provenance fixpoints. The summary
        is the return register's STRUCT provenance agreed on ALL
        RETURN ops, with a non-empty layout (an empty layout
        resolves nothing, so it is not stored -- the CALL branch
        falls back to an empty struct anyway). Any RETURN with a
        null inState, a non-STRUCT provenance, or a disagreeing
        layout blocks the summary. Argument dependence needs no
        separate check: the fixpoint ran under the provEntries
        meet, so a layout depending on a non-agreed argument is
        unknown here. Dual-keyed like provSummaries. */
    private Map<Long, Prov> extractStructProvSummaries(
        List<FuncRec> funcRecs) {
        Map<Long, Prov> out = new HashMap<Long, Prov>();
        String retKey = isa.registerSpaceName() + ":" +
            isa.returnRegisterOffset() + ":" + isa.pointerSize();
        for (FuncRec rec : funcRecs) {
            if (rec.pv == null || !rec.pv.converged ||
                rec.pv.inStates == null) continue;
            Prov agree = null;
            boolean seen = false;
            boolean bad = false;
            List<OpRec> pops = rec.or.ops;
            for (int i = 0; i < pops.size(); i++) {
                if (!pops.get(i).mnem.equals("RETURN")) continue;
                if (i >= rec.pv.inStates.length) {
                    bad = true;
                    break;
                }
                ProvState st = rec.pv.inStates[i];
                if (st == null) {
                    bad = true;
                    break;
                }
                Prov p = st.varProv.get(retKey);
                if (p == null || p.kind != Prov.STRUCT ||
                    p.layout == null || p.layout.isEmpty()) {
                    bad = true;
                    break;
                }
                if (!seen) {
                    agree = p;
                    seen = true;
                } else if (!agree.equals(p)) {
                    bad = true;
                    break;
                }
            }
            if (seen && !bad) {
                out.put(rec.entryKey, agree);
                long stripped =
                    isa.stripInstructionTag(rec.entryKey);
                if (stripped != rec.entryKey) {
                    out.put(stripped, agree);
                }
            }
        }
        return out;
    }

    /** v8 retprop: extract one return summary per callee from the
        current must-fixpoints. The summary is the return-register
        value agreed on ALL RETURN ops: the same exact constant, or
        the same BAR/BASE symbol at the same width. Any RETURN with
        a null inState (unreached or unmodelled path), an unknown
        or partial value, or a value disagreeing with another RETURN
        blocks the summary (unknown, never a guess). A callee with
        no RETURN ops (noreturn, or tail-called away) has no
        summary. Argument dependence needs no separate check: the
        fixpoint ran under the constprop entry, so a value depending
        on a non-agreed argument is unknown here (or
        argument-independent, which is valid at every site). The
        result is dual-keyed (entry key + stripped entry key, like
        funcByEntry) so the CALL branch can apply it from the raw
        call target alone. */
    private Map<Long, Bits> extractRetSummaries(
        List<FuncRec> funcRecs) {
        Map<Long, Bits> out = new HashMap<Long, Bits>();
        String retKey = isa.registerSpaceName() + ":" +
            isa.returnRegisterOffset() + ":" + isa.pointerSize();
        long mask = sizeMask(isa.pointerSize());
        for (FuncRec rec : funcRecs) {
            if (rec.fx == null || !rec.fx.converged ||
                rec.fx.inStates == null) continue;
            Bits agree = null;
            boolean seen = false;
            boolean bad = false;
            List<OpRec> pops = rec.or.ops;
            for (int i = 0; i < pops.size(); i++) {
                if (!pops.get(i).mnem.equals("RETURN")) continue;
                if (i >= rec.fx.inStates.length) {
                    bad = true;
                    break;
                }
                Map<String, Bits> st = rec.fx.inStates[i];
                if (st == null) {
                    bad = true;
                    break;
                }
                Bits b = st.get(retKey);
                Bits cand = null;
                if (b != null && b.sym != null) {
                    if (Bits.parseBarSym(b.sym) != null) {
                        cand = Bits.symBits(b.sym, b.symW);
                    }
                } else if (b != null) {
                    Long v = b.exactValue(mask);
                    if (v != null) {
                        cand = Bits.exact(v.longValue(), mask);
                    }
                }
                if (cand == null) {
                    bad = true;
                    break;
                }
                if (!seen) {
                    agree = cand;
                    seen = true;
                } else if (!sameBits(agree, cand)) {
                    bad = true;
                    break;
                }
            }
            if (seen && !bad) {
                out.put(rec.entryKey, agree);
                long stripped =
                    isa.stripInstructionTag(rec.entryKey);
                if (stripped != rec.entryKey) {
                    out.put(stripped, agree);
                }
            }
        }
        return out;
    }

    /** v9 struct: extract one field summary per callee from the
        current must-fixpoints. The summary exists only when the
        return register holds the SAME abstract object (same OBJ
        symbol, delta 0) on ALL RETURN ops: the object the callee
        returns. Its fields are the field cells for that object
        agreed on ALL RETURN ops (same key, sameBits-equal value
        everywhere; a field missing from any RETURN, or disagreeing,
        is excluded -- unknown, never a guess). A field stored on
        only one path is already dropped by the must-meet before
        it reaches any RETURN, so path coverage needs no separate
        check. The creating call site must not be loop-carried
        (the transfer never creates an OBJ symbol there, so such a
        summary cannot form -- this check is belt-and-braces).
        Dual-keyed like retSummaries. A callee with no RETURN ops,
        or whose return is not an object, has no summary. */
    private Map<Long, Map<String, Bits>> extractStructSummaries(
        List<FuncRec> funcRecs) {
        Map<Long, Map<String, Bits>> out =
            new HashMap<Long, Map<String, Bits>>();
        String retKey = isa.registerSpaceName() + ":" +
            isa.returnRegisterOffset() + ":" + isa.pointerSize();
        for (FuncRec rec : funcRecs) {
            if (rec.fx == null || !rec.fx.converged ||
                rec.fx.inStates == null) continue;
            List<OpRec> pops = rec.or.ops;
            String objId = null;
            boolean seen = false;
            boolean bad = false;
            for (int i = 0; i < pops.size(); i++) {
                if (!pops.get(i).mnem.equals("RETURN")) continue;
                if (i >= rec.fx.inStates.length) {
                    bad = true;
                    break;
                }
                Map<String, Bits> st = rec.fx.inStates[i];
                if (st == null) {
                    bad = true;
                    break;
                }
                Bits b = st.get(retKey);
                if (b == null || b.sym == null) {
                    bad = true;
                    break;
                }
                long[] o = Bits.parseObjSym(b.sym);
                if (o == null || o[1] != 0) {
                    bad = true;
                    break;
                }
                String id = Bits.objSym(o[0], 0);
                if (!seen) {
                    objId = id;
                    seen = true;
                } else if (!objId.equals(id)) {
                    bad = true;
                    break;
                }
            }
            if (!seen || bad || objId == null) continue;
            long[] oid = Bits.parseObjSym(objId);
            boolean looped = false;
            if (rec.loopCallOps != null && oid != null) {
                for (int i = 0; i < pops.size(); i++) {
                    if (pops.get(i).instrAddr.getOffset() == oid[0] &&
                        rec.loopCallOps.contains(i)) {
                        looped = true;
                        break;
                    }
                }
            }
            if (looped) continue;
            Map<String, Bits> fields = null;
            boolean first = true;
            for (int i = 0; i < pops.size(); i++) {
                if (!pops.get(i).mnem.equals("RETURN")) continue;
                Map<String, Bits> st = rec.fx.inStates[i];
                Map<String, Bits> mine = new HashMap<String, Bits>();
                for (Map.Entry<String, Bits> e : st.entrySet()) {
                    long[] f = parseFldKey(e.getKey());
                    if (f == null || f[0] != oid[0]) continue;
                    mine.put(f[1] + ":" + f[2], e.getValue());
                }
                if (first) {
                    fields = mine;
                    first = false;
                } else {
                    Map<String, Bits> inter =
                        new HashMap<String, Bits>();
                    for (Map.Entry<String, Bits> e :
                        fields.entrySet()) {
                        Bits o2 = mine.get(e.getKey());
                        if (o2 != null &&
                            sameBits(e.getValue(), o2)) {
                            inter.put(e.getKey(), e.getValue());
                        }
                    }
                    fields = inter;
                }
            }
            if (fields == null || fields.isEmpty()) continue;
            out.put(rec.entryKey, fields);
            long stripped =
                isa.stripInstructionTag(rec.entryKey);
            if (stripped != rec.entryKey) {
                out.put(stripped, fields);
            }
        }
        return out;
    }

    /** v9 struct: equality of two field-summary maps. */
    private static boolean sameStructSummaries(
        Map<Long, Map<String, Bits>> a,
        Map<Long, Map<String, Bits>> b) {
        if (a == b) return true;
        if (a == null || b == null) return false;
        if (a.size() != b.size()) return false;
        for (Map.Entry<Long, Map<String, Bits>> e : a.entrySet()) {
            Map<String, Bits> o = b.get(e.getKey());
            if (o == null || o.size() != e.getValue().size()) {
                return false;
            }
            for (Map.Entry<String, Bits> fe :
                e.getValue().entrySet()) {
                if (!sameBits(fe.getValue(), o.get(fe.getKey()))) {
                    return false;
                }
            }
        }
        return true;
    }

    /** Meet over ALL direct call sites of one callee: an argument
        register is bound only when every site agrees on the same
        value -- the same exact constant (v2 item #2), or, since v8
        retprop, the same BAR/BASE symbol (a symbol argument, e.g.
        a BASE returned by one helper and passed to the next).
        Anything else (unknown, partial, mixed kinds, disagreeing
        values) stays unknown (absent from the returned map). */
    private Map<String, Bits> meetOverSites(long calleeKey,
        Map<Long, List<CallSite>> sitesByCallee,
        Map<Long, long[]> argRegsByCallee) {
        Map<String, Bits> out = new HashMap<String, Bits>();
        List<CallSite> sites = sitesByCallee.get(calleeKey);
        long[] argRegs = argRegsByCallee.get(calleeKey);
        if (sites == null || sites.isEmpty() || argRegs == null) {
            return out;
        }
        int ptrSize = isa.pointerSize();
        long mask = sizeMask(ptrSize);
        for (long off : argRegs) {
            Varnode vn = regVarnode(off, ptrSize);
            if (vn == null) continue;
            Long agreedVal = null;
            String agreedSym = null;
            int agreedSymW = 0;
            boolean isSym = false;
            boolean first = true;
            boolean allAgree = true;
            for (CallSite s : sites) {
                FixResult fx = s.caller.fx;
                Bits b = null;
                if (fx != null && fx.inStates != null &&
                    s.opIdx < fx.inStates.length &&
                    fx.inStates[s.opIdx] != null) {
                    b = resolveBits(vn, fx.inStates[s.opIdx]);
                }
                if (b == null || (b.sym == null &&
                    b.exactValue(mask) == null)) {
                    allAgree = false;
                    break;
                }
                if (b.sym != null) {
                    if (Bits.parseBarSym(b.sym) == null) {
                        allAgree = false;
                        break;
                    }
                    if (first) {
                        isSym = true;
                        agreedSym = b.sym;
                        agreedSymW = b.symW;
                        first = false;
                    } else if (!isSym ||
                        !agreedSym.equals(b.sym) ||
                        agreedSymW != b.symW) {
                        allAgree = false;
                        break;
                    }
                } else {
                    Long v = b.exactValue(mask);
                    if (first) {
                        agreedVal = v;
                        first = false;
                    } else if (isSym || !agreedVal.equals(v)) {
                        allAgree = false;
                        break;
                    }
                }
            }
            if (allAgree && !first) {
                if (isSym) {
                    out.put(isa.registerSpaceName() + ":" + off +
                        ":" + ptrSize,
                        Bits.symBits(agreedSym, agreedSymW));
                } else {
                    out.put(isa.registerSpaceName() + ":" + off +
                        ":" + ptrSize,
                        Bits.exact(agreedVal.longValue(), mask));
                }
            }
        }
        return out;
    }

    /** v12 persite: MUST-finding recording for ONE op under ONE
        in-state, factored out of the emission loop so per-site
        clone fixpoints can be recorded with the IDENTICAL logic
        (no duplicated predicates to drift apart). Appends the
        same JSON strings the emission loop used to build inline
        (mmio LOAD/STORE + COPY-to-ram, CALLOTHER port/MSR, BAR
        symbols) and records each finding's identity (instr +
        accessed location) in the parallel sets. Returns true iff
        a LOAD/STORE must-MMIO was recorded (the may gate). A null
        in-state records nothing. */
    private boolean recordMustFindings(OpRec op,
        Map<String, Bits> bvals, Memory mem,
        List<String> mmio, List<String> portIo, List<String> msr,
        List<String> barRel,
        List<String> mmioIds, List<String> portIds,
        List<String> msrIds, List<String> barIds,
        List<BoundaryAccess> bnd, List<BoundaryAccess> bndExt,
        BoundaryProfile bndProfile) {
        boolean mustRecorded = false;
        if (bvals == null) return false;
        // ---- MMIO recording (LOAD/STORE) ----
        // Masks and exact values print UNSIGNED (v3.8): a
        // 64-bit mask/value with the high bit set prints
        // negative as a Java long, which Lean's Nat parser
        // rejects. 32-bit values print identically either way.
        if (op.mnem.equals("LOAD") || op.mnem.equals("STORE")) {
            if (op.ins.length >= 2) {
                Bits valBits = Bits.unknown();
                if (op.mnem.equals("LOAD") && op.out != null) {
                    valBits = loadBits(op.ins, op.out, bvals, mem);
                } else if (op.mnem.equals("STORE") &&
                    op.ins.length >= 3) {
                    valBits = resolveBits(op.ins[2], bvals);
                }
                Long addr = resolveAddressExact(op.ins[1], bvals);
                if (addr != null && isa.isMmioAddress(addr)) {
                    int sz = (op.mnem.equals("STORE") &&
                        op.ins.length >= 3)
                        ? op.ins[2].getSize()
                        : (op.out != null ? op.out.getSize() : 0);
                    Long exact = valBits.exactValue(
                        sizeMask(sz == 0 ? 4 : sz));
                    mmio.add("{\"instr\": \"" + op.instrAddr +
                        "\", \"op\": \"" + op.mnem +
                        "\", \"address\": \"0x" + Long.toHexString(addr) +
                        "\", \"size\": " + sz +
                        ", \"value\": " +
                        (exact == null ? "null" : Long.toUnsignedString(exact)) +
                        ", \"value_known_ones\": " + Long.toUnsignedString(valBits.ones) +
                        ", \"value_known_zeroes\": " + Long.toUnsignedString(valBits.zeroes) + "}");
                    mmioIds.add("mmio:" + op.instrAddr + ":0x" +
                        Long.toHexString(addr));
                    mustRecorded = true;
                    // Phase 4 V1: boundary candidate, aligned
                    // 1:1 with the mmio entry just appended.
                    if (bnd != null) {
                        bnd.add(new BoundaryAccess(
                            op.instrAddr.toString(), op.mnem,
                            addr.longValue(), exact));
                    }
                } else if (addr != null && bndProfile != null &&
                    bndProfile.regionFor(addr.longValue()) != null) {
                    // Phase 4 RAM-region extension, replay form
                    // (same rule as the emission loop; mmio
                    // strings are untouched, so the replay
                    // guard cannot trip on this).
                    Long extExact = null;
                    if (op.mnem.equals("STORE") &&
                        op.ins.length >= 3) {
                        extExact = valBits.exactValue(sizeMask(
                            op.ins[2].getSize()));
                    }
                    if (bndExt != null) {
                        bndExt.add(new BoundaryAccess(
                            op.instrAddr.toString(), op.mnem,
                            addr.longValue(), extExact));
                    }
                }
            }
        }
        // ---- v9 struct: COPY-to-ram MMIO stores ----
        // The transfer treats COPY-to-ram as an absolute
        // store (x86-64 movabs / RIP-relative stores never
        // become STORE ops), but emission only recorded
        // LOAD/STORE, so absolute MMIO stores were silently
        // dropped. A COPY-to-ram address is a constant, so
        // this is a must-recording, never a may. Value and
        // size mirror the STORE rule.
        if (op.mnem.equals("COPY") && op.out != null &&
            isRamSpace(op.out) && op.ins.length >= 1) {
            // v10 u32: band-gated canonicalization, so
            // a movabs to 0xFFFFFFFFFED00020 records as
            // the MMIO address 0xFED00020.
            long a = canonicalizeBandAddr(op.out.getOffset());
            if (isa.isMmioAddress(a)) {
                Bits valBits = resolveBits(op.ins[0], bvals);
                int sz = op.out.getSize();
                Long exact = valBits.exactValue(
                    sizeMask(sz == 0 ? 4 : sz));
                mmio.add("{\"instr\": \"" + op.instrAddr +
                    "\", \"op\": \"" + op.mnem +
                    "\", \"address\": \"0x" + Long.toHexString(a) +
                    "\", \"size\": " + sz +
                    ", \"value\": " +
                    (exact == null ? "null" : Long.toUnsignedString(exact)) +
                    ", \"value_known_ones\": " + Long.toUnsignedString(valBits.ones) +
                    ", \"value_known_zeroes\": " + Long.toUnsignedString(valBits.zeroes) + "}");
                mmioIds.add("mmio:" + op.instrAddr + ":0x" +
                    Long.toHexString(a));
                // Phase 4 V1: boundary candidate, COPY form.
                if (bnd != null) {
                    bnd.add(new BoundaryAccess(
                        op.instrAddr.toString(), op.mnem, a, exact));
                }
            } else if (bndProfile != null &&
                bndProfile.regionFor(a) != null) {
                // Phase 4 RAM-region extension, COPY form.
                if (bndExt != null) {
                    Bits valBits = resolveBits(op.ins[0], bvals);
                    int sz = op.out.getSize();
                    Long extExact = valBits.exactValue(
                        sizeMask(sz == 0 ? 4 : sz));
                    bndExt.add(new BoundaryAccess(
                        op.instrAddr.toString(), op.mnem, a, extExact));
                }
            }
        }
        // ---- Port I/O + MSR recording (x86 CALLOTHER) ----
        // Ghidra lifts IN/OUT/RDMSR/WRMSR to CALLOTHER
        // userops; the instruction mnemonic (op.instrAsm)
        // is the signal, NOT the userop index (a Ghidra
        // internal). Port/MSR spaces are disjoint from
        // memory, so they get their own JSON classes (v3.8
        // shape change) instead of polluting mmio_accesses.
        // Port numbers are masked to the 16-bit port space.
        // IN/RDMSR values are hardware inputs -> null.
        // PCI config ports 0xCF8/0xCFC fall out raw here;
        // BDF decoding is v2.
        if (op.mnem.equals("CALLOTHER") &&
            op.ins.length >= 1) {
            String am = op.instrAsm;
            if (am.equalsIgnoreCase("OUT") &&
                op.ins.length >= 3) {
                // v10 u32: band-gated address helper
                // (a no-op after the 0xFFFF mask below,
                // kept for uniformity with MMIO sites).
                Long port = resolveAddressExact(op.ins[1],
                    bvals);
                if (port != null) {
                    Bits vb = resolveBitsSlice(op.ins[2],
                        bvals);
                    int sz = op.ins[2].getSize();
                    Long exact = vb.exactValue(
                        sizeMask(sz));
                    portIo.add("{\"instr\": \"" +
                        op.instrAddr + "\", \"op\": \"OUT\"" +
                        ", \"direction\": \"OUT\"" +
                        ", \"port\": \"0x" +
                        Long.toHexString(port & 0xFFFFL) +
                        "\", \"size\": " + sz +
                        ", \"value\": " +
                        (exact == null ? "null" :
                            Long.toUnsignedString(exact)) +
                        ", \"value_known_ones\": " +
                        Long.toUnsignedString(vb.ones) +
                        ", \"value_known_zeroes\": " +
                        Long.toUnsignedString(vb.zeroes) + "}");
                    portIds.add("port:" + op.instrAddr + ":0x" +
                        Long.toHexString(port & 0xFFFFL));
                }
            } else if (am.equalsIgnoreCase("IN") &&
                op.ins.length >= 2) {
                Long port = resolveAddressExact(op.ins[1],
                    bvals);
                if (port != null) {
                    int sz = op.out != null ?
                        op.out.getSize() : 0;
                    portIo.add("{\"instr\": \"" +
                        op.instrAddr + "\", \"op\": \"IN\"" +
                        ", \"direction\": \"IN\"" +
                        ", \"port\": \"0x" +
                        Long.toHexString(port & 0xFFFFL) +
                        "\", \"size\": " + sz +
                        ", \"value\": null" +
                        ", \"value_known_ones\": 0" +
                        ", \"value_known_zeroes\": 0}");
                    portIds.add("port:" + op.instrAddr + ":0x" +
                        Long.toHexString(port & 0xFFFFL));
                }
            } else if (am.equalsIgnoreCase("WRMSR") &&
                op.ins.length >= 3) {
                // v10 u32: MSR indices are 32-bit by
                // architecture, so a sext-shaped index
                // reads as its low 32 bits (no band gate).
                Long idx = resolveMsrIndexExact(op.ins[1],
                    bvals);
                if (idx != null) {
                    // Combined 64-bit value (EDX:EAX):
                    // an intra-instruction unique, so
                    // exact-key lookup resolves it.
                    Bits vb = resolveBits(op.ins[2],
                        bvals);
                    Long exact = vb.exactValue(
                        sizeMask(8));
                    msr.add("{\"instr\": \"" +
                        op.instrAddr +
                        "\", \"op\": \"WRMSR\"" +
                        ", \"direction\": \"WR\"" +
                        ", \"index\": \"0x" +
                        Long.toHexString(idx) +
                        "\", \"size\": 8" +
                        ", \"value\": " +
                        (exact == null ? "null" :
                            Long.toUnsignedString(exact)) +
                        ", \"value_known_ones\": " +
                        Long.toUnsignedString(vb.ones) +
                        ", \"value_known_zeroes\": " +
                        Long.toUnsignedString(vb.zeroes) + "}");
                    msrIds.add("msr:" + op.instrAddr + ":0x" +
                        Long.toHexString(idx));
                }
            } else if (am.equalsIgnoreCase("RDMSR") &&
                op.ins.length >= 2) {
                Long idx = resolveMsrIndexExact(op.ins[1],
                    bvals);
                if (idx != null) {
                    msr.add("{\"instr\": \"" +
                        op.instrAddr +
                        "\", \"op\": \"RDMSR\"" +
                        ", \"direction\": \"RD\"" +
                        ", \"index\": \"0x" +
                        Long.toHexString(idx) +
                        "\", \"size\": 8" +
                        ", \"value\": null" +
                        ", \"value_known_ones\": 0" +
                        ", \"value_known_zeroes\": 0}");
                    msrIds.add("msr:" + op.instrAddr + ":0x" +
                        Long.toHexString(idx));
                }
            }
        }
        // v7 cfgspace: BAR-relative findings. The access
        // address is a BASE symbol (masked BAR + constant
        // offset). This is a provenance statement (device
        // BDF, BAR index, offset), never a fixed address:
        // MUST-class is forbidden for symbolic values, and
        // the may-trace parses hex addresses, so a symbolic
        // address must not enter may_accesses either. Raw
        // BAR symbols (unmasked flag bits) never yield a
        // finding. Guard null like the neighboring blocks:
        // ops in unreached code have a null in-state, and
        // resolveBits would NPE on it (hit on DxeCore,
        // PciBusDxe, stripped BMP).
        {
            Bits ab = null;
            int asz = 0;
            if (op.mnem.equals("LOAD") && op.out != null &&
                op.ins.length >= 2) {
                ab = resolveBits(op.ins[1], bvals);
                asz = op.out.getSize();
            } else if (op.mnem.equals("STORE") &&
                op.ins.length >= 3) {
                ab = resolveBits(op.ins[1], bvals);
                asz = op.ins[2].getSize();
            }
            if (ab != null && ab.sym != null) {
                long[] p = Bits.parseBarSym(ab.sym);
                if (p != null && p[0] == 1) {
                    barRel.add("{\"instr\": \"" +
                        op.instrAddr +
                        "\", \"op\": \"" + op.mnem + "\"" +
                        ", \"bus\": " + p[1] +
                        ", \"device\": " + p[2] +
                        ", \"function\": " + p[3] +
                        ", \"bar\": " + p[4] +
                        ", \"offset\": " + p[5] +
                        ", \"size\": " + asz + "}");
                    barIds.add("bar:" + op.instrAddr + ":" +
                        p[1] + ":" + p[2] + ":" + p[3] + ":" +
                        p[4] + ":" + p[5]);
                }
            }
        }
        return mustRecorded;
    }

    /** v12 persite: one per-site clone of a callee: the callee
        analyzed with ONE argument-binding group as its entry,
        instead of the merged all-sites-agree entry. The clone's
        findings belong to the callee function (where the
        instruction lives); the group key records which binding
        produced them, so a human can attribute every extra
        finding to its site group. Clones never merge back into
        a shared summary: each clone's fixpoint is used only to
        record extra findings for its own group. */
    private static class PerSiteGroup {
        long calleeKey;
        String groupKey;
        FixResult fx;
        List<String> sites;
        PerSiteGroup(long calleeKey, String groupKey,
            FixResult fx, List<String> sites) {
            this.calleeKey = calleeKey;
            this.groupKey = groupKey;
            this.fx = fx;
            this.sites = sites;
        }
    }

    /** v12 persite: canonical encoding of ONE argument-register
        value for grouping. Mirrors meetOverSites' discipline:
        only exact constants and BAR symbols count as
        informative; anything else (unknown, partial, non-BAR
        symbol) is "U". Two sites share a group iff every
        argument register encodes identically. */
    private String persiteComponent(Bits b, long mask) {
        if (b == null) return "U";
        if (b.sym != null) {
            if (Bits.parseBarSym(b.sym) == null) return "U";
            return "B:" + b.sym + ":" + b.symW;
        }
        Long v = b.exactValue(mask);
        if (v == null) return "U";
        return "V:" + Long.toUnsignedString(v);
    }

    /** v12 persite: group key for a binding vector (one
        component per argument register, in convention order). */
    private String persiteGroupKey(List<Bits> vals, long mask) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < vals.size(); i++) {
            if (i > 0) sb.append(",");
            sb.append(persiteComponent(vals.get(i), mask));
        }
        return sb.toString();
    }

    /** v12 persite: true when every component is "U" (no
        informative argument at all -- a clone with this
        binding could add nothing over the merged analysis). */
    private boolean persiteAllUnknown(String groupKey) {
        if (groupKey.length() == 0) return true;
        for (String c : groupKey.split(",", -1)) {
            if (!c.equals("U")) return false;
        }
        return true;
    }

    /** v12 persite: argument-register values at a direct call
        site, resolved in the CALL op's in-state (the state
        BEFORE the call's clobber -- the site's own values).
        Null entries mark unresolvable registers. */
    private List<Bits> persiteBindingFromState(
        Map<String, Bits> state, long[] argRegs) {
        List<Bits> vals = new ArrayList<Bits>();
        int ptrSize = isa.pointerSize();
        for (long off : argRegs) {
            Bits b = null;
            if (state != null) {
                Varnode vn = regVarnode(off, ptrSize);
                if (vn != null) b = resolveBits(vn, state);
            }
            vals.add(b);
        }
        return vals;
    }

    /** v12 persite: entry map for a clone: the group's
        informative bindings as register keys, plus the
        program-wide global seeds (mirroring Phase M's final
        entry construction: merged entry + seeds, with the
        group binding in place of the merged entry). Unknown
        components stay absent (= unknown), exactly as in
        meetOverSites. */
    private Map<String, Bits> persiteEntry(List<Bits> vals,
        long[] argRegs, Map<String, Bits> memSeeds, long mask) {
        Map<String, Bits> entry = new HashMap<String, Bits>();
        int ptrSize = isa.pointerSize();
        for (int i = 0; i < vals.size(); i++) {
            Bits b = vals.get(i);
            if (b == null) continue;
            if (b.sym != null) {
                if (Bits.parseBarSym(b.sym) == null) continue;
                entry.put(isa.registerSpaceName() + ":" +
                    argRegs[i] + ":" + ptrSize,
                    Bits.symBits(b.sym, b.symW));
            } else {
                Long v = b.exactValue(mask);
                if (v == null) continue;
                entry.put(isa.registerSpaceName() + ":" +
                    argRegs[i] + ":" + ptrSize,
                    Bits.exact(v.longValue(), mask));
            }
        }
        if (memSeeds != null) entry.putAll(memSeeds);
        return entry;
    }

    /** v12 persite: true when a group's binding equals the
        callee's merged entry on every argument register
        (absent merged key = unknown). Such a clone would
        reproduce the merged fixpoint exactly, so it is
        skipped for efficiency, never for soundness. */
    private boolean persiteEqualsMerged(String groupKey,
        Map<String, Bits> mergedEntry, long[] argRegs,
        long mask) {
        String[] comps = groupKey.split(",", -1);
        for (int i = 0; i < argRegs.length; i++) {
            String gc = (i < comps.length) ? comps[i] : "U";
            String mc = "U";
            if (mergedEntry != null) {
                Bits mb = mergedEntry.get(
                    isa.registerSpaceName() + ":" + argRegs[i] +
                    ":" + isa.pointerSize());
                if (mb != null) mc = persiteComponent(mb, mask);
            }
            if (!gc.equals(mc)) return false;
        }
        return true;
    }

    /** v14 zephyr: resolve ONE indirect call to a (target,
        device) pair from a pre-call in-state. Fast path only:
        the CALLIND target varnode and argument register 0 must
        both be exact constants in the given state, and the
        Thumb-stripped target must be a known non-external
        function entry. Anything else (unknown, partial, symbol
        value, non-function target, self-call is filtered by the
        caller) returns null -- never a guess. The same helper
        serves the seed pass (merged in-states) and the worklist
        pass (clone in-states). */
    private long[] resolveDeviceCallSite(List<OpRec> ops,
        Map<String, Bits> st, int opIdx, long devRegOff,
        int ptrSize, long mask,
        Map<Long, FuncRec> funcByEntry) {
        if (st == null || opIdx < 0 || opIdx >= ops.size()) {
            return null;
        }
        OpRec op = ops.get(opIdx);
        if (op == null || !"CALLIND".equals(op.mnem) ||
            op.ins == null || op.ins.length < 1) {
            return null;
        }
        Bits tb = resolveBits(op.ins[0], st);
        if (tb == null) return null;
        Long t = tb.exactValue(mask);
        if (t == null) return null;
        Varnode dvn = regVarnode(devRegOff, ptrSize);
        if (dvn == null) return null;
        Bits db = resolveBits(dvn, st);
        if (db == null) return null;
        Long d = db.exactValue(mask);
        if (d == null) return null;
        long te = isa.stripInstructionTag(t.longValue());
        FuncRec tgt = funcByEntry.get(te);
        if (tgt == null) tgt = funcByEntry.get(t.longValue());
        if (tgt == null || tgt.f.isExternal()) return null;
        return new long[]{tgt.entryKey, d.longValue()};
    }

    /** v14 zephyr: true when addr looks like a Zephyr device
        struct in initialised, NON-writable memory, with its
        init word a known function entry and its config/api
        words readable. The non-writable gate is the soundness
        argument: the initial image value is the runtime value
        (a store to flash would fault on real hardware), so
        resolving config/api/init from image bytes is sound
        for such structs. Any read failure returns false. */
    private boolean looksLikeDeviceStruct(Memory mem, long addr,
        Map<Long, FuncRec> funcByEntry) {
        try {
            MemoryBlock blk = mem.getBlock(toAddr(addr));
            if (blk == null || !blk.isInitialized() ||
                blk.isWrite()) return false;
            long init = isa.stripInstructionTag(
                isa.readPointer(mem, toAddr(addr + 20)));
            if (!funcByEntry.containsKey(init)) return false;
            isa.readPointer(mem, toAddr(addr + 4));
            isa.readPointer(mem, toAddr(addr + 8));
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    /** Empty must-fixpoint fallback (same as the old per-function
        exception fallback: claim nothing). */
    private static FixResult emptyFix(int nOps) {
        Map<String, Bits>[] empty = new Map[nOps];
        for (int i = 0; i < empty.length; i++) {
            empty[i] = new HashMap<String, Bits>();
        }
        return new FixResult(empty, false);
    }

    // ---------------- memory/global propagation helpers ----------------

    /** True when the varnode lives in the ram address space
        (absolute memory: globals on x86-64, where Ghidra models
        RIP-relative access as COPY-to/from-ram rather than
        LOAD/STORE). */
    private static boolean isRamSpace(Varnode v) {
        return v != null && v.getAddress() != null &&
            "ram".equals(v.getAddress().getAddressSpace().getName());
    }

    private static String memKey(long addr, int size) {
        return "mem:" + addr + ":" + size;
    }

    private static String gmemKey(long addr, int size) {
        return "gmem:" + addr + ":" + size;
    }

    /** Parse a mem:/gmem: key into {addr, size}; null when malformed. */
    private static long[] parseMemKey(String k) {
        if (k == null) return null;
        if (!k.startsWith("mem:") && !k.startsWith("gmem:")) return null;
        String[] p = k.split(":");
        if (p.length != 3) return null;
        try {
            return new long[] { Long.parseLong(p[1]), Long.parseLong(p[2]) };
        } catch (Exception e) {
            return null;
        }
    }

    /** Drop memState entries overlapping [addr, addr+size).
        includeGmem also drops seeded globals (an intra-procedural
        store overlapping a seed wins over the seed on
        contradiction); calls and unknown stores drop "mem:" only. */
    private static void dropMemRange(Map<String, Bits> m, long addr,
        int size, boolean includeGmem) {
        long end = addr + size;
        List<String> drop = new ArrayList<String>();
        for (String k : m.keySet()) {
            if (!k.startsWith("mem:") &&
                !(includeGmem && k.startsWith("gmem:"))) continue;
            long[] as = parseMemKey(k);
            if (as == null) continue;
            if (as[0] < end && addr < as[0] + as[1]) drop.add(k);
        }
        for (String k : drop) m.remove(k);
    }

    /** Drop intra-procedural memState only (never seeded globals). */
    private static void dropAllMem(Map<String, Bits> m) {
        List<String> drop = new ArrayList<String>();
        for (String k : m.keySet()) {
            if (k.startsWith("mem:")) drop.add(k);
        }
        for (String k : drop) m.remove(k);
    }

    // ---------------- v14 stack slots: stk: cells ----------------
    // A stack slot is a (function, delta) cell: the SP symbol's
    // entry address identifies the function, the delta
    // identifies the slot within its frame. Key form:
    // "stk:SP:<funcEntry>:<delta>:<size>". Cells live in the
    // same must-state map, so meet()'s agree-or-drop applies
    // exactly as to registers and mem: cells. They never
    // overlap mem:/gmem:/fld: cells (different key prefixes),
    // and two functions never share a cell (distinct entry
    // addresses in the symbol). Diagnostics: counts below are
    // accumulated over every must-fixpoint run in the process
    // and printed once with the persite summary.
    private int stkStoreCount = 0;
    private int stkLoadHitCount = 0;

    private static String stkKey(long funcEntry, long delta,
        int size) {
        return "stk:SP:" + funcEntry + ":" + delta + ":" + size;
    }

    private static long[] parseStkKey(String k) {
        if (k == null || !k.startsWith("stk:SP:")) return null;
        String[] p = k.split(":");
        if (p.length != 5) return null;
        try {
            return new long[] { Long.parseLong(p[2]),
                Long.parseLong(p[3]), Long.parseLong(p[4]) };
        } catch (NumberFormatException e) {
            return null;
        }
    }

    private static void dropStkRange(Map<String, Bits> m,
        long funcEntry, long delta, int size) {
        long end = delta + size;
        List<String> drop = new ArrayList<String>();
        for (String k : m.keySet()) {
            long[] as = parseStkKey(k);
            if (as == null || as[0] != funcEntry) continue;
            if (as[1] < end && delta < as[1] + as[2]) drop.add(k);
        }
        for (String k : drop) m.remove(k);
    }

    private static void dropAllStk(Map<String, Bits> m) {
        List<String> drop = new ArrayList<String>();
        for (String k : m.keySet()) {
            if (k.startsWith("stk:")) drop.add(k);
        }
        for (String k : drop) m.remove(k);
    }

    /** Byte-assembling stk: lookup, mirroring memLookupPrefix:
        returns null unless stk: cells fully cover
        [delta, delta+size) for this function's SP symbol
        (size <= 8, else unrepresentable in Bits). Symbols in
        cells are NOT assembled (a stored symbol covers its
        whole cell exactly: partial-symbol reads fall back to
        the exact-cell case below via the covering check --
        a symbol cell only satisfies a load of exactly its
        range; wider/narrower reads over a symbol cell return
        null, i.e. unknown, which is sound). */
    private Bits stkLookup(Map<String, Bits> m, long funcEntry,
        long delta, int size) {
        if (size <= 0 || size > 8) return null;
        // Exact-cell fast path (covers the symbol case).
        Bits exact = m.get(stkKey(funcEntry, delta, size));
        if (exact != null) {
            stkLoadHitCount++;
            return exact;
        }
        long end = delta + size;
        long cov = 0;
        long ones = 0, zeroes = 0;
        for (Map.Entry<String, Bits> e : m.entrySet()) {
            long[] as = parseStkKey(e.getKey());
            if (as == null || as[0] != funcEntry) continue;
            long t = as[2];
            if (t <= 0 || t > 8) continue;
            Bits eb = e.getValue();
            if (eb.sym != null) continue;
            long b = as[1];
            long is = Math.max(delta, b), ie = Math.min(end, b + t);
            if (is >= ie) continue;
            for (long p = is; p < ie; p++) {
                long ej = p - b;
                long lb = p - delta;
                long srcShift = memBigEndian ?
                    (t - 1 - ej) * 8 : ej * 8;
                long dstShift = memBigEndian ?
                    (size - 1 - lb) * 8 : lb * 8;
                ones |= ((eb.ones >>> srcShift) & 0xffL) << dstShift;
                zeroes |= ((eb.zeroes >>> srcShift) & 0xffL)
                    << dstShift;
                cov |= (1L << lb);
            }
        }
        if (cov != ((1L << size) - 1)) return null;
        stkLoadHitCount++;
        return new Bits(ones, zeroes);
    }

    // ---------------- v9 struct: object field cells ----------------
    // Field cells live in the same must-state map as memState, but
    // under "fld:" keys, so the must-meet's agree-or-drop
    // discipline applies to them exactly as to registers and
    // memState: a cell survives a join only when every incoming
    // path agrees on it (a field stored on one branch only dies
    // at the join -- no separate dominance check is needed).
    // Key form: "fld:OBJ:<callAddr>:<delta>:<size>", where the
    // OBJ symbol already carries the field offset (its delta).
    // Cells of distinct objects never overlap (distinct call
    // addresses), and never overlap mem:/gmem: cells (abstract
    // objects are disjoint from real addresses by construction).

    /** Parse a field-cell key into [callAddr, delta, size], or
        null when malformed. */
    private static long[] parseFldKey(String k) {
        if (k == null || !k.startsWith("fld:OBJ:")) return null;
        String[] p = k.split(":");
        if (p.length != 5) return null;
        try {
            return new long[] { Long.parseLong(p[2]),
                Long.parseLong(p[3]), Long.parseLong(p[4]) };
        } catch (NumberFormatException e) {
            return null;
        }
    }

    /** Drop field cells of one object overlapping
        [delta, delta+size) -- the field-cell twin of dropMemRange
        (cells of other objects are untouched). */
    private static void fldDropRange(Map<String, Bits> m, long callAddr,
        long delta, int size) {
        long end = delta + size;
        List<String> drop = new ArrayList<String>();
        for (String k : m.keySet()) {
            long[] f = parseFldKey(k);
            if (f == null || f[0] != callAddr) continue;
            if (f[1] < end && delta < f[1] + f[2]) drop.add(k);
        }
        for (String k : drop) m.remove(k);
    }

    /** Write one field cell (dropping overlapped cells first).
        An unknown value removes the cell (putKnown semantics):
        an unknown store to a field makes the field unknown. Full
        Bits are stored, symbols included (unlike memState). */
    private static void fldStore(Map<String, Bits> m, String objSym,
        int size, Bits v) {
        long[] o = Bits.parseObjSym(objSym);
        if (o == null || size <= 0 || size > 8) return;
        fldDropRange(m, o[0], o[1], size);
        String k = "fld:" + objSym + ":" + size;
        if (v.ones == 0 && v.zeroes == 0 && v.sym == null) {
            m.remove(k);
        } else {
            m.put(k, v);
        }
    }

    /** Read a field value: the cells covering [delta, delta+size)
        must cover the whole range. A single covering symbol cell
        yields its symbol only when the load starts at the cell
        base and covers at least the symbol's width (the v7 view
        rule); otherwise all covering cells must be exact and
        their bytes are assembled (memLookup discipline).
        Anything else -> null (unknown). */
    private Bits fldLookup(Map<String, Bits> m, String objSym,
        int size) {
        long[] o = Bits.parseObjSym(objSym);
        if (o == null || size <= 0 || size > 8) return null;
        long callAddr = o[0], delta = o[1], end = delta + size;
        List<long[]> cells = new ArrayList<long[]>();
        List<Bits> vals = new ArrayList<Bits>();
        for (Map.Entry<String, Bits> e : m.entrySet()) {
            long[] f = parseFldKey(e.getKey());
            if (f == null || f[0] != callAddr) continue;
            if (f[1] < end && delta < f[1] + f[2]) {
                cells.add(f);
                vals.add(e.getValue());
            }
        }
        if (cells.isEmpty()) return null;
        long cov = 0;
        for (long[] f : cells) {
            long is = Math.max(delta, f[1]);
            long ie = Math.min(end, f[1] + f[2]);
            for (long p = is; p < ie; p++) cov |= (1L << (p - delta));
        }
        if (cov != ((1L << size) - 1)) return null;
        if (cells.size() == 1) {
            Bits v = vals.get(0);
            if (v.sym != null) {
                long[] f = cells.get(0);
                if (delta == f[1] && size >= v.symW) return v;
                return null;
            }
        }
        long ones = 0, zeroes = 0;
        for (int i = 0; i < cells.size(); i++) {
            long[] f = cells.get(i);
            Bits eb = vals.get(i);
            if (eb.sym != null) return null;
            long is = Math.max(delta, f[1]);
            long ie = Math.min(end, f[1] + f[2]);
            for (long p = is; p < ie; p++) {
                long ej = p - f[1];
                long lb = p - delta;
                long srcShift = memBigEndian ? (f[2] - 1 - ej) * 8 :
                    ej * 8;
                long dstShift = memBigEndian ? (size - 1 - lb) * 8 :
                    lb * 8;
                ones |= ((eb.ones >>> srcShift) & 0xffL) << dstShift;
                zeroes |= ((eb.zeroes >>> srcShift) & 0xffL) << dstShift;
            }
        }
        return new Bits(ones, zeroes);
    }

    /** Covering memState lookup for a load of [addr, addr+size).
        "mem:" entries win over "gmem:" entries; within one prefix,
        entries never overlap (store rule + meet discipline), so
        combination is unambiguous. Returns null unless the union
        of entries covers the whole range. Values wider than 8
        bytes are unrepresentable in Bits and never enter memState,
        so larger loads fall back to image bytes, as before. */
    private Bits memLookup(Map<String, Bits> m, long addr, int size) {
        Bits r = memLookupPrefix(m, addr, size, "mem:");
        if (r != null) return r;
        return memLookupPrefix(m, addr, size, "gmem:");
    }

    private Bits memLookupPrefix(Map<String, Bits> m, long addr,
        int size, String pfx) {
        if (size <= 0 || size > 8) return null;
        long end = addr + size;
        long cov = 0;
        long ones = 0, zeroes = 0;
        for (Map.Entry<String, Bits> e : m.entrySet()) {
            String k = e.getKey();
            if (!k.startsWith(pfx)) continue;
            long[] as = parseMemKey(k);
            if (as == null) continue;
            long b = as[0], t = as[1];
            if (t <= 0 || t > 8) continue;
            long is = Math.max(addr, b), ie = Math.min(end, b + t);
            if (is >= ie) continue;
            Bits eb = e.getValue();
            for (long p = is; p < ie; p++) {
                long ej = p - b;
                long lb = p - addr;
                long srcShift = memBigEndian ? (t - 1 - ej) * 8 : ej * 8;
                long dstShift = memBigEndian ? (size - 1 - lb) * 8 : lb * 8;
                ones |= ((eb.ones >>> srcShift) & 0xffL) << dstShift;
                zeroes |= ((eb.zeroes >>> srcShift) & 0xffL) << dstShift;
                cov |= (1L << lb);
            }
        }
        if (cov != ((1L << size) - 1)) return null;
        return new Bits(ones, zeroes);
    }

    /** True when a LOAD/STORE address varnode is provably
        stack-derived: its def chain (COPY / INT_ADD / INT_SUB,
        bounded hops) reaches the stack-pointer or frame-pointer
        register. A register that is neither is followed through
        its def (it may be COPY(SP)); a constant, a memory cell,
        or a non-arithmetic def ends the walk as not-stack. The
        frame-pointer leg uses the same assumption as Prov's
        rbpSlotOf (RBP is the frame pointer, stable after the
        prologue); only unambiguous FP names (RBP/FP) enable it. */
    private boolean isStackAddr(List<OpRec> ops, Varnode v, int pos) {
        Varnode cur = v;
        for (int hop = 0; hop < 6; hop++) {
            if (cur == null) return false;
            if (cur.isConstant()) return false;
            if (cur.getAddress() != null) {
                String sp = cur.getAddress().getAddressSpace().getName();
                if (isa.registerSpaceName().equals(sp)) {
                    long off = cur.getOffset();
                    if (off == memSpOff) return true;
                    if (memFpOff >= 0 && off == memFpOff) return true;
                } else if (!"unique".equals(sp)) {
                    return false;
                }
            }
            int d = findDefWide(ops, vkey(cur), pos);
            if (d < 0) return false;
            OpRec dd = ops.get(d);
            if (dd.mnem.equals("COPY") && dd.ins.length == 1) {
                cur = dd.ins[0];
                pos = d;
                continue;
            }
            if ((dd.mnem.equals("INT_ADD") || dd.mnem.equals("INT_SUB")) &&
                dd.ins.length == 2) {
                Varnode next = null;
                for (int s = 0; s < 2; s++) {
                    if (!dd.ins[s].isConstant()) {
                        next = dd.ins[s];
                        break;
                    }
                }
                if (next == null) return false;
                cur = next;
                pos = d;
                continue;
            }
            return false;
        }
        return false;
    }

    /** One collected store for seed computation: val == null means
        the stored value was unknown or partial (not exact). */
    private static class MemStore {
        final long addr;
        final int size;
        final Long val;
        MemStore(long a, int s, Long v) { addr = a; size = s; val = v; }
    }

    private static class MemSeedResult {
        final Map<String, Bits> seeds = new HashMap<String, Bits>();
        int cells = 0;
        boolean hasUnknownStore = false;
        int blockedLeak = 0;
        int blockedConflict = 0;
        int nonConvergedFns = 0;
    }

    /** Scan a must-state's register values for leaked candidate
        addresses (used for unknown-convention calls, indirect
        calls, and returns: over-blocking is sound here). */
    private static void leakScanRegs(Map<String, Bits> st,
        Set<Long> candAddrs, Set<Long> leaked, String regSpace) {
        for (Map.Entry<String, Bits> e : st.entrySet()) {
            String k = e.getKey();
            if (!k.startsWith(regSpace + ":")) continue;
            String[] p = k.split(":");
            if (p.length != 3) continue;
            try {
                int sz = Integer.parseInt(p[2]);
                Long v = e.getValue().exactValue(sizeMask(sz));
                if (v != null && candAddrs.contains(v.longValue())) {
                    leaked.add(v.longValue());
                }
            } catch (Exception ex) {
                // Non-numeric key: not a register view.
            }
        }
    }

    /** Program-wide global-seed computation from the current
        fixpoints. See the Phase M header for the rule: a cell is
        seeded only when every overlapping store in the whole
        program targets exactly that cell with the same exact
        value, at least one such store exists, no unknown non-stack
        store exists anywhere, and the address never leaks (call
        argument, stored value, return register). */
    private MemSeedResult collectMemSeeds(List<FuncRec> funcRecs,
        Map<Long, FuncRec> funcByEntry) {
        MemSeedResult res = new MemSeedResult();
        List<MemStore> allStores = new ArrayList<MemStore>();
        // Pass A: stores + unknown-store flag. STORE ops cover
        // register-indirect stores (all ISAs); COPY-to-ram ops
        // cover absolute stores (x86-64 RIP-relative globals --
        // their address is exact by construction, so they never
        // set the unknown-store flag).
        for (FuncRec rec : funcRecs) {
            if (rec.fx == null || !rec.fx.converged) {
                res.nonConvergedFns++;
            }
            List<OpRec> ops = rec.or.ops;
            for (int i = 0; i < ops.size(); i++) {
                OpRec op = ops.get(i);
                boolean isCopyRam = op.mnem.equals("COPY") &&
                    op.ins.length == 1 && op.out != null &&
                    isRamSpace(op.out);
                boolean isStore = op.mnem.equals("STORE") &&
                    op.ins.length >= 3;
                if (!isCopyRam && !isStore) continue;
                if (isStore && op.addrIsStack) continue;
                Map<String, Bits> st = (rec.fx == null ||
                    rec.fx.inStates == null ||
                    i >= rec.fx.inStates.length) ? null : rec.fx.inStates[i];
                if (st == null) continue; // unreachable op: never executes
                long a;
                int sz;
                Bits vb;
                if (isCopyRam) {
                    a = op.out.getOffset();
                    sz = op.out.getSize();
                    vb = resolveBits(op.ins[0], st);
                } else {
                    Long addr = resolveAddressExact(op.ins[1], st);
                    if (addr == null) {
                        res.hasUnknownStore = true;
                        continue;
                    }
                    a = addr.longValue();
                    sz = op.ins[2].getSize();
                    vb = resolveBits(op.ins[2], st);
                }
                if (isa.isMmioAddress(a)) continue;
                Long exact = (sz > 0 && sz <= 8) ?
                    vb.exactValue(sizeMask(sz)) : null;
                allStores.add(new MemStore(a, sz, exact));
            }
        }
        // Candidate cells: distinct (addr, size) with >=1 store.
        Set<String> cells = new HashSet<String>();
        for (MemStore s : allStores) {
            cells.add(s.addr + ":" + s.size);
        }
        res.cells = cells.size();
        // For each cell: every overlapping store must target exactly
        // this cell with the same exact value.
        Map<String, Long> agreed = new HashMap<String, Long>();
        Set<Long> candAddrs = new HashSet<Long>();
        for (String key : cells) {
            String[] parts = key.split(":");
            long A = Long.parseLong(parts[0]);
            int S = Integer.parseInt(parts[1]);
            Long v = null;
            boolean ok = true;
            for (MemStore s : allStores) {
                if (s.addr < A + S && A < s.addr + s.size) {
                    if (s.addr != A || s.size != S || s.val == null) {
                        ok = false;
                        break;
                    }
                    if (v == null) v = s.val;
                    else if (!v.equals(s.val)) { ok = false; break; }
                }
            }
            if (ok && v != null) {
                agreed.put(key, v);
                candAddrs.add(A);
            } else {
                res.blockedConflict++;
            }
        }
        if (res.hasUnknownStore) {
            // No seed at all: an unknown store may alias any global.
            return res;
        }
        // Pass B: leaks. An address that escapes (call argument,
        // stored value, return register) can be written through
        // invisible paths, so it is never seeded.
        Set<Long> leaked = new HashSet<Long>();
        int ptrSize = isa.pointerSize();
        String regSpace = isa.registerSpaceName();
        for (FuncRec rec : funcRecs) {
            List<OpRec> ops = rec.or.ops;
            for (int i = 0; i < ops.size(); i++) {
                OpRec op = ops.get(i);
                Map<String, Bits> st = (rec.fx == null ||
                    rec.fx.inStates == null ||
                    i >= rec.fx.inStates.length) ? null : rec.fx.inStates[i];
                if (st == null) continue;
                if (op.mnem.equals("CALL") && op.ins.length >= 1) {
                    long[] argRegs = null;
                    Varnode t = op.ins[0];
                    if (t != null && t.getAddress() != null &&
                        "ram".equals(t.getAddress().getAddressSpace()
                            .getName())) {
                        FuncRec callee = funcByEntry.get(t.getOffset());
                        if (callee == null) callee = funcByEntry.get(
                            isa.stripInstructionTag(t.getOffset()));
                        if (callee != null) {
                            argRegs = isa.argumentRegisterOffsets(
                                callConvMap.get(callee.entryKey));
                        }
                    }
                    if (argRegs == null) {
                        leakScanRegs(st, candAddrs, leaked, regSpace);
                    } else {
                        for (long off : argRegs) {
                            Varnode vn = regVarnode(off, ptrSize);
                            if (vn == null) continue;
                            Long v = resolveAddressExact(vn, st);
                            if (v != null &&
                                candAddrs.contains(v.longValue())) {
                                leaked.add(v.longValue());
                            }
                        }
                    }
                } else if (op.mnem.equals("CALLIND")) {
                    leakScanRegs(st, candAddrs, leaked, regSpace);
                } else if (op.mnem.equals("STORE") && op.ins.length >= 3) {
                    Long v = resolveAddressExact(op.ins[2], st);
                    if (v != null && candAddrs.contains(v.longValue())) {
                        leaked.add(v.longValue());
                    }
                } else if (op.mnem.equals("COPY") && op.ins.length == 1 &&
                    op.out != null && isRamSpace(op.out)) {
                    // COPY-to-ram store of a candidate address
                    // leaks it (storing &global into another
                    // global is an escape, same as a STORE).
                    Long v = resolveAddressExact(op.ins[0], st);
                    if (v != null && candAddrs.contains(v.longValue())) {
                        leaked.add(v.longValue());
                    }
                } else if (op.mnem.equals("RETURN")) {
                    leakScanRegs(st, candAddrs, leaked, regSpace);
                }
            }
        }
        for (Map.Entry<String, Long> e : agreed.entrySet()) {
            String[] parts = e.getKey().split(":");
            long A = Long.parseLong(parts[0]);
            int S = Integer.parseInt(parts[1]);
            if (leaked.contains(A)) {
                res.blockedLeak++;
                continue;
            }
            res.seeds.put(gmemKey(A, S),
                Bits.exact(e.getValue().longValue(), sizeMask(S)));
        }
        return res;
    }

    // ---------------- v3.15 bounds (computed-pointer copy) analysis ----
    // One CFG must-fixpoint provenance scan per function over its
    // P-Code ops (same successor rules as the value fixpoint, via
    // buildSucc; a register keeps provenance only if EVERY
    // predecessor agrees). It tracks a small symbolic expression per register /
    // unique varnode, seeded at function entry with ARG tokens for the
    // ISA's argument registers (ARM AAPCS r0-r3, RISC-V a0-a7, MIPS
    // a0-a3; x86-64 needs a known convention and x86-32 passes args on
    // the stack, so both yield no sites -- see design.md §5).
    //   COPY propagates; INT_ADD folds constants (ADD(CONST,CONST) and
    //   ADD(x,CONST 0)); LOAD through ADD(ptr,CONST off) yields
    //   FIELD(ptr,off); INT_ZEXT/SEXT yields EXT(inner,size); CALL and
    //   CALLIND kill the ISA's caller-saved registers; every other op
    //   result is TOP. Memory is NOT tracked: a value spilled to the
    //   stack and reloaded comes back TOP, so the scan can miss a site
    //   (false negative) but cannot invent provenance it never saw.
    // A copy site is a direct CALL (or tail BRANCH) to a function named
    // memcpy/memmove where the dst or src argument register holds
    // ADD(FIELD(structPtr,baseOff), ARG(n)) at the call. Bounds
    // Phase 1 extends the site set (same scan, same guards): DMA
    // sites (any callee that programs a computed-pointer argument
    // into a constant address, role "dma") and command-address
    // sites (any callee that programs a bare ARG|ROOT offset into
    // a constant address or uses it as a store address, role
    // "cmdaddr"), plus inter-procedural caller validation
    // (a flagged site is suppressed with guard "caller-check"
    // when every known direct caller validates the same
    // (base, offset, size) triple). The site is
    // FLAGGED iff the same function also contains, before the call,
    // the unsound check shape -- an unsigned INT_LESS/INT_LESSEQUAL
    // between ADD(ARG(n),X) and FIELD(structPtr,sizeOff) -- and no
    // sound guard: no signed INT_SLESS/INT_SLESSEQUAL between ARG(n)
    // and CONST 0, no wide (ZEXT/SEXT past pointer size) check of the
    // same offset against the same struct's field, no guard-call
    // (a direct CALL before the copy to a function that itself
    // contains a signed ARG-vs-0 comparison, with a CBRANCH between
    // that call and the copy), and no multi-word compare guard
    // (bounds v3: low-word unsigned compare + SBCS with carry +
    // carry-tested branch gating the transfer -- see
    // boundsMultiwordGuard). Guard detection is deliberately
    // over-approximate (any candidate signed check suppresses), so a
    // FLAGGED site means not even a candidate sound guard exists in
    // the function. Sites with a computed pointer but no unsound
    // check are still emitted (flagged=false) for audit; the Lean
    // verdict only counts flagged sites. Guard/check search is in
    // listing order (a superset of path order -- over-approximate
    // suppression, the safe direction for FAIL); provenance itself
    // is CFG-correct via the must-fixpoint.

    /** Symbolic provenance expression for the bounds scan. */
    private static class BExpr {
        // TOP, ARG, CONST, FIELD, ADD, SUB, ZEXT, SEXT, ROOT (v3.16:
        // ARG(n) plus unknown loop accumulation -- produced ONLY
        // by the must-join of a value that IS ARG(n)/ROOT(n) with
        // a value containing ARG(n); see containsArgRoot. A path
        // with exactly ARG(n) reaches the join, so the v1 escape
        // argument still holds.)
        final String kind;
        final int argIdx;
        final long constVal;
        final BExpr base; // FIELD base, EXT inner, ADD/SUB left
        final BExpr other; // ADD/SUB right
        final long off; // FIELD offset
        final int extSize; // ZEXT/SEXT output size
        private BExpr(String k, int a, long c, BExpr b, BExpr o,
            long f, int e) {
            kind = k; argIdx = a; constVal = c; base = b; other = o;
            off = f; extSize = e;
        }
        static final BExpr TOP = new BExpr("TOP", -1, 0, null, null, 0, 0);
        static BExpr arg(int i) {
            return new BExpr("ARG", i, 0, null, null, 0, 0);
        }
        static BExpr root(int i) {
            return new BExpr("ROOT", i, 0, null, null, 0, 0);
        }
        static BExpr cnst(long v) {
            return new BExpr("CONST", -1, v, null, null, 0, 0);
        }
        static BExpr field(BExpr b, long o) {
            return new BExpr("FIELD", -1, 0, b, null, o, 0);
        }
        static BExpr add(BExpr l, BExpr r) {
            // ROOT absorption, except across a FIELD: a FIELD
            // addend turns the sum into a POINTER (base + offset
            // -- the site shape), not an offset, so collapsing it
            // to ROOT would hide the base field from the site
            // matcher. Any non-FIELD addend is accumulation, so
            // ADD(ROOT, accumulation) stays ROOT (offset-like).
            if (l.kind.equals("ROOT") && !r.kind.equals("FIELD")) {
                return l;
            }
            if (r.kind.equals("ROOT") && !l.kind.equals("FIELD")) {
                return r;
            }
            // Preserve ADD(ARG, unknown): the join needs to see
            // the ARG root through an unknown accumulation (the
            // loop-carried offset case: offset += chunk_len with
            // chunk_len unknown). The site matcher still requires
            // ARG or ROOT as the offset side, so a straight-line
            // ADD(ARG, TOP) never matches a site by itself.
            if ((l.kind.equals("ARG") && r == TOP) ||
                (r.kind.equals("ARG") && l == TOP)) {
                return new BExpr("ADD", -1, 0, l, r, 0, 0);
            }
            if (l == TOP || r == TOP) return TOP;
            if (l.kind.equals("CONST") && r.kind.equals("CONST")) {
                return cnst(l.constVal + r.constVal);
            }
            if (l.kind.equals("CONST") && l.constVal == 0) return r;
            if (r.kind.equals("CONST") && r.constVal == 0) return l;
            return new BExpr("ADD", -1, 0, l, r, 0, 0);
        }
        static BExpr sub(BExpr l, BExpr r) {
            if (l == TOP || r == TOP) return TOP;
            if (l.kind.equals("ROOT")) return l;
            if (l.kind.equals("CONST") && r.kind.equals("CONST")) {
                return cnst(l.constVal - r.constVal);
            }
            // x - 0 == x (Ghidra lowers cmp r, #0 to SUB(r, 0)
            // followed by SLESS on the difference, so without this
            // fold a plain `cmp offset, #0` would not match ARG).
            if (r.kind.equals("CONST") && r.constVal == 0) return l;
            return new BExpr("SUB", -1, 0, l, r, 0, 0);
        }
        static BExpr ext(BExpr in, int sz, boolean zero) {
            if (in == TOP) return TOP;
            // ZEXT and SEXT are distinct kinds (v3 refinement):
            // only zero-extension is a sound wide guard; a
            // sign-extending widening alone leaves small
            // negatives unchecked, same as the ASR lowering.
            return new BExpr(zero ? "ZEXT" : "SEXT",
                -1, 0, in, null, 0, sz);
        }
        String key() {
            if (kind.equals("TOP")) return "TOP";
            if (kind.equals("ARG")) return "A" + argIdx;
            if (kind.equals("ROOT")) return "R" + argIdx;
            if (kind.equals("CONST")) return "C" + constVal;
            if (kind.equals("FIELD")) {
                return "F(" + base.key() + "," + off + ")";
            }
            if (kind.equals("ZEXT") || kind.equals("SEXT")) {
                return kind + "(" + base.key() + "," + extSize + ")";
            }
            return kind + "(" + base.key() + "," + other.key() + ")";
        }
        @Override public boolean equals(Object o) {
            return o instanceof BExpr && key().equals(((BExpr) o).key());
        }
        @Override public int hashCode() { return key().hashCode(); }
        /** True iff this expression is ADD(offsetArg, anything). */
        BExpr addOtherSide(BExpr offsetArg) {
            if (!kind.equals("ADD")) return null;
            if (base.equals(offsetArg)) return other;
            if (other.equals(offsetArg)) return base;
            return null;
        }
        /** True iff this expression contains ZEXT(offsetArg)
            wider than pointer size (a 64-bit-style range check
            operand). SEXT does NOT count (v3 refinement): a
            sign-extending widening alone does not reject
            negative offsets, so it is not a sound wide guard.
            A ROOT base counts: a widened loop-carried offset is
            still the same argument's guard. */
        boolean containsWideExt(BExpr offsetArg, int ptrSize) {
            if (kind.equals("ZEXT")) {
                return (base.equals(offsetArg) ||
                    (base.kind.equals("ROOT") &&
                     base.argIdx == offsetArg.argIdx)) &&
                    extSize > ptrSize;
            }
            if (kind.equals("ADD") || kind.equals("SUB")) {
                return base.containsWideExt(offsetArg, ptrSize) ||
                    other.containsWideExt(offsetArg, ptrSize);
            }
            return false;
        }
    }

    /** One comparison op seen by the bounds scan, with operand
        provenance as of that op. */
    private static class BoundsCmp {
        final int idx;
        final String mnem;
        final BExpr a;
        final BExpr b;
        BoundsCmp(int i, String m, BExpr x, BExpr y) {
            idx = i; mnem = m; a = x; b = y;
        }
        boolean isUnsigned() {
            return mnem.equals("INT_LESS") ||
                mnem.equals("INT_LESSEQUAL");
        }
        boolean isSigned() {
            return mnem.equals("INT_SLESS") ||
                mnem.equals("INT_SLESSEQUAL");
        }
    }

    /** One direct CALL seen by the bounds scan (guard-call search). */
    private static class BoundsCall {
        final int idx;
        final long entry;
        BoundsCall(int i, long e) { idx = i; entry = e; }
    }

    /** One emitted copy site: JSON text + flagged bit. */
    private static class BoundsSiteRec {
        final String json;
        final boolean flagged;
        BoundsSiteRec(String j, boolean f) { json = j; flagged = f; }
    }

    /** Result of evaluating one site's check/guard evidence
        (bounds Phase 1 refactor: the memcpy/cache block, the DMA
        block and the cmdaddr block all share this evaluation, so
        guard semantics cannot drift between site kinds).
        checkFieldBase is the FIELD base of the matched unsound
        check (for pointer sites it equals the pointer's struct
        base by construction; for cmdaddr sites it is the only
        struct base in evidence). */
    private static class BoundsEval {
        boolean unsound = false;
        long sizeOff = -1;
        String guard = "none";
        BExpr checkFieldBase = null;
    }

    /** One direct call edge out of a scanned function (bounds
        Phase 1, item 3): the call op index, the callee entry key,
        and the provenance of every argument slot at the call
        (before the call clobber). Recorded for every resolved
        direct CALL/BRANCH, transfer or not. */
    private static class BoundsCallEdge {
        final int idx;
        final long entry;
        final BExpr[] slotProv;
        BoundsCallEdge(int i, long e, BExpr[] s) {
            idx = i; entry = e; slotProv = s;
        }
    }

    /** Callee-side register-programming evidence (bounds Phase 1,
        items 1-2): which argument slots the callee stores to a
        constant address (valueProg), uses as a store address
        (addrProg), and re-derives as ADD(FIELD, slot) (baseOff).
        Computed by a linear listing-order walk, so it is
        over-approximate (see boundsCalleeProg). */
    private static class BoundsCalleeProg {
        final java.util.Set<Integer> valueProg =
            new java.util.HashSet<Integer>();
        final java.util.Set<Integer> addrProg =
            new java.util.HashSet<Integer>();
        // Bounds Phase 1 fix (length-site false flags): a slot
        // whose value is stored BARE into a fixed address (e.g. a
        // DMA length, or any config value) is not address
        // programming. addrForm marks slots whose stored value is
        // an ADD combining the slot with a FIELD or CONST base
        // (base+offset re-derivation, or constant-base + offset)
        // — the value shape that proves the slot is an address
        // component, not a length/config value.
        final java.util.Set<Integer> addrForm =
            new java.util.HashSet<Integer>();
        final Map<Integer, Long> baseOff =
            new HashMap<Integer, Long>();
    }

    /** Per-function caller-validation record (bounds Phase 1,
        item 3), built by the pre-pass scan: signed-checked
        argument indices (ARG or ROOT vs CONST 0), the function's
        full compare list (for wide/multiword evaluation at
        suppression time), its ops + branch targets (for group-map
        rebuild), its outgoing call edges, and its pointer size. */
    private static class BoundsValid {
        final java.util.Set<Integer> signedArgs =
            new java.util.HashSet<Integer>();
        // Bounds Phase 1, cmdaddr pointer-use gate: argument
        // slots this function dereferences (load/store address
        // base positions), from the pre-pass scan. A slot in
        // these sets is a POINTER, not an offset integer.
        final java.util.Set<Integer> derefArgs =
            new java.util.HashSet<Integer>();
        final java.util.Set<Integer> derefRoots =
            new java.util.HashSet<Integer>();
        List<BoundsCmp> cmps = null;
        List<OpRec> ops = null;
        Map<Integer, List<Integer>> branchTargets = null;
        List<BoundsCallEdge> edges = null;
        int ptrSize = 4;
    }

    /** Instruction-group maps for the multi-word guard matcher
        (bounds Phase 1 refactor: shared by boundsScan's own walk
        and by caller-side multiword evaluation). */
    private static class BoundsGroups {
        int[] opGroup = new int[0];
        List<Integer> grpStarts = new ArrayList<Integer>();
        Map<String, Integer> addrToGroup =
            new HashMap<String, Integer>();
        List<List<Integer>> grpSucc = null;
    }

    /** Result of one bounds scan: comparison events, copy sites, and
        whether the function contains a signed ARG-vs-0 comparison
        (the guard-call pre-pass reads only this last field). */
    private static class BoundsScan {
        final List<BoundsCmp> cmps = new ArrayList<BoundsCmp>();
        final List<BoundsSiteRec> sites = new ArrayList<BoundsSiteRec>();
        boolean hasSignedArgCheck = false;
        // Bounds Phase 1, item 3: signed-checked argument indices
        // (ARG or ROOT vs CONST 0), outgoing direct-call edges,
        // and pointer size, for the pre-pass validation records.
        final java.util.Set<Integer> signedArgs =
            new java.util.HashSet<Integer>();
        final List<BoundsCallEdge> edges =
            new ArrayList<BoundsCallEdge>();
        int ptrSize = 4;
        // Bounds Phase 1, cmdaddr pointer-use gate: slots this
        // function dereferences (see BoundsValid above).
        final java.util.Set<Integer> derefArgs =
            new java.util.HashSet<Integer>();
        final java.util.Set<Integer> derefRoots =
            new java.util.HashSet<Integer>();
        // Transfer-call form census (v3.16): key "kind:form" per
        // pointer argument, plus the transfer-call count. Only
        // the main pass reads these (the pre-pass ignores them).
        final Map<String, Integer> formCounts =
            new HashMap<String, Integer>();
        int transferCalls = 0;
    }

    /** Provenance of one varnode under the bounds scan. Constants
        fold; ram-space (global) and unknown varnodes are TOP. */
    private BExpr boundsProvOf(Varnode v, Map<String, BExpr> prov) {
        if (v == null) return BExpr.TOP;
        try {
            if (v.isConstant()) return BExpr.cnst(v.getOffset());
        } catch (Exception e) {
            return BExpr.TOP;
        }
        String space;
        try {
            space = v.getAddress().getAddressSpace().getName();
        } catch (Exception e) {
            return BExpr.TOP;
        }
        if (!space.equals("register") && !space.equals("unique")) {
            return BExpr.TOP;
        }
        BExpr p = prov.get(space + ":" + v.getOffset());
        return p == null ? BExpr.TOP : p;
    }

    private void boundsPut(Varnode v, BExpr p, Map<String, BExpr> prov) {
        if (v == null) return;
        String space;
        try {
            space = v.getAddress().getAddressSpace().getName();
        } catch (Exception e) {
            return;
        }
        if (!space.equals("register") && !space.equals("unique")) return;
        String k = space + ":" + v.getOffset();
        if (p == BExpr.TOP) prov.remove(k);
        else prov.put(k, p);
    }

    /** Argument-register offsets for one function: the ISA's
        argument registers under the function's own calling
        convention (null/empty = unmodelled: no sites, no guard). */
    private long[] boundsArgOffsets(FuncRec rec) {
        try {
            String conv = callConvMap.get(rec.entryKey);
            if (conv == null) {
                conv = callConvMap.get(
                    isa.stripInstructionTag(rec.entryKey));
            }
            return isa.argumentRegisterOffsets(conv);
        } catch (Exception e) {
            return null;
        }
    }

    /** Transfer for one bounds-scan op: a copy of the incoming
        provenance map with this op's effect applied. COPY propagates,
        INT_ADD folds constants, LOAD through ADD(ptr, const) yields
        FIELD(ptr, const), INT_ZEXT/SEXT yields EXT(inner, size),
        CALL/CALLIND kill the ISA's caller-saved registers, and every
        other op result is TOP. When stripUniques is true (first op
        of an instruction), unique-space temporaries are dropped
        first: they are local to one instruction (same rule as the
        value fixpoint), so a stale unique from a predecessor
        instruction must never be readable here. */
    /** True iff e is, or additively contains, argument n (ARG,
        ROOT, or an ADD chain with n as a term). Used only by the
        must-join: joining a value that IS ARG(n)/ROOT(n) with a
        value containing ARG(n) yields ROOT(n), because a path
        carrying exactly ARG(n) reaches the join (entry edge of a
        loop, or the untouched branch), so the v1 escape argument
        still holds for the rooted form. Values with no exact-ARG
        path (two ADD-chains, a constant, another argument) do
        NOT merge -- they drop, as before. */
    private boolean containsArgRoot(BExpr e, int n) {
        if (e == null) return false;
        if (e.kind.equals("ARG") || e.kind.equals("ROOT")) {
            return e.argIdx == n;
        }
        if (e.kind.equals("ADD")) {
            return containsArgRoot(e.base, n) ||
                containsArgRoot(e.other, n);
        }
        return false;
    }

    /** True iff e is offset argument n itself (ARG) or its
        loop-carried rooted form (ROOT) -- guards written against
        the entry value match both. */
    private boolean boundsIsOffset(BExpr e, int n) {
        return e != null && ((e.kind.equals("ARG") ||
            e.kind.equals("ROOT")) && e.argIdx == n);
    }

    /** Cache-range calls: range operations on a pointer+length,
        the transfer generalisation of memcpy/memmove (v3.16).
        Explicit name set -- no pattern guessing. DMA reload
        calls are NOT in the set: their arguments carry no
        computed pointer in the CVE case (source = caller buffer,
        dest = controller register), and DMA names are
        driver-specific, so no canonical set exists. DMA transfers
        are instead covered since Phase 1 by the structural
        callee-programming rule (see boundsCalleeProg), with no
        name set at all. */
    private boolean isBoundsCacheCall(String name) {
        return name.equals("arch_dcache_invd_range") ||
            name.equals("arch_dcache_flush_range") ||
            name.equals("arch_dcache_clean_range") ||
            name.equals("sys_cache_data_invd_range") ||
            name.equals("sys_cache_data_flush_range") ||
            name.equals("sys_cache_instr_invd_range");
    }

    private boolean isBoundsTransferCall(String name) {
        return name.equals("memcpy") || name.equals("memmove") ||
            isBoundsCacheCall(name);
    }

    /** Pointer-form census class for one transfer-call argument:
        site = ADD(FIELD, ARG|ROOT) (matches a site); plain_arg,
        field_only, const, top, other = everything else. */
    private String boundsFormOf(BExpr p) {
        if (p == null) return "top";
        if (p.kind.equals("ADD") &&
            ((p.base.kind.equals("FIELD") &&
              (p.other.kind.equals("ARG") ||
               p.other.kind.equals("ROOT"))) ||
             (p.other.kind.equals("FIELD") &&
              (p.base.kind.equals("ARG") ||
               p.base.kind.equals("ROOT"))))) {
            return "site";
        }
        if (p.kind.equals("ARG")) return "plain_arg";
        if (p.kind.equals("FIELD")) return "field_only";
        if (p.kind.equals("CONST")) return "const";
        if (p.kind.equals("TOP")) return "top";
        return "other";
    }

    /** True iff BExpr e contains ARG(p) or ROOT(p) as a VALUE
        contribution (ADD/SUB term, direct, or ZEXT/SEXT inner).
        A FIELD base does NOT count: a callee that merely loads a
        field through slot p (e.g. storing d->base + off, where
        slot 0 is the struct pointer) is programming the OFFSET
        (slot 1), not the struct pointer — counting FIELD bases
        would emit a noise site for every struct-pointer slot of
        every register-programming helper. Distinct from
        containsArgRoot (the must-join predicate). */
    private boolean boundsContainsArg(BExpr e, int p) {
        if (e == null) return false;
        if (e.kind.equals("ARG") || e.kind.equals("ROOT")) {
            return e.argIdx == p;
        }
        if (e.kind.equals("ADD") || e.kind.equals("SUB")) {
            return boundsContainsArg(e.base, p) ||
                boundsContainsArg(e.other, p);
        }
        if (e.kind.equals("ZEXT") || e.kind.equals("SEXT")) {
            return boundsContainsArg(e.base, p);
        }
        return false;
    }

    /** Slots appearing in BASE positions of a BExpr address
        (bounds Phase 1, cmdaddr pointer-use gate): a direct
        ARG/ROOT, a FIELD base, an ADD/SUB base, or an EXT inner.
        The OFFSET side of an ADD/SUB is deliberately NOT
        traversed: buf[off] uses off as an integer index, and
        marking it pointer-like would block true cmdaddr sites
        whose offset also indexes a buffer. */
    private void boundsBaseSlots(BExpr e,
        java.util.Set<String> out) {
        if (e == null) return;
        if (e.kind.equals("ARG") || e.kind.equals("ROOT")) {
            out.add(e.kind + ":" + e.argIdx);
            return;
        }
        if (e.kind.equals("FIELD")) {
            boundsBaseSlots(e.base, out);
            return;
        }
        if (e.kind.equals("ADD") || e.kind.equals("SUB")) {
            boundsBaseSlots(e.base, out);
            return;
        }
        if (e.kind.equals("ZEXT") || e.kind.equals("SEXT")) {
            boundsBaseSlots(e.base, out);
            return;
        }
    }

    /** Callee-side register-programming walk (bounds Phase 1,
        items 1-2). Seeds the callee's argument registers with
        ARG(i) and walks its ops once in listing order (uniques
        stripped at each instruction start, CALL/CALLIND clobber
        via boundsTransfer). At each STORE (ins[1] = address,
        ins[2] = value): a FIXED address with a value containing
        ARG(p) marks valueProg(p); an address containing ARG(p)
        marks addrProg(p); a value of shape ADD(FIELD, ARG|ROOT(p))
        records baseOff(p) = the FIELD offset. "Fixed" means
        CONST provenance OR fixed-base provenance (see below).
        Fixed-base tracking: real peripheral code (and the
        synthetic corpus) reaches register addresses through
        literal-pool loads, which Ghidra lifts as COPY from a ram
        varnode (the pool slot) — provenance TOP, since the main
        scan does not track memory. A register COPY'd from a ram
        varnode is therefore tracked as fixed-base, and
        ADD/SUB(fixed-base, CONST) stays fixed-base, mirroring
        the provenance walk (uniques tracked within a group,
        caller-saved cleared on CALL/CALLIND, LOAD clears). This
        deliberately conflates pool-loaded peripheral bases with
        pool-loaded global addresses (both are link-time
        constants; the walk cannot tell a global from a register):
        a helper storing an argument into a global also counts as
        programming. That over-approx is bounded by the
        caller-side unsound-only shape (a flag still needs it)
        and measured by the regression (new flagged sites on real
        targets would be the signal). NOT a fixpoint: values can
        leak across branches, so the result is over-approximate
        (adds candidates, never removes a true one). Returns an
        empty program when the callee has no ops or no modelled
        convention. */
    private BoundsCalleeProg boundsCalleeProg(FuncRec calleeRec,
        long[] calleeArgOffs) {
        BoundsCalleeProg prog = new BoundsCalleeProg();
        if (calleeRec == null || calleeRec.or == null ||
            calleeRec.or.ops == null || calleeArgOffs == null ||
            calleeArgOffs.length < 1) {
            return prog;
        }
        List<OpRec> cops = calleeRec.or.ops;
        Map<String, BExpr> working = new HashMap<String, BExpr>();
        Map<String, Boolean> fixed = new HashMap<String, Boolean>();
        for (int k = 0; k < calleeArgOffs.length; k++) {
            working.put("register:" + calleeArgOffs[k],
                BExpr.arg(k));
        }
        long[] saved = null;
        try {
            saved = isa.callerSavedRegisterOffsets();
        } catch (Exception e) {
            saved = null;
        }
        for (int i = 0; i < cops.size(); i++) {
            OpRec op = cops.get(i);
            boolean isStart = i == 0 ||
                !op.instrAddr.equals(cops.get(i - 1).instrAddr);
            if (isStart) {
                java.util.Iterator<String> it =
                    working.keySet().iterator();
                while (it.hasNext()) {
                    if (it.next().startsWith("unique:")) {
                        it.remove();
                    }
                }
                java.util.Iterator<String> fit =
                    fixed.keySet().iterator();
                while (fit.hasNext()) {
                    if (fit.next().startsWith("unique:")) {
                        fit.remove();
                    }
                }
            }
            if (op.mnem.equals("STORE") && op.ins.length >= 3) {
                BExpr addr = boundsProvOf(op.ins[1], working);
                BExpr val = boundsProvOf(op.ins[2], working);
                boolean addrFixed = addr.kind.equals("CONST") ||
                    Boolean.TRUE.equals(
                        fixed.get(boundsVnKey(op.ins[1])));
                for (int p = 0; p < calleeArgOffs.length; p++) {
                    if (addrFixed &&
                        boundsContainsArg(val, p)) {
                        prog.valueProg.add(p);
                        if (val.kind.equals("ADD")) {
                            BExpr f = null;
                            BExpr o = null;
                            if (val.base.kind.equals("FIELD") &&
                                (val.other.kind.equals("ARG") ||
                                 val.other.kind.equals("ROOT")) &&
                                val.other.argIdx == p) {
                                f = val.base; o = val.other;
                            } else if (val.other.kind.equals("FIELD") &&
                                (val.base.kind.equals("ARG") ||
                                 val.base.kind.equals("ROOT")) &&
                                val.base.argIdx == p) {
                                f = val.other; o = val.base;
                            }
                            if (f != null && o != null &&
                                !prog.baseOff.containsKey(p)) {
                                prog.baseOff.put(p, f.off);
                            }
                            // Address-derivation shape: the slot
                            // is ADD-combined with a FIELD or
                            // CONST base (bare stores do not
                            // qualify — see addrForm).
                            boolean argBase =
                                (val.base.kind.equals("ARG") ||
                                 val.base.kind.equals("ROOT")) &&
                                val.base.argIdx == p;
                            boolean argOther =
                                (val.other.kind.equals("ARG") ||
                                 val.other.kind.equals("ROOT")) &&
                                val.other.argIdx == p;
                            boolean baseFieldOrConst =
                                val.base.kind.equals("FIELD") ||
                                val.base.kind.equals("CONST");
                            boolean otherFieldOrConst =
                                val.other.kind.equals("FIELD") ||
                                val.other.kind.equals("CONST");
                            if ((argBase && otherFieldOrConst) ||
                                (argOther && baseFieldOrConst)) {
                                prog.addrForm.add(p);
                            }
                        }
                    }
                    if (boundsContainsArg(addr, p)) {
                        prog.addrProg.add(p);
                    }
                }
            }
            // Fixed-base update for this op, from pre-op state
            // (STORE ops have no out, so this is a no-op for
            // them; evaluation above already used pre-op state).
            if (op.out != null) {
                String outKey = boundsVnKey(op.out);
                boolean outFixed = false;
                if (op.mnem.equals("COPY") && op.ins.length == 1) {
                    try {
                        String sp = op.ins[0].getAddress()
                            .getAddressSpace().getName();
                        if (sp.equals("ram")) {
                            outFixed = true;
                        } else {
                            outFixed = Boolean.TRUE.equals(fixed.get(
                                boundsVnKey(op.ins[0])));
                        }
                    } catch (Exception e) {
                        outFixed = false;
                    }
                } else if ((op.mnem.equals("INT_ADD") ||
                    op.mnem.equals("INT_SUB")) &&
                    op.ins.length == 2) {
                    BExpr p0 = boundsProvOf(op.ins[0], working);
                    BExpr p1 = boundsProvOf(op.ins[1], working);
                    boolean f0 = Boolean.TRUE.equals(fixed.get(
                        boundsVnKey(op.ins[0])));
                    boolean f1 = Boolean.TRUE.equals(fixed.get(
                        boundsVnKey(op.ins[1])));
                    outFixed = (f0 && p1.kind.equals("CONST")) ||
                        (f1 && p0.kind.equals("CONST"));
                }
                if (outFixed) fixed.put(outKey, Boolean.TRUE);
                else fixed.remove(outKey);
            }
            if ((op.mnem.equals("CALL") ||
                op.mnem.equals("CALLIND")) && saved != null) {
                for (long ro : saved) {
                    String pfx = "register:" + ro + ":";
                    java.util.Iterator<String> cit =
                        fixed.keySet().iterator();
                    while (cit.hasNext()) {
                        if (cit.next().startsWith(pfx)) {
                            cit.remove();
                        }
                    }
                }
            }
            working = boundsTransfer(working, op, saved, false);
        }
        return prog;
    }

    /** Instruction-group maps from an op list + op successors
        (bounds Phase 1 refactor of the inline construction in
        boundsScan; identical semantics: group = one machine
        instruction, successors mapped to groups). */
    private BoundsGroups boundsGroupMaps(List<OpRec> ops,
        List<List<Integer>> succ) {
        BoundsGroups bg = new BoundsGroups();
        int n = ops.size();
        bg.opGroup = new int[n];
        for (int i = 0; i < n; i++) {
            boolean isStart = i == 0 ||
                !ops.get(i).instrAddr.equals(
                    ops.get(i - 1).instrAddr);
            if (isStart) bg.grpStarts.add(i);
            bg.opGroup[i] = bg.grpStarts.size() - 1;
        }
        for (int g = 0; g < bg.grpStarts.size(); g++) {
            bg.addrToGroup.put(
                ops.get(bg.grpStarts.get(g)).instrAddr.toString(),
                g);
        }
        if (succ != null) {
            bg.grpSucc = new ArrayList<List<Integer>>();
            for (int g = 0; g < bg.grpStarts.size(); g++) {
                bg.grpSucc.add(new ArrayList<Integer>());
            }
            for (int g = 0; g < bg.grpStarts.size(); g++) {
                int gs = bg.grpStarts.get(g);
                int ge = (g + 1 < bg.grpStarts.size()) ?
                    bg.grpStarts.get(g + 1) : n;
                java.util.Set<Integer> ss =
                    new java.util.HashSet<Integer>();
                for (int i = gs; i < ge; i++) {
                    for (int s : succ.get(i)) {
                        if (s >= 0 && s < n) ss.add(bg.opGroup[s]);
                    }
                }
                bg.grpSucc.get(g).addAll(ss);
            }
        }
        return bg;
    }

    /** Shared check/guard evaluation for one site (bounds Phase 1
        refactor of the previously inline memcpy/cache block;
        semantics verbatim: unsound = unsigned ADD(offset,X-known)
        vs same-struct FIELD; guards in order signed, wide (ZEXT
        only), guard-call, multi-word; multiword sizeOff -1 means
        any size field, >= 0 requires the matched FIELD offset). */
    private BoundsEval boundsEvalSite(List<BoundsCmp> cmps,
        List<BoundsCall> calls, List<Integer> cbranchIdx,
        Map<Long, Boolean> signedCheckByEntry, List<OpRec> ops,
        int[] opGroup, List<Integer> grpStarts,
        List<List<Integer>> grpSucc,
        Map<String, Integer> addrToGroup, int callOpIdx,
        int offIdx, BExpr structBase, int ptrSize) {
        BoundsEval ev = new BoundsEval();
        BExpr offRef = BExpr.arg(offIdx);
        // structBase == null (cmdaddr sites: no pointer FIELD in
        // the call) means ANY FIELD base qualifies for the unsound
        // check; the matched FIELD's base then becomes the guard
        // base below. Pointer sites always pass a non-null base,
        // so their behaviour is unchanged.
        for (BoundsCmp c : cmps) {
            if (!c.isUnsigned()) continue;
            BExpr fld = null;
            BExpr otherSide = c.a.addOtherSide(offRef);
            if (otherSide != null &&
                !otherSide.kind.equals("TOP") &&
                c.b.kind.equals("FIELD") &&
                (structBase == null ||
                 c.b.base.equals(structBase))) {
                fld = c.b;
            } else if ((otherSide =
                c.b.addOtherSide(offRef)) != null &&
                !otherSide.kind.equals("TOP") &&
                c.a.kind.equals("FIELD") &&
                (structBase == null ||
                 c.a.base.equals(structBase))) {
                fld = c.a;
            }
            if (fld != null) {
                ev.unsound = true;
                ev.sizeOff = fld.off;
                ev.checkFieldBase = fld.base;
                break;
            }
        }
        BExpr guardBase =
            structBase != null ? structBase : ev.checkFieldBase;
        String guard = "none";
        for (BoundsCmp c : cmps) {
            if (!c.isSigned()) continue;
            if ((boundsIsOffset(c.a, offIdx) &&
                c.b.kind.equals("CONST") &&
                c.b.constVal == 0) ||
                (boundsIsOffset(c.b, offIdx) &&
                    c.a.kind.equals("CONST") &&
                    c.a.constVal == 0)) {
                guard = "signed-check";
                break;
            }
        }
        if (guard.equals("none")) {
            for (BoundsCmp c : cmps) {
                if (!c.isUnsigned()) continue;
                boolean wide = false;
                if (c.a.containsWideExt(offRef, ptrSize) &&
                    c.b.kind.equals("FIELD") &&
                    c.b.base.equals(guardBase)) {
                    wide = true;
                } else if (c.b.containsWideExt(offRef,
                    ptrSize) && c.a.kind.equals("FIELD") &&
                    c.a.base.equals(guardBase)) {
                    wide = true;
                }
                if (wide) {
                    guard = "wide-check";
                    break;
                }
            }
        }
        if (guard.equals("none") &&
            signedCheckByEntry != null) {
            for (BoundsCall gc : calls) {
                Boolean sc =
                    signedCheckByEntry.get(gc.entry);
                if (sc == null || !sc) continue;
                for (int cb : cbranchIdx) {
                    if (cb > gc.idx && cb < callOpIdx) {
                        guard = "guard-call";
                        break;
                    }
                }
                if (!guard.equals("none")) break;
            }
        }
        if (guard.equals("none") &&
            signedCheckByEntry != null) {
            String mw = boundsMultiwordGuard(cmps,
                ops, opGroup, grpStarts, grpSucc,
                addrToGroup, opGroup[callOpIdx], offIdx,
                guardBase, -1);
            if (mw != null) guard = mw;
        }
        ev.guard = guard;
        return ev;
    }

    /** One call edge's validation of one callee site (bounds
        Phase 1, item 3): the value passed in the site's offset
        slot must be the caller's own argument m (value flow),
        and the caller must hold a sound guard for m — signed
        (struct-independent), or wide-EXT / multi-word against
        the same size field (sizeOff) and the same struct value
        (mapped = the value passed in the site's struct slot).
        Wide/multi-word are skipped when the size is unknown or
        the struct base is not a plain ARG slot (signed still
        applies). Returns true iff this edge validates. */
    private boolean boundsEdgeValidates(BoundsCallEdge ed,
        BoundsValid fv, int offIdx, long sizeOff,
        BExpr structBase) {
        if (ed == null || fv == null || ed.slotProv == null) {
            return false;
        }
        if (offIdx < 0 || offIdx >= ed.slotProv.length) {
            return false;
        }
        BExpr passed = ed.slotProv[offIdx];
        if (passed == null) return false;
        int m = -1;
        if (passed.kind.equals("ARG") || passed.kind.equals("ROOT")) {
            m = passed.argIdx;
        } else {
            return false;
        }
        if (fv.signedArgs.contains(m)) return true;
        if (sizeOff < 0 || fv.cmps == null) return false;
        BExpr mapped = null;
        if (structBase != null && structBase.kind.equals("ARG")) {
            int s = structBase.argIdx;
            if (s >= 0 && s < ed.slotProv.length) {
                mapped = ed.slotProv[s];
            }
        }
        if (mapped == null || mapped.kind.equals("TOP")) {
            return false;
        }
        BExpr offRef = BExpr.arg(m);
        for (BoundsCmp c : fv.cmps) {
            if (!c.isUnsigned()) continue;
            boolean wide = false;
            if (c.a.containsWideExt(offRef, fv.ptrSize) &&
                c.b.kind.equals("FIELD") && c.b.off == sizeOff &&
                c.b.base.equals(mapped)) {
                wide = true;
            } else if (c.b.containsWideExt(offRef, fv.ptrSize) &&
                c.a.kind.equals("FIELD") && c.a.off == sizeOff &&
                c.a.base.equals(mapped)) {
                wide = true;
            }
            if (wide) return true;
        }
        if (fv.ops == null || fv.branchTargets == null) {
            return false;
        }
        try {
            List<List<Integer>> succ =
                buildSucc(fv.ops, fv.branchTargets);
            BoundsGroups bg = boundsGroupMaps(fv.ops, succ);
            if (bg.grpSucc == null ||
                ed.idx < 0 || ed.idx >= fv.ops.size()) {
                return false;
            }
            String mw = boundsMultiwordGuard(fv.cmps, fv.ops,
                bg.opGroup, bg.grpStarts, bg.grpSucc,
                bg.addrToGroup, bg.opGroup[ed.idx], m, mapped,
                sizeOff);
            if (mw != null) return true;
        } catch (Exception e) {
            return false;
        }
        return false;
    }

    /** Caller validation for one callee site (bounds Phase 1,
        item 3): returns "caller-check" iff the callee has at
        least one known caller and EVERY known caller validates
        the site on EVERY direct edge to the callee. Known
        callers = union of Ghidra's calling-functions (callerSets)
        and the pre-pass direct edges; a caller with no record,
        no edge, or any non-validating edge blocks suppression
        (fail-closed). A sentinel entry (Long.MIN_VALUE) in
        callerSets marks an unmappable caller and always blocks.
        Null maps (pre-pass) mean no suppression. */
    private String boundsCallerGuard(long selfEntry, int offIdx,
        long sizeOff, BExpr structBase,
        Map<Long, BoundsValid> validByEntry,
        Map<Long, Set<Long>> callerSets) {
        if (validByEntry == null || callerSets == null) {
            return null;
        }
        Set<Long> known = callerSets.get(selfEntry);
        if (known == null) {
            try {
                known = callerSets.get(
                    isa.stripInstructionTag(selfEntry));
            } catch (Exception e) {
                known = null;
            }
        }
        Map<Long, List<BoundsCallEdge>> direct =
            new HashMap<Long, List<BoundsCallEdge>>();
        for (Map.Entry<Long, BoundsValid> e :
            validByEntry.entrySet()) {
            if (e.getValue() == null ||
                e.getValue().edges == null) continue;
            for (BoundsCallEdge ed : e.getValue().edges) {
                boolean match = ed.entry == selfEntry;
                if (!match) {
                    try {
                        match = isa.stripInstructionTag(ed.entry) ==
                            isa.stripInstructionTag(selfEntry);
                    } catch (Exception ex) {
                        match = false;
                    }
                }
                if (!match) continue;
                List<BoundsCallEdge> l = direct.get(e.getKey());
                if (l == null) {
                    l = new ArrayList<BoundsCallEdge>();
                    direct.put(e.getKey(), l);
                }
                l.add(ed);
            }
        }
        java.util.Set<Long> must = new java.util.HashSet<Long>();
        if (known != null) must.addAll(known);
        must.addAll(direct.keySet());
        if (must.isEmpty()) return null;
        for (Long ce : must) {
            BoundsValid fv = validByEntry.get(ce);
            if (fv == null) return null;
            List<BoundsCallEdge> eds = direct.get(ce);
            if (eds == null || eds.isEmpty()) return null;
            for (BoundsCallEdge ed : eds) {
                if (!boundsEdgeValidates(ed, fv, offIdx, sizeOff,
                    structBase)) return null;
            }
        }
        return "caller-check";
    }

    /** Site JSON builder (bounds Phase 1 refactor; byte-identical
        format to the previously inline builder). baseOffNull
        means base_field renders as JSON null (cmdaddr sites with
        no recovered base field). */
    private String boundsSiteJson(String func, String addrHex,
        String kind, String role, int offIdx, Long baseOff,
        long sizeOff, boolean unsound, String guard,
        boolean flagged) {
        StringBuilder sb = new StringBuilder();
        sb.append("{\"func\": \"");
        sb.append(esc(func));
        sb.append("\", \"instr\": \"").append(addrHex);
        sb.append("\", \"kind\": \"").append(kind).append("\"");
        sb.append(", \"role\": \"").append(role).append("\"");
        sb.append(", \"offset_arg\": ").append(offIdx);
        sb.append(", \"base_field\": ");
        if (baseOff == null) sb.append("null");
        else sb.append(baseOff.longValue());
        sb.append(", \"size_field\": ");
        if (sizeOff >= 0) sb.append(sizeOff);
        else sb.append("null");
        sb.append(", \"unsound_check\": ").append(unsound);
        sb.append(", \"sound_guard\": \"").append(guard).append("\"");
        sb.append(", \"flagged\": ").append(flagged);
        sb.append("}");
        return sb.toString();
    }

    /** Varnode identity key for matcher bookkeeping
        (space:offset:size). Register-space keys are stable across
        instructions (flag registers); unique-space keys are valid
        only within one instruction group (temporaries never leak
        across groups -- see boundsTransfer's unique stripping). */
    private String boundsVnKey(Varnode v) {
        if (v == null) return "null";
        try {
            return v.getAddress().getAddressSpace().getName() + ":" +
                v.getOffset() + ":" + v.getSize();
        } catch (Exception e) {
            return "null";
        }
    }

    /** Group-level reachability (BFS over grpSucc). Identity counts
        as reachable (a fall-through group that IS the transfer's
        group reaches it). */
    private boolean boundsGroupReaches(List<List<Integer>> grpSucc,
        int from, int to) {
        if (from == to) return true;
        java.util.Set<Integer> seen = new java.util.HashSet<Integer>();
        java.util.ArrayDeque<Integer> q =
            new java.util.ArrayDeque<Integer>();
        seen.add(from);
        q.add(from);
        while (!q.isEmpty()) {
            int u = q.remove();
            for (int v : grpSucc.get(u)) {
                if (v == to) return true;
                if (seen.add(v)) q.add(v);
            }
        }
        return false;
    }

    /** Multi-word compare guard (bounds v3). A 64-bit range check
        on 32-bit ARM lowers to three consecutive instruction
        groups: [low-word unsigned compare] + [SBCS with carry] +
        [carry-tested branch gating the transfer]. The low compare
        is the unsound shape itself (unsigned ADD(offset,X) vs the
        same struct's size field); the SBCS group is recognised by
        its lowering signature (INT_SBORROW + INT_LESS + BOOL_OR in
        one group -- the cmp group has INT_SBORROW but no INT_LESS /
        BOOL_OR, the ADC group has BOOL_OR but no INT_SBORROW /
        INT_LESS, so the triple separates them); the branch group
        must test the carry flag the SBCS wrote (found dynamically
        as the COPY destination of the SBCS BOOL_OR output -- no
        hardcoded flag offsets), and the transfer must be reachable
        from exactly the carry-set (in-range) successor: bcc
        (carry==0, taken = reject) with the transfer reachable only
        from the fall-through, or bcs (carry==1, taken = in-range)
        with the transfer reachable only from the branch target.
        Returns "multiword-check" or null. The high-word dataflow
        tie is the carry-flag chain (compare writes carry, SBCS
        reads it, branch reads the SBCS carry) plus strict
        adjacency -- not full high-word provenance, which is TOP
        (ASR/ADC lower through flag registers the scan does not
        track). A pathological unrelated SBCS chained on the
        compare's carry could over-suppress (false negative
        direction -- a missed flag, never a false flag). A lone
        compare, a compare + SBCS without the gating branch, or a
        branch that does not gate the transfer do NOT count.
        Refinement: the idiom is a sound guard only if the
        widened offset is zero-extended (boundsMultiwordWidening);
        a sign-extending ASR widening alone vetoes the guard,
        because it does not reject negative offsets. */
    private String boundsMultiwordGuard(List<BoundsCmp> cmps,
        List<OpRec> ops, int[] opGroup, List<Integer> grpStarts,
        List<List<Integer>> grpSucc, Map<String, Integer> addrToGroup,
        int callGroup, int offIdx, BExpr structBase,
        long sizeOff) {
        if (grpSucc == null) return null;
        BExpr offRef = BExpr.arg(offIdx);
        int nGroups = grpStarts.size();
        for (BoundsCmp c : cmps) {
            if (!c.isUnsigned()) continue;
            // Same shape as the unsound check, duplicated from the
            // site block deliberately: refactoring it would risk
            // changing existing flag behaviour.
            BExpr fld = null;
            BExpr otherSide = c.a.addOtherSide(offRef);
            if (otherSide != null && !otherSide.kind.equals("TOP") &&
                c.b.kind.equals("FIELD") &&
                c.b.base.equals(structBase)) {
                fld = c.b;
            } else if ((otherSide =
                c.b.addOtherSide(offRef)) != null &&
                !otherSide.kind.equals("TOP") &&
                c.a.kind.equals("FIELD") &&
                c.a.base.equals(structBase)) {
                fld = c.a;
            }
            if (fld == null) continue;
            // Caller-side size agreement (bounds Phase 1, item 3):
            // when sizeOff >= 0 the matched low compare must be
            // against that size field; -1 (site-guard calls)
            // preserves the old any-field behaviour.
            if (sizeOff >= 0 && fld.off != sizeOff) continue;
            int g0 = opGroup[c.idx];
            int g1 = g0 + 1;
            int g2 = g0 + 2;
            int g3 = g0 + 3;
            if (g1 >= nGroups || g2 >= nGroups || g3 >= nGroups) {
                continue;
            }
            if (g1 >= callGroup || g2 >= callGroup) continue;
            int s0 = grpStarts.get(g0);
            int e0 = grpStarts.get(g0 + 1);
            int s1 = grpStarts.get(g1);
            int e1 = (g1 + 1 < nGroups) ?
                grpStarts.get(g1 + 1) : ops.size();
            int s2 = grpStarts.get(g2);
            int e2 = (g2 + 1 < nGroups) ?
                grpStarts.get(g2 + 1) : ops.size();
            // SBCS signature in g1.
            boolean hasSborrow = false, hasLess = false,
                hasBoolOr = false;
            for (int k = s1; k < e1; k++) {
                String m = ops.get(k).mnem;
                if (m.equals("INT_SBORROW")) hasSborrow = true;
                else if (m.equals("INT_LESS")) hasLess = true;
                else if (m.equals("BOOL_OR")) hasBoolOr = true;
            }
            if (!hasSborrow || !hasLess || !hasBoolOr) continue;
            // Carry register written by g0's compare: COPY dst
            // whose src is the compare op's output.
            String cmpOut = boundsVnKey(ops.get(c.idx).out);
            List<String> c1s = new ArrayList<String>();
            for (int k = s0; k < e0; k++) {
                OpRec o = ops.get(k);
                if (o.mnem.equals("COPY") && o.ins.length >= 1 &&
                    boundsVnKey(o.ins[0]).equals(cmpOut)) {
                    c1s.add(boundsVnKey(o.out));
                }
            }
            if (c1s.isEmpty()) continue;
            // SBCS group must read that carry (carry chain).
            boolean readsC1 = false;
            for (int k = s1; k < e1 && !readsC1; k++) {
                OpRec o = ops.get(k);
                for (int t = 0; t < o.ins.length; t++) {
                    if (c1s.contains(boundsVnKey(o.ins[t]))) {
                        readsC1 = true;
                        break;
                    }
                }
            }
            if (!readsC1) continue;
            // Carry registers written by g1's SBCS: COPY dsts
            // whose src is a BOOL_OR output in g1.
            List<String> c2s = new ArrayList<String>();
            for (int k = s1; k < e1; k++) {
                OpRec o = ops.get(k);
                if (!o.mnem.equals("BOOL_OR")) continue;
                String boOut = boundsVnKey(o.out);
                for (int j = s1; j < e1; j++) {
                    OpRec cp = ops.get(j);
                    if (cp.mnem.equals("COPY") && cp.ins.length >= 1 &&
                        boundsVnKey(cp.ins[0]).equals(boOut)) {
                        c2s.add(boundsVnKey(cp.out));
                    }
                }
            }
            if (c2s.isEmpty()) continue;
            // Branch group g2: CBRANCH testing a C2 flag, with the
            // branch direction + reachability gating the transfer.
            Integer branchK = null;
            Long branchTarget = null;
            for (int k = s2; k < e2 && branchK == null; k++) {
                OpRec o = ops.get(k);
                if (!o.mnem.equals("CBRANCH") || o.ins.length < 2) {
                    continue;
                }
                String condKey = boundsVnKey(o.ins[1]);
                for (int j = s2; j < e2; j++) {
                    OpRec e = ops.get(j);
                    if (!(e.mnem.equals("INT_EQUAL") ||
                        e.mnem.equals("INT_NOTEQUAL"))) continue;
                    if (!boundsVnKey(e.out).equals(condKey)) continue;
                    if (e.ins.length < 2) continue;
                    String l = boundsVnKey(e.ins[0]);
                    String r = boundsVnKey(e.ins[1]);
                    boolean isEq = e.mnem.equals("INT_EQUAL");
                    for (String c2 : c2s) {
                        long cv = -1;
                        boolean ok = false;
                        if (l.equals(c2) && e.ins[1].isConstant()) {
                            cv = e.ins[1].getOffset();
                            ok = true;
                        } else if (r.equals(c2) &&
                            e.ins[0].isConstant()) {
                            cv = e.ins[0].getOffset();
                            ok = true;
                        }
                        if (!ok) continue;
                        if (isEq && cv == 0) branchK = 0;
                        else if (isEq && cv == 1) branchK = 1;
                        else if (!isEq && cv == 0) branchK = 1;
                        else if (!isEq && cv == 1) branchK = 0;
                        else continue;
                        branchTarget = o.ins[0].getOffset();
                        break;
                    }
                    if (branchK != null) break;
                }
            }
            if (branchK == null || branchTarget == null) continue;
            Integer tgtGroup =
                addrToGroup.get(isa.formatCodeAddress(branchTarget));
            if (tgtGroup == null) {
                tgtGroup = addrToGroup.get(isa.formatCodeAddress(
                    isa.stripInstructionTag(branchTarget)));
            }
            if (tgtGroup == null) continue;
            boolean reachFall =
                boundsGroupReaches(grpSucc, g3, callGroup);
            boolean reachTgt =
                boundsGroupReaches(grpSucc, tgtGroup, callGroup);
            if ((branchK == 0 && reachFall && !reachTgt) ||
                (branchK == 1 && reachTgt && !reachFall)) {
                // Widening refinement (v3 refinement): the idiom
                // is a sound guard ONLY if the widened offset is
                // zero-extended. A sign-extending widening (ASR
                // by 31 / SEXT) alone does not reject negative
                // offsets (off=-1, n=16 wraps to a small sum),
                // so it vetoes the guard (try the next compare);
                // an unrecognised widening vetoes too -- only a
                // proven zero-fill suppresses a flag.
                if (!boundsMultiwordWidening(ops, grpStarts, g0)
                    .equals("ZERO")) continue;
                return "multiword-check";
            }
        }
        return null;
    }

    /** Widening classification for a multi-word guard (bounds v3
        refinement). The 64-bit sum's high word is computed by an
        ADC group (BOOL_OR without INT_SBORROW/INT_LESS, found by
        scanning back from the low-compare group, bounded to 8
        groups -- the ADC precedes the compare it feeds). In that
        group, a high-word add is an INT_ADD consuming no
        intra-group INT_ADD output and no carry extension (a
        carry-add consumes a partial sum or the carry, and tracing
        through it would veto every guard); each high-word add
        input is traced back through COPY chains to its defining
        op (see boundsTraceWidening). Returns "ZERO"
        only if every traced high-word input is ZERO; "SIGN" if
        any input is SIGN; "UNKNOWN" otherwise. The caller vetoes
        the guard unless the result is "ZERO": a sign-extending
        widening alone does not reject negative offsets, and an
        unrecognised widening must not be claimed sound.
        Fail-safe direction: misidentifying the ADC group, or
        hitting an unrecognised input, yields UNKNOWN (veto ->
        flag), never a false sound verdict. */
    private String boundsMultiwordWidening(List<OpRec> ops,
        List<Integer> grpStarts, int g0) {
        int adc = -1;
        for (int g = g0 - 1; g >= 0 && g >= g0 - 8; g--) {
            boolean hasOr = false, hasSborrow = false,
                hasLess = false;
            int s = grpStarts.get(g);
            int e = (g + 1 < grpStarts.size()) ?
                grpStarts.get(g + 1) : ops.size();
            for (int k = s; k < e; k++) {
                String m = ops.get(k).mnem;
                if (m.equals("BOOL_OR")) hasOr = true;
                if (m.equals("INT_SBORROW")) hasSborrow = true;
                if (m.equals("INT_LESS")) hasLess = true;
            }
            if (hasOr && !hasSborrow && !hasLess) {
                adc = g;
                break;
            }
        }
        if (adc < 0) return "UNKNOWN";
        int s = grpStarts.get(adc);
        int e = (adc + 1 < grpStarts.size()) ?
            grpStarts.get(adc + 1) : ops.size();
        // Carry extensions: INT_ZEXT outputs whose input is a
        // 1-byte flag varnode. A pure high-word add consumes only
        // original values (registers/consts defined before the
        // group, or intra-group COPYs of consts); a carry-add
        // consumes a partial sum (an intra-group INT_ADD output)
        // or a carry extension, and tracing THROUGH it would hit
        // the INT_ADD definition itself (UNKNOWN) and veto every
        // guard. So an INT_ADD counts as a high-word add only if
        // none of its inputs is an intra-group INT_ADD output or
        // a carry extension.
        java.util.Set<String> carryExt =
            new java.util.HashSet<String>();
        java.util.Set<String> addOuts =
            new java.util.HashSet<String>();
        for (int k = s; k < e; k++) {
            OpRec o = ops.get(k);
            if (o.mnem.equals("INT_ZEXT") && o.ins != null &&
                o.ins.length >= 1 && o.ins[0] != null &&
                o.ins[0].getSize() == 1 && o.out != null) {
                carryExt.add(boundsVnKey(o.out));
            }
            if (o.mnem.equals("INT_ADD") && o.out != null) {
                addOuts.add(boundsVnKey(o.out));
            }
        }
        boolean sawAdd = false;
        boolean sawSign = false;
        boolean sawUnknown = false;
        for (int k = s; k < e; k++) {
            OpRec o = ops.get(k);
            if (!o.mnem.equals("INT_ADD") || o.ins == null) continue;
            boolean carryAdd = false;
            for (Varnode in : o.ins) {
                if (in != null &&
                    (carryExt.contains(boundsVnKey(in)) ||
                     addOuts.contains(boundsVnKey(in)))) {
                    carryAdd = true;
                    break;
                }
            }
            if (carryAdd) continue;
            sawAdd = true;
            for (Varnode in : o.ins) {
                if (in == null) continue;
                String r = boundsTraceWidening(ops, k, in);
                if (r.equals("SIGN")) sawSign = true;
                else if (!r.equals("ZERO")) sawUnknown = true;
            }
        }
        if (!sawAdd) return "UNKNOWN";
        if (sawSign) return "SIGN";
        if (sawUnknown) return "UNKNOWN";
        return "ZERO";
    }

    /** Trace one widening input back through COPY chains.
        fromIdx is the using op's index; the walk covers all ops
        before it in this function. Returns "SIGN", "ZERO", or
        "UNKNOWN". A CALL/CALLIND between use and definition
        yields UNKNOWN (a call would clobber a caller-saved high
        word, so the pre-call definition is not the value used).
        INT_SRIGHT is SIGN only when the shift is the sign bit
        (input size * 8 - 1: 31 for a 32-bit widening); any other
        defining op (ADD, LOAD, call return, ...) is UNKNOWN. */
    private String boundsTraceWidening(List<OpRec> ops, int fromIdx,
        Varnode start) {
        if (start == null) return "UNKNOWN";
        if (start.isConstant()) {
            return start.getOffset() == 0 ? "ZERO" : "UNKNOWN";
        }
        String cur = boundsVnKey(start);
        for (int k = fromIdx - 1; k >= 0; k--) {
            OpRec o = ops.get(k);
            if (o.mnem.equals("CALL") || o.mnem.equals("CALLIND")) {
                return "UNKNOWN";
            }
            if (o.out == null) continue;
            if (!boundsVnKey(o.out).equals(cur)) continue;
            if (o.mnem.equals("COPY") && o.ins != null &&
                o.ins.length == 1 && o.ins[0] != null) {
                if (o.ins[0].isConstant()) {
                    return o.ins[0].getOffset() == 0 ?
                        "ZERO" : "UNKNOWN";
                }
                cur = boundsVnKey(o.ins[0]);
                continue;
            }
            if (o.mnem.equals("INT_SRIGHT") && o.ins != null &&
                o.ins.length >= 2 && o.ins[0] != null &&
                o.ins[1] != null && o.ins[1].isConstant() &&
                o.ins[1].getOffset() ==
                    o.ins[0].getSize() * 8 - 1) {
                return "SIGN";
            }
            if (o.mnem.equals("INT_SEXT")) return "SIGN";
            if (o.mnem.equals("INT_ZEXT")) return "ZERO";
            return "UNKNOWN";
        }
        return "UNKNOWN";
    }

    private Map<String, BExpr> boundsTransfer(Map<String, BExpr> in,
        OpRec op, long[] saved, boolean stripUniques) {
        Map<String, BExpr> prov = new HashMap<String, BExpr>(in);
        if (stripUniques) {
            java.util.Iterator<String> it = prov.keySet().iterator();
            while (it.hasNext()) {
                if (it.next().startsWith("unique:")) it.remove();
            }
        }
        String mnem = op.mnem;
        if (op.out != null) {
            if (mnem.equals("COPY") && op.ins.length == 1) {
                boundsPut(op.out, boundsProvOf(op.ins[0], prov), prov);
            } else if (mnem.equals("LOAD") && op.ins.length >= 2) {
                BExpr addr = boundsProvOf(op.ins[1], prov);
                if (addr.kind.equals("ADD") &&
                    addr.other.kind.equals("CONST")) {
                    boundsPut(op.out,
                        BExpr.field(addr.base, addr.other.constVal),
                        prov);
                } else if (addr.kind.equals("ADD") &&
                    addr.base.kind.equals("CONST")) {
                    boundsPut(op.out,
                        BExpr.field(addr.other, addr.base.constVal),
                        prov);
                } else if (addr.kind.equals("ARG") ||
                    addr.kind.equals("FIELD")) {
                    boundsPut(op.out, BExpr.field(addr, 0), prov);
                } else {
                    boundsPut(op.out, BExpr.TOP, prov);
                }
            } else if (mnem.equals("INT_ADD") && op.ins.length == 2) {
                boundsPut(op.out,
                    BExpr.add(boundsProvOf(op.ins[0], prov),
                        boundsProvOf(op.ins[1], prov)),
                    prov);
            } else if (mnem.equals("INT_SUB") && op.ins.length == 2) {
                boundsPut(op.out,
                    BExpr.sub(boundsProvOf(op.ins[0], prov),
                        boundsProvOf(op.ins[1], prov)),
                    prov);
            } else if ((mnem.equals("INT_ZEXT") || mnem.equals("INT_SEXT")) &&
                op.ins.length == 1) {
                boundsPut(op.out,
                    BExpr.ext(boundsProvOf(op.ins[0], prov),
                        op.out.getSize(), mnem.equals("INT_ZEXT")),
                    prov);
            } else {
                boundsPut(op.out, BExpr.TOP, prov);
            }
        }
        if (mnem.equals("CALL") || mnem.equals("CALLIND")) {
            if (saved != null) {
                for (long ro : saved) prov.remove("register:" + ro);
            }
        }
        return prov;
    }

    /** Full bounds scan of one function's ops: a CFG must-fixpoint
        over provenance maps (same successor rules as the value
        fixpoint, via buildSucc; Gauss-Seidel sweeps in listing
        order, so forward chains propagate within one sweep), then
        one event/site pass that walks instruction by instruction
        from the final IN states with a working map. Must-join: a register keeps provenance only
        if EVERY predecessor agrees, so provenance never flows down
        a path that cannot reach the op -- the linear scan this
        replaced did exactly that (an epilogue pop block listed
        before the memcpy block clobbered the live struct pointer).
        signedCheckByEntry (built by the pre-pass) maps callee entries
        to their hasSignedArgCheck bit; null during the pre-pass
        itself, in which case guard-call classification is skipped
        (sites are still recorded, but the pre-pass ignores them).
        If the fixpoint does not converge in 500 sweeps, sites are
        dropped (only the suppression-leaning hasSignedArgCheck is
        kept): a non-converged iterate may still hold provenance
        the true fixpoint would drop, and a site built on it would
        not be proven. */
    private BoundsScan boundsScan(Function callerFn, List<OpRec> ops,
        Map<Integer, List<Integer>> branchTargets, long[] argOffs,
        Map<Long, FuncRec> funcByEntry,
        Map<Long, Boolean> signedCheckByEntry,
        long selfEntry, Map<Long, BoundsValid> validByEntry,
        Map<Long, Set<Long>> callerSets) {
        BoundsScan res = new BoundsScan();
        if (argOffs == null || argOffs.length < 3) return res;
        int n = ops.size();
        if (n == 0) return res;
        Map<String, BExpr> seeds = new HashMap<String, BExpr>();
        for (int i = 0; i < argOffs.length; i++) {
            seeds.put("register:" + argOffs[i], BExpr.arg(i));
        }
        long[] saved = null;
        try {
            saved = isa.callerSavedRegisterOffsets();
        } catch (Exception e) {
            saved = null;
        }
        List<List<Integer>> succ = null;
        try {
            succ = buildSucc(ops, branchTargets);
        } catch (Exception e) {
            succ = null;
        }
        List<List<Integer>> pred = new ArrayList<List<Integer>>();
        for (int i = 0; i < n; i++) pred.add(new ArrayList<Integer>());
        if (succ != null) {
            for (int i = 0; i < n; i++) {
                for (int j : succ.get(i)) {
                    if (j >= 0 && j < n) pred.get(j).add(i);
                }
            }
        } else {
            for (int i = 1; i < n; i++) pred.get(i).add(i - 1);
        }
        Map<String, BExpr>[] inStates = new Map[n];
        Map<String, BExpr>[] outStates = new Map[n];
        for (int i = 0; i < n; i++) {
            inStates[i] = new HashMap<String, BExpr>(seeds);
            outStates[i] = new HashMap<String, BExpr>();
        }
        // Gauss-Seidel sweeps in listing order: each op's IN is
        // rejoined from its predecessors' latest OUTs and its OUT
        // recomputed immediately, so forward chains propagate within
        // a single sweep (a Jacobi iteration needs one round per
        // CFG edge of depth, which a 184-op function already
        // exceeds). A sweep with zero IN changes is the fixpoint.
        // First op of each instruction strips uniques (see
        // boundsTransfer); IN[0] stays the entry seeds.
        boolean[] isInstrStart = new boolean[n];
        for (int i = 0; i < n; i++) {
            isInstrStart[i] = i == 0 ||
                !ops.get(i).instrAddr.equals(ops.get(i - 1).instrAddr);
        }
        boolean converged = false;
        // Reverse-postorder sweeps + visited-pred joins (v3.16
        // fixes): outStates start EMPTY, so a loop head joined
        // against an unprocessed back edge in sweep 1 would
        // poison its IN to empty and never recover (must-joins
        // only remove). Skipping unvisited preds makes sweep 1
        // optimistic -- but listing order is NOT topological:
        // the FIXED write lays its loop latch (0x12018a6c)
        // before its chunk-setup block (0x12018a76) in address
        // order, so a listing-order sweep processes the latch
        // (spurious empty OUT, downstream of the empty head)
        // before chunk-setup and the join poisons chunk-setup,
        // the head, and the whole loop body to the trivial empty
        // fixpoint. RPO processes every forward pred before its
        // successors, so pass 1 seeds the loop with the entry
        // value and later passes refine it to ROOT; by
        // convergence every pred has been visited, so the final
        // INs are exact joins -- the greatest fixpoint.
        java.util.List<Integer> rpo =
            new java.util.ArrayList<Integer>();
        {
            boolean[] seen = new boolean[n];
            java.util.List<Integer> post =
                new java.util.ArrayList<Integer>();
            java.util.ArrayDeque<int[]> st =
                new java.util.ArrayDeque<int[]>();
            if (n > 0) {
                st.push(new int[] { 0, 0 });
                seen[0] = true;
            }
            while (!st.isEmpty()) {
                int[] top = st.peek();
                int u = top[0];
                java.util.List<Integer> ss;
                if (succ != null) {
                    ss = succ.get(u);
                } else {
                    ss = new java.util.ArrayList<Integer>();
                    if (u + 1 < n) ss.add(u + 1);
                }
                if (top[1] < ss.size()) {
                    int v = ss.get(top[1]++);
                    if (v >= 0 && v < n && !seen[v]) {
                        seen[v] = true;
                        st.push(new int[] { v, 0 });
                    }
                } else {
                    post.add(u);
                    st.pop();
                }
            }
            for (int i = post.size() - 1; i >= 0; i--) {
                rpo.add(post.get(i));
            }
            for (int i = 0; i < n; i++) {
                if (!seen[i]) rpo.add(i);
            }
        }
        boolean[] visited = new boolean[n];
        for (int sweep = 0; sweep < 500 && !converged; sweep++) {
            boolean changed = false;
            for (int ri = 0; ri < rpo.size(); ri++) {
                int i = rpo.get(ri);
                if (i == 0) {
                    outStates[0] = boundsTransfer(inStates[0],
                        ops.get(0), saved, true);
                    visited[0] = true;
                    continue;
                }
                List<Integer> ps = pred.get(i);
                Map<String, BExpr> joined;
                java.util.List<Integer> vps =
                    new java.util.ArrayList<Integer>();
                for (int p : ps) {
                    if (visited[p]) vps.add(p);
                }
                if (vps.isEmpty()) {
                    joined = new HashMap<String, BExpr>();
                } else {
                    joined =
                        new HashMap<String, BExpr>(outStates[vps.get(0)]);
                    for (int k = 1; k < vps.size(); k++) {
                        Map<String, BExpr> o = outStates[vps.get(k)];
                        java.util.Iterator<Map.Entry<String, BExpr>> it =
                            joined.entrySet().iterator();
                        while (it.hasNext()) {
                            Map.Entry<String, BExpr> e = it.next();
                            BExpr v = o.get(e.getKey());
                            if (v == null) {
                                it.remove();
                            } else if (!v.equals(e.getValue())) {
                                // Rooted merge (v3.16): a value that
                                // IS ARG(n)/ROOT(n) joined with a
                                // value containing ARG(n) keeps
                                // ROOT(n) instead of dropping.
                                BExpr old = e.getValue();
                                int rn = -1;
                                if (old.kind.equals("ARG") ||
                                    old.kind.equals("ROOT")) {
                                    rn = old.argIdx;
                                } else if (v.kind.equals("ARG") ||
                                    v.kind.equals("ROOT")) {
                                    rn = v.argIdx;
                                }
                                if (rn >= 0 &&
                                    containsArgRoot(old, rn) &&
                                    containsArgRoot(v, rn)) {
                                    e.setValue(BExpr.root(rn));
                                } else {
                                    it.remove();
                                }
                            }
                        }
                    }
                }
                if (!joined.equals(inStates[i])) {
                    inStates[i] = joined;
                    changed = true;
                }
                outStates[i] = boundsTransfer(inStates[i], ops.get(i),
                    saved, isInstrStart[i]);
                visited[i] = true;
            }
            if (!changed) converged = true;
        }
        int ptrSize = 4;
        try {
            ptrSize = isa.pointerSize();
        } catch (Exception e) {
            ptrSize = 4;
        }
        res.ptrSize = ptrSize;
        // Instruction-group maps for the multi-word guard check
        // (bounds v3): op index -> group index, group start op
        // indices, group-level successors from buildSucc, and
        // group-start address -> group index. If buildSucc failed
        // (succ == null), grpSucc stays null and the multi-word
        // guard is disabled (miss direction).
        // (bounds Phase 1 refactor: group maps via the shared
        // helper; identical semantics to the old inline block.)
        BoundsGroups bg = boundsGroupMaps(ops, succ);
        int[] opGroup = bg.opGroup;
        List<Integer> grpStarts = bg.grpStarts;
        Map<String, Integer> addrToGroup = bg.addrToGroup;
        List<List<Integer>> grpSucc = bg.grpSucc;
        List<BoundsCall> calls = new ArrayList<BoundsCall>();
        List<Integer> cbranchIdx = new ArrayList<Integer>();
        // Bounds Phase 1, items 1-2: per-callee programming
        // evidence, computed lazily once per callee per scan.
        Map<Long, BoundsCalleeProg> progCache =
            new HashMap<Long, BoundsCalleeProg>();
        // Phase 2 walks instruction by instruction: the working map
        // starts from the first op's IN state with uniques stripped,
        // then advances op by op within the instruction, so a
        // comparison or CALL reads unique temporaries defined
        // earlier in the SAME instruction (e.g. cmp lowering's SUB
        // result feeding SLESS) while never seeing a stale unique
        // from another instruction.
        for (int grp = 0; grp < n;) {
            int grpEnd = grp + 1;
            while (grpEnd < n && ops.get(grpEnd).instrAddr.equals(
                ops.get(grp).instrAddr)) grpEnd++;
            Map<String, BExpr> working =
                new HashMap<String, BExpr>(inStates[grp]);
            java.util.Iterator<String> wit =
                working.keySet().iterator();
            while (wit.hasNext()) {
                if (wit.next().startsWith("unique:")) wit.remove();
            }
            for (int i = grp; i < grpEnd; i++) {
            OpRec op = ops.get(i);
            String mnem = op.mnem;
            Map<String, BExpr> prov = working;
            if (mnem.equals("CBRANCH")) cbranchIdx.add(i);
            if ((mnem.equals("INT_LESS") || mnem.equals("INT_LESSEQUAL") ||
                mnem.equals("INT_SLESS") || mnem.equals("INT_SLESSEQUAL")) &&
                op.ins.length == 2) {
                BExpr a = boundsProvOf(op.ins[0], prov);
                BExpr b = boundsProvOf(op.ins[1], prov);
                res.cmps.add(new BoundsCmp(i, mnem, a, b));
                if ((mnem.equals("INT_SLESS") ||
                    mnem.equals("INT_SLESSEQUAL")) &&
                    ((a.kind.equals("ARG") && b.kind.equals("CONST") &&
                        b.constVal == 0) ||
                    (b.kind.equals("ARG") && a.kind.equals("CONST") &&
                        a.constVal == 0))) {
                    res.hasSignedArgCheck = true;
                }
                // Bounds Phase 1, item 3: signed-checked argument
                // indices for caller validation (ARG or ROOT vs
                // CONST 0; a superset of the hasSignedArgCheck
                // bit, which stays ARG-only for guard-call use).
                if (mnem.equals("INT_SLESS") ||
                    mnem.equals("INT_SLESSEQUAL")) {
                    if ((a.kind.equals("ARG") ||
                        a.kind.equals("ROOT")) &&
                        b.kind.equals("CONST") &&
                        b.constVal == 0) {
                        res.signedArgs.add(a.argIdx);
                    } else if ((b.kind.equals("ARG") ||
                        b.kind.equals("ROOT")) &&
                        a.kind.equals("CONST") &&
                        a.constVal == 0) {
                        res.signedArgs.add(b.argIdx);
                    }
                }
            }
            // Bounds Phase 1, cmdaddr pointer-use gate: a slot
            // used as a load/store address base in this function
            // is a POINTER, not an offset integer. Recorded for
            // every LOAD/STORE (pre-op provenance), regardless
            // of convergence, like cmps above: the pre-pass
            // record must cover the whole function, since a
            // dereference after the call still proves
            // pointer-ness. Only BASE positions count (see
            // boundsBaseSlots).
            if ((mnem.equals("LOAD") || mnem.equals("STORE")) &&
                op.ins.length >= 2) {
                BExpr ad = boundsProvOf(op.ins[1], prov);
                java.util.Set<String> bs =
                    new java.util.HashSet<String>();
                boundsBaseSlots(ad, bs);
                for (String s : bs) {
                    try {
                        int ci = s.indexOf(':');
                        int si = Integer.parseInt(
                            s.substring(ci + 1));
                        if (s.startsWith("ARG")) {
                            res.derefArgs.add(si);
                        } else {
                            res.derefRoots.add(si);
                        }
                    } catch (Exception e) {
                        // Ignore malformed slot keys.
                    }
                }
            }
            if (converged) {
            if (mnem.equals("CALL") || mnem.equals("BRANCH")) {
                FuncRec callee = null;
                String calleeName = null;
                if (op.ins.length >= 1) {
                    try {
                        String sp = op.ins[0].getAddress()
                            .getAddressSpace().getName();
                        if (sp.equals("ram") && funcByEntry != null) {
                            long tgt = op.ins[0].getOffset();
                            callee = funcByEntry.get(tgt);
                            if (callee == null) {
                                callee = funcByEntry.get(
                                    isa.stripInstructionTag(tgt));
                            }
                            if (callee != null && callee.f != null) {
                                calleeName = callee.f.getName();
                            }
                        }
                    } catch (Exception e) {
                        callee = null;
                    }
                }
                // Bounds Phase 1, item 3: record every resolved
                // direct call edge (transfer or not) with the
                // per-slot passed provenance at the call.
                if (callee != null) {
                    BExpr[] slots = new BExpr[argOffs.length];
                    for (int k = 0; k < argOffs.length; k++) {
                        slots[k] = boundsProvOf(
                            regVarnode(argOffs[k], 4), prov);
                    }
                    long ent;
                    try {
                        ent = callee.entryKey;
                    } catch (Exception e) {
                        ent = -1;
                    }
                    res.edges.add(new BoundsCallEdge(i, ent,
                        slots));
                }
                if (calleeName != null &&
                    isBoundsTransferCall(calleeName)) {
                    boolean isCache = isBoundsCacheCall(calleeName);
                    // Snapshot argument registers from the IN state
                    // (before the call clobber). Cache-range calls
                    // take (address, length): only arg0 is a
                    // pointer candidate, role "addr".
                    BExpr dst = boundsProvOf(
                        regVarnode(argOffs[0], 4), prov);
                    BExpr src = isCache ? BExpr.TOP : boundsProvOf(
                        regVarnode(argOffs[1], 4), prov);
                    // One site per call, memcpy/memmove role = src
                    // if the source is computed, else dst; both ->
                    // "both". Cache role = "addr".
                    BExpr[] ptrs = isCache ? new BExpr[] { dst } :
                        new BExpr[] { src, dst };
                    String[] roles = isCache ? new String[] { "addr" } :
                        new String[] { "src", "dst" };
                    BExpr offArg = null;
                    BExpr structBase = null;
                    long baseOff = 0;
                    String role = null;
                    for (int pi = 0; pi < ptrs.length; pi++) {
                        BExpr p = ptrs[pi];
                        if (!p.kind.equals("ADD")) continue;
                        BExpr f = null;
                        BExpr o = null;
                        if (p.base.kind.equals("FIELD") &&
                            (p.other.kind.equals("ARG") ||
                             p.other.kind.equals("ROOT"))) {
                            f = p.base; o = p.other;
                        } else if (p.other.kind.equals("FIELD") &&
                            (p.base.kind.equals("ARG") ||
                             p.base.kind.equals("ROOT"))) {
                            f = p.other; o = p.base;
                        }
                        if (f == null) continue;
                        if (role == null) {
                            role = roles[pi]; offArg = o;
                            structBase = f.base; baseOff = f.off;
                        } else {
                            role = "both";
                        }
                    }
                    if (role != null) {
                        // (bounds Phase 1 refactor: evaluation via
                        // the shared helper; semantics verbatim.)
                        // Matching reference: the original argument
                        // (a ROOT offset was ARG at function entry,
                        // so entry checks/guards match against ARG).
                        int offIdx = offArg.argIdx;
                        BoundsEval ev = boundsEvalSite(res.cmps,
                            calls, cbranchIdx, signedCheckByEntry,
                            ops, opGroup, grpStarts, grpSucc,
                            addrToGroup, i, offIdx, structBase,
                            ptrSize);
                        boolean unsound = ev.unsound;
                        long sizeOff = ev.sizeOff;
                        String guard = ev.guard;
                        boolean flagged = unsound &&
                            guard.equals("none");
                        // Bounds Phase 1, item 3: inter-procedural
                        // caller validation may suppress a flag.
                        if (flagged) {
                            String cg = boundsCallerGuard(selfEntry,
                                offIdx, sizeOff, ev.checkFieldBase,
                                validByEntry, callerSets);
                            if (cg != null) {
                                guard = cg;
                                flagged = false;
                            }
                        }
                        String addrHex;
                        try {
                            addrHex = "0x" + Long.toHexString(
                                op.instrAddr.getOffset());
                        } catch (Exception e) {
                            addrHex = "0x0";
                        }
                        // The site lives in the CALLER function.
                        String funcName;
                        try {
                            funcName = callerFn.getName();
                        } catch (Exception e) {
                            funcName = "?";
                        }
                        res.sites.add(new BoundsSiteRec(
                            boundsSiteJson(funcName, addrHex,
                                calleeName, role, offArg.argIdx,
                                baseOff, sizeOff, unsound, guard,
                                flagged),
                            flagged));
                    }
                    // Transfer-call form census (v3.16): every
                    // transfer call's pointer args, matched or not.
                    {
                        String formKind = isCache ? "cache" :
                            calleeName.equals("memmove") ? "memmove" :
                            "memcpy";
                        BExpr[] formArgs = isCache ?
                            new BExpr[] { dst } :
                            new BExpr[] { src, dst };
                        for (BExpr fa : formArgs) {
                            String fk = formKind + ":" +
                                boundsFormOf(fa);
                            Integer prev = res.formCounts.get(fk);
                            res.formCounts.put(fk,
                                prev == null ? 1 : prev + 1);
                        }
                        res.transferCalls++;
                    }
                } else if (signedCheckByEntry != null &&
                    callee != null) {
                    // Bounds Phase 1, items 1-2: DMA / cmdaddr
                    // sites on direct calls to non-transfer
                    // callees. Skipped in the pre-pass (null
                    // signedCheckByEntry), like the multi-word
                    // guard. Precedence: known-transfer calls
                    // above; a call matching neither form below
                    // is not a site. A call matching both forms
                    // on different slots emits both sites (one
                    // transfer call in the census).
                    BoundsCalleeProg prog = null;
                    try {
                        prog = progCache.get(callee.entryKey);
                    } catch (Exception e) {
                        prog = null;
                    }
                    if (prog == null) {
                        long[] caOffs = null;
                        try {
                            caOffs = boundsArgOffsets(callee);
                        } catch (Exception e) {
                            caOffs = null;
                        }
                        prog = boundsCalleeProg(callee, caOffs);
                        try {
                            progCache.put(callee.entryKey, prog);
                        } catch (Exception e) {
                            // Uncached; recomputed per site.
                        }
                    }
                    boolean countedCall = false;
                    String addrHex2;
                    try {
                        addrHex2 = "0x" + Long.toHexString(
                            op.instrAddr.getOffset());
                    } catch (Exception e) {
                        addrHex2 = "0x0";
                    }
                    String funcName2;
                    try {
                        funcName2 = callerFn.getName();
                    } catch (Exception e) {
                        funcName2 = "?";
                    }
                    // DMA: some slot holds ADD(FIELD, ARG|ROOT)
                    // and the callee programs that slot's value
                    // to a constant address.
                    for (int p = 0; p < argOffs.length; p++) {
                        BExpr pv = boundsProvOf(
                            regVarnode(argOffs[p], 4), prov);
                        if (!pv.kind.equals("ADD")) continue;
                        BExpr f = null;
                        BExpr o = null;
                        if (pv.base.kind.equals("FIELD") &&
                            (pv.other.kind.equals("ARG") ||
                             pv.other.kind.equals("ROOT"))) {
                            f = pv.base; o = pv.other;
                        } else if (pv.other.kind.equals("FIELD") &&
                            (pv.base.kind.equals("ARG") ||
                             pv.base.kind.equals("ROOT"))) {
                            f = pv.other; o = pv.base;
                        }
                        if (f == null) continue;
                        if (!prog.valueProg.contains(p)) continue;
                        int offIdx = o.argIdx;
                        BoundsEval ev = boundsEvalSite(res.cmps,
                            calls, cbranchIdx, signedCheckByEntry,
                            ops, opGroup, grpStarts, grpSucc,
                            addrToGroup, i, offIdx, f.base,
                            ptrSize);
                        String guard = ev.guard;
                        boolean flagged = ev.unsound &&
                            guard.equals("none");
                        if (flagged) {
                            String cg = boundsCallerGuard(selfEntry,
                                offIdx, ev.sizeOff,
                                ev.checkFieldBase, validByEntry,
                                callerSets);
                            if (cg != null) {
                                guard = cg;
                                flagged = false;
                            }
                        }
                        res.sites.add(new BoundsSiteRec(
                            boundsSiteJson(funcName2, addrHex2,
                                calleeName, "dma", offIdx, f.off,
                                ev.sizeOff, ev.unsound, guard,
                                flagged),
                            flagged));
                        Integer prev =
                            res.formCounts.get("dma:site");
                        res.formCounts.put("dma:site",
                            prev == null ? 1 : prev + 1);
                        if (!countedCall) {
                            res.transferCalls++;
                            countedCall = true;
                        }
                    }
                    // Cmdaddr: some slot holds a bare ARG|ROOT
                    // and the callee programs that slot as an
                    // ADDRESS component — either used as a store
                    // address (addrProg), or ADD-combined with a
                    // FIELD/CONST base into a fixed address
                    // (addrForm). A bare store of the slot into
                    // a fixed address does NOT qualify: that is
                    // a length/config value, not an address (the
                    // DMA-length false flags proved this).
                    // The struct base for guard matching is the
                    // unsound check's FIELD base (boundsEvalSite
                    // with a null base accepts any FIELD and
                    // returns it).
                    for (int p = 0; p < argOffs.length; p++) {
                        BExpr pv = boundsProvOf(
                            regVarnode(argOffs[p], 4), prov);
                        if (!pv.kind.equals("ARG") &&
                            !pv.kind.equals("ROOT")) continue;
                        // Bounds Phase 1, cmdaddr pointer-use
                        // gate: if this caller dereferences the
                        // passed slot (load/store address base),
                        // the slot is a POINTER, not an offset
                        // integer — the Zephyr sys_dlist_remove
                        // false flag (pointer passed, address-vs-
                        // head comparison mistaken for a bounds
                        // check). Fail-closed when the caller's
                        // pre-pass record is missing.
                        BoundsValid cv = null;
                        if (validByEntry != null) {
                            try {
                                cv = validByEntry.get(selfEntry);
                            } catch (Exception ex) {
                                cv = null;
                            }
                        }
                        boolean ptrLike = true;
                        if (cv != null) {
                            if (pv.kind.equals("ARG")) {
                                ptrLike = cv.derefArgs.contains(
                                    pv.argIdx);
                            } else {
                                ptrLike = cv.derefRoots.contains(
                                    pv.argIdx);
                            }
                        }
                        if (ptrLike) continue;
                        if (!prog.addrForm.contains(p) &&
                            !prog.addrProg.contains(p)) continue;
                        int offIdx = pv.argIdx;
                        BoundsEval ev = boundsEvalSite(res.cmps,
                            calls, cbranchIdx, signedCheckByEntry,
                            ops, opGroup, grpStarts, grpSucc,
                            addrToGroup, i, offIdx, null,
                            ptrSize);
                        String guard = ev.guard;
                        boolean flagged = ev.unsound &&
                            guard.equals("none");
                        if (flagged) {
                            String cg = boundsCallerGuard(selfEntry,
                                offIdx, ev.sizeOff,
                                ev.checkFieldBase, validByEntry,
                                callerSets);
                            if (cg != null) {
                                guard = cg;
                                flagged = false;
                            }
                        }
                        // Bounds Phase 1 emission rule (cmdaddr
                        // only): a bare integer carries no offset
                        // evidence by itself — unlike the pointer
                        // shape, which proves offset-ness — so a
                        // cmdaddr site is emitted ONLY when the
                        // caller has the unsound check for this
                        // arg: the unsigned ADD(arg, X) vs FIELD
                        // comparison is what identifies the bare
                        // arg AS a bounded offset. Without this
                        // gate, every pointer-storing helper call
                        // (list removal, memset, ...) emits a
                        // noise site (47 such sites on the CVE
                        // firmware, all unsound=False); a
                        // guard-only gate still admits one
                        // (gmtime_r -> memset, via a coincidental
                        // guard-call). A guarded cmdaddr call
                        // with no unsound check at all is
                        // therefore not emitted (miss direction
                        // for that shape, not a flag). DMA sites
                        // keep unconditional emission: their
                        // pointer shape is self-identifying.
                        if (ev.unsound) {
                            Long bf = prog.baseOff.get(p);
                            res.sites.add(new BoundsSiteRec(
                                boundsSiteJson(funcName2, addrHex2,
                                    calleeName, "cmdaddr", offIdx, bf,
                                    ev.sizeOff, ev.unsound, guard,
                                    flagged),
                                flagged));
                            Integer prev = res.formCounts.get(
                                "cmdaddr:site");
                            res.formCounts.put("cmdaddr:site",
                                prev == null ? 1 : prev + 1);
                            if (!countedCall) {
                                res.transferCalls++;
                                countedCall = true;
                            }
                        }
                    }
                    // Preserve the old guard-call recording:
                    // non-transfer CALLs (not tail BRANCHes) are
                    // guard-call candidates for LATER transfers.
                    // Added AFTER site evaluation so the current
                    // call is never its own guard candidate.
                    if (mnem.equals("CALL")) {
                        long ent;
                        try {
                            ent = callee.entryKey;
                        } catch (Exception e) {
                            ent = -1;
                        }
                        calls.add(new BoundsCall(i, ent));
                    }
                } else if (mnem.equals("CALL") && callee != null) {
                    long ent;
                    try {
                        ent = callee.entryKey;
                    } catch (Exception e) {
                        ent = -1;
                    }
                    calls.add(new BoundsCall(i, ent));
                }
            }
            }
            working = boundsTransfer(working, op, saved, false);
            }
            grp = grpEnd;
        }
        return res;
    }

    // ============ Phase 4 V1: security-boundary property ============
    // Design: ~/workspace/v32-phase4/design-phase4.md (approved).
    // V1 sources ONLY: static profile regions + image-level agent +
    // profile veneer list (+ SG-at-entry when Ghidra lifts it) +
    // DMA transfer synthesis for profile-declared programming
    // functions. NOT in V1: static-table learning, config-write
    // learning with must-precede, thread-entry attribution,
    // CONTROL/PSR tracking, PRIMASK/FAULTMASK/handler-ness/name
    // heuristics (REJECTED, never implemented here).
    // ---- Phase 4 V1.5 (LOCAL ONLY, stamp stays v3.20) ----
    // Adds, both OPT-IN via the boundary profile (absent = V1
    // behaviour exactly, so unprofiled runs are byte-identical):
    // (1) static-table region learning (design §1.3 source 2)
    // under the EVIDENCE RULE: table-present != table-applied. A
    // table entry becomes a region ONLY when (a) its symbol
    // resolves into a READ-ONLY block, (b) some function in the
    // image directly CALLs a profile-declared consumer function,
    // AND (c) that consumer's own must-fixpoint contains a LOAD
    // (or COPY-from-ram) resolving exactly to the table address
    // or into the config struct (consumer reads the table). Any
    // failing condition -> NO regions from that table, with the
    // status recorded in boundary_table_learning (never silent).
    // Learned regions sort BELOW profile regions (numbers from
    // -1000 under highest-wins, +1000 under lowest-wins), so an
    // explicit profile region always wins an overlap against a
    // derived one. Supported decodes: zephyr_mpu_v8 (Zephyr 4.4
    // ARMv8-M arm_mpu_region, no-PXN layout, verified on the
    // v2m_musca_b1 build), base_size, base_limit. Other Zephyr
    // versions/layouts (ARMv7-M RASR, PXN, ARMv8-R) are NOT
    // claimed: they need a new profile entry + verification.
    // (2) thread-entry attribution (design §2.2 item 4): direct
    // CALLs to k_thread_create / z_impl_k_thread_create (exact
    // API names, plus compiler-clone suffix variants of those
    // exact names) resolve entry = register arg 3 and options =
    // stack slot 4 (AAPCS: args 0-3 in r0-r3, options is arg 8)
    // from the call-site must-fixpoint (register + stk: cells).
    // K_USER bit (profile thread_user_option_bit, default 4 =
    // Zephyr BIT(2)) -> unprivileged, else privileged. A thread
    // entry also directly called elsewhere, or with conflicting
    // options across sites, is UNKNOWN (counted, never flagged):
    // per-function attribution cannot decide a two-privilege
    // function. Thread learning sets the PRIVILEGE axis only;
    // domain still comes from image/veneer. ARM AAPCS only.
    // NOT in V1.5 (design-only, see v15_report.md): config-write
    // learning with must-precede (the engine has no must-precede
    // reasoning: no dominators, no boot-order model, and SAU/MPU
    // config sequences need RNR-sequence order too). No
    // order-free config learning is implemented: the task
    // forbids faking must-precede with order-free reasoning.
    // Lean is UNCHANGED by V1.5: the verdict path reads only
    // boundary_sites + counts, which learned agents/regions feed
    // through unchanged; no new Lean lines are needed.
    // Violation rule (design §3, all six conditions required):
    // must-proven address, known agent, known region (or profile
    // default), agent not allowed on some leg (domain, privilege,
    // permission), no legitimate-crossing evidence, static regions.
    // Unknown agent / unknown region: NEVER a flag, ALWAYS counted
    // (boundary_unknown_agent_total /
    // boundary_unknown_region_total) — the zero-silent-gaps rule.
    // A violation is a NECESSARY condition for privilege
    // escalation, never proof of an exploit.
    //
    // Profile delivery (no new CLI flags, no ingest change): an
    // optional Ghidra script arg boundary_profile=<path>
    // (precedent: the existing mmio=/abi= script args), else a
    // sidecar <workspace>/binaries/<binary>.boundary.json derived
    // from the report output path. No profile -> boundary fields
    // are empty/zero and the Lean line passes vacuously (same
    // class as clock v1 no-RCC: no configured boundary to cross).

    /** Minimal JSON parser for boundary profiles (objects, arrays,
        strings with escapes, booleans, null, integers). No
        third-party dependency; a parse failure is reported by the
        caller and yields no profile, never a half-profile. */
    private static class MiniJson {
        final String s; int i;
        MiniJson(String s) { this.s = s; }
        Object parse() throws Exception {
            skip(); Object v = value(); skip();
            if (i != s.length()) throw new Exception("trailing data");
            return v;
        }
        void skip() {
            while (i < s.length() && Character.isWhitespace(s.charAt(i))) i++;
        }
        Object value() throws Exception {
            skip();
            if (i >= s.length()) throw new Exception("unexpected end");
            char c = s.charAt(i);
            if (c == '{') return obj();
            if (c == '[') return arr();
            if (c == '"') return str();
            if (c == 't') { expect("true"); return Boolean.TRUE; }
            if (c == 'f') { expect("false"); return Boolean.FALSE; }
            if (c == 'n') { expect("null"); return null; }
            return num();
        }
        void expect(String w) throws Exception {
            if (!s.startsWith(w, i)) throw new Exception("bad literal");
            i += w.length();
        }
        Map<String, Object> obj() throws Exception {
            Map<String, Object> m = new HashMap<String, Object>();
            i++; skip();
            if (i < s.length() && s.charAt(i) == '}') { i++; return m; }
            while (true) {
                skip();
                String k = str(); skip();
                if (i >= s.length() || s.charAt(i) != ':')
                    throw new Exception("expected ':'");
                i++; Object v = value(); m.put(k, v); skip();
                if (i < s.length() && s.charAt(i) == ',') { i++; continue; }
                if (i < s.length() && s.charAt(i) == '}') { i++; return m; }
                throw new Exception("expected ',' or '}'");
            }
        }
        List<Object> arr() throws Exception {
            List<Object> a = new ArrayList<Object>();
            i++; skip();
            if (i < s.length() && s.charAt(i) == ']') { i++; return a; }
            while (true) {
                a.add(value()); skip();
                if (i < s.length() && s.charAt(i) == ',') { i++; continue; }
                if (i < s.length() && s.charAt(i) == ']') { i++; return a; }
                throw new Exception("expected ',' or ']'");
            }
        }
        String str() throws Exception {
            if (s.charAt(i) != '"') throw new Exception("expected string");
            i++; StringBuilder b = new StringBuilder();
            while (i < s.length()) {
                char c = s.charAt(i++);
                if (c == '"') return b.toString();
                if (c == '\\') {
                    if (i >= s.length()) break;
                    char e = s.charAt(i++);
                    if (e == 'u') {
                        b.append((char) Integer.parseInt(
                            s.substring(i, i + 4), 16)); i += 4;
                    } else if (e == 'n') b.append('\n');
                    else if (e == 't') b.append('\t');
                    else if (e == 'r') b.append('\r');
                    else b.append(e);
                } else b.append(c);
            }
            throw new Exception("unterminated string");
        }
        Object num() throws Exception {
            int st = i;
            while (i < s.length() && "-+0123456789.eE".indexOf(
                s.charAt(i)) >= 0) i++;
            String t = s.substring(st, i);
            try {
                if (t.contains(".") || t.contains("e") || t.contains("E"))
                    return Double.parseDouble(t);
                return Long.parseLong(t);
            } catch (Exception e) {
                throw new Exception("bad number: " + t);
            }
        }
    }

    private static String mjStr(Map<String, Object> m, String k) {
        Object v = m.get(k);
        return (v instanceof String) ? (String) v : null;
    }
    private static Map<String, Object> mjObj(Object v) {
        if (v instanceof Map) {
            @SuppressWarnings("unchecked")
            Map<String, Object> m = (Map<String, Object>) v;
            return m;
        }
        return null;
    }
    private static List<Object> mjArr(Object v) {
        if (v instanceof List) {
            @SuppressWarnings("unchecked")
            List<Object> a = (List<Object>) v;
            return a;
        }
        return null;
    }
    private static long mjHex(Object v, long dflt) {
        if (v instanceof Number) return ((Number) v).longValue();
        if (v instanceof String) {
            String t = ((String) v).trim();
            try {
                if (t.startsWith("0x") || t.startsWith("0X"))
                    return Long.parseLong(t.substring(2), 16);
                return Long.parseLong(t);
            } catch (Exception e) { return dflt; }
        }
        return dflt;
    }
    private static boolean mjBool(Map<String, Object> m, String k,
        boolean dflt) {
        Object v = m.get(k);
        return (v instanceof Boolean) ? ((Boolean) v).booleanValue() : dflt;
    }
    private static long mjLong(Object v, long dflt) {
        if (v instanceof Number) return ((Number) v).longValue();
        if (v instanceof String) {
            String t = ((String) v).trim();
            try {
                if (t.startsWith("0x") || t.startsWith("0X"))
                    return Long.parseLong(t.substring(2), 16);
                return Long.parseLong(t);
            } catch (Exception e) { return dflt; }
        }
        return dflt;
    }

    private static class BoundaryRegion {
        String name; long start, end; String domain, minPriv;
        boolean read, write; long number; String source, mechanism;
        String json() {
            return "{\"name\": \"" + esc(name) + "\", \"start\": \"0x" +
                Long.toHexString(start) + "\", \"end\": \"0x" +
                Long.toHexString(end) + "\", \"domain\": \"" + domain +
                "\", \"min_privilege\": \"" + minPriv + "\", \"read\": " +
                read + ", \"write\": " + write + ", \"number\": " + number +
                ", \"source\": \"" + esc(source) + "\", \"mechanism\": \"" +
                esc(mechanism) + "\"}";
        }
    }

    /** One must-proven data access, for boundary judgment. The
        value is the STORE's exact value when known (null for LOADs
        and unknown values); DMA endpoint synthesis needs it. */
    private static class BoundaryAccess {
        String instr, op; long addr; Long value;
        BoundaryAccess(String instr, String op, long addr, Long value) {
            this.instr = instr; this.op = op; this.addr = addr;
            this.value = value;
        }
    }

    /** V1.5: one profile-declared static table to learn regions
        from. Field offsets are byte offsets within one entry;
        defaults are filled in per decode in parseBoundaryProfile
        (zephyr_mpu_v8 defaults differ from the generic ones). */
    private static class StaticTableSpec {
        String name, tableSymbol, configSymbol, decode, domain,
            mechanism, defMinPriv;
        long count = -1, countOff = 0, ptrOff = 4, stride = 0;
        long baseOff = 0, sizeOff = 4, limitOff = 8, attrOff = 8,
            nameOff = 4;
        boolean defRead = true, defWrite = true;
        List<String> consumerNames = new ArrayList<String>();
    }

    /** V1.5: one learned thread entry. priv == null means the
        function is NOT learnable (conflict across sites, or also
        directly called): evaluation treats it as unknown. */
    private static class ThreadEntry {
        String priv; int sites; String status;
        ThreadEntry(String p, int s, String st) {
            priv = p; sites = s; status = st;
        }
    }

    private static class BoundaryProfile {
        List<BoundaryRegion> regions = new ArrayList<BoundaryRegion>();
        boolean highestWins = true;
        boolean hasDefault = false;
        String defDomain, defPriv;
        String imageSec, imagePriv; // null = unknown
        boolean mpuPrivdefena = false;
        String source;
        Map<String, String> overrides = new HashMap<String, String>();
        Set<String> veneerNames = new HashSet<String>();
        // V1.5: opt-in learning inputs + results. Empty when the
        // profile declares neither (V1 behaviour, exactly).
        List<StaticTableSpec> staticTables =
            new ArrayList<StaticTableSpec>();
        boolean threadLearning = false;
        Set<String> threadCreateNames = new HashSet<String>();
        long threadUserBit = 4;
        Map<String, ThreadEntry> threadEntries =
            new HashMap<String, ThreadEntry>();
        int threadUnresolvedSites = 0;
        List<String> tableLearningJson = new ArrayList<String>();
        // controller name -> [domain, privilege]
        Map<String, String[]> dmaControllers =
            new HashMap<String, String[]>();
        /** Winning region covering addr under the set's precedence
            (highest number wins by default, lowest wins for a
            PMP-style set). Null when no region covers addr. */
        BoundaryRegion regionFor(long addr) {
            BoundaryRegion win = null;
            for (BoundaryRegion r : regions) {
                if (addr < r.start || addr >= r.end) continue;
                if (win == null) { win = r; continue; }
                if (highestWins ? r.number > win.number
                    : r.number < win.number) win = r;
            }
            return win;
        }
        /** Region for judgment: the winning region, else the
            profile default as a pseudo-region, else null (UNKNOWN
            region — counted, never flagged). The MPU background
            rule is NOT folded in here; the evaluator applies it
            explicitly so the two cases stay distinguishable. */
        BoundaryRegion resolveOrDefault(long addr) {
            BoundaryRegion r = regionFor(addr);
            if (r != null) return r;
            if (!hasDefault) return null;
            BoundaryRegion d = new BoundaryRegion();
            d.name = "default"; d.start = addr; d.end = addr + 1;
            d.domain = defDomain; d.minPriv = defPriv;
            d.read = true; d.write = true; d.number = -1;
            d.source = "profile-default"; d.mechanism = "profile-only";
            return d;
        }
    }

    private BoundaryProfile loadBoundaryProfile(String outputJson) {
        String explicit = null;
        for (String a : getScriptArgs()) {
            if (a.startsWith("boundary_profile="))
                explicit = a.substring("boundary_profile=".length());
        }
        List<String> candidates = new ArrayList<String>();
        if (explicit != null) {
            candidates.add(explicit);
        } else {
            try {
                File out = new File(outputJson);
                File reportsDir = out.getParentFile();
                File ws = (reportsDir != null)
                    ? reportsDir.getParentFile() : null;
                if (ws != null) {
                    candidates.add(new File(new File(ws, "binaries"),
                        currentProgram.getName() + ".boundary.json")
                        .getPath());
                }
                if (reportsDir != null) {
                    candidates.add(new File(reportsDir,
                        currentProgram.getName() + ".boundary.json")
                        .getPath());
                }
            } catch (Exception e) {
                // Sidecar discovery is best-effort; no profile then.
            }
        }
        for (String cand : candidates) {
            File f = new File(cand);
            if (!f.isFile()) {
                if (explicit != null)
                    println("[!] boundary: explicit profile not found: "
                        + cand);
                continue;
            }
            try {
                StringBuilder sb = new StringBuilder();
                java.io.BufferedReader br =
                    new java.io.BufferedReader(new java.io.FileReader(f));
                String line;
                while ((line = br.readLine()) != null) sb.append(line)
                    .append("\n");
                br.close();
                Object parsed = new MiniJson(sb.toString()).parse();
                Map<String, Object> root = mjObj(parsed);
                if (root == null) throw new Exception("root not object");
                BoundaryProfile p = parseBoundaryProfile(root);
                p.source = f.getPath();
                // Image selection: program name minus extension
                // (ns_image.elf -> ns_image). No match -> image
                // agent unknown (counted per access, never guessed).
                String prog = currentProgram.getName();
                String key = prog;
                int dot = prog.lastIndexOf('.');
                if (dot > 0) key = prog.substring(0, dot);
                Map<String, Object> images = mjObj(root.get("images"));
                Map<String, Object> img = (images != null)
                    ? mjObj(images.get(key)) : null;
                if (img == null && images != null)
                    img = mjObj(images.get(prog));
                if (img != null) {
                    p.imageSec = mjStr(img, "security_state");
                    if ("unknown".equals(p.imageSec)) p.imageSec = null;
                    p.imagePriv = mjStr(img, "privilege");
                    if ("unknown".equals(p.imagePriv)) p.imagePriv = null;
                    if (!p.hasDefault) {
                        Map<String, Object> da =
                            mjObj(img.get("default_attribute"));
                        if (da != null) {
                            p.defDomain = mjStr(da, "domain");
                            p.defPriv = mjStr(da, "min_privilege");
                            if (p.defDomain != null && p.defPriv != null)
                                p.hasDefault = true;
                        }
                    }
                    // V1.5 fix (pre-existing V1 bug): profiles
                    // without function_agent_overrides NPE'd here
                    // (mjObj(null).get) and lost the whole profile.
                    // All V1 profiles happened to carry overrides,
                    // so it never fired until V1.5 profiles omitted
                    // the section. Absent overrides = none, not an
                    // unusable profile.
                    Map<String, Object> ovsRoot = mjObj(
                        root.get("function_agent_overrides"));
                    Map<String, Object> ovs = (ovsRoot != null)
                        ? mjObj(ovsRoot.get(key)) : null;
                    if (ovs == null && ovsRoot != null)
                        ovs = mjObj(ovsRoot.get(prog));
                    if (ovs != null) {
                        for (Map.Entry<String, Object> e : ovs.entrySet()) {
                            if (e.getKey().startsWith("_")) continue;
                            Map<String, Object> o = mjObj(e.getValue());
                            String ag = (o != null)
                                ? mjStr(o, "agent") : null;
                            if (ag == null && e.getValue() instanceof String)
                                ag = (String) e.getValue();
                            if (ag != null)
                                p.overrides.put(e.getKey(), ag);
                        }
                    }
                }
                println("[*] boundary: profile " + f.getPath() +
                    " image=" + key + " regions=" + p.regions.size() +
                    " imageSec=" + p.imageSec + " imagePriv=" +
                    p.imagePriv + " default=" + p.hasDefault);
                return p;
            } catch (Exception e) {
                println("[!] boundary: profile " + cand +
                    " unusable (" + e.getMessage() + "); no boundary.");
                return null;
            }
        }
        println("[*] boundary: no profile; verdict vacuous (no " +
            "configured boundary to cross).");
        return null;
    }

    private BoundaryProfile parseBoundaryProfile(Map<String, Object> root) {
        BoundaryProfile p = new BoundaryProfile();
        String prec = mjStr(root, "boundary_precedence");
        if ("lowest-wins".equals(prec)) p.highestWins = false;
        Map<String, Object> da = mjObj(root.get("boundary_default_attribute"));
        if (da != null) {
            p.defDomain = mjStr(da, "domain");
            p.defPriv = mjStr(da, "min_privilege");
            if (p.defDomain != null && p.defPriv != null)
                p.hasDefault = true;
        }
        p.mpuPrivdefena = mjBool(root, "mpu_privdefena", false);
        List<Object> vlist = mjArr(root.get("veneer_functions"));
        if (vlist != null) {
            for (Object v : vlist)
                if (v instanceof String) p.veneerNames.add((String) v);
        }
        Map<String, Object> dmas = mjObj(root.get("dma_controllers"));
        if (dmas != null) {
            for (Map.Entry<String, Object> e : dmas.entrySet()) {
                Map<String, Object> c = mjObj(e.getValue());
                if (c == null) continue;
                String dom = mjStr(c, "domain");
                String priv = mjStr(c, "privilege");
                if (dom != null)
                    p.dmaControllers.put(e.getKey(), new String[] { dom,
                        (priv != null) ? priv : "any" });
            }
        }
        // V1.5: static-table specs + thread-entry learning flags.
        // thread_create_functions defaults (when learning is on
        // and no list is given) to the two Zephyr entry points:
        // the public API and its syscall implementation, which
        // compiler-specialized clones forward to.
        p.threadLearning = mjBool(root, "thread_entry_learning",
            false);
        p.threadUserBit = mjLong(root.get("thread_user_option_bit"),
            4);
        List<Object> tcf = mjArr(root.get("thread_create_functions"));
        if (tcf != null) {
            for (Object v : tcf)
                if (v instanceof String) p.threadCreateNames.add(
                    (String) v);
        } else if (p.threadLearning) {
            p.threadCreateNames.add("k_thread_create");
            p.threadCreateNames.add("z_impl_k_thread_create");
        }
        List<Object> tabs = mjArr(root.get("static_tables"));
        if (tabs != null) {
            for (Object tv : tabs) {
                Map<String, Object> t = mjObj(tv);
                if (t == null) continue;
                StaticTableSpec sp = new StaticTableSpec();
                sp.name = mjStr(t, "name");
                if (sp.name == null) continue;
                sp.tableSymbol = mjStr(t, "table_symbol");
                sp.configSymbol = mjStr(t, "config_symbol");
                sp.decode = mjStr(t, "decode");
                if (sp.decode == null) sp.decode = "base_size";
                sp.domain = mjStr(t, "domain");
                if (sp.domain == null) sp.domain = "both";
                sp.mechanism = mjStr(t, "mechanism");
                if (sp.mechanism == null) sp.mechanism = "mpu";
                sp.defMinPriv = mjStr(t, "default_min_privilege");
                if (sp.defMinPriv == null) sp.defMinPriv = "any";
                sp.defRead = mjBool(t, "default_read", true);
                sp.defWrite = mjBool(t, "default_write", true);
                sp.count = mjLong(t.get("count"), -1);
                sp.countOff = mjLong(t.get("count_offset"), 0);
                sp.ptrOff = mjLong(t.get("ptr_offset"), 4);
                List<Object> cons =
                    mjArr(t.get("consumer_functions"));
                if (cons != null) {
                    for (Object cv : cons)
                        if (cv instanceof String)
                            sp.consumerNames.add((String) cv);
                }
                sp.stride = mjLong(t.get("stride"), 0);
                // Decode-specific field defaults: the Zephyr
                // ARMv8-M layout is {base u32, name ptr,
                // attr bitfields byte + pad, r_limit u32}
                // (stride 16, no-PXN); generic tables default
                // to {base, size} pairs.
                if ("zephyr_mpu_v8".equals(sp.decode)) {
                    sp.baseOff = mjLong(t.get("base_offset"), 0);
                    sp.nameOff = mjLong(t.get("name_offset"), 4);
                    sp.attrOff = mjLong(t.get("attr_offset"), 8);
                    sp.limitOff = mjLong(t.get("limit_offset"), 12);
                    if (sp.stride == 0) sp.stride = 16;
                } else {
                    sp.baseOff = mjLong(t.get("base_offset"), 0);
                    sp.sizeOff = mjLong(t.get("size_offset"), 4);
                    sp.limitOff = mjLong(t.get("limit_offset"), 8);
                    sp.attrOff = mjLong(t.get("attr_offset"), 8);
                    sp.nameOff = mjLong(t.get("name_offset"), 4);
                }
                p.staticTables.add(sp);
            }
        }
        List<Object> regs = mjArr(root.get("regions"));
        if (regs != null) {
            for (Object rv : regs) {
                Map<String, Object> r = mjObj(rv);
                if (r == null) continue;
                BoundaryRegion br = new BoundaryRegion();
                br.name = mjStr(r, "name");
                if (br.name == null) continue;
                br.start = mjHex(r.get("start"), 0);
                br.end = mjHex(r.get("end"), 0);
                br.domain = mjStr(r, "domain");
                if (br.domain == null) br.domain = "both";
                br.minPriv = mjStr(r, "min_privilege");
                if (br.minPriv == null) br.minPriv = "any";
                br.read = mjBool(r, "read", true);
                br.write = mjBool(r, "write", true);
                Object num = r.get("number");
                br.number = (num instanceof Number)
                    ? ((Number) num).longValue() : 0;
                br.source = mjStr(r, "source");
                if (br.source == null) br.source = "profile";
                br.mechanism = mjStr(r, "mechanism");
                if (br.mechanism == null) br.mechanism = "profile-only";
                p.regions.add(br);
            }
        }
        return p;
    }

    /** Agent as (domain, privilege, kind) with per-axis unknown
        (null). Fully unknown (both axes null) -> unknown-agent
        count, never a flag. A single known axis is still judged
        on that axis (miss direction on the unknown axis only). */
    private static class BoundaryAgent {
        String domain, priv, kind;
        BoundaryAgent(String d, String pr, String k) {
            domain = d; priv = pr; kind = k;
        }
        boolean fullyUnknown() { return domain == null && priv == null; }
        String label() {
            if ("dma".equals(kind)) return "dma";
            if ("unprivileged".equals(priv))
                return (domain == null ? "unknown" : domain)
                    + "-unprivileged";
            return (domain == null ? "unknown" : domain) + "-cpu";
        }
    }

    /** Parse a profile agent string: secure-cpu,
        nonsecure-unprivileged, secure-unprivileged, dma, unknown. */
    private BoundaryAgent agentFromString(String s, BoundaryProfile p) {
        if (s == null || "unknown".equals(s)) return null;
        if ("dma".equals(s)) return new BoundaryAgent(null, null, "dma");
        String dom = null, priv = "privileged";
        if (s.contains("secure") && !s.contains("nonsecure"))
            dom = "secure";
        else if (s.contains("nonsecure")) dom = "nonsecure";
        if (s.contains("unprivileged")) priv = "unprivileged";
        return new BoundaryAgent(dom, priv, "cpu");
    }

    private static class BoundaryEval {
        List<String> siteJsons = new ArrayList<String>();
        int checked, violations, unknownAgent, unknownRegion;
    }

    /** Judge one access. Returns the violation leg, or null when
        compliant, unknown, or background-ruled. Counts unknowns
        in the eval record. Leg order: domain, privilege,
        permission (first failing leg is reported). */
    private String judgeAccess(BoundaryEval ev, BoundaryAgent ag,
        long addr, String kind, BoundaryProfile p) {
        if (ag == null || ag.fullyUnknown()) {
            ev.unknownAgent++;
            return null;
        }
        BoundaryRegion r = p.resolveOrDefault(addr);
        if (r == null) {
            // MPU background rule (profile fact only): a
            // privileged agent may touch an unmatched address
            // when PRIVDEFENA is set; an unprivileged agent may
            // not (that access faults -> privilege-leg violation
            // on the background rule). Without PRIVDEFENA the
            // address is UNKNOWN: counted, never flagged.
            if (p.mpuPrivdefena && "privileged".equals(ag.priv))
                return null;
            if (p.mpuPrivdefena && "unprivileged".equals(ag.priv))
                return "privilege";
            ev.unknownRegion++;
            return null;
        }
        if (ag.domain != null && !"both".equals(r.domain)
            && !r.domain.equals(ag.domain)) return "domain";
        if (ag.priv != null && !"any".equals(ag.priv)
            && "privileged".equals(r.minPriv)
            && !"privileged".equals(ag.priv)) return "privilege";
        if ("read".equals(kind) && !r.read) return "permission";
        if ("write".equals(kind) && !r.write) return "permission";
        return null;
    }

    private void emitBoundarySite(BoundaryEval ev, String fn, long addr,
        BoundaryAgent ag, BoundaryRegion r, String kind, String leg) {
        String regionName = (r != null) ? r.name : "background";
        ev.siteJsons.add("{\"function\": \"" + esc(fn) +
            "\", \"address\": \"0x" + Long.toHexString(addr) +
            "\", \"agent\": \"" + ag.label() + "\", \"region\": \"" +
            esc(regionName) + "\", \"kind\": \"" + kind +
            "\", \"leg\": \"" + leg + "\", \"violated\": true}");
        ev.violations++;
    }

    /** SG at function entry (TrustZone-M veneer). Ghidra's ARM
        lifting is checked empirically (see implementation.md);
        when SG is not lifted this returns false and the profile
        veneer list is the fallback. Only the FIRST instruction
        counts: a veneer entry is SG, nothing else. */
    private boolean functionStartsWithSg(List<OpRec> ops) {
        for (OpRec op : ops) {
            if (op.instrAsm == null) continue;
            String a = op.instrAsm.trim();
            if (a.isEmpty()) continue;
            String tok = a.split("[\\s,]+")[0].toLowerCase();
            return "sg".equals(tok);
        }
        return false;
    }

    /** Evaluate one function's must accesses under the boundary
        profile. Data accesses of a dma-programming function are
        judged as CPU accesses (the PROGRAMMING leg); the transfer
        it programs is judged separately as DMA-agent accesses
        (the TRANSFER leg) — the two-judgment rule, design §2.4. */
    private BoundaryEval evaluateBoundary(String fn, List<OpRec> ops,
        List<BoundaryAccess> accesses, BoundaryProfile p) {
        BoundaryEval ev = new BoundaryEval();
        // Dedup by (instr, op, addr), first occurrence wins:
        // main-loop findings and clone-replay findings for the
        // same access are ONE candidate (mirroring the mmio
        // list's identity dedup; value refinement is deliberately
        // not emitted, same policy as persite extras).
        List<BoundaryAccess> deduped = new ArrayList<BoundaryAccess>();
        Set<String> seenBnd = new HashSet<String>();
        for (BoundaryAccess a : accesses) {
            String id = a.instr + ":" + a.op + ":0x" +
                Long.toHexString(a.addr);
            if (seenBnd.add(id)) deduped.add(a);
        }
        accesses = deduped;
        boolean isVeneer = functionStartsWithSg(ops)
            || p.veneerNames.contains(fn);
        String override = p.overrides.get(fn);
        boolean isDmaProg = "dma".equals(override);
        BoundaryAgent imageAgent = new BoundaryAgent(
            p.imageSec, p.imagePriv, "cpu");
        BoundaryAgent dataAgent;
        if (isDmaProg) {
            dataAgent = imageAgent; // programming leg: CPU agent
        } else if (override != null) {
            dataAgent = agentFromString(override, p);
            if (dataAgent == null)
                dataAgent = new BoundaryAgent(null, null, "cpu");
        } else {
            // V1.5 composition: image default, veneer sets the
            // DOMAIN axis (secure), thread-entry learning sets
            // the PRIVILEGE axis (or unknown on conflict /
            // also-direct-called). Profile overrides (above)
            // still win over both learned signals.
            dataAgent = imageAgent;
            if (isVeneer) {
                // Veneer body executes secure; privilege stays
                // the image's (null when undeclared -> privilege
                // leg passes, domain leg still judged; miss
                // direction).
                dataAgent = new BoundaryAgent("secure",
                    p.imagePriv, "cpu");
            }
            ThreadEntry te = p.threadEntries.get(fn);
            if (te != null) {
                if (te.priv == null) {
                    dataAgent = new BoundaryAgent(null, null,
                        "cpu");
                } else {
                    dataAgent = new BoundaryAgent(dataAgent.domain,
                        te.priv, "cpu");
                }
            }
        }
        for (BoundaryAccess a : accesses) {
            ev.checked++;
            String kind = "STORE".equals(a.op) ? "write" : "read";
            // Background-rule violations need a region name for
            // the site; judgeAccess returns the leg, and the
            // region is resolved again here for emission.
            BoundaryRegion r = p.resolveOrDefault(a.addr);
            String leg = judgeAccess(ev, dataAgent, a.addr, kind, p);
            if (leg != null) emitBoundarySite(ev, fn, a.addr,
                dataAgent, r, kind, leg);
        }
        // ---- DMA transfer synthesis (V1, narrow and declared) ----
        // Only in a profile-declared programming function, only
        // when the controller is unambiguous (exactly one profile
        // controller), only for stored values that resolve to a
        // boundary region (literal endpoints). Endpoints in
        // register-offset order: lowest offset = source (read
        // leg), next = destination (write leg). A different
        // controller register layout needs a profile register map
        // (V1.5); this rule never guesses one.
        if (isDmaProg && p.dmaControllers.size() == 1) {
            Map.Entry<String, String[]> ctrl =
                p.dmaControllers.entrySet().iterator().next();
            BoundaryAgent dmaAgent = new BoundaryAgent(
                ctrl.getValue()[0], ctrl.getValue()[1], "dma");
            List<BoundaryAccess> endpoints =
                new ArrayList<BoundaryAccess>();
            for (BoundaryAccess a : accesses) {
                if (!"STORE".equals(a.op) || a.value == null) continue;
                if (p.regionFor(a.value.longValue()) == null) continue;
                endpoints.add(a);
            }
            java.util.Collections.sort(endpoints,
                new java.util.Comparator<BoundaryAccess>() {
                    public int compare(BoundaryAccess x,
                        BoundaryAccess y) {
                        return Long.compare(x.addr, y.addr);
                    }
                });
            if (endpoints.size() >= 2) {
                long src = endpoints.get(0).value.longValue();
                long dst = endpoints.get(1).value.longValue();
                BoundaryRegion rs = p.resolveOrDefault(src);
                BoundaryRegion rd = p.resolveOrDefault(dst);
                ev.checked++;
                String legS = judgeAccess(ev, dmaAgent, src, "read", p);
                if (legS != null) emitBoundarySite(ev, fn, src,
                    dmaAgent, rs, "read", legS);
                ev.checked++;
                String legD = judgeAccess(ev, dmaAgent, dst, "write", p);
                if (legD != null) emitBoundarySite(ev, fn, dst,
                    dmaAgent, rd, "write", legD);
            }
        }
        return ev;
    }

    // ============ Phase 4 V1.5: static-table learning ============
    // Evidence rule (design §1.3, table-present != table-applied):
    // a table yields regions ONLY when symbol + read-only block +
    // direct consumer call + consumer reads table/config ALL hold.
    // Every failure mode is recorded (never silent) and yields
    // zero regions from that table. Evidence is checked BEFORE
    // decoding, so an unapplied table's bytes are never trusted.

    private Long findSymbolAddress(String name) {
        if (name == null) return null;
        try {
            SymbolIterator sit =
                currentProgram.getSymbolTable().getSymbolIterator();
            while (sit.hasNext()) {
                Symbol s = sit.next();
                if (name.equals(s.getName()))
                    return s.getAddress().getOffset();
            }
        } catch (Exception e) {
            // No symbol: the caller records no-symbol.
        }
        return null;
    }

    private Long readMemU32(long addr) {
        try {
            return currentProgram.getMemory().getInt(toAddr(addr))
                & 0xffffffffL;
        } catch (Exception e) {
            return null;
        }
    }

    private Long readMemU8(long addr) {
        try {
            return (long) (currentProgram.getMemory().getByte(
                toAddr(addr)) & 0xff);
        } catch (Exception e) {
            return null;
        }
    }

    /** C string at addr from program memory (max 64 chars,
        printable ASCII only); null when unreadable. Used only
        for learned-region names; a failure never blocks learning. */
    private String readMemCString(long addr) {
        try {
            Memory mem = currentProgram.getMemory();
            StringBuilder b = new StringBuilder();
            for (int i = 0; i < 64; i++) {
                byte c = mem.getByte(toAddr(addr + i));
                if (c == 0) {
                    if (b.length() == 0) return null;
                    return b.toString();
                }
                if (c < 32 || c > 126) return null;
                b.append((char) c);
            }
            return null;
        } catch (Exception e) {
            return null;
        }
    }

    /** True when some function in the image directly CALLs a
        function whose name matches target (exact, or target +
        "." + a compiler-clone suffix). CALLIND never counts:
        an indirect call target is not a proven consumer call. */
    private boolean anyDirectCallTo(List<FuncRec> funcRecs,
        Map<Long, FuncRec> funcByEntry, String target) {
        for (FuncRec rec : funcRecs) {
            for (OpRec op : rec.or.ops) {
                if (!"CALL".equals(op.mnem) || op.ins.length < 1)
                    continue;
                Varnode t = op.ins[0];
                if (t == null || t.getAddress() == null ||
                    !"ram".equals(t.getAddress().getAddressSpace()
                        .getName())) continue;
                FuncRec callee = funcByEntry.get(t.getOffset());
                if (callee == null) callee = funcByEntry.get(
                    isa.stripInstructionTag(t.getOffset()));
                if (callee == null) continue;
                String nm = callee.f.getName();
                if (target.equals(nm) ||
                    nm.startsWith(target + ".")) return true;
            }
        }
        return false;
    }

    /** True when any function named target (exact or clone
        suffix) contains a LOAD (or COPY-from-ram) whose address
        resolves exactly, in its own must-fixpoint, to tableAddr
        or into [configAddr, configAddr + 8) (the config struct's
        count + pointer words). A non-converged fixpoint has
        emptied states, so this fails closed (no evidence). */
    private boolean consumerReadsTable(List<FuncRec> funcRecs,
        String target, long tableAddr, Long configAddr) {
        for (FuncRec rec : funcRecs) {
            String nm = rec.f.getName();
            if (!target.equals(nm) && !nm.startsWith(target + "."))
                continue;
            if (rec.fx == null || !rec.fx.converged ||
                rec.fx.inStates == null) continue;
            List<OpRec> ops = rec.or.ops;
            for (int i = 0; i < ops.size(); i++) {
                OpRec op = ops.get(i);
                if (i >= rec.fx.inStates.length ||
                    rec.fx.inStates[i] == null) continue;
                if ("LOAD".equals(op.mnem) && op.ins.length >= 2) {
                    Long a = resolveAddressExact(op.ins[1],
                        rec.fx.inStates[i]);
                    if (a != null && (a.longValue() == tableAddr ||
                        (configAddr != null &&
                            a.longValue() >= configAddr.longValue() &&
                            a.longValue() < configAddr.longValue() + 8)))
                        return true;
                } else if ("COPY".equals(op.mnem) &&
                    op.ins.length >= 1 && op.ins[0] != null &&
                    op.ins[0].getAddress() != null &&
                    "ram".equals(op.ins[0].getAddress()
                        .getAddressSpace().getName())) {
                    long a = op.ins[0].getOffset();
                    if (a == tableAddr || (configAddr != null &&
                        a >= configAddr.longValue() &&
                        a < configAddr.longValue() + 8)) return true;
                }
            }
        }
        return false;
    }

    private void recordTableStatus(BoundaryProfile p, String name,
        String status, int regions) {
        p.tableLearningJson.add("{\"table\": \"" + esc(name) +
            "\", \"status\": \"" + status + "\", \"regions\": " +
            regions + "}");
        println("[*] boundary table: " + name + " -> " + status +
            " (" + regions + " regions)");
    }

    /** V1.5 item 1. Appends learned regions to p.regions (with
        below-profile numbers) and records one status per table.
        Call once, before the emission loop, so learned regions
        feed the RAM-extension check and the report JSON. */
    private void learnStaticTables(BoundaryProfile p,
        List<FuncRec> funcRecs, Map<Long, FuncRec> funcByEntry) {
        if (p.staticTables.isEmpty()) return;
        Memory mem = currentProgram.getMemory();
        int learnedIdx = 0;
        for (StaticTableSpec sp : p.staticTables) {
            Long symAddr = (sp.tableSymbol == null) ? null
                : findSymbolAddress(sp.tableSymbol);
            Long cfgAddr = (sp.configSymbol == null) ? null
                : findSymbolAddress(sp.configSymbol);
            if (sp.tableSymbol == null && sp.configSymbol == null) {
                recordTableStatus(p, sp.name, "no-symbol", 0);
                continue;
            }
            if ((sp.tableSymbol != null && symAddr == null &&
                sp.configSymbol == null) ||
                (sp.configSymbol != null && cfgAddr == null)) {
                recordTableStatus(p, sp.name, "no-symbol", 0);
                continue;
            }
            // Block gate: the probed address (table symbol, else
            // config struct) must sit in a read-only block. A
            // writable table can be rewritten at runtime, so its
            // bytes prove nothing static.
            long probeAddr = (symAddr != null)
                ? symAddr.longValue() : cfgAddr.longValue();
            MemoryBlock blk = null;
            try {
                blk = mem.getBlock(toAddr(probeAddr));
            } catch (Exception e) {
                blk = null;
            }
            if (blk == null) {
                recordTableStatus(p, sp.name, "no-block", 0);
                continue;
            }
            if (blk.isWrite()) {
                recordTableStatus(p, sp.name, "writable-block", 0);
                continue;
            }
            // Evidence, in order. The consumer list is a profile
            // field (the profile names the target's real
            // consumer, e.g. z_arm_mpu_init); this method never
            // guesses consumers. An empty consumer list can
            // never satisfy the rule.
            boolean called = false;
            for (String c : sp.consumerNames) {
                if (anyDirectCallTo(funcRecs, funcByEntry, c)) {
                    called = true;
                    break;
                }
            }
            if (!called) {
                recordTableStatus(p, sp.name, "no-call", 0);
                continue;
            }
            boolean reads = false;
            for (String c : sp.consumerNames) {
                if (consumerReadsTable(funcRecs, c,
                    probeAddr, cfgAddr)) {
                    reads = true;
                    break;
                }
            }
            if (!reads) {
                recordTableStatus(p, sp.name, "no-reference", 0);
                continue;
            }
            // Decode. Count + table address come from the config
            // struct when one is declared (the config is what
            // the consumer reads); otherwise from the symbol +
            // profile count. A config pointer disagreeing with
            // the table symbol fails closed (config-mismatch).
            Long count = null;
            Long tableAddr = null;
            if (cfgAddr != null) {
                count = readMemU32(cfgAddr.longValue()
                    + sp.countOff);
                Long ptr = readMemU32(cfgAddr.longValue()
                    + sp.ptrOff);
                if (count == null || ptr == null) {
                    recordTableStatus(p, sp.name,
                        "decode-failed", 0);
                    continue;
                }
                tableAddr = ptr;
                if (symAddr != null &&
                    symAddr.longValue() != ptr.longValue()) {
                    recordTableStatus(p, sp.name,
                        "config-mismatch", 0);
                    continue;
                }
            } else {
                tableAddr = symAddr;
                if (sp.count >= 0) count = sp.count;
            }
            if (count == null || count.longValue() <= 0 ||
                count.longValue() > 64 || sp.stride <= 0) {
                recordTableStatus(p, sp.name, "decode-failed", 0);
                continue;
            }
            // The resolved table must itself be read-only.
            MemoryBlock tblk = null;
            try {
                tblk = mem.getBlock(toAddr(tableAddr.longValue()));
            } catch (Exception e) {
                tblk = null;
            }
            if (tblk == null || tblk.isWrite()) {
                recordTableStatus(p, sp.name,
                    tblk == null ? "no-block" : "writable-block",
                    0);
                continue;
            }
            List<BoundaryRegion> learned =
                new ArrayList<BoundaryRegion>();
            boolean bad = false;
            for (long i = 0; i < count.longValue(); i++) {
                long e = tableAddr.longValue() + i * sp.stride;
                Long base = readMemU32(e + sp.baseOff);
                if (base == null) { bad = true; break; }
                BoundaryRegion br = new BoundaryRegion();
                br.source = "static-table";
                br.mechanism = sp.mechanism;
                br.domain = sp.domain;
                if ("zephyr_mpu_v8".equals(sp.decode)) {
                    Long attr = readMemU8(e + sp.attrOff);
                    Long limit = readMemU32(e + sp.limitOff);
                    if (attr == null || limit == null) {
                        bad = true; break;
                    }
                    // ARMv8-M RBAR attr byte: SH[4:3], AP[2:1],
                    // XN[0]. AP 0 = P_RW_U_NA, 1 = P_RW_U_RW,
                    // 2 = P_RO_U_NA, 3 = P_RO_U_RO (CMSIS
                    // MPU_RBAR_AP_Pos = 1). XN is fetch, not
                    // data: ignored (design §5, no XN rule).
                    // RLAR limit field is 32-byte aligned;
                    // the region end is limit + 32 (exclusive).
                    long ap = (attr.longValue() >> 1) & 0x3L;
                    br.start = base.longValue() & ~0x1fL;
                    br.end = (limit.longValue() & ~0x1fL) + 0x20L;
                    br.minPriv = (ap == 1 || ap == 3)
                        ? "any" : "privileged";
                    br.read = true;
                    br.write = (ap == 0 || ap == 1);
                    Long nmPtr = readMemU32(e + sp.nameOff);
                    String nm = (nmPtr == null) ? null
                        : readMemCString(nmPtr.longValue());
                    br.name = (nm != null) ? nm
                        : sp.name + "#" + i;
                    if (br.start % 32 != 0 || br.end % 32 != 0) {
                        bad = true; break;
                    }
                } else if ("base_limit".equals(sp.decode)) {
                    Long limit = readMemU32(e + sp.limitOff);
                    if (limit == null) { bad = true; break; }
                    br.start = base.longValue();
                    br.end = limit.longValue();
                    br.minPriv = sp.defMinPriv;
                    br.read = sp.defRead;
                    br.write = sp.defWrite;
                    br.name = sp.name + "#" + i;
                } else {
                    // base_size (default generic decode).
                    Long size = readMemU32(e + sp.sizeOff);
                    if (size == null) { bad = true; break; }
                    br.start = base.longValue();
                    br.end = base.longValue() + size.longValue();
                    br.minPriv = sp.defMinPriv;
                    br.read = sp.defRead;
                    br.write = sp.defWrite;
                    br.name = sp.name + "#" + i;
                }
                if (br.start >= br.end ||
                    br.end - br.start > 0x80000000L) {
                    bad = true; break;
                }
                learned.add(br);
            }
            if (bad || learned.isEmpty()) {
                recordTableStatus(p, sp.name, "decode-failed", 0);
                continue;
            }
            // Learned regions sort BELOW profile regions: an
            // explicit profile region always wins an overlap
            // against a derived one (explicit beats derived).
            for (BoundaryRegion br : learned) {
                br.number = (p.highestWins ? -1000L : 1000L)
                    + learnedIdx;
                learnedIdx++;
                p.regions.add(br);
            }
            recordTableStatus(p, sp.name, "learned",
                learned.size());
        }
    }

    // ============ Phase 4 V1.5: thread-entry attribution ============
    // Zephyr userspace (design §2.2 item 4). A thread's entry
    // function runs at that thread's privilege: k_thread_create
    // (or its syscall implementation z_impl_k_thread_create, which
    // compiler-specialized clones forward to) is called with
    // entry in register arg 3 and options in stack slot 4 (arg 8
    // under AAPCS: args 0-3 in registers, args 4+ on the stack).
    // Resolution uses the caller function's must-fixpoint IN
    // state at the CALL op: registers for entry, stk: cells for
    // the stack slot (the CALL transfer drops stk: cells, so the
    // POST-call state must never be used here). A site that does
    // not resolve exactly (unknown entry, unknown options, entry
    // not a known function, non-converged fixpoint) is counted
    // in threadUnresolvedSites and learns nothing. Merging: one
    // privilege across all resolved sites -> learned; both
    // privileges -> conflict (unknown); an entry function that
    // is ALSO a direct CALL target runs at two privileges under
    // per-function attribution -> also-direct-called (unknown).
    // Unknown here means the evaluator counts the access as
    // unknown-agent, never flags it. K_THREAD_DEFINE static
    // threads are NOT covered: their records live in the
    // _static_thread_data section, whose layout was not
    // verified against a built image in this task (see
    // v15_report.md); adding it unverified would overclaim.
    // CONTROL/PSR tracking stays deferred to V2 (design §2.2.5);
    // PRIMASK/FAULTMASK/handler-ness/name heuristics are
    // REJECTED (design §2.3) and no such code exists here: the
    // callee-name match below identifies the Zephyr API
    // k_thread_create itself (design §2.2.4's own mechanism),
    // not a security property guessed from a name.

    private void learnThreadEntries(BoundaryProfile p,
        List<FuncRec> funcRecs, Map<Long, FuncRec> funcByEntry) {
        if (!p.threadLearning) return;
        if (!"ARM".equals(isa.name())) {
            println("[!] boundary thread-entry: non-ARM ISA (" +
                isa.name() + "); learning disabled, no entries.");
            return;
        }
        if (memSpOff < 0) {
            println("[!] boundary thread-entry: no SP register; " +
                "learning disabled, no entries.");
            return;
        }
        // Direct-call targets, for the also-direct-called rule.
        Set<String> calledNames = new HashSet<String>();
        for (FuncRec rec : funcRecs) {
            for (OpRec op : rec.or.ops) {
                if (!"CALL".equals(op.mnem) || op.ins.length < 1)
                    continue;
                Varnode t = op.ins[0];
                if (t == null || t.getAddress() == null ||
                    !"ram".equals(t.getAddress().getAddressSpace()
                        .getName())) continue;
                FuncRec callee = funcByEntry.get(t.getOffset());
                if (callee == null) callee = funcByEntry.get(
                    isa.stripInstructionTag(t.getOffset()));
                if (callee != null)
                    calledNames.add(callee.f.getName());
            }
        }
        Map<String, Set<String>> privsByEntry =
            new HashMap<String, Set<String>>();
        Map<String, Integer> sitesByEntry =
            new HashMap<String, Integer>();
        int unresolved = 0;
        int ps = isa.pointerSize();
        for (FuncRec rec : funcRecs) {
            if (rec.fx == null || !rec.fx.converged ||
                rec.fx.inStates == null) continue;
            List<OpRec> ops = rec.or.ops;
            for (int i = 0; i < ops.size(); i++) {
                OpRec op = ops.get(i);
                if (!"CALL".equals(op.mnem) || op.ins.length < 1)
                    continue;
                Varnode t = op.ins[0];
                if (t == null || t.getAddress() == null ||
                    !"ram".equals(t.getAddress().getAddressSpace()
                        .getName())) continue;
                FuncRec callee = funcByEntry.get(t.getOffset());
                if (callee == null) callee = funcByEntry.get(
                    isa.stripInstructionTag(t.getOffset()));
                if (callee == null) continue;
                String cnm = callee.f.getName();
                boolean isCreate = false;
                for (String tc : p.threadCreateNames) {
                    if (tc.equals(cnm) || cnm.startsWith(tc + ".")) {
                        isCreate = true;
                        break;
                    }
                }
                if (!isCreate) continue;
                if (i >= rec.fx.inStates.length ||
                    rec.fx.inStates[i] == null) {
                    unresolved++;
                    continue;
                }
                Map<String, Bits> st = rec.fx.inStates[i];
                // Forwarding-clone test: a k_thread_create callee
                // (never z_impl itself) whose body CALLs
                // z_impl_k_thread_create is a compiler-specialized
                // clone: its caller-site convention is NOT the
                // 10-arg layout (the real MPU build's clone takes
                // (thread, stack, entry) and bakes the rest), so
                // reading r3/options at the caller site would be
                // meaningless, and the clone's merged fixpoint
                // meets two different entries to unknown. Such
                // sites take Path 2 ONLY (never Path 1).
                boolean forwards = false;
                if (!cnm.equals("z_impl_k_thread_create") &&
                    !cnm.startsWith("z_impl_k_thread_create.")) {
                    for (OpRec cop : callee.or.ops) {
                        if (!"CALL".equals(cop.mnem) ||
                            cop.ins.length < 1) continue;
                        Varnode ct = cop.ins[0];
                        if (ct == null || ct.getAddress() == null ||
                            !"ram".equals(ct.getAddress()
                                .getAddressSpace().getName()))
                            continue;
                        FuncRec cc = funcByEntry.get(
                            ct.getOffset());
                        if (cc == null) cc = funcByEntry.get(
                            isa.stripInstructionTag(
                                ct.getOffset()));
                        if (cc == null) continue;
                        String ccn = cc.f.getName();
                        if ("z_impl_k_thread_create".equals(ccn) ||
                            ccn.startsWith(
                                "z_impl_k_thread_create.")) {
                            forwards = true;
                            break;
                        }
                    }
                }
                String priv = null;
                String enm = null;
                if (forwards) {
                    // Path 2: per-site seeded fixpoint. Seed the
                    // clone's fixpoint with THIS caller site's
                    // argument registers (only registers: entry
                    // maps never carry stk: cells, and the clone
                    // rebuilds its z_impl stack args in-body),
                    // run it, and read entry + options at the
                    // clone's own z_impl call. A non-converged
                    // rerun empties its states -> unresolved
                    // (fail closed, never a merged guess).
                    long[] cargRegs = null;
                    try {
                        cargRegs = isa.argumentRegisterOffsets(
                            callConvMap.get(callee.entryKey));
                    } catch (Exception e) {
                        cargRegs = null;
                    }
                    if (cargRegs != null && cargRegs.length >= 4) {
                        Map<String, Bits> seed =
                            new HashMap<String, Bits>();
                        for (long off : cargRegs) {
                            Varnode vn = regVarnode(off, ps);
                            if (vn == null) continue;
                            putKnown(seed, vkey(vn),
                                resolveBits(vn, st));
                        }
                        FixResult cfx = null;
                        try {
                            cfx = runFixpoint(callee.or.ops,
                                currentProgram.getMemory(),
                                callee.branchTargets, seed,
                                callee.loopCallOps);
                        } catch (Exception e) {
                            cfx = null;
                        }
                        if (cfx != null && cfx.converged &&
                            cfx.inStates != null) {
                            Set<String> pairs =
                                new HashSet<String>();
                            String pairEntry = null;
                            String pairPriv = null;
                            List<OpRec> cops = callee.or.ops;
                            for (int ci = 0; ci < cops.size();
                                ci++) {
                                OpRec cop = cops.get(ci);
                                if (!"CALL".equals(cop.mnem) ||
                                    cop.ins.length < 1) continue;
                                Varnode ct = cop.ins[0];
                                if (ct == null ||
                                    ct.getAddress() == null ||
                                    !"ram".equals(ct.getAddress()
                                        .getAddressSpace()
                                        .getName())) continue;
                                FuncRec cc = funcByEntry.get(
                                    ct.getOffset());
                                if (cc == null) cc =
                                    funcByEntry.get(
                                        isa.stripInstructionTag(
                                            ct.getOffset()));
                                if (cc == null) continue;
                                String ccn = cc.f.getName();
                                if (!"z_impl_k_thread_create"
                                    .equals(ccn) &&
                                    !ccn.startsWith(
                                        "z_impl_k_thread_create."))
                                    continue;
                                if (ci >= cfx.inStates.length ||
                                    cfx.inStates[ci] == null)
                                    continue;
                                Map<String, Bits> cst =
                                    cfx.inStates[ci];
                                long[] zarg = null;
                                try {
                                    zarg = isa
                                        .argumentRegisterOffsets(
                                            callConvMap.get(
                                                cc.entryKey));
                                } catch (Exception e) {
                                    zarg = null;
                                }
                                if (zarg == null ||
                                    zarg.length < 4) continue;
                                Varnode evn = regVarnode(
                                    zarg[3], ps);
                                if (evn == null) continue;
                                Long eval = resolveAddressExact(
                                    evn, cst);
                                if (eval == null) continue;
                                FuncRec erec = funcByEntry.get(
                                    eval.longValue());
                                if (erec == null) erec =
                                    funcByEntry.get(
                                        isa.stripInstructionTag(
                                            eval.longValue()));
                                if (erec == null) continue;
                                Varnode spv = regVarnode(
                                    memSpOff, ps);
                                if (spv == null) continue;
                                Bits spb = resolveBits(spv, cst);
                                long[] sps = (spb.sym == null)
                                    ? null
                                    : Bits.parseSpSym(spb.sym);
                                if (sps == null) continue;
                                Bits ob = stkLookup(cst, sps[0],
                                    sps[1] + 16, 4);
                                if (ob == null) continue;
                                Long oval = ob.exactValue(
                                    0xffffffffL);
                                if (oval == null) continue;
                                String pv = ((oval.longValue()
                                    & p.threadUserBit) != 0)
                                    ? "unprivileged"
                                    : "privileged";
                                pairs.add(erec.f.getName() + "\n"
                                    + pv);
                                pairEntry = erec.f.getName();
                                pairPriv = pv;
                            }
                            if (pairs.size() == 1) {
                                enm = pairEntry;
                                priv = pairPriv;
                            }
                        }
                    }
                    if (enm == null) { unresolved++; continue; }
                } else {
                    // Path 1: direct endpoint (the real
                    // k_thread_create, or z_impl itself): entry
                    // in register arg 3, options in stack slot 4
                    // (arg 8) = SP + 16 at the CALL. SP must be
                    // an SP symbol; the slot value comes from
                    // stk: cells (byte-assembling lookup covers
                    // strd 8-byte stores over slots 4-5).
                    long[] argRegs = null;
                    try {
                        argRegs = isa.argumentRegisterOffsets(
                            callConvMap.get(callee.entryKey));
                    } catch (Exception e) {
                        argRegs = null;
                    }
                    if (argRegs == null || argRegs.length < 4) {
                        unresolved++;
                        continue;
                    }
                    Varnode entryVn = regVarnode(argRegs[3], ps);
                    if (entryVn == null) { unresolved++; continue; }
                    Long entryVal = resolveAddressExact(entryVn, st);
                    if (entryVal == null) {
                        unresolved++;
                        continue;
                    }
                    FuncRec entryRec = funcByEntry.get(
                        entryVal.longValue());
                    if (entryRec == null) entryRec =
                        funcByEntry.get(isa.stripInstructionTag(
                            entryVal.longValue()));
                    if (entryRec == null) {
                        unresolved++;
                        continue;
                    }
                    Varnode spVn = regVarnode(memSpOff, ps);
                    if (spVn == null) { unresolved++; continue; }
                    Bits spBits = resolveBits(spVn, st);
                    long[] sps = (spBits.sym == null) ? null
                        : Bits.parseSpSym(spBits.sym);
                    if (sps == null) { unresolved++; continue; }
                    Bits optBits = stkLookup(st, sps[0],
                        sps[1] + 16, 4);
                    if (optBits == null) {
                        unresolved++;
                        continue;
                    }
                    Long optVal = optBits.exactValue(0xffffffffL);
                    if (optVal == null) {
                        unresolved++;
                        continue;
                    }
                    priv = ((optVal.longValue()
                        & p.threadUserBit) != 0) ? "unprivileged"
                        : "privileged";
                    enm = entryRec.f.getName();
                }
                Set<String> s = privsByEntry.get(enm);
                if (s == null) {
                    s = new HashSet<String>();
                    privsByEntry.put(enm, s);
                }
                s.add(priv);
                Integer c = sitesByEntry.get(enm);
                sitesByEntry.put(enm, (c == null) ? 1 : c + 1);
            }
        }
        p.threadUnresolvedSites = unresolved;
        for (Map.Entry<String, Set<String>> e :
            privsByEntry.entrySet()) {
            String enm = e.getKey();
            int sites = sitesByEntry.get(enm).intValue();
            ThreadEntry te;
            if (calledNames.contains(enm)) {
                te = new ThreadEntry(null, sites,
                    "also-direct-called");
            } else if (e.getValue().size() == 1) {
                te = new ThreadEntry(
                    e.getValue().iterator().next(), sites,
                    "learned");
            } else {
                te = new ThreadEntry(null, sites, "conflict");
            }
            p.threadEntries.put(enm, te);
            println("[*] boundary thread-entry: " + enm + " -> " +
                te.status + (te.priv == null ? "" :
                    " (" + te.priv + ")") + " [" + sites +
                " site(s)]");
        }
        println("[*] boundary thread-entry: unresolved sites=" +
            unresolved + ", entries=" + p.threadEntries.size());
    }

    @Override
    public void run() throws Exception {
        if (getScriptArgs().length < 1) {
            println("[!] ExtractIR needs an output JSON path argument.");
            return;
        }
        String outputJson = getScriptArgs()[0];
        // ISA selection: Ghidra auto-detects the language on import
        // (ingest passes no language flag), so select the adapter from
        // the program's processor. Default stays ARM (pre-step-1
        // behaviour, unchanged for ARM programs).
        String proc = currentProgram.getLanguage().getProcessor().toString();
        if ("RISCV".equals(proc)) {
            boolean is64 = false;
            try {
                String langId = currentProgram.getLanguage()
                    .getLanguageID().getIdAsString();
                String[] parts = langId.split(":");
                is64 = parts.length >= 3 && "64".equals(parts[2]);
            } catch (Exception e) {
                // Fall through to RV32.
            }
            List<long[]> windows = defaultRiscvMmioWindows();
            if (getScriptArgs().length >= 2 &&
                getScriptArgs()[1].startsWith("mmio=")) {
                List<long[]> parsed = parseMmioWindows(
                    getScriptArgs()[1].substring(5));
                if (parsed != null && !parsed.isEmpty()) {
                    windows = parsed;
                } else {
                    println("[!] Bad mmio= window spec, using " +
                        "RISC-V defaults.");
                }
            }
            isa = new RiscVIsa(is64, windows);
            println("[*] ISA adapter: RISCV (" + (is64 ? "RV64" : "RV32") +
                ")");
        } else if ("MIPS".equals(proc)) {
            boolean is64 = false;
            try {
                String langId = currentProgram.getLanguage()
                    .getLanguageID().getIdAsString();
                String[] parts = langId.split(":");
                is64 = parts.length >= 3 && "64".equals(parts[2]);
            } catch (Exception e) {
                // Fall through to MIPS32.
            }
            List<long[]> windows = defaultMipsMmioWindows();
            if (getScriptArgs().length >= 2 &&
                getScriptArgs()[1].startsWith("mmio=")) {
                List<long[]> parsed = parseMmioWindows(
                    getScriptArgs()[1].substring(5));
                if (parsed != null && !parsed.isEmpty()) {
                    windows = parsed;
                } else {
                    println("[!] Bad mmio= window spec, using " +
                        "MIPS defaults.");
                }
            }
            isa = new MipsIsa(is64, windows);
            println("[*] ISA adapter: MIPS (" + (is64 ? "MIPS64" : "MIPS32") +
                ")");
        } else if ("x86".equals(proc)) {
            boolean is64 = false;
            boolean is16 = false;
            try {
                String langId = currentProgram.getLanguage()
                    .getLanguageID().getIdAsString();
                String[] parts = langId.split(":");
                is64 = parts.length >= 3 && "64".equals(parts[2]);
                is16 = parts.length >= 3 && "16".equals(parts[2]);
            } catch (Exception e) {
                // Fall through to x86-32.
            }
            if (is16) {
                println("[!] x86-16 real mode is NOT implemented " +
                    "in v1: analysis proceeds with the 32-bit " +
                    "adapter as a best effort and results are " +
                    "NOT reliable (segmented addressing is " +
                    "unmodelled).");
            }
            // Binary default convention: PE -> Windows, ELF ->
            // System V. The format string is the loader's name
            // (e.g. "Portable Executable (PE)" for PE, "ELF"
            // for ELF, which contains no "PE" substring).
            boolean windowsDefault = false;
            try {
                String fmt = currentProgram.getExecutableFormat();
                if (fmt != null &&
                    fmt.toUpperCase().contains("PE")) {
                    windowsDefault = true;
                }
            } catch (Exception e) {
                // Fall through to System V.
            }
            List<long[]> windows = defaultX86MmioWindows();
            boolean mmioOverridden = false;
            for (String a : getScriptArgs()) {
                if (a.startsWith("mmio=")) {
                    List<long[]> parsed = parseMmioWindows(
                        a.substring(5));
                    if (parsed != null && !parsed.isEmpty()) {
                        windows = parsed;
                        mmioOverridden = true;
                    } else {
                        println("[!] Bad mmio= window spec, using " +
                            "x86 defaults.");
                    }
                } else if (a.startsWith("abi=")) {
                    String v = a.substring(4).trim();
                    if (v.equalsIgnoreCase("windows")) {
                        windowsDefault = true;
                    } else if (v.equalsIgnoreCase("sysv") ||
                        v.equalsIgnoreCase("systemv")) {
                        windowsDefault = false;
                    } else {
                        println("[!] Bad abi= value (want windows " +
                            "or sysv), using binary default.");
                    }
                }
            }
            // v2 item #4: union MCFG-derived ECAM bands from the
            // input image into the DEFAULT band set only; an
            // explicit mmio= override replaces all bands by user
            // choice and suppresses augmentation.
            if (!mmioOverridden) {
                augmentX86WindowsWithAcpi(windows);
            } else {
                println("[*] acpi: mmio= override supplied; " +
                    "ACPI bands not added.");
            }
            isa = new X86Isa(is64, windows, windowsDefault);
            println("[*] ISA adapter: X86 (" + (is64 ? "X86-64" :
                (is16 ? "X86-16 (best effort)" : "X86-32")) + ")");
        }
        // Per-callee calling conventions for signature-driven
        // clobbers (x86 v1). Built from Ghidra's per-function
        // signature; a function with no recovered convention
        // simply has no entry (unknown callee -> union fallback).
        // For single-convention adapters the map is inert
        // (clobberForConvention ignores the name), so building it
        // unconditionally costs one cheap function iteration.
        try {
            FunctionIterator convFns =
                currentProgram.getFunctionManager().getFunctions(true);
            while (convFns.hasNext() && !monitor.isCancelled()) {
                Function gf = convFns.next();
                try {
                    Address ep = gf.getEntryPoint();
                    if (ep == null || ep.getAddressSpace() == null ||
                        !"ram".equals(ep.getAddressSpace().getName())) {
                        continue;
                    }
                    String cn = gf.getCallingConventionName();
                    if (cn != null) {
                        callConvMap.put(ep.getOffset(), cn);
                    }
                } catch (Exception e) {
                    // Skip this function; unknown-callee fallback.
                }
            }
        } catch (Exception e) {
            // Map stays partial/empty; fallbacks cover it.
        }
        PrintWriter w = new PrintWriter(new FileWriter(outputJson));

        // Phase 4 V1: boundary profile (null = no profile, verdict
        // vacuous). Loaded before the function loop: region ranges
        // extend the must-recording set for boundary judgment
        // (RAM regions outside every MMIO window, e.g. SEC_RAM),
        // without touching mmio_accesses or mmio_access_total.
        BoundaryProfile bndProfile = loadBoundaryProfile(outputJson);

        w.println("{");
        w.println("  \"binary_name\": \"" + esc(currentProgram.getName()) + "\",");
        w.println("  \"language\": \"" +
            esc(currentProgram.getLanguage().getLanguageID().getIdAsString()) + "\",");
        w.println("  \"extractor_version\": \"v3.23\",");
        // Effective MMIO bands, so the Lean verifier can check the
        // trace against this platform's bands (single source of
        // truth: the adapter's own constants, not a user-retyped
        // CLI window). Hex strings, like "address" elsewhere.
        List<long[]> effWins = isa.mmioWindows();
        if (effWins == null || effWins.isEmpty()) {
            println("[!] Adapter returned no MMIO bands; emitting ARM default.");
            effWins = new ArrayList<long[]>();
            effWins.add(new long[] {0x40000000L, 0x60000000L});
        }
        w.println("  \"mmio_windows\": [");
        for (int wi = 0; wi < effWins.size(); wi++) {
            long[] win = effWins.get(wi);
            w.println("    [\"0x" + Long.toHexString(win[0]) +
                "\", \"0x" + Long.toHexString(win[1]) + "\"]" +
                (wi + 1 < effWins.size() ? "," : ""));
        }
        w.println("  ],");
        w.println("  \"functions\": [");

        boolean firstFn = true;
        int fnCount = 0;
        int totalMmio = 0;
        int totalMay = 0;
        int totalPortIo = 0;
        int totalMsr = 0;
        int totalIndirect = 0;
        int totalIndSucc = 0;
        int totalMayCallSites = 0;
        int totalMayCallTargets = 0;
        int totalUnresolved = 0;
        int totalTailCallSites = 0;
        int totalTailCallTargets = 0;
        int totalUnresolvedTail = 0;
        int totalProtoEdges = 0;
        int totalBarRel = 0;
        // v3.15 bounds: aggregated copy sites + flagged count.
        int totalCopySites = 0;
        int totalBoundsFlagged = 0;
        List<String> allCopySites = new ArrayList<String>();
        // Phase 4 V1: report-level boundary accumulators.
        List<String> allBoundarySites = new ArrayList<String>();
        int totalBoundaryChecked = 0;
        int totalBoundaryViolations = 0;
        int totalBoundaryUnknownAgent = 0;
        int totalBoundaryUnknownRegion = 0;
        Map<String, Integer> totalFormCounts =
            new HashMap<String, Integer>();
        int totalTransferCalls = 0;
        // v3.5 pass 1: function-pointer store map for the whole
        // program, before any function is printed (may-edges need
        // cross-function stores). Best-effort: a failure here only
        // shrinks may-sets, never breaks the report.
        Map<Long, Set<String>> funcPtrByOffset =
            new HashMap<Long, Set<String>>();
        Map<Long, Set<String>> funcPtrByAddr =
            new HashMap<Long, Set<String>>();
        try {
            FunctionIterator allFns =
                currentProgram.getFunctionManager().getFunctions(true);
            while (allFns.hasNext() && !monitor.isCancelled()) {
                Function pf = allFns.next();
                try {
                    OpsResult por = buildOps(pf);
                    collectFuncPtrStores(por.ops,
                        currentProgram.getMemory(),
                        currentProgram.getFunctionManager(),
                        funcPtrByOffset, funcPtrByAddr);
                } catch (Exception e) {
                    // best-effort; continue with the next function
                }
            }
        } catch (Exception e) {
            // best-effort; may-sets degrade to empty
        }
        // v3.6: whole-image literal scan merges name-attributed
        // stored pointers into the offset map before pass 2.
        LiteralScanResult litScan;
        try {
            litScan = scanLiteralStores(currentProgram.getMemory(),
                currentProgram.getFunctionManager(), funcPtrByOffset,
                funcPtrByAddr);
        } catch (Exception e) {
            litScan = new LiteralScanResult(
                new HashMap<String, Set<String>>(),
                new ArrayList<String>(), 0);
        }
        // ---- v2 item #2, Phase A: per-function records + call-site map ----
        // The emission loop used to analyse each function inline; the
        // must-fixpoint now needs cross-function entry states, so all
        // per-function inputs are built first (same computations, same
        // order: ops, jump-table targets, indirect recovery with the
        // successor merge, tail calls), then Phase B iterates the
        // must-fixpoints, then emission reuses the stored results.
        // The may-fixpoint, points-to and emission code below are
        // unchanged (may still starts all-unknown).
        Memory memA = currentProgram.getMemory();
        // Memory-propagation stack registers, resolved by name
        // (absent = that leg disabled, never guessed).
        try {
            if (currentProgram.getRegister("RSP") != null) {
                memSpOff = currentProgram.getRegister("RSP")
                    .getOffset();
            } else if (currentProgram.getRegister("SP") != null) {
                memSpOff = currentProgram.getRegister("SP")
                    .getOffset();
            }
            if (currentProgram.getRegister("RBP") != null) {
                memFpOff = currentProgram.getRegister("RBP")
                    .getOffset();
            } else if (currentProgram.getRegister("FP") != null) {
                memFpOff = currentProgram.getRegister("FP")
                    .getOffset();
            }
            memBigEndian = currentProgram.getLanguage()
                .isBigEndian();
        } catch (Exception e) {
            // Legs stay disabled; memState then treats stack
            // stores as unknown (sound, less precise).
        }
        // v3.19 Phase 3 item 6 (S2): RP2040 second-stage boot
        // code lives in a .boot2 section that Ghidra does not
        // recover as a function (raw assembly, no symbols),
        // so the pipeline never analyzes it. If a .boot2
        // block exists on an ARM program and no function
        // covers its start, create one over the block so the
        // normal pipeline analyzes it. Best-effort and
        // guarded: any failure (no transaction, code-unit
        // conflict, non-Thumb bytes) leaves the program
        // unchanged and the item as a documented remainder.
        // The created function is named "boot2" and is
        // indistinguishable downstream from a recovered
        // function -- its findings come from the pipeline's
        // own fixpoint, never from a side-channel parse.
        try {
            if ("ARM".equals(isa.name())) {
                MemoryBlock boot2blk =
                    currentProgram.getMemory().getBlock(".boot2");
                if (boot2blk != null) {
                    FunctionManager fm0 =
                        currentProgram.getFunctionManager();
                    Address bStart = boot2blk.getStart();
                    Function cov = fm0.getFunctionContaining(bStart);
                    if (cov == null) {
                        int tx = currentProgram.startTransaction(
                            "phase3-boot2");
                        try {
                            // The section arrives as defined
                            // data; a function entry may not
                            // be created on defined data, so
                            // clear the code units, disassemble
                            // (Thumb-forced: Cortex-M executes
                            // Thumb only, and the section's
                            // first halfword b500 is `push
                            // {lr}`), then create the function
                            // over the disassembled set. Same
                            // transaction throughout, so a
                            // later failure rolls the clear
                            // back with it.
                            currentProgram.getListing()
                                .clearCodeUnits(bStart,
                                    boot2blk.getEnd(), false);
                            AddressSet bRange = new AddressSet(
                                bStart, boot2blk.getEnd());
                            ArmDisassembleCommand dc =
                                new ArmDisassembleCommand(bStart,
                                    bRange, true);
                            try {
                                ghidra.program.model.lang.Register
                                    tm = currentProgram
                                        .getRegister("TMode");
                                if (tm != null) {
                                    dc.setInitialContext(
                                        new RegisterValue(tm,
                                            java.math.BigInteger.ONE));
                                }
                            } catch (Exception e) {
                                // Default context; disassembly
                                // still attempted below.
                            }
                            boolean disOk = dc.applyTo(
                                currentProgram, monitor);
                            AddressSet bSet = new AddressSet(
                                dc.getDisassembledAddressSet());
                            Function bf = null;
                            if (disOk && !bSet.isEmpty()) {
                                bf = fm0.createFunction(
                                    "boot2", bStart, bSet,
                                    SourceType.USER_DEFINED);
                            }
                            println("[*] boot2: disassembled=" +
                                disOk + " addrs=" +
                                bSet.getNumAddresses() +
                                " function=" +
                                (bf == null ? "FAILED" :
                                    bf.getName()));
                        } finally {
                            currentProgram.endTransaction(tx, true);
                        }
                    }
                }
            }
        } catch (Exception e) {
            println("[!] boot2: creation failed, continuing " +
                "without it: " + e);
        }
        // v3.19 Phase 3 item 5 (L1): table-driven function
        // discovery for stripped binaries. Ghidra's
        // symbol-driven discovery loses functions that are
        // reachable only through tables (device init fns,
        // API slot fns, ISR handlers) -- on stripped Zephyr
        // that is 100 of 269 functions, and it also blocks
        // L2 (device enumeration needs init fns to exist).
        // The tables themselves are linker-defined and
        // survive stripping: sw_isr_table entries are
        // (arg, handler) pairs, device_area records carry an
        // init pointer, *_driver_api_area sections are pure
        // API function-pointer tables, and initlevel is an
        // init function-pointer array. A word qualifies only
        // if it has the Thumb bit set, its stripped target
        // lies in an executable block, and no function
        // already covers it. Qualified targets are
        // disassembled (Thumb-forced, as for boot2) when
        // they hold no instruction yet, then created via
        // CreateFunctionCmd, whose flow analysis computes
        // the body (stopping at existing functions). Every
        // candidate is best-effort and independent: a
        // failure skips that candidate only. Binaries
        // without these sections (everything in the corpus
        // except Zephyr) and unstripped binaries (every
        // table target already a function) are unaffected
        // -- verified by the regression, not assumed.
        try {
            if ("ARM".equals(isa.name())) {
                FunctionManager fm1 =
                    currentProgram.getFunctionManager();
                int tx2 = currentProgram.startTransaction(
                    "phase3-table-fns");
                int created = 0;
                int skipped = 0;
                List<Address> createdQueue =
                    new ArrayList<Address>();
                try {
                    for (MemoryBlock tb :
                        currentProgram.getMemory().getBlocks()) {
                        String tn = tb.getName();
                        if (!"sw_isr_table".equals(tn) &&
                            !"device_area".equals(tn) &&
                            !"initlevel".equals(tn) &&
                            !tn.endsWith("_driver_api_area")) {
                            continue;
                        }
                        long a = tb.getStart().getOffset();
                        long e = tb.getEnd().getOffset();
                        for (long woff = a; woff + 3 <= e;
                            woff += 4) {
                            long word;
                            try {
                                word = isa.readPointer(
                                    currentProgram.getMemory(),
                                    toAddr(woff)) & 0xffffffffL;
                            } catch (Exception ex) {
                                continue;
                            }
                            if ((word & 1L) == 0) continue;
                            long tgt = word & ~1L;
                            Address tAddr;
                            MemoryBlock xb;
                            try {
                                tAddr = toAddr(tgt);
                                xb = currentProgram.getMemory()
                                    .getBlock(tAddr);
                            } catch (Exception ex) {
                                continue;
                            }
                            if (xb == null || !xb.isExecute()) {
                                continue;
                            }
                            try {
                                if (fm1.getFunctionContaining(
                                    tAddr) != null) {
                                    skipped++;
                                    continue;
                                }
                            } catch (Exception ex) {
                                continue;
                            }
                            try {
                                if (currentProgram.getListing()
                                    .getInstructionAt(tAddr)
                                    == null) {
                                    AddressSet xr =
                                        new AddressSet(
                                            xb.getStart(),
                                            xb.getEnd());
                                    ArmDisassembleCommand dc2 =
                                        new ArmDisassembleCommand(
                                            tAddr, xr, true);
                                    try {
                                        ghidra.program.model.lang.Register
                                            tm2 = currentProgram
                                                .getRegister("TMode");
                                        if (tm2 != null) {
                                            dc2.setInitialContext(
                                                new RegisterValue(tm2,
                                                    java.math.BigInteger.ONE));
                                        }
                                    } catch (Exception ex) {
                                        // Default context.
                                    }
                                    dc2.applyTo(currentProgram,
                                        monitor);
                                }
                                CreateFunctionCmd cfc =
                                    new CreateFunctionCmd(tAddr);
                                cfc.applyTo(currentProgram,
                                    monitor);
                                if (cfc.getFunction() != null) {
                                    created++;
                                    createdQueue.add(tAddr);
                                }
                            } catch (Exception ex) {
                                // This candidate stays
                                // undiscovered; continue.
                            }
                        }
                    }
                // Closure pass: table-created functions call
                // further functions that stripped analysis also
                // missed (e.g. uarte_0_init -> pinctrl_apply_state
                // -> pinctrl_configure_pins; clock API fns ->
                // nrfx_clock_*). Follow direct CALL/BRANCH
                // targets of created functions to fixpoint
                // (capped), creating each newly found function
                // the same way. Intra-function branches are
                // skipped by the covering-function test;
                // BRANCHIND (jump tables, callbacks) is never
                // followed here -- only direct targets.
                {
                    // Seed: entries created by the table
                    // pass above (explicit list -- the
                    // created functions' source type is
                    // NOT USER_DEFINED, so it cannot be
                    // used to identify them).
                    List<Address> queue = createdQueue;
                    int qi = 0;
                    while (qi < queue.size() &&
                        created < 512) {
                        Address ce = queue.get(qi++);
                        Function cf;
                        try {
                            cf = fm1.getFunctionAt(ce);
                        } catch (Exception ex) {
                            continue;
                        }
                        if (cf == null) continue;
                        OpsResult cor;
                        try {
                            cor = buildOps(cf);
                        } catch (Exception ex) {
                            continue;
                        }
                        for (OpRec o : cor.ops) {
                            if (!o.mnem.equals("CALL") &&
                                !o.mnem.equals("BRANCH")) {
                                continue;
                            }
                            if (o.ins.length < 1) continue;
                            Varnode tv = o.ins[0];
                            if (tv == null ||
                                tv.isConstant()) continue;
                            Address ta;
                            MemoryBlock xb2;
                            try {
                                if (!"ram".equals(tv.getAddress()
                                    .getAddressSpace().getName())) {
                                    continue;
                                }
                                ta = toAddr(tv.getOffset());
                                xb2 = currentProgram.getMemory()
                                    .getBlock(ta);
                            } catch (Exception ex) {
                                continue;
                            }
                            if (xb2 == null ||
                                !xb2.isExecute()) continue;
                            try {
                                if (fm1.getFunctionContaining(
                                    ta) != null) continue;
                            } catch (Exception ex) {
                                continue;
                            }
                            try {
                                if (currentProgram.getListing()
                                    .getInstructionAt(ta)
                                    == null) {
                                    AddressSet xr2 =
                                        new AddressSet(
                                            xb2.getStart(),
                                            xb2.getEnd());
                                    ArmDisassembleCommand dc3 =
                                        new ArmDisassembleCommand(
                                            ta, xr2, true);
                                    try {
                                        ghidra.program.model.lang.Register
                                            tm3 = currentProgram
                                                .getRegister("TMode");
                                        if (tm3 != null) {
                                            dc3.setInitialContext(
                                                new RegisterValue(tm3,
                                                    java.math.BigInteger.ONE));
                                        }
                                    } catch (Exception ex) {
                                        // Default context.
                                    }
                                    dc3.applyTo(currentProgram,
                                        monitor);
                                }
                                CreateFunctionCmd cfc2 =
                                    new CreateFunctionCmd(ta);
                                cfc2.applyTo(currentProgram,
                                    monitor);
                                if (cfc2.getFunction() != null) {
                                    created++;
                                    queue.add(ta);
                                }
                            } catch (Exception ex) {
                                // Candidate skipped.
                            }
                        }
                    }
                }
                } finally {
                    currentProgram.endTransaction(tx2, true);
                }
                println("[*] table-fns: created=" + created +
                    " skippedAlreadyFn=" + skipped);
            }
        } catch (Exception e) {
            println("[!] table-fns: discovery failed, " +
                "continuing without it: " + e);
        }
        FunctionManager fmA = currentProgram.getFunctionManager();
        List<FuncRec> funcRecs = new ArrayList<FuncRec>();
        Map<Long, FuncRec> funcByEntry = new HashMap<Long, FuncRec>();
        FunctionIterator pafns = fmA.getFunctions(true);
        while (pafns.hasNext() && !monitor.isCancelled()) {
            Function pf = pafns.next();
            FuncRec rec = new FuncRec();
            rec.f = pf;
            rec.or = buildOps(pf);
            List<OpRec> pops = rec.or.ops;
            try {
                rec.branchTargets = isa.recoverJumpTableTargets(pops, memA);
            } catch (Exception e) {
                rec.branchTargets = new HashMap<Integer, List<Integer>>();
            }
            try {
                rec.ind = recoverIndirect(pops, memA, fmA,
                    rec.branchTargets.keySet());
            } catch (Exception e) {
                rec.ind = new IndirectResult(new ArrayList<String>(), 0,
                    new HashMap<Integer, List<Integer>>(),
                    new HashSet<Integer>());
            }
            for (Map.Entry<Integer, List<Integer>> e :
                rec.ind.successors.entrySet()) {
                List<Integer> cur = rec.branchTargets.get(e.getKey());
                if (cur == null) {
                    rec.branchTargets.put(e.getKey(), e.getValue());
                } else {
                    for (Integer j : e.getValue()) {
                        if (!cur.contains(j)) cur.add(j);
                    }
                }
            }
            // v9 struct: loop-carried call sites (branchTargets are
            // final here, so the CFG used matches the fixpoints').
            try {
                rec.loopCallOps = loopCallOpsFor(pops,
                    rec.branchTargets);
            } catch (Exception e) {
                rec.loopCallOps = new HashSet<Integer>();
            }
            try {
                long funcStart = pf.getEntryPoint().getOffset();
                long funcEnd = funcStart + 1L;
                try {
                    funcEnd = pf.getBody().getMaxAddress().getOffset() + 1L;
                } catch (Exception e) {
                }
                rec.tc = recoverTailCalls(pops, memA, fmA,
                    funcPtrByOffset, funcPtrByAddr,
                    rec.ind.resolvedBranchInds,
                    rec.branchTargets.keySet(), funcStart, funcEnd);
            } catch (Exception e) {
                rec.tc = new TailCallResult(new ArrayList<String>(), 0, 0);
            }
            long ep = pf.getEntryPoint().getOffset();
            rec.entryKey = ep;
            rec.fx = emptyFix(pops.size());
            funcRecs.add(rec);
            funcByEntry.put(ep, rec);
            long stripped = isa.stripInstructionTag(ep);
            if (stripped != ep) funcByEntry.put(stripped, rec);
        }
        // Direct call sites, grouped by callee, + caller -> callees.
        Map<Long, List<CallSite>> sitesByCallee =
            new HashMap<Long, List<CallSite>>();
        Map<Long, Set<Long>> calleesByCaller =
            new HashMap<Long, Set<Long>>();
        Map<Long, Set<Long>> directCallersByCallee =
            new HashMap<Long, Set<Long>>();
        int tailSitesAdded = 0;
        for (FuncRec rec : funcRecs) {
            List<OpRec> pops = rec.or.ops;
            for (int i = 0; i < pops.size(); i++) {
                OpRec op = pops.get(i);
                boolean isCall = op.mnem.equals("CALL");
                // v14 tail calls: a direct BRANCH to another
                // function's entry is a tail call -- control
                // never returns to the caller, and the argument
                // registers at the branch ARE the callee's entry
                // values (the target's RETURN goes to the
                // caller's caller, not to the branch). Such
                // sites therefore seed per-site clones exactly
                // like CALL sites. They are added ONLY to
                // sitesByCallee: directCallersByCallee and
                // calleesByCaller are deliberately untouched,
                // so merged-constprop eligibility, Prov
                // eligibility, and clobber edges keep today's
                // behaviour (a tail-involved callee stays
                // merged-ineligible via the every-caller-direct
                // guard, since its Ghidra callers are not direct
                // callers). Retprop/struct agreement over the
                // enlarged site set is stricter, never looser.
                // RESIDUAL: a branch to a misidentified
                // "function" (shared code Ghidra labeled as a
                // function, noreturn handler entered with
                // arbitrary registers) would seed a clone from
                // a non-argument binding. The regression set
                // (zero lost + every addition verified
                // code-true) is the backstop; a hallucination
                // here reverts this block.
                boolean isTailBranch = op.mnem.equals("BRANCH");
                if ((!isCall && !isTailBranch) ||
                    op.ins.length < 1) {
                    continue;
                }
                Varnode t = op.ins[0];
                if (t == null) continue;
                if (isCall && (t.getAddress() == null ||
                    !"ram".equals(t.getAddress().getAddressSpace().
                        getName()))) {
                    continue;
                }
                FuncRec callee = funcByEntry.get(t.getOffset());
                if (callee == null) {
                    callee = funcByEntry.get(
                        isa.stripInstructionTag(t.getOffset()));
                }
                if (callee == null) continue;
                if (isTailBranch) {
                    long selfStripped = isa.stripInstructionTag(
                        rec.entryKey);
                    long tgtStripped = isa.stripInstructionTag(
                        callee.entryKey);
                    if (selfStripped == tgtStripped) continue;
                }
                List<CallSite> sl = sitesByCallee.get(callee.entryKey);
                if (sl == null) {
                    sl = new ArrayList<CallSite>();
                    sitesByCallee.put(callee.entryKey, sl);
                }
                sl.add(new CallSite(rec, i));
                if (isTailBranch) tailSitesAdded++;
                if (!isTailBranch) {
                    Set<Long> cb = calleesByCaller.get(rec.entryKey);
                    if (cb == null) {
                        cb = new HashSet<Long>();
                        calleesByCaller.put(rec.entryKey, cb);
                    }
                    cb.add(callee.entryKey);
                    Set<Long> dc = directCallersByCallee.get(
                        callee.entryKey);
                    if (dc == null) {
                        dc = new HashSet<Long>();
                        directCallersByCallee.put(callee.entryKey,
                            dc);
                    }
                    dc.add(rec.entryKey);
                }
            }
        }
        // Guards (see the v2 item #2 header comment).
        Set<String> addrTakenNames = new HashSet<String>();
        for (Set<String> s : funcPtrByOffset.values()) {
            addrTakenNames.addAll(s);
        }
        for (Set<String> s : funcPtrByAddr.values()) {
            addrTakenNames.addAll(s);
        }
        Set<String> tailTargetNames = new HashSet<String>();
        for (FuncRec rec : funcRecs) {
            tailTargetNames.addAll(rec.tc.targetNames);
        }
        Map<Long, Boolean> eligible = new HashMap<Long, Boolean>();
        Map<Long, long[]> argRegsByCallee =
            new HashMap<Long, long[]>();
        for (FuncRec callee : funcRecs) {
            boolean ok = true;
            List<CallSite> sites = sitesByCallee.get(callee.entryKey);
            if (callee.f.isExternal() || sites == null ||
                sites.isEmpty()) {
                ok = false;
            }
            if (ok && addrTakenNames.contains(callee.f.getName())) {
                ok = false;
            }
            if (ok && tailTargetNames.contains(callee.f.getName())) {
                ok = false;
            }
            if (ok) {
                try {
                    Set<Function> callers =
                        callee.f.getCallingFunctions(monitor);
                    Set<Long> directCallers =
                        directCallersByCallee.get(callee.entryKey);
                    for (Function cf : callers) {
                        FuncRec callerRec = funcByEntry.get(
                            cf.getEntryPoint().getOffset());
                        if (callerRec == null || directCallers == null ||
                            !directCallers.contains(callerRec.entryKey)) {
                            ok = false;
                            break;
                        }
                    }
                } catch (Exception e) {
                    ok = false;
                }
            }
            long[] argRegs = null;
            if (ok) {
                argRegs = isa.argumentRegisterOffsets(
                    callConvMap.get(callee.entryKey));
                if (argRegs == null) ok = false;
            }
            eligible.put(callee.entryKey, ok);
            if (ok) argRegsByCallee.put(callee.entryKey, argRegs);
        }
        // ---- v13 clobber refinement: per-callee may-write sets
        // (must-only; may/taint transfers stay conservative) ----
        clobberRef = computeClobberRef(funcRecs, funcByEntry);
        // ---- v2 item #2, Phase B: worklist iteration over entries ----
        Map<Long, Map<String, Bits>> entries =
            new HashMap<Long, Map<String, Bits>>();
        Set<Long> worklist = new HashSet<Long>();
        for (FuncRec rec : funcRecs) worklist.add(rec.entryKey);
        boolean cpConverged = false;
        int cpRounds = 0;
        for (int round = 0; round < MAX_CONSTPROP_ROUNDS && !cpConverged;
            round++) {
            if (monitor.isCancelled()) break;
            cpRounds++;
            for (Long ek : worklist) {
                FuncRec rec = funcByEntry.get(ek);
                if (rec == null) continue;
                Map<String, Bits> e = entries.get(ek);
                FixResult nfx;
                try {
                    nfx = runFixpoint(rec.or.ops, memA,
                        rec.branchTargets, e,
                        rec.loopCallOps);
                } catch (Exception ex) {
                    nfx = emptyFix(rec.or.ops.size());
                }
                // Keep a previous converged result over a fresh
                // non-converged one (whose states were emptied):
                // the old result is a sound under-approximation
                // under the more-precise entry, and swapping in
                // emptied states would make entries oscillate.
                if (nfx.converged || rec.fx == null ||
                    !rec.fx.converged) {
                    rec.fx = nfx;
                }
            }
            Set<Long> affected = new HashSet<Long>();
            for (Long ek : worklist) {
                Set<Long> cb = calleesByCaller.get(ek);
                if (cb != null) affected.addAll(cb);
            }
            Set<Long> nextWorklist = new HashSet<Long>();
            for (Long ck : affected) {
                if (!Boolean.TRUE.equals(eligible.get(ck))) continue;
                Map<String, Bits> m = meetOverSites(ck, sitesByCallee,
                    argRegsByCallee);
                if (!entrySame(entries.get(ck), m)) {
                    entries.put(ck, m);
                    nextWorklist.add(ck);
                }
            }
            if (nextWorklist.isEmpty()) {
                cpConverged = true;
            } else {
                worklist = nextWorklist;
            }
        }
        if (!cpConverged && !worklist.isEmpty() &&
            !monitor.isCancelled()) {
            // Final pass so emission uses fixpoints consistent with
            // the final entries (capped iteration is still sound:
            // every iterate is justified, just possibly less precise).
            for (Long ek : worklist) {
                FuncRec rec = funcByEntry.get(ek);
                if (rec == null) continue;
                try {
                    FixResult nfx = runFixpoint(rec.or.ops, memA,
                        rec.branchTargets, entries.get(ek),
                        rec.loopCallOps);
                    if (nfx.converged || rec.fx == null ||
                        !rec.fx.converged) {
                        rec.fx = nfx;
                    }
                } catch (Exception ex) {
                    // Keep the previous fixpoint.
                }
            }
            println("[!] constprop: stopped after " +
                MAX_CONSTPROP_ROUNDS +
                " rounds without convergence; using last entries.");
        }
        {
            int withEntries = 0;
            int totalConsts = 0;
            int eligibleCount = 0;
            for (FuncRec rec : funcRecs) {
                if (Boolean.TRUE.equals(eligible.get(rec.entryKey))) {
                    eligibleCount++;
                }
                Map<String, Bits> e = entries.get(rec.entryKey);
                if (e != null && !e.isEmpty()) {
                    withEntries++;
                    totalConsts += e.size();
                }
            }
            println("[*] constprop: " + cpRounds + " rounds, converged=" +
                cpConverged + ", eligible callees=" + eligibleCount +
                ", functions with propagated entries=" + withEntries +
                ", entry constants=" + totalConsts + ".");
        }
        // ---- v8 retprop, Phase R: return-value propagation ----
        // A callee's return summary is the return-register value
        // agreed on ALL its RETURN ops (extractRetSummaries), and
        // the CALL branch applies it to the caller's return register
        // after the clobber. Iteration is JOINT over entries and
        // summaries: a summary applied in a caller creates a new
        // agreed argument at the next callee's sites (e.g. a BASE
        // symbol returned by one helper and passed to the next),
        // so each round refreshes constprop entries from the
        // current fixpoints (same eligibility filter as Phase B)
        // AND re-extracts summaries, then re-runs all functions.
        // Nested returns need a second round (a caller of a
        // summarized callee gains a summary only once the callee's
        // summary is applied), and recursion never yields an
        // unsound summary (a recursive call's return is unknown
        // until the callee has a summary, so a recursive callee's
        // RETURNs disagree and no summary forms -- the loop then
        // converges on unknown). Entries and summaries only gain
        // precision across rounds (the transfer is monotone in
        // input precision, same argument as constprop), so the
        // round cap is a safety bound; non-convergence drops ALL
        // summaries AND restores the Phase B entries, then re-runs,
        // so no unstable summary or entry ever reaches emission.
        // No constprop-eligibility filter on summaries themselves:
        // a summary is a property of the callee's own fixpoint, and
        // the agree discipline already covers argument dependence
        // (see extractRetSummaries). Phase M's re-runs below apply
        // the final summaries automatically (same instance field)
        // and use the (possibly refined) entries map.
        Map<Long, Map<String, Bits>> entriesBeforeR =
            new HashMap<Long, Map<String, Bits>>();
        for (Map.Entry<Long, Map<String, Bits>> e :
            entries.entrySet()) {
            entriesBeforeR.put(e.getKey(), e.getValue() == null ?
                null : new HashMap<String, Bits>(e.getValue()));
        }
        boolean retConverged = false;
        int retRounds = 0;
        for (int round = 0; round < MAX_CONSTPROP_ROUNDS &&
            !retConverged; round++) {
            if (monitor.isCancelled()) break;
            retRounds++;
            boolean entriesChanged = false;
            for (Long ck : sitesByCallee.keySet()) {
                if (!Boolean.TRUE.equals(eligible.get(ck))) continue;
                Map<String, Bits> m = meetOverSites(ck, sitesByCallee,
                    argRegsByCallee);
                if (!entrySame(entries.get(ck), m)) {
                    entries.put(ck, m);
                    entriesChanged = true;
                }
            }
            Map<Long, Bits> next = extractRetSummaries(funcRecs);
            boolean summariesChanged =
                !sameRetSummaries(retSummaries, next);
            if (!entriesChanged && !summariesChanged) {
                retConverged = true;
                break;
            }
            retSummaries = next;
            for (FuncRec rec : funcRecs) {
                FixResult nfx;
                try {
                    nfx = runFixpoint(rec.or.ops, memA,
                        rec.branchTargets, entries.get(rec.entryKey),
                        rec.loopCallOps);
                } catch (Exception ex) {
                    nfx = emptyFix(rec.or.ops.size());
                }
                if (nfx.converged || rec.fx == null ||
                    !rec.fx.converged) {
                    rec.fx = nfx;
                }
            }
        }
        if (!retConverged && !monitor.isCancelled()) {
            retSummaries = new HashMap<Long, Bits>();
            entries.clear();
            entries.putAll(entriesBeforeR);
            for (FuncRec rec : funcRecs) {
                try {
                    FixResult nfx = runFixpoint(rec.or.ops, memA,
                        rec.branchTargets, entries.get(rec.entryKey),
                        rec.loopCallOps);
                    if (nfx.converged || rec.fx == null ||
                        !rec.fx.converged) {
                        rec.fx = nfx;
                    }
                } catch (Exception ex) {
                    // Keep the previous fixpoint.
                }
            }
            println("[!] retprop: stopped after " +
                MAX_CONSTPROP_ROUNDS +
                " rounds without convergence; summaries dropped.");
        }
        println("[*] retprop: " + retRounds + " rounds, converged=" +
            retConverged + ", summaries=" + retSummaries.size() +
            ".");
        // ---- v9 struct, Phase S: struct return summaries ----
        // A callee's field summary is the field cells for the
        // object it returns, agreed on ALL its RETURN ops (see
        // extractStructSummaries), and the CALL branch installs
        // those cells under each direct call site's own object id.
        // Iteration is JOINT like Phase R: an installed summary
        // lets a wrapper callee form its own summary (it returns
        // the object it received, whose cells are the installed
        // ones), so nested struct returns need a second round.
        // Recursion never yields an unsound summary (a recursive
        // callee's RETURNs disagree on the object id, so no summary
        // forms -- the loop converges on unknown). Non-convergence
        // drops ALL summaries and re-runs, so no unstable summary
        // ever reaches emission. Phase M's re-runs below apply the
        // final summaries automatically (same instance field).
        boolean structConverged = false;
        int structRounds = 0;
        for (int round = 0; round < MAX_CONSTPROP_ROUNDS &&
            !structConverged; round++) {
            if (monitor.isCancelled()) break;
            structRounds++;
            Map<Long, Map<String, Bits>> next =
                extractStructSummaries(funcRecs);
            if (sameStructSummaries(structSummaries, next)) {
                structConverged = true;
                break;
            }
            structSummaries = next;
            for (FuncRec rec : funcRecs) {
                FixResult nfx;
                try {
                    nfx = runFixpoint(rec.or.ops, memA,
                        rec.branchTargets, entries.get(rec.entryKey),
                        rec.loopCallOps);
                } catch (Exception ex) {
                    nfx = emptyFix(rec.or.ops.size());
                }
                if (nfx.converged || rec.fx == null ||
                    !rec.fx.converged) {
                    rec.fx = nfx;
                }
            }
        }
        if (!structConverged && !monitor.isCancelled()) {
            structSummaries = new HashMap<Long, Map<String, Bits>>();
            for (FuncRec rec : funcRecs) {
                try {
                    FixResult nfx = runFixpoint(rec.or.ops, memA,
                        rec.branchTargets, entries.get(rec.entryKey),
                        rec.loopCallOps);
                    if (nfx.converged || rec.fx == null ||
                        !rec.fx.converged) {
                        rec.fx = nfx;
                    }
                } catch (Exception ex) {
                    // Keep the previous fixpoint.
                }
            }
            println("[!] struct: stopped after " +
                MAX_CONSTPROP_ROUNDS +
                " rounds without convergence; summaries dropped.");
        }
        int structFields = 0;
        for (Map<String, Bits> f : structSummaries.values()) {
            structFields += f.size();
        }
        println("[*] struct: " + structRounds + " rounds, converged=" +
            structConverged + ", summaries=" + structSummaries.size() +
            ", fields=" + structFields + ".");
        // ---- v2 item #3, Phase P: protocol-aware points-to ----
        // Gated to x86-64 (UEFI Boot Services + protocol tables
        // are x86-64 ABI facts; other ISAs keep v3.9 behaviour
        // (the Prov pass alone uses the wide def window, see
        // findDefWide).
        boolean isX86_64 = false;
        try {
            String langId = currentProgram.getLanguage()
                .getLanguageID().getIdAsString();
            isX86_64 = "x86".equals(proc) && langId.contains(":64:");
        } catch (Exception e) {
        }
        ProvCtx provCtx = null;
        if (isX86_64) {
            provCtx = new ProvCtx();
            provCtx.mem = currentProgram.getMemory();
            provCtx.protos = protoTable();
            provCtx.bsMethods = bsMethods();
            try {
                provCtx.rspOff = currentProgram.getRegister("RSP")
                    .getOffset();
                provCtx.rbpOff = currentProgram.getRegister("RBP")
                    .getOffset();
            } catch (Exception e) {
                provCtx.rspOff = 0x20L;
                provCtx.rbpOff = 0x28L;
            }
            // gBS fingerprint (syntactic, no fixpoint needed).
            Set<Long> gbsAddrs = findGbsGlobals(funcRecs,
                provCtx.bsMethods);
            Map<Long, Prov> provGlobalPre = new HashMap<Long, Prov>();
            for (Long g : gbsAddrs) {
                provGlobalPre.put(g, Prov.bs());
            }
            provCtx.gbsAddrs = gbsAddrs;
            provCtx.globalProvPre = provGlobalPre;
            println("[*] proto: gBS globals=" + gbsAddrs);
            // Pre-pass: intra-only Prov (unknown entries) to collect
            // global interface assignments. Disagreeing assignments
            // (across paths or functions) drop to unknown: a global
            // whose value is not certain everywhere is not bound.
            Map<Long, Prov> collected = new HashMap<Long, Prov>();
            Map<Long, Boolean> conflicted =
                new HashMap<Long, Boolean>();
            for (FuncRec rec : funcRecs) {
                try {
                    ProvResult pre = runProvFixpoint(rec.or.ops,
                        rec.branchTargets, null, provCtx);
                    for (int i = 0; i < rec.or.ops.size(); i++) {
                        if (pre.inStates[i] == null) continue;
                        ProvState out = new ProvState(pre.inStates[i]);
                        applyProvTransfer(out, rec.or.ops.get(i),
                            rec.or.ops, i, provCtx);
                        for (Map.Entry<Long, Prov> e :
                            out.globalProv.entrySet()) {
                            if (conflicted.containsKey(e.getKey())) {
                                continue;
                            }
                            Prov old = collected.get(e.getKey());
                            if (old == null) {
                                collected.put(e.getKey(),
                                    e.getValue());
                            } else if (!old.equals(e.getValue())) {
                                collected.remove(e.getKey());
                                conflicted.put(e.getKey(), true);
                            }
                        }
                    }
                } catch (Exception e) {
                    // best-effort; the main pass still runs
                }
            }
            for (Map.Entry<Long, Prov> e : collected.entrySet()) {
                if (!provGlobalPre.containsKey(e.getKey())) {
                    provGlobalPre.put(e.getKey(), e.getValue());
                }
            }
            provCtx.globalProvPre = provGlobalPre;
            println("[*] proto: pre-pass globals=" +
                provGlobalPre.size());
            // Parameter provenance propagation (mirror constprop
            // Phase B): worklist over entries, meet over sites.
            // Eligibility: same call-graph guards as constprop
            // (direct callers only, not address-taken, not a tail
            // target, not external). The register set is the
            // x86-64 union, so no convention-null exclusion
            // applies (unlike constprop's convention-specific
            // argument registers).
            Map<Long, Boolean> provEligible =
                new HashMap<Long, Boolean>();
            for (FuncRec callee : funcRecs) {
                boolean ok = true;
                List<CallSite> sites =
                    sitesByCallee.get(callee.entryKey);
                if (callee.f.isExternal() || sites == null ||
                    sites.isEmpty()) ok = false;
                if (ok && addrTakenNames.contains(
                    callee.f.getName())) ok = false;
                if (ok && tailTargetNames.contains(
                    callee.f.getName())) ok = false;
                if (ok) {
                    try {
                        Set<Function> callers = callee.f
                            .getCallingFunctions(monitor);
                        Set<Long> directCallers =
                            directCallersByCallee.get(
                                callee.entryKey);
                        for (Function cf : callers) {
                            FuncRec callerRec = funcByEntry.get(
                                cf.getEntryPoint().getOffset());
                            if (callerRec == null ||
                                directCallers == null ||
                                !directCallers.contains(
                                    callerRec.entryKey)) {
                                ok = false;
                                break;
                            }
                        }
                    } catch (Exception e) {
                        ok = false;
                    }
                }
                provEligible.put(callee.entryKey, ok);
            }
            Map<Long, Map<String, Prov>> provEntries =
                new HashMap<Long, Map<String, Prov>>();
            Set<Long> pWorklist = new HashSet<Long>();
            for (FuncRec rec : funcRecs) {
                pWorklist.add(rec.entryKey);
            }
            boolean provConverged = false;
            int provRounds = 0;
            for (int round = 0; round < MAX_CONSTPROP_ROUNDS &&
                !provConverged; round++) {
                if (monitor.isCancelled()) break;
                provRounds++;
                for (Long ek : pWorklist) {
                    FuncRec rec = funcByEntry.get(ek);
                    if (rec == null) continue;
                    try {
                        rec.pv = runProvFixpoint(rec.or.ops,
                            rec.branchTargets,
                            provEntries.get(ek), provCtx);
                    } catch (Exception ex) {
                        rec.pv = null;
                    }
                }
                Set<Long> affected = new HashSet<Long>();
                for (Long ek : pWorklist) {
                    Set<Long> cb = calleesByCaller.get(ek);
                    if (cb != null) affected.addAll(cb);
                }
                Set<Long> nextWorklist = new HashSet<Long>();
                for (Long ck : affected) {
                    if (!Boolean.TRUE.equals(
                        provEligible.get(ck))) continue;
                    Map<String, Prov> m = meetOverSitesProv(ck,
                        sitesByCallee);
                    if (!provEntrySame(provEntries.get(ck), m)) {
                        provEntries.put(ck, m);
                        nextWorklist.add(ck);
                    }
                }
                if (nextWorklist.isEmpty()) {
                    provConverged = true;
                } else {
                    pWorklist = nextWorklist;
                }
            }
            if (!provConverged && !pWorklist.isEmpty() &&
                !monitor.isCancelled()) {
                for (Long ek : pWorklist) {
                    FuncRec rec = funcByEntry.get(ek);
                    if (rec == null) continue;
                    try {
                        rec.pv = runProvFixpoint(rec.or.ops,
                            rec.branchTargets,
                            provEntries.get(ek), provCtx);
                    } catch (Exception ex) {
                    }
                }
                println("[!] proto: stopped after " +
                    MAX_CONSTPROP_ROUNDS +
                    " rounds without convergence; using last entries.");
            }
            // Safety net: any function without a Prov result (fixpoint
            // threw) gets one more attempt with its current entries.
            for (FuncRec rec : funcRecs) {
                if (rec.pv == null) {
                    try {
                        rec.pv = runProvFixpoint(rec.or.ops,
                            rec.branchTargets,
                            provEntries.get(rec.entryKey), provCtx);
                    } catch (Exception ex) {
                        rec.pv = null;
                    }
                }
            }
            int withProvEntries = 0;
            for (FuncRec rec : funcRecs) {
                Map<String, Prov> e = provEntries.get(rec.entryKey);
                if (e != null && !e.isEmpty()) withProvEntries++;
            }
            println("[*] proto: " + provRounds + " rounds, converged=" +
                provConverged + ", functions with propagated entries=" +
                withProvEntries + ".");
            // ---- v8 retprop (Prov), Phase P2: interface returns ----
            // A second, separate iteration AFTER Phase P's loop (the
            // loop above is untouched, so its behaviour cannot
            // regress): extract interface summaries from the final
            // provenance fixpoints, apply them at direct CALLs via
            // the provSummaries field, and re-run all provenance
            // fixpoints until summaries stabilize. A caller that
            // receives an interface through a CALL return can then
            // resolve a member CALLIND (and its Pci.Read/Write port
            // attribution) exactly as if it had acquired the
            // interface itself. Non-convergence drops ALL summaries
            // and re-runs with provEntries only, so no unstable
            // summary ever reaches emission. provEntries are NOT
            // refreshed here (Phase P already converged them; a
            // summary is a property of the callee's own fixpoint).
            boolean provRetConverged = false;
            int provRetRounds = 0;
            for (int round = 0; round < MAX_CONSTPROP_ROUNDS &&
                !provRetConverged; round++) {
                if (monitor.isCancelled()) break;
                provRetRounds++;
                Map<Long, Prov> next =
                    extractProvSummaries(funcRecs);
                if (sameProvSummaries(provSummaries, next)) {
                    provRetConverged = true;
                    break;
                }
                provSummaries = next;
                for (FuncRec rec : funcRecs) {
                    try {
                        rec.pv = runProvFixpoint(rec.or.ops,
                            rec.branchTargets,
                            provEntries.get(rec.entryKey), provCtx);
                    } catch (Exception ex) {
                        // Keep the previous Prov result.
                    }
                }
            }
            if (!provRetConverged && !monitor.isCancelled()) {
                provSummaries = new HashMap<Long, Prov>();
                for (FuncRec rec : funcRecs) {
                    try {
                        rec.pv = runProvFixpoint(rec.or.ops,
                            rec.branchTargets,
                            provEntries.get(rec.entryKey), provCtx);
                    } catch (Exception ex) {
                        // Keep the previous Prov result.
                    }
                }
                println("[!] provret: stopped after " +
                    MAX_CONSTPROP_ROUNDS +
                    " rounds without convergence; summaries dropped.");
            }
            println("[*] provret: " + provRetRounds + " rounds, converged=" +
                provRetConverged + ", summaries=" + provSummaries.size() +
                ".");
            // ---- v9 struct (Prov), Phase S-Prov: struct layouts ----
            // A second, separate iteration AFTER Phase P2's loop
            // (that loop is untouched, so its behaviour cannot
            // regress): extract struct-layout summaries from the
            // final provenance fixpoints, apply them at direct
            // CALLs via the structProvSummaries field, and re-run
            // all provenance fixpoints until summaries stabilize.
            // A caller that receives a struct through a CALL return
            // can then resolve a member CALLIND through a field
            // interface exactly as if it had filled the struct
            // itself. Non-convergence drops ALL struct summaries
            // and re-runs with provEntries + provSummaries only, so
            // no unstable summary ever reaches emission.
            boolean structProvConverged = false;
            int structProvRounds = 0;
            for (int round = 0; round < MAX_CONSTPROP_ROUNDS &&
                !structProvConverged; round++) {
                if (monitor.isCancelled()) break;
                structProvRounds++;
                Map<Long, Prov> next =
                    extractStructProvSummaries(funcRecs);
                if (sameProvSummaries(structProvSummaries, next)) {
                    structProvConverged = true;
                    break;
                }
                structProvSummaries = next;
                for (FuncRec rec : funcRecs) {
                    try {
                        rec.pv = runProvFixpoint(rec.or.ops,
                            rec.branchTargets,
                            provEntries.get(rec.entryKey), provCtx);
                    } catch (Exception ex) {
                        // Keep the previous Prov result.
                    }
                }
            }
            if (!structProvConverged && !monitor.isCancelled()) {
                structProvSummaries = new HashMap<Long, Prov>();
                for (FuncRec rec : funcRecs) {
                    try {
                        rec.pv = runProvFixpoint(rec.or.ops,
                            rec.branchTargets,
                            provEntries.get(rec.entryKey), provCtx);
                    } catch (Exception ex) {
                        // Keep the previous Prov result.
                    }
                }
                println("[!] structprov: stopped after " +
                    MAX_CONSTPROP_ROUNDS +
                    " rounds without convergence; summaries dropped.");
            }
            println("[*] structprov: " + structProvRounds +
                " rounds, converged=" + structProvConverged +
                ", summaries=" + structProvSummaries.size() + ".");
        }

        // ---- Memory/global propagation, Phase M ----
        // SOUND SLICES, not a redesign. Two layers, both feeding
        // the existing must-fixpoint (so recording picks them up
        // with no JSON shape change and no emission change):
        //
        // STAGE 1 (intra-procedural memState): "mem:" keys in the
        // must-state map. A STORE to a known non-MMIO address
        // records the value (dropping overlapping cells); a store
        // to an unknown non-stack address clears all of memState
        // (it may alias any global); a CALL clears memState (a
        // callee may store anywhere); stack stores are ignored
        // (proven-stack via def-chain to SP/FP -- they can never
        // alias a global). COPY-to/from-ram ops are the SAME
        // operations in x86-64 dress: Ghidra models absolute
        // (RIP-relative) global access as COPY, not LOAD/STORE,
        // so COPY-to-ram stores update memState and COPY-from-ram
        // loads consult it -- without this the globals slice
        // would be vacuous on x86-64, including OVMF. A LOAD
        // consults memState before image
        // bytes: a covering entry proves a dominating store wrote
        // the range on every path, so the image bytes are stale
        // there; no covering entry keeps exactly today's behaviour.
        // The must-meet's agree-or-drop discipline applies to cells
        // exactly as to registers (a cell survives a join only when
        // every incoming path agrees on it).
        //
        // STAGE 2 (program-wide global seeds): "gmem:" keys injected
        // at every function entry, computed by collectMemSeeds from
        // the current fixpoints and iterated like constprop (seeds
        // only shrink, so the loop terminates; the cap is a safety
        // bound, and non-convergence drops all seeds and re-runs
        // with constprop entries only, so no unstable seed ever
        // reaches emission). A cell (addr, size) is seeded ONLY when
        // (a) every overlapping store in the whole program targets
        // exactly that cell with the same exact value, (b) at least
        // one such store exists, (c) NO unknown non-stack store
        // exists anywhere in the program, and (d) the address never
        // leaks: it never appears as a call-argument value, a
        // stored value, or a return-register value. Seeded cells
        // survive CALLs (the seed rule guarantees no callee can
        // change one to a different value); an intra-procedural
        // store overlapping a seed drops it (defensive: a seed
        // contradicting a fresh store is dropped, never trusted).
        //
        // EXPLICITLY OUT OF THIS SLICE: heap memory with unknown
        // base (a heap struct field needs object identity, which
        // provenance alone does not provide -- two devices' PciIo
        // pointers share a protocol provenance but are different
        // objects, so conflating them would be unsound); struct
        // fields whose base is a KNOWN global ARE covered (the
        // field address is exact, so it is just a global cell);
        // stack values that escape (covered by the leak guards
        // above when they pass through a call/store/return).
        //
        // DOCUMENTED RESIDUAL RISK (narrow, same honesty policy as
        // v2 item #2's address-taken hole): an external function
        // writing a FIELD of a caller-provided struct/buffer that
        // coincides with a seeded global, where the global's own
        // address was never passed to it. Direct flows are all
        // guarded (call-arg, store-value, return); only a callee
        // that knows the caller's private layout and writes
        // through a struct pointer could break a seed, and UEFI
        // Boot Services / protocol methods do not write
        // driver-private globals that way (they write out-params
        // and their own device state, both guarded above).
        Map<String, Bits> memSeeds = new HashMap<String, Bits>();
        boolean memConverged = false;
        int memRounds = 0;
        MemSeedResult lastSeedRes = null;
        for (int round = 0; round < MAX_CONSTPROP_ROUNDS &&
            !memConverged; round++) {
            if (monitor.isCancelled()) break;
            memRounds++;
            MemSeedResult sr = collectMemSeeds(funcRecs, funcByEntry);
            lastSeedRes = sr;
            if (sameState(memSeeds, sr.seeds)) {
                memConverged = true;
                break;
            }
            memSeeds = sr.seeds;
            for (FuncRec rec : funcRecs) {
                Map<String, Bits> e = entries.get(rec.entryKey);
                Map<String, Bits> merged = new HashMap<String, Bits>();
                if (e != null) merged.putAll(e);
                merged.putAll(memSeeds);
                FixResult nfx;
                try {
                    nfx = runFixpoint(rec.or.ops, memA,
                        rec.branchTargets, merged,
                        rec.loopCallOps);
                } catch (Exception ex) {
                    nfx = emptyFix(rec.or.ops.size());
                }
                if (nfx.converged || rec.fx == null ||
                    !rec.fx.converged) {
                    rec.fx = nfx;
                }
            }
        }
        if (!memConverged) {
            memSeeds = new HashMap<String, Bits>();
            for (FuncRec rec : funcRecs) {
                try {
                    FixResult nfx = runFixpoint(rec.or.ops, memA,
                        rec.branchTargets, entries.get(rec.entryKey),
                        rec.loopCallOps);
                    if (nfx.converged || rec.fx == null ||
                        !rec.fx.converged) {
                        rec.fx = nfx;
                    }
                } catch (Exception ex) {
                    // Keep the previous fixpoint.
                }
            }
            println("[!] memprop: stopped after " +
                MAX_CONSTPROP_ROUNDS +
                " rounds without convergence; seeds dropped.");
        }
        {
            StringBuilder sb = new StringBuilder();
            sb.append("[*] memprop: ").append(memRounds)
                .append(" rounds, converged=").append(memConverged)
                .append(", seeds=").append(memSeeds.size());
            if (lastSeedRes != null) {
                sb.append(", cells=").append(lastSeedRes.cells)
                    .append(", hasUnknownStore=")
                    .append(lastSeedRes.hasUnknownStore)
                    .append(", blockedLeak=")
                    .append(lastSeedRes.blockedLeak)
                    .append(", blockedConflict=")
                    .append(lastSeedRes.blockedConflict);
            }
            println(sb.toString());
            int shown = 0;
            for (Map.Entry<String, Bits> e : memSeeds.entrySet()) {
                if (shown >= 20) {
                    println("    ... and " + (memSeeds.size() - shown) +
                        " more seeds.");
                    break;
                }
                long[] as = parseMemKey(e.getKey());
                Long v = (as == null) ? null : e.getValue()
                    .exactValue(sizeMask((int) as[1]));
                println("    seed " + e.getKey() + " = " +
                    (v == null ? "?" : ("0x" + Long.toHexString(v))));
                shown++;
            }
        }
        // ---- v12 persite: per-site transfer ----
        // Constprop (v3.9), retprop (v8) and struct summaries
        // (v9) all use the all-sites-agree discipline: a callee
        // entry/return/field summary forms only when EVERY call
        // site agrees. QemuVideoDxe breaks it (its config-read
        // helper is called with different ports), and so does
        // any helper whose sites legitimately disagree. This
        // phase analyzes a callee separately per DISTINCT
        // argument-binding group, so each site gets its own
        // propagated values instead of one merged summary that
        // dies on disagreement.
        //
        // DESIGN DECISIONS (each justified, none silent):
        // (a) GRANULARITY: clone per distinct argument-binding
        // equivalence class, not per call site: sites with
        // identical bindings share one analysis. Blowup is
        // bounded by distinct vectors per callee (OVMF: every
        // callee has a handful of sites; the caps below bind
        // first on pathological inputs, never on this corpus).
        // (b) ATTRIBUTION: a clone's findings are recorded
        // under the CALLEE function (where the instruction
        // lives), deduped by (instr + accessed location)
        // against the merged lists. A finding identical
        // across clones is recorded ONCE (the identity set
        // dedups it); a finding that differs by location
        // across clones is recorded per location, which is
        // exactly the per-site win. Clones never merge back
        // into a shared summary.
        // (c) RECURSION: a clone's own fixpoint is
        // intra-procedural (inner CALLs use merged summaries),
        // so clones never recurse into themselves. Inner
        // sites whose callee is the clone's own function are
        // skipped (self-recursion keeps merged behaviour);
        // mutual recursion is bounded by the global clone
        // cap below, which stops generation (never guesses).
        // (d) MERGED INTERACTION: per-site applies ONLY where
        // merged is weaker. Groups identical to the merged
        // entry are skipped (their clone would reproduce the
        // merged fixpoint exactly); merged findings are never
        // removed or replaced -- extras only ADD at (instr,
        // class, location) triples the merged analysis missed.
        // (e) CAPS: 32 groups per callee, 1024 clones total.
        // Exceeding a cap skips the excess groups (those
        // sites keep merged behaviour = unknown, never a
        // guessed value), and the skip is logged.
        // (f) VALUE CLASSES: argument constants + BAR/BASE
        // symbols flow per-site (the binding vector carries
        // full Bits, so symbols group and propagate exactly
        // like constants). Struct/interface provenance
        // (Prov) per-site is OUT -- the Prov fixpoint is a
        // separate analysis that clones would need to
        // replicate; named as the next slice, not silently
        // omitted. Value refinement (same location, more
        // precise value than merged) is also OUT: extras
        // never replace a merged finding.
        //
        // SOUNDNESS: a clone's entry is read from its own
        // sites' CALL-op in-states (pre-clobber values), so a
        // site's value can never leak to another site: each
        // clone's fixpoint starts from exactly its group's
        // bindings, and each clone's findings are recorded
        // only under the callee with location dedup. A site
        // with an unknown argument joins the all-unknown
        // group, which is skipped (no clone, merged
        // behaviour for that site, other sites unaffected).
        // Per-site eligibility is deliberately RELAXED vs
        // merged (no address-taken / tail-call /
        // every-caller-direct guards): a clone models ONE
        // direct site, and other entries to the callee
        // (indirect calls, tail jumps) keep merged
        // behaviour -- they cannot invalidate the direct
        // site's own binding.
        Map<Long, long[]> persiteArgRegs =
            new HashMap<Long, long[]>();
        for (FuncRec callee : funcRecs) {
            if (callee.f.isExternal()) continue;
            // v14: no longer restricted to callees with direct
            // sites -- device-API and enumeration clones need
            // argument registers for functions with zero direct
            // sites. The seed loop below null-guards its site
            // lists, so a site-less callee simply yields no
            // site-driven groups.
            long[] argRegs = isa.argumentRegisterOffsets(
                callConvMap.get(callee.entryKey));
            if (argRegs == null) continue;
            persiteArgRegs.put(callee.entryKey, argRegs);
        }
        Map<Long, Map<String, PerSiteGroup>> persiteMap =
            new HashMap<Long, Map<String, PerSiteGroup>>();
        List<PerSiteGroup> persiteQueue =
            new ArrayList<PerSiteGroup>();
        int persiteSkippedIdentical = 0;
        int persiteSkippedUnknown = 0;
        int persiteSkippedCap = 0;
        int persiteSkippedNonconv = 0;
        int persiteClones = 0;
        long persiteMask = sizeMask(isa.pointerSize());
        // ---- v14 zephyr: device-API dispatch ----
        // Site-driven: every CALLIND whose target varnode and
        // argument register 0 are both exact constants in the
        // caller's final in-state resolves to exactly one
        // (target, device) pair, fed to the seed loop below
        // through a persite-only site list. sitesByCallee is
        // untouched, so merged phases are unaffected.
        // Table-driven: device init functions (symbols
        // __device_dts_ord_*) and ISR table entries
        // (sw_isr_table block, (arg, isr) pairs), each
        // validated as a device struct in non-writable memory,
        // seeded directly after the seed loop. All three feeds
        // use the existing clone caps/skips; nothing here
        // changes the merged analysis or the JSON shape.
        Map<Long, List<CallSite>> deviceSitesByCallee =
            new HashMap<Long, List<CallSite>>();
        List<long[]> deviceEnumPairs =
            new ArrayList<long[]>();
        // v14: addresses of validated device structs (from
        // init enumeration). ISR-table args must be members:
        // a bare shape check is not enough -- the ARM vector
        // table at address 0 also "looks like" a struct (its
        // word at +20 is a handler entry), and every unused
        // ISR entry carries arg 0, which would otherwise seed
        // dozens of bogus r0=0 clones.
        Set<Long> deviceAddrs = new HashSet<Long>();
        int devApiSites = 0, devApiSkipped = 0;
        int devInitFound = 0, devIsrFound = 0;
        int devPtrSize = isa.pointerSize();
        for (FuncRec rec : funcRecs) {
            if (rec.f.isExternal() || rec.fx == null ||
                rec.fx.inStates == null) continue;
            long[] convRegs = isa.argumentRegisterOffsets(
                callConvMap.get(rec.entryKey));
            if (convRegs == null || convRegs.length < 1) continue;
            List<OpRec> pops = rec.or.ops;
            for (int oi = 0; oi < pops.size(); oi++) {
                OpRec op = pops.get(oi);
                if (op == null || !"CALLIND".equals(op.mnem)) {
                    continue;
                }
                if (oi >= rec.fx.inStates.length ||
                    rec.fx.inStates[oi] == null) continue;
                long[] pair = resolveDeviceCallSite(pops,
                    rec.fx.inStates[oi], oi, convRegs[0],
                    devPtrSize, persiteMask, funcByEntry);
                if (pair == null) {
                    devApiSkipped++;
                    continue;
                }
                if (pair[0] == rec.entryKey) continue;
                List<CallSite> dl =
                    deviceSitesByCallee.get(pair[0]);
                if (dl == null) {
                    dl = new ArrayList<CallSite>();
                    deviceSitesByCallee.put(pair[0], dl);
                }
                dl.add(new CallSite(rec, oi));
                devApiSites++;
            }
        }
        try {
            SymbolIterator sit =
                currentProgram.getSymbolTable().getSymbolIterator();
            while (sit.hasNext()) {
                Symbol s = sit.next();
                String nm = s.getName();
                if (nm == null ||
                    !nm.startsWith("__device_dts_ord_")) continue;
                long da = s.getAddress().getOffset();
                if (!looksLikeDeviceStruct(memA, da,
                    funcByEntry)) continue;
                long init = isa.stripInstructionTag(
                    isa.readPointer(memA, toAddr(da + 20)));
                FuncRec tgt = funcByEntry.get(init);
                if (tgt == null || tgt.f.isExternal()) continue;
                deviceEnumPairs.add(
                    new long[]{tgt.entryKey, da, 0});
                deviceAddrs.add(da);
                devInitFound++;
            }
        } catch (Exception e) {
            // Init enumeration is best-effort; a symbol-table
            // failure must not lose the site-driven results.
        }
        // v3.19 Phase 3 item 5 (L2): section-based device
        // enumeration, FALLBACK ONLY -- it runs only when the
        // symbol scan above found zero devices, so an
        // unstripped binary's numbers are untouched (its pairs
        // come from symbols exactly as before). On a stripped
        // Zephyr binary the symbol names are gone but the
        // section headers survive, and the linker-defined
        // device_area section still holds the device records
        // contiguously: [name, ?, api, state, data, init, 0]
        // (init at +20, as the symbol path reads it). A
        // candidate record start must pass
        // looksLikeDeviceStruct (readonly block, init at +20
        // is a known function) AND the section-specific gate
        // that the word at +8 points into a
        // *_driver_api_area section. The gate is what kills
        // intra-record shifted windows: for a window inside
        // a true record, the +8 word is a state/data pointer
        // (RAM), an init code pointer (text), zero, or a
        // name pointer (rodata) -- never an api-area start.
        // Records are found by scanning forward 4 bytes at a
        // time for the next passing start, so no record
        // stride is hardcoded (it varies by Zephyr version
        // and config). Pairs feed the same clone machinery
        // as symbol pairs, and the ISR enumeration below
        // (already section-based, gated on deviceAddrs) then
        // works on stripped binaries too.
        if (devInitFound == 0) {
            try {
                MemoryBlock devBlk = null;
                for (MemoryBlock b : memA.getBlocks()) {
                    if ("device_area".equals(b.getName())) {
                        devBlk = b;
                        break;
                    }
                }
                if (devBlk != null) {
                    long a = devBlk.getStart().getOffset();
                    long e = devBlk.getEnd().getOffset();
                    while (a + 27 <= e) {
                        long rec = -1;
                        for (long c = a; c + 27 <= e; c += 4) {
                            if (!looksLikeDeviceStruct(memA, c,
                                funcByEntry)) continue;
                            MemoryBlock apiBlk = null;
                            try {
                                long apiPtr = isa.readPointer(
                                    memA, toAddr(c + 8));
                                apiBlk = memA.getBlock(
                                    toAddr(apiPtr));
                            } catch (Exception ex) {
                                apiBlk = null;
                            }
                            if (apiBlk == null ||
                                !apiBlk.getName().endsWith(
                                    "_driver_api_area")) {
                                continue;
                            }
                            rec = c;
                            break;
                        }
                        if (rec < 0) break;
                        long init = isa.stripInstructionTag(
                            isa.readPointer(memA,
                                toAddr(rec + 20)));
                        FuncRec tgt = funcByEntry.get(init);
                        if (tgt != null &&
                            !tgt.f.isExternal()) {
                            deviceEnumPairs.add(
                                new long[]{tgt.entryKey, rec, 0});
                            deviceAddrs.add(rec);
                            devInitFound++;
                        }
                        a = rec + 4;
                    }
                }
            } catch (Exception e) {
                // Section fallback is best-effort; a failure
                // leaves the stripped binary at the
                // site-driven results, never worse.
            }
        }
        try {
            MemoryBlock isrBlk = null;
            for (MemoryBlock b : memA.getBlocks()) {
                if ("sw_isr_table".equals(b.getName())) {
                    isrBlk = b;
                    break;
                }
            }
            if (isrBlk != null) {
                long a = isrBlk.getStart().getOffset();
                long e = isrBlk.getEnd().getOffset();
                while (a + 7 <= e) {
                    long arg = isa.readPointer(memA, toAddr(a));
                    long isr = isa.stripInstructionTag(
                        isa.readPointer(memA, toAddr(a + 4)));
                    FuncRec tgt = funcByEntry.get(isr);
                    if (tgt != null && !tgt.f.isExternal() &&
                        deviceAddrs.contains(arg) &&
                        looksLikeDeviceStruct(memA, arg,
                            funcByEntry)) {
                        deviceEnumPairs.add(
                            new long[]{tgt.entryKey, arg, 1});
                        devIsrFound++;
                    }
                    a += 8;
                }
            }
        } catch (Exception e) {
            // ISR enumeration is best-effort, as above.
        }
        // Seed groups from merged contexts (caller final
        // fixpoints), grouped by binding vector.
        for (FuncRec callee : funcRecs) {
            long[] argRegs = persiteArgRegs.get(callee.entryKey);
            if (argRegs == null) continue;
            // v14: union of direct sites and device-API sites
            // (CALL vs CALLIND ops, so the two lists are
            // disjoint and no dedup is needed). Null-guarded:
            // persiteArgRegs is now widened to site-less
            // callees, which simply yield empty unions.
            List<CallSite> sites = new ArrayList<CallSite>();
            List<CallSite> directSites =
                sitesByCallee.get(callee.entryKey);
            if (directSites != null) sites.addAll(directSites);
            List<CallSite> devSites =
                deviceSitesByCallee.get(callee.entryKey);
            if (devSites != null) sites.addAll(devSites);
            Map<String, List<Bits>> valsByKey =
                new HashMap<String, List<Bits>>();
            Map<String, List<String>> sitesByKey =
                new HashMap<String, List<String>>();
            for (CallSite s : sites) {
                Map<String, Bits> st = null;
                if (s.caller.fx != null &&
                    s.caller.fx.inStates != null &&
                    s.opIdx < s.caller.fx.inStates.length) {
                    st = s.caller.fx.inStates[s.opIdx];
                }
                List<Bits> vals =
                    persiteBindingFromState(st, argRegs);
                String key = persiteGroupKey(vals, persiteMask);
                if (!valsByKey.containsKey(key)) {
                    valsByKey.put(key, vals);
                    sitesByKey.put(key, new ArrayList<String>());
                }
                String desc = s.caller.f.getName() + "@" +
                    s.caller.or.ops.get(s.opIdx).instrAddr;
                sitesByKey.get(key).add(desc);
            }
            List<String> keys =
                new ArrayList<String>(valsByKey.keySet());
            java.util.Collections.sort(keys);
            for (String key : keys) {
                if (persiteAllUnknown(key)) {
                    persiteSkippedUnknown++;
                    continue;
                }
                if (persiteEqualsMerged(key,
                    entries.get(callee.entryKey), argRegs,
                    persiteMask)) {
                    persiteSkippedIdentical++;
                    continue;
                }
                Map<String, PerSiteGroup> have =
                    persiteMap.get(callee.entryKey);
                if (have != null && have.size() >= 32) {
                    persiteSkippedCap++;
                    continue;
                }
                if (persiteClones >= 1024) {
                    persiteSkippedCap++;
                    continue;
                }
                Map<String, Bits> entry = persiteEntry(
                    valsByKey.get(key), argRegs, memSeeds,
                    persiteMask);
                FixResult cfx;
                try {
                    cfx = runFixpoint(callee.or.ops, memA,
                        callee.branchTargets, entry,
                        callee.loopCallOps);
                } catch (Exception ex) {
                    cfx = emptyFix(callee.or.ops.size());
                }
                if (!cfx.converged) {
                    persiteSkippedNonconv++;
                    continue;
                }
                PerSiteGroup g = new PerSiteGroup(
                    callee.entryKey, key, cfx, sitesByKey.get(key));
                if (have == null) {
                    have = new HashMap<String, PerSiteGroup>();
                    persiteMap.put(callee.entryKey, have);
                }
                have.put(key, g);
                persiteQueue.add(g);
                persiteClones++;
            }
        }
        // v14: seed enumeration pairs (device init fns +
        // ISR table entries) as clones with r0 = device
        // address. Same caps/skips/group discipline as the
        // seed loop; a pair whose group already exists (e.g.
        // a site-driven clone for the same function+device)
        // is skipped, never duplicated. Enumeration clones
        // join the same queue, so the worklist extends them.
        for (long[] pair : deviceEnumPairs) {
            long calleeKey = pair[0];
            long devAddr = pair[1];
            FuncRec calleeRec = funcByEntry.get(calleeKey);
            if (calleeRec == null) continue;
            long[] argRegs = persiteArgRegs.get(calleeKey);
            if (argRegs == null) continue;
            List<Bits> vals = new ArrayList<Bits>();
            for (int vi = 0; vi < argRegs.length; vi++) {
                vals.add(vi == 0 ?
                    Bits.exact(devAddr, persiteMask) : null);
            }
            String key = persiteGroupKey(vals, persiteMask);
            if (persiteAllUnknown(key)) {
                persiteSkippedUnknown++;
                continue;
            }
            if (persiteEqualsMerged(key,
                entries.get(calleeKey), argRegs,
                persiteMask)) {
                persiteSkippedIdentical++;
                continue;
            }
            Map<String, PerSiteGroup> have =
                persiteMap.get(calleeKey);
            if (have != null && have.containsKey(key)) continue;
            if (have != null && have.size() >= 32) {
                persiteSkippedCap++;
                continue;
            }
            if (persiteClones >= 1024) {
                persiteSkippedCap++;
                continue;
            }
            Map<String, Bits> entry = persiteEntry(
                vals, argRegs, memSeeds, persiteMask);
            FixResult cfx;
            try {
                cfx = runFixpoint(calleeRec.or.ops, memA,
                    calleeRec.branchTargets, entry,
                    calleeRec.loopCallOps);
            } catch (Exception ex) {
                cfx = emptyFix(calleeRec.or.ops.size());
            }
            if (!cfx.converged) {
                persiteSkippedNonconv++;
                continue;
            }
            List<String> desc = new ArrayList<String>();
            desc.add((pair[2] == 0 ? "device-init:0x" :
                "isr-table:0x") + Long.toHexString(devAddr));
            PerSiteGroup g = new PerSiteGroup(
                calleeKey, key, cfx, desc);
            if (have == null) {
                have = new HashMap<String, PerSiteGroup>();
                persiteMap.put(calleeKey, have);
            }
            have.put(key, g);
            persiteQueue.add(g);
            persiteClones++;
        }
        // Worklist: scan each clone's ops for inner CALLs
        // and device-API CALLINDs, whose bindings (read from
        // the CLONE's in-states) may form new groups for the
        // inner callee. Termination is structural: groups are
        // only
        // added (never modified), keyed by (callee, vector),
        // and bounded by the caps above.
        int persiteQueueIdx = 0;
        while (persiteQueueIdx < persiteQueue.size()) {
            PerSiteGroup g = persiteQueue.get(persiteQueueIdx++);
            FuncRec calleeRec = funcByEntry.get(g.calleeKey);
            if (calleeRec == null || g.fx == null ||
                g.fx.inStates == null) continue;
            List<OpRec> pops = calleeRec.or.ops;
            for (int pi = 0; pi < pops.size(); pi++) {
                OpRec op = pops.get(pi);
                if (op.ins.length < 1) continue;
                FuncRec inner = null;
                if (op.mnem.equals("CALL")) {
                    Varnode t = op.ins[0];
                    if (t == null || t.getAddress() == null ||
                        !"ram".equals(t.getAddress().
                            getAddressSpace().getName())) {
                        continue;
                    }
                    inner = funcByEntry.get(t.getOffset());
                    if (inner == null) {
                        inner = funcByEntry.get(
                            isa.stripInstructionTag(
                                t.getOffset()));
                    }
                } else if (op.mnem.equals("CALLIND")) {
                    // v14: indirect calls inside a clone
                    // resolve against the CLONE's in-state
                    // (not the merged fixpoint), so a wrapper
                    // cloned with r0 = device dispatches to
                    // the real driver function.
                    long[] wRegs = isa.argumentRegisterOffsets(
                        callConvMap.get(g.calleeKey));
                    if (wRegs == null || wRegs.length < 1) {
                        continue;
                    }
                    if (pi >= g.fx.inStates.length ||
                        g.fx.inStates[pi] == null) continue;
                    long[] pair = resolveDeviceCallSite(pops,
                        g.fx.inStates[pi], pi, wRegs[0],
                        devPtrSize, persiteMask, funcByEntry);
                    if (pair != null) {
                        inner = funcByEntry.get(pair[0]);
                    }
                } else {
                    continue;
                }
                if (inner == null) continue;
                // Self-recursion keeps merged behaviour (see
                // design note (c)); the clone's own entry
                // already models this caller's context.
                if (inner.entryKey == g.calleeKey) continue;
                long[] innerRegs =
                    persiteArgRegs.get(inner.entryKey);
                if (innerRegs == null) continue;
                if (pi >= g.fx.inStates.length ||
                    g.fx.inStates[pi] == null) continue;
                List<Bits> vals = persiteBindingFromState(
                    g.fx.inStates[pi], innerRegs);
                String key =
                    persiteGroupKey(vals, persiteMask);
                if (persiteAllUnknown(key)) {
                    persiteSkippedUnknown++;
                    continue;
                }
                if (persiteEqualsMerged(key,
                    entries.get(inner.entryKey), innerRegs,
                    persiteMask)) {
                    persiteSkippedIdentical++;
                    continue;
                }
                Map<String, PerSiteGroup> have =
                    persiteMap.get(inner.entryKey);
                if (have != null && have.containsKey(key)) continue;
                if (have != null && have.size() >= 32) {
                    persiteSkippedCap++;
                    continue;
                }
                if (persiteClones >= 1024) {
                    persiteSkippedCap++;
                    continue;
                }
                Map<String, Bits> entry = persiteEntry(
                    vals, innerRegs, memSeeds, persiteMask);
                FixResult cfx;
                try {
                    cfx = runFixpoint(inner.or.ops, memA,
                        inner.branchTargets, entry,
                        inner.loopCallOps);
                } catch (Exception ex) {
                    cfx = emptyFix(inner.or.ops.size());
                }
                if (!cfx.converged) {
                    persiteSkippedNonconv++;
                    continue;
                }
                List<String> desc = new ArrayList<String>();
                desc.add(calleeRec.f.getName() + "@" +
                    op.instrAddr + " [clone " + g.groupKey + "]");
                PerSiteGroup ng = new PerSiteGroup(
                    inner.entryKey, key, cfx, desc);
                if (have == null) {
                    have = new HashMap<String, PerSiteGroup>();
                    persiteMap.put(inner.entryKey, have);
                }
                have.put(key, ng);
                persiteQueue.add(ng);
                persiteClones++;
            }
        }
        // Sorted per-callee group lists for deterministic
        // emission order (the emission block below iterates
        // these in order; dedup makes order irrelevant to
        // the result, but determinism keeps diffs clean).
        Map<Long, List<PerSiteGroup>> persiteByCallee =
            new HashMap<Long, List<PerSiteGroup>>();
        for (Map.Entry<Long, Map<String, PerSiteGroup>> e :
            persiteMap.entrySet()) {
            List<PerSiteGroup> gl =
                new ArrayList<PerSiteGroup>(e.getValue().values());
            java.util.Collections.sort(gl,
                new java.util.Comparator<PerSiteGroup>() {
                    public int compare(PerSiteGroup a,
                        PerSiteGroup b) {
                        return a.groupKey.compareTo(b.groupKey);
                    }
                });
            persiteByCallee.put(e.getKey(), gl);
        }
        int persiteExtraMmio = 0;
        int persiteExtraPort = 0;
        int persiteExtraMsr = 0;
        int persiteExtraBar = 0;
        int persiteSkippedIdent = 0;
        int persiteReplayMismatch = 0;
        {
            int shown = 0;
            for (Map.Entry<Long, List<PerSiteGroup>> e :
                persiteByCallee.entrySet()) {
                FuncRec cr = funcByEntry.get(e.getKey());
                String cn = (cr == null) ? ("0x" +
                    Long.toHexString(e.getKey())) : cr.f.getName();
                for (PerSiteGroup g : e.getValue()) {
                    if (shown < 200) {
                        println("[*] persite: clone " + cn +
                            " group [" + g.groupKey + "] sites=" +
                            g.sites.size());
                        shown++;
                    }
                }
            }
            println("[*] persite: callees=" +
                persiteByCallee.size() + ", clones=" +
                persiteClones + ", skippedIdentical=" +
                persiteSkippedIdentical + ", skippedUnknown=" +
                persiteSkippedUnknown + ", skippedCap=" +
                persiteSkippedCap + ", skippedNonconv=" +
                persiteSkippedNonconv + ".");
            println("[*] devicesites: apiSites=" +
                devApiSites + ", apiSkipped=" +
                devApiSkipped + ", devInit=" +
                devInitFound + ", devIsr=" + devIsrFound +
                ".");
        println("[*] stackslot: stores=" + stkStoreCount +
            ", loadHits=" + stkLoadHitCount + ".");
        println("[*] tailsites: direct-branch tail-call sites " +
            "added to sitesByCallee=" + tailSitesAdded + ".");
        }
        // v3.15 bounds pre-pass: per-function signed-ARG-vs-0 bit,
        // used for guard-call classification in the main scan.
        // Best-effort: a failure here only loses guard-call
        // suppression (sites stay, possibly flagged), never the
        // report.
        Map<Long, Boolean> signedCheckByEntry =
            new HashMap<Long, Boolean>();
        // Bounds Phase 1, item 3: per-function caller-validation
        // records (built from the same pre-pass scans) and the
        // Ghidra-known caller sets. A caller set that cannot be
        // built, or that names a function with no FuncRec, gets
        // the Long.MIN_VALUE sentinel, which always blocks
        // suppression (fail-closed).
        Map<Long, BoundsValid> validByEntry =
            new HashMap<Long, BoundsValid>();
        Map<Long, Set<Long>> callerSets =
            new HashMap<Long, Set<Long>>();
        try {
            Map<Function, Long> funcToEntry =
                new HashMap<Function, Long>();
            for (FuncRec gr : funcRecs) {
                funcToEntry.put(gr.f, gr.entryKey);
            }
            for (FuncRec gr : funcRecs) {
                try {
                    long[] goffs = boundsArgOffsets(gr);
                    if (goffs == null || goffs.length < 3) {
                        signedCheckByEntry.put(gr.entryKey, false);
                        continue;
                    }
                    BoundsScan gs = boundsScan(gr.f, gr.or.ops,
                        gr.branchTargets, goffs, funcByEntry, null,
                        gr.entryKey, null, null);
                    signedCheckByEntry.put(gr.entryKey,
                        gs.hasSignedArgCheck);
                    BoundsValid bv = new BoundsValid();
                    bv.signedArgs.addAll(gs.signedArgs);
                    bv.derefArgs.addAll(gs.derefArgs);
                    bv.derefRoots.addAll(gs.derefRoots);
                    bv.cmps = gs.cmps;
                    bv.ops = gr.or.ops;
                    bv.branchTargets = gr.branchTargets;
                    bv.edges = gs.edges;
                    bv.ptrSize = gs.ptrSize;
                    validByEntry.put(gr.entryKey, bv);
                } catch (Exception e) {
                    // Unknown for this function; guard-call lookup
                    // treats a missing entry as "not a guard", and
                    // caller validation treats it as unvalidated.
                }
            }
            for (FuncRec gr : funcRecs) {
                Set<Long> cs = new HashSet<Long>();
                try {
                    Set<Function> callers =
                        gr.f.getCallingFunctions(monitor);
                    for (Function cf : callers) {
                        Long ce = funcToEntry.get(cf);
                        if (ce == null) {
                            cs.add(Long.MIN_VALUE);
                        } else {
                            cs.add(ce);
                        }
                    }
                } catch (Exception e) {
                    cs.add(Long.MIN_VALUE);
                }
                callerSets.put(gr.entryKey, cs);
            }
        } catch (Exception e) {
            // Maps stay partial; guard-call lookup tolerates it,
            // and caller validation fails closed on missing data.
        }
        // v3.19 Phase 3 item 1: tdcall-IO-read wrapper map
        // (entryKey -> size), x86-64 only. Best-effort: a
        // failure here only loses the new port entries, never
        // the function's existing findings. Keyed by the
        // stripped entry key (same key the emission loop's
        // CALL targets resolve to via funcByEntry).
        Map<Long, Integer> tdcallReadWrappers =
            new HashMap<Long, Integer>();
        if (isX86_64) {
            try {
                for (FuncRec gr : funcRecs) {
                    try {
                        Integer sz = tdcallReadSize(gr.or.ops);
                        if (sz != null) {
                            tdcallReadWrappers.put(gr.entryKey, sz);
                            println("[*] tdcall-read wrapper: " +
                                gr.f.getName() + " size=" + sz);
                        }
                    } catch (Exception e) {
                        // This wrapper stays unrecognized.
                    }
                }
            } catch (Exception e) {
                // Map stays partial/empty; fail-closed.
            }
        }
        // Phase 4 V1.5: static-table + thread-entry learning.
        // Runs once, after every fixpoint is final and before
        // the emission loop, so learned regions feed the
        // RAM-extension check and learned agents feed every
        // function's boundary judgment. A failure here learns
        // nothing (V1 behaviour) and never loses MMIO findings.
        if (bndProfile != null) {
            try {
                learnStaticTables(bndProfile, funcRecs,
                    funcByEntry);
            } catch (Exception e) {
                println("[!] boundary table learning failed: " + e);
            }
            try {
                learnThreadEntries(bndProfile, funcRecs,
                    funcByEntry);
            } catch (Exception e) {
                println("[!] boundary thread learning failed: " + e);
            }
        }
        for (FuncRec rec : funcRecs) {
            Function f = rec.f;
            if (!firstFn) w.println(",");
            firstFn = false;
            fnCount++;

            w.println("    {");
            w.println("      \"name\": \"" + esc(f.getName()) + "\",");
            w.println("      \"address\": \"" + f.getEntryPoint() + "\",");
            w.println("      \"size\": " + f.getBody().getNumAddresses() + ",");
            w.println("      \"is_external\": " + f.isExternal() + ",");

            // XREFs: who this function calls, and who calls it
            w.print("      \"called_functions\": [");
            try {
                Set<Function> called = f.getCalledFunctions(monitor);
                boolean first = true;
                for (Function c : called) {
                    if (!first) w.print(", ");
                    w.print("\"" + esc(c.getName()) + "\"");
                    first = false;
                }
            } catch (Exception e) {
                // keep JSON valid even if call graph lookup fails
            }
            w.println("],");
            w.print("      \"calling_functions\": [");
            try {
                Set<Function> callers = f.getCallingFunctions(monitor);
                boolean first = true;
                for (Function c : callers) {
                    if (!first) w.print(", ");
                    w.print("\"" + esc(c.getName()) + "\"");
                    first = false;
                }
            } catch (Exception e) {
            }
            w.println("],");

            // Emission reuses the Phase A/B results: ops, merged
            // branch targets, indirect recovery, and the final
            // must-fixpoint (with inter-procedural entry states).
            // The may-fixpoint below still runs inline, all-unknown,
            // exactly as before v2 item #2.
            OpsResult or = rec.or;
            List<OpRec> ops = or.ops;
            // v3.15 bounds: computed-pointer copy sites for this
            // function (additive evidence; a failure here must not
            // lose the function's MMIO findings).
            List<BoundsSiteRec> copySites =
                new ArrayList<BoundsSiteRec>();
            int copyFlagged = 0;
            try {
                long[] boffs = boundsArgOffsets(rec);
                if (boffs != null && boffs.length >= 3) {
                    BoundsScan bs = boundsScan(f, ops, rec.branchTargets,
                        boffs, funcByEntry, signedCheckByEntry,
                        rec.entryKey, validByEntry, callerSets);
                    copySites = bs.sites;
                    for (BoundsSiteRec sr : copySites) {
                        if (sr.flagged) copyFlagged++;
                    }
                    for (Map.Entry<String, Integer> fe :
                        bs.formCounts.entrySet()) {
                        Integer prev = totalFormCounts.get(fe.getKey());
                        totalFormCounts.put(fe.getKey(), prev == null ?
                            fe.getValue() : prev + fe.getValue());
                    }
                    totalTransferCalls += bs.transferCalls;
                }
            } catch (Exception e) {
                // copySites stays empty; report continues.
            }
            boolean truncated = or.truncated;
            int opCount = ops.size();
            Map<Integer, List<Integer>> branchTargets = rec.branchTargets;
            IndirectResult ind = rec.ind;
            FixResult fx = rec.fx;
            MayResult my;
            try {
                my = runMayFixpoint(ops, currentProgram.getMemory(),
                    branchTargets);
            } catch (Exception e) {
                Map<String, Map<Long, Set<Integer>>>[] emptyMay =
                    new Map[ops.size()];
                for (int i = 0; i < emptyMay.length; i++) {
                    emptyMay[i] =
                        new HashMap<String, Map<Long, Set<Integer>>>();
                }
                my = new MayResult(emptyMay, false);
            }

            w.println("      \"pcode\": [");
            boolean firstOp = true;
            List<String> mmio = new ArrayList<String>();
            List<String> may = new ArrayList<String>();
            List<String> portIo = new ArrayList<String>();
            List<String> msr = new ArrayList<String>();
            // v7 cfgspace: BAR-relative findings (additive class).
            List<String> barRel = new ArrayList<String>();
            // Phase 4 V1: must accesses for boundary judgment
            // (mmio-window accesses + profile-region extension).
            List<BoundaryAccess> bndAccesses =
                new ArrayList<BoundaryAccess>();
            Memory mem = currentProgram.getMemory();
            // Successors for the recording-time feasibility filter.
            List<List<Integer>> maySucc = buildSucc(ops, branchTargets);
            for (int i = 0; i < ops.size(); i++) {
                OpRec op = ops.get(i);
                if (!firstOp) w.println(",");
                firstOp = false;
                w.print("        {\"addr\": \"" + op.instrAddr +
                    "\", \"asm\": \"" + esc(op.instrAsm) +
                    "\", \"op\": \"" + esc(op.mnem) + "\", \"inputs\": [");
                for (int k = 0; k < op.ins.length; k++) {
                    if (k > 0) w.print(", ");
                    w.print(varnodeJson(op.ins[k]));
                }
                w.print("], \"output\": " + varnodeJson(op.out) + "}");

                // ---- MMIO recording from the FINAL fixpoint state ----
                // Masks and exact values print UNSIGNED (v3.8): a
                // 64-bit mask/value with the high bit set prints
                // negative as a Java long, which Lean's Nat parser
                // rejects. 32-bit values print identically either way.
                boolean mustRecorded = false;
                if (op.mnem.equals("LOAD") || op.mnem.equals("STORE")) {
                    Map<String, Bits> bvals = fx.inStates[i];
                    if (bvals != null && op.ins.length >= 2) {
                        Bits valBits = Bits.unknown();
                        if (op.mnem.equals("LOAD") && op.out != null) {
                            valBits = loadBits(op.ins, op.out, bvals, mem);
                        } else if (op.mnem.equals("STORE") && op.ins.length >= 3) {
                            valBits = resolveBits(op.ins[2], bvals);
                        }
                        Long addr = resolveAddressExact(op.ins[1], bvals);
                        if (addr != null && isa.isMmioAddress(addr)) {
                            int sz = (op.mnem.equals("STORE") && op.ins.length >= 3)
                                ? op.ins[2].getSize()
                                : (op.out != null ? op.out.getSize() : 0);
                            Long exact = valBits.exactValue(
                                sizeMask(sz == 0 ? 4 : sz));
                            mmio.add("{\"instr\": \"" + op.instrAddr +
                                "\", \"op\": \"" + op.mnem +
                                "\", \"address\": \"0x" + Long.toHexString(addr) +
                                "\", \"size\": " + sz +
                                ", \"value\": " +
                                (exact == null ? "null" : Long.toUnsignedString(exact)) +
                                ", \"value_known_ones\": " + Long.toUnsignedString(valBits.ones) +
                                ", \"value_known_zeroes\": " + Long.toUnsignedString(valBits.zeroes) + "}");
                            mustRecorded = true;
                            if (bndProfile != null) {
                                bndAccesses.add(new BoundaryAccess(
                                    op.instrAddr.toString(), op.mnem,
                                    addr.longValue(), exact));
                            }
                        } else if (addr != null && bndProfile != null &&
                            bndProfile.regionFor(addr.longValue()) != null) {
                            // Phase 4 RAM-region extension: a
                            // must-proven access inside a profile
                            // region but outside every MMIO window
                            // (e.g. SEC_RAM at 0x30000000) is a
                            // boundary candidate, NOT an mmio
                            // trace op: mmio_access_total and the
                            // Lean window check are untouched.
                            Long extExact = null;
                            if (op.mnem.equals("STORE") &&
                                op.ins.length >= 3) {
                                extExact = valBits.exactValue(sizeMask(
                                    op.ins[2].getSize()));
                            }
                            bndAccesses.add(new BoundaryAccess(
                                op.instrAddr.toString(), op.mnem,
                                addr.longValue(), extExact));
                        }
                    }
                }
                // ---- v9 struct: COPY-to-ram MMIO stores ----
                // The transfer treats COPY-to-ram as an absolute
                // store (x86-64 movabs / RIP-relative stores never
                // become STORE ops), but emission only recorded
                // LOAD/STORE, so absolute MMIO stores were silently
                // dropped. A COPY-to-ram address is a constant, so
                // this is a must-recording, never a may. Value and
                // size mirror the STORE rule.
                if (op.mnem.equals("COPY") && op.out != null &&
                    isRamSpace(op.out) && op.ins.length >= 1) {
                    Map<String, Bits> bvals = fx.inStates[i];
                    if (bvals != null) {
                        // v10 u32: band-gated canonicalization, so
                        // a movabs to 0xFFFFFFFFFED00020 records as
                        // the MMIO address 0xFED00020.
                        long a = canonicalizeBandAddr(op.out.getOffset());
                        if (isa.isMmioAddress(a)) {
                            Bits valBits = resolveBits(op.ins[0], bvals);
                            int sz = op.out.getSize();
                            Long exact = valBits.exactValue(
                                sizeMask(sz == 0 ? 4 : sz));
                            mmio.add("{\"instr\": \"" + op.instrAddr +
                                "\", \"op\": \"" + op.mnem +
                                "\", \"address\": \"0x" + Long.toHexString(a) +
                                "\", \"size\": " + sz +
                                ", \"value\": " +
                                (exact == null ? "null" : Long.toUnsignedString(exact)) +
                                ", \"value_known_ones\": " + Long.toUnsignedString(valBits.ones) +
                                ", \"value_known_zeroes\": " + Long.toUnsignedString(valBits.zeroes) + "}");
                            if (bndProfile != null) {
                                bndAccesses.add(new BoundaryAccess(
                                    op.instrAddr.toString(), op.mnem, a, exact));
                            }
                        } else if (bndProfile != null &&
                            bndProfile.regionFor(a) != null) {
                            // Phase 4 RAM-region extension, COPY
                            // form (same rule as the LOAD/STORE
                            // form above).
                            Bits valBits = resolveBits(op.ins[0], bvals);
                            int sz = op.out.getSize();
                            Long extExact = valBits.exactValue(
                                sizeMask(sz == 0 ? 4 : sz));
                            bndAccesses.add(new BoundaryAccess(
                                op.instrAddr.toString(), op.mnem, a, extExact));
                        }
                    }
                }
                // ---- MAY recording: sites the must-analysis drops ----
                // (path-dependent address) but with a finite set of
                // possible MMIO addresses. Value masks come from the
                // must-state (a STORE's value does not depend on its
                // address); MAY-LOAD values are unknown (the must
                // address is unknown, so no program-memory read applies).
                // v3.7: values whose every defining op is provably
                // dead at this use (redefined on every feasible path
                // -- the correlated if/else-assign false positive) are
                // dropped before the MMIO filter; anything doubtful
                // is kept, so no true may-address is ever lost.
                if ((op.mnem.equals("LOAD") || op.mnem.equals("STORE")) &&
                    !mustRecorded && my.inStates[i] != null &&
                    op.ins.length >= 2) {
                    Set<Long> addrSet = null;
                    if (op.ins[1].isConstant()) {
                        addrSet = new HashSet<Long>();
                        addrSet.add(op.ins[1].getOffset() &
                            sizeMask(op.ins[1].getSize()));
                    } else {
                        Map<Long, Set<Integer>> prov =
                            my.inStates[i].get(vkey(op.ins[1]));
                        if (prov != null) {
                            addrSet = new HashSet<Long>();
                            for (Map.Entry<Long, Set<Integer>> e :
                                prov.entrySet()) {
                                boolean keep = e.getValue().isEmpty();
                                if (!keep) {
                                    for (int d : e.getValue()) {
                                        if (!isKilledDef(d, i, vkey(op.ins[1]),
                                            ops, maySucc)) {
                                            keep = true;
                                            break;
                                        }
                                    }
                                }
                                if (keep) addrSet.add(e.getKey());
                            }
                        }
                    }
                    if (addrSet != null) {
                        List<Long> win = new ArrayList<Long>();
                        for (long a : addrSet) {
                            if (isa.isMmioAddress(a)) win.add(a);
                            // v10 u32: may-addresses are exact longs
                            // (the may transfer computes SEXT exactly),
                            // so the shape test applies directly: a
                            // sext-shaped may-address whose low 32
                            // bits are in a band is that band address.
                            else if (isSext32Value(a) &&
                                isa.isMmioAddress(a & 0xFFFFFFFFL)) {
                                win.add(a & 0xFFFFFFFFL);
                            }
                        }
                        if (!win.isEmpty()) {
                            java.util.Collections.sort(win);
                            int sz = (op.mnem.equals("STORE") && op.ins.length >= 3)
                                ? op.ins[2].getSize()
                                : (op.out != null ? op.out.getSize() : 0);
                            Bits valBits = Bits.unknown();
                            Long exact = null;
                            if (op.mnem.equals("STORE") && op.ins.length >= 3 &&
                                fx.inStates[i] != null) {
                                valBits = resolveBits(op.ins[2], fx.inStates[i]);
                                exact = valBits.exactValue(
                                    sizeMask(sz == 0 ? 4 : sz));
                            }
                            StringBuilder ab = new StringBuilder();
                            for (int k = 0; k < win.size(); k++) {
                                if (k > 0) ab.append(", ");
                                ab.append("\"0x" + Long.toHexString(win.get(k)) + "\"");
                            }
                            may.add("{\"instr\": \"" + op.instrAddr +
                                "\", \"op\": \"" + op.mnem +
                                "\", \"addresses\": [" + ab.toString() +
                                "], \"size\": " + sz +
                                ", \"value\": " +
                                (exact == null ? "null" : Long.toUnsignedString(exact)) +
                                ", \"value_known_ones\": " + Long.toUnsignedString(valBits.ones) +
                                ", \"value_known_zeroes\": " + Long.toUnsignedString(valBits.zeroes) + "}");
                        }
                    }
                }
                // ---- Port I/O + MSR recording (x86 CALLOTHER) ----
                // Ghidra lifts IN/OUT/RDMSR/WRMSR to CALLOTHER
                // userops; the instruction mnemonic (op.instrAsm)
                // is the signal, NOT the userop index (a Ghidra
                // internal). Port/MSR spaces are disjoint from
                // memory, so they get their own JSON classes (v3.8
                // shape change) instead of polluting mmio_accesses.
                // Port numbers are masked to the 16-bit port space.
                // IN/RDMSR values are hardware inputs -> null.
                // PCI config ports 0xCF8/0xCFC fall out raw here;
                // BDF decoding is v2.
                if (op.mnem.equals("CALLOTHER") &&
                    op.ins.length >= 1) {
                    Map<String, Bits> bvals = fx.inStates[i];
                    if (bvals != null) {
                        String am = op.instrAsm;
                        if (am.equalsIgnoreCase("OUT") &&
                            op.ins.length >= 3) {
                            // v10 u32: band-gated address helper
                            // (a no-op after the 0xFFFF mask below,
                            // kept for uniformity with MMIO sites).
                            Long port = resolveAddressExact(op.ins[1],
                                bvals);
                            if (port != null) {
                                Bits vb = resolveBitsSlice(op.ins[2],
                                    bvals);
                                int sz = op.ins[2].getSize();
                                Long exact = vb.exactValue(
                                    sizeMask(sz));
                                portIo.add("{\"instr\": \"" +
                                    op.instrAddr + "\", \"op\": \"OUT\"" +
                                    ", \"direction\": \"OUT\"" +
                                    ", \"port\": \"0x" +
                                    Long.toHexString(port & 0xFFFFL) +
                                    "\", \"size\": " + sz +
                                    ", \"value\": " +
                                    (exact == null ? "null" :
                                        Long.toUnsignedString(exact)) +
                                    ", \"value_known_ones\": " +
                                    Long.toUnsignedString(vb.ones) +
                                    ", \"value_known_zeroes\": " +
                                    Long.toUnsignedString(vb.zeroes) + "}");
                            }
                        } else if (am.equalsIgnoreCase("IN") &&
                            op.ins.length >= 2) {
                            Long port = resolveAddressExact(op.ins[1],
                                bvals);
                            if (port != null) {
                                int sz = op.out != null ?
                                    op.out.getSize() : 0;
                                portIo.add("{\"instr\": \"" +
                                    op.instrAddr + "\", \"op\": \"IN\"" +
                                    ", \"direction\": \"IN\"" +
                                    ", \"port\": \"0x" +
                                    Long.toHexString(port & 0xFFFFL) +
                                    "\", \"size\": " + sz +
                                    ", \"value\": null" +
                                    ", \"value_known_ones\": 0" +
                                    ", \"value_known_zeroes\": 0}");
                            }
                        } else if (am.equalsIgnoreCase("WRMSR") &&
                            op.ins.length >= 3) {
                            // v10 u32: MSR indices are 32-bit by
                            // architecture, so a sext-shaped index
                            // reads as its low 32 bits (no band gate).
                            Long idx = resolveMsrIndexExact(op.ins[1],
                                bvals);
                            if (idx != null) {
                                // Combined 64-bit value (EDX:EAX):
                                // an intra-instruction unique, so
                                // exact-key lookup resolves it.
                                Bits vb = resolveBits(op.ins[2],
                                    bvals);
                                Long exact = vb.exactValue(
                                    sizeMask(8));
                                msr.add("{\"instr\": \"" +
                                    op.instrAddr +
                                    "\", \"op\": \"WRMSR\"" +
                                    ", \"direction\": \"WR\"" +
                                    ", \"index\": \"0x" +
                                    Long.toHexString(idx) +
                                    "\", \"size\": 8" +
                                    ", \"value\": " +
                                    (exact == null ? "null" :
                                        Long.toUnsignedString(exact)) +
                                    ", \"value_known_ones\": " +
                                    Long.toUnsignedString(vb.ones) +
                                    ", \"value_known_zeroes\": " +
                                    Long.toUnsignedString(vb.zeroes) + "}");
                            }
                        } else if (am.equalsIgnoreCase("RDMSR") &&
                            op.ins.length >= 2) {
                            Long idx = resolveMsrIndexExact(op.ins[1],
                                bvals);
                            if (idx != null) {
                                msr.add("{\"instr\": \"" +
                                    op.instrAddr +
                                    "\", \"op\": \"RDMSR\"" +
                                    ", \"direction\": \"RD\"" +
                                    ", \"index\": \"0x" +
                                    Long.toHexString(idx) +
                                    "\", \"size\": 8" +
                                    ", \"value\": null" +
                                    ", \"value_known_ones\": 0" +
                                    ", \"value_known_zeroes\": 0}");
                            }
                        }
                    }
                }
                // v7 cfgspace: BAR-relative findings. The access
                // address is a BASE symbol (masked BAR + constant
                // offset). This is a provenance statement (device
                // BDF, BAR index, offset), never a fixed address:
                // MUST-class is forbidden for symbolic values, and
                // the may-trace parses hex addresses, so a symbolic
                // address must not enter may_accesses either. Raw
                // BAR symbols (unmasked flag bits) never yield a
                // finding. Uses fx.inStates[i], the same mechanism
                // the CALLOTHER port/MSR block above relies on.
                // Guard null like the neighboring blocks: ops in
                // unreached code have a null in-state, and
                // resolveBits would NPE on it (hit on DxeCore,
                // PciBusDxe, stripped BMP).
                if (i < rec.fx.inStates.length &&
                    rec.fx.inStates[i] != null) {
                    Map<String, Bits> eb = rec.fx.inStates[i];
                    Bits ab = null;
                    int asz = 0;
                    if (op.mnem.equals("LOAD") && op.out != null &&
                        op.ins.length >= 2) {
                        ab = resolveBits(op.ins[1], eb);
                        asz = op.out.getSize();
                    } else if (op.mnem.equals("STORE") &&
                        op.ins.length >= 3) {
                        ab = resolveBits(op.ins[1], eb);
                        asz = op.ins[2].getSize();
                    }
                    if (ab != null && ab.sym != null) {
                        long[] p = Bits.parseBarSym(ab.sym);
                        if (p != null && p[0] == 1) {
                            barRel.add("{\"instr\": \"" +
                                op.instrAddr +
                                "\", \"op\": \"" + op.mnem + "\"" +
                                ", \"bus\": " + p[1] +
                                ", \"device\": " + p[2] +
                                ", \"function\": " + p[3] +
                                ", \"bar\": " + p[4] +
                                ", \"offset\": " + p[5] +
                                ", \"size\": " + asz + "}");
                        }
                    }
                }
            }
            // v12 persite: append per-site clone findings.
            // Runs BEFORE the protocol block below, so the
            // replay comparison stays exact (protocol ports
            // append to portIo afterwards, from CALLIND ops
            // that can never collide with clone CALLOTHER
            // findings). A clone finding is appended ONLY
            // when its identity (instr + accessed location)
            // is absent from the merged lists: merged
            // findings are never duplicated, never replaced,
            // and value refinement (same location, more
            // precise value) is deliberately NOT emitted
            // here -- it needs its own design. The replay
            // guard below makes this fail-safe: if the
            // factored recording ever diverges from the
            // inline walk, extras are skipped for that
            // function instead of duplicating findings.
            {
                List<PerSiteGroup> pgroups = null;
                if (persiteByCallee != null) {
                    pgroups = persiteByCallee.get(rec.entryKey);
                }
                if (pgroups != null && !pgroups.isEmpty()) {
                    List<String> rMmio = new ArrayList<String>();
                    List<String> rPortIo = new ArrayList<String>();
                    List<String> rMsr = new ArrayList<String>();
                    List<String> rBarRel = new ArrayList<String>();
                    List<String> rMmioIds = new ArrayList<String>();
                    List<String> rPortIds = new ArrayList<String>();
                    List<String> rMsrIds = new ArrayList<String>();
                    List<String> rBarIds = new ArrayList<String>();
                    for (int ri = 0; ri < ops.size(); ri++) {
                        Map<String, Bits> rb =
                            (ri < fx.inStates.length) ?
                            fx.inStates[ri] : null;
                        recordMustFindings(ops.get(ri), rb, mem,
                            rMmio, rPortIo, rMsr, rBarRel,
                            rMmioIds, rPortIds, rMsrIds, rBarIds,
                            null, null, null);
                    }
                    if (rMmio.equals(mmio) && rPortIo.equals(portIo) &&
                        rMsr.equals(msr) && rBarRel.equals(barRel)) {
                        Set<String> rMmioSet =
                            new HashSet<String>(rMmioIds);
                        Set<String> rPortSet =
                            new HashSet<String>(rPortIds);
                        Set<String> rMsrSet =
                            new HashSet<String>(rMsrIds);
                        Set<String> rBarSet =
                            new HashSet<String>(rBarIds);
                        for (PerSiteGroup g : pgroups) {
                            if (g.fx == null ||
                                g.fx.inStates == null) continue;
                            List<String> tMmio =
                                new ArrayList<String>();
                            List<String> tPortIo =
                                new ArrayList<String>();
                            List<String> tMsr =
                                new ArrayList<String>();
                            List<String> tBarRel =
                                new ArrayList<String>();
                            List<String> tMmioIds =
                                new ArrayList<String>();
                            List<String> tPortIds =
                                new ArrayList<String>();
                            List<String> tMsrIds =
                                new ArrayList<String>();
                            List<String> tBarIds =
                                new ArrayList<String>();
                            // Phase 4 V1: clone-replay boundary
                            // candidates (mmio-aligned + region
                            // extension). Collected here, deduped
                            // at evaluation: a clone finding that
                            // duplicates a main-loop finding is
                            // judged once, never twice.
                            List<BoundaryAccess> tBnd =
                                new ArrayList<BoundaryAccess>();
                            List<BoundaryAccess> tBndExt =
                                new ArrayList<BoundaryAccess>();
                            for (int ci = 0; ci < ops.size(); ci++) {
                                Map<String, Bits> cb =
                                    (ci < g.fx.inStates.length) ?
                                    g.fx.inStates[ci] : null;
                                recordMustFindings(ops.get(ci), cb,
                                    mem, tMmio, tPortIo, tMsr,
                                    tBarRel, tMmioIds, tPortIds,
                                    tMsrIds, tBarIds,
                                    tBnd, tBndExt, bndProfile);
                            }
                            if (bndProfile != null) {
                                bndAccesses.addAll(tBnd);
                                bndAccesses.addAll(tBndExt);
                            }
                            for (int ti = 0; ti < tMmio.size(); ti++) {
                                if (rMmioSet.add(tMmioIds.get(ti))) {
                                    mmio.add(tMmio.get(ti));
                                    persiteExtraMmio++;
                                } else {
                                    persiteSkippedIdent++;
                                }
                            }
                            for (int ti = 0; ti < tPortIo.size(); ti++) {
                                if (rPortSet.add(tPortIds.get(ti))) {
                                    portIo.add(tPortIo.get(ti));
                                    persiteExtraPort++;
                                } else {
                                    persiteSkippedIdent++;
                                }
                            }
                            for (int ti = 0; ti < tMsr.size(); ti++) {
                                if (rMsrSet.add(tMsrIds.get(ti))) {
                                    msr.add(tMsr.get(ti));
                                    persiteExtraMsr++;
                                } else {
                                    persiteSkippedIdent++;
                                }
                            }
                            for (int ti = 0; ti < tBarRel.size(); ti++) {
                                if (rBarSet.add(tBarIds.get(ti))) {
                                    barRel.add(tBarRel.get(ti));
                                    persiteExtraBar++;
                                } else {
                                    persiteSkippedIdent++;
                                }
                            }
                        }
                    } else {
                        println("[!] persite: replay mismatch in " +
                            f.getName() + ", extras skipped.");
                        persiteReplayMismatch++;
                    }
                }
            }
            // v2 item #3: protocol/BS call resolution from the
            // provenance fixpoint (Phase P). A resolved site is
            // explained, so it is excluded from the points-to
            // may/unresolved counts below (via ptCertain). Hardware
            // effects land in the EXISTING port_io_accesses class
            // with the exact existing entry shape; attribution
            // lives in protocol_call_edges (joinable on instr).
            Set<Integer> protoResolved = new HashSet<Integer>();
            List<String> protoEdges = new ArrayList<String>();
            if (isX86_64 && provCtx != null && rec.pv != null &&
                rec.pv.inStates != null) {
                for (int i = 0; i < ops.size(); i++) {
                    OpRec op = ops.get(i);
                    if (!op.mnem.equals("CALLIND")) continue;
                    if (i >= rec.pv.inStates.length ||
                        rec.pv.inStates[i] == null) continue;
                    ProtoCall pc = resolveProtoCall(op,
                        rec.pv.inStates[i], provCtx);
                    if (pc == null) continue;
                    protoResolved.add(i);
                    protoEdges.add("{\"instr\": \"" + op.instrAddr +
                        "\", \"protocol\": \"" + pc.guid +
                        "\", \"method\": \"" + pc.method +
                        "\", \"offset\": \"0x" +
                        Long.toHexString(pc.off) + "\"}");
                    String[][] eff = protoHwEffect(pc);
                    if (eff != null) {
                        for (String[] e : eff) {
                            portIo.add("{\"instr\": \"" + op.instrAddr +
                                "\", \"op\": \"" + e[1] + "\"" +
                                ", \"direction\": \"" + e[1] + "\"" +
                                ", \"port\": \"" + e[0] + "\"" +
                                ", \"size\": 4" +
                                ", \"value\": null" +
                                ", \"value_known_ones\": 0" +
                                ", \"value_known_zeroes\": 0}");
                        }
                    }
                }
            }
            // v3.19 Phase 3 item 1: tdcall-IO-read call-site
            // ports. Ghidra lifts `tdcall` to no pcode, so a
            // tdcall-only read wrapper (e.g. EDK2 IoRead8)
            // contributes no CALLOTHER IN of its own; the
            // access is emitted here, attributed to the CALL
            // instruction in the caller (same precedent as the
            // protocol effects above), with the exact existing
            // entry shape. Only exact argument values emit:
            // a computed port (e.g. 0xcfc + low bits) yields
            // nothing. Deduped on (instr, port) so a wrapper
            // call site shared by merged + clone recording
            // cannot double-count (this block runs on merged
            // state only, so duplicates can only come from
            // an identical raw entry -- checked anyway).
            if (isX86_64 && !tdcallReadWrappers.isEmpty() &&
                fx != null && fx.inStates != null) {
                Set<String> tdcallSeen = new HashSet<String>();
                for (int i = 0; i < ops.size(); i++) {
                    OpRec op = ops.get(i);
                    if (!op.mnem.equals("CALL") ||
                        op.ins.length < 1) continue;
                    Varnode tgt = op.ins[0];
                    if (tgt == null || tgt.isConstant()) continue;
                    long tgtOff;
                    try {
                        if (!"ram".equals(tgt.getAddress()
                            .getAddressSpace().getName())) continue;
                        tgtOff = tgt.getOffset();
                    } catch (Exception e) {
                        continue;
                    }
                    Integer wsz = tdcallReadWrappers.get(tgtOff);
                    if (wsz == null) continue;
                    if (i >= fx.inStates.length ||
                        fx.inStates[i] == null) continue;
                    Varnode arg0 = regVarnode(0x8L,
                        isa.pointerSize());
                    if (arg0 == null) continue;
                    Bits pb = resolveBits(arg0, fx.inStates[i]);
                    if (pb == null) continue;
                    Long port = pb.exactValue(0xFFFFL);
                    if (port == null) continue;
                    String id = "port:" + op.instrAddr + ":0x" +
                        Long.toHexString(port.longValue());
                    // A CALL instruction cannot also be a raw
                    // CALLOTHER entry, so per-function dedup on
                    // (instr, port) is sufficient here.
                    if (!tdcallSeen.add(id)) continue;
                    portIo.add("{\"instr\": \"" + op.instrAddr +
                        "\", \"op\": \"IN\"" +
                        ", \"direction\": \"IN\"" +
                        ", \"port\": \"0x" +
                        Long.toHexString(port.longValue()) +
                        "\", \"size\": " + wsz.intValue() +
                        ", \"value\": null" +
                        ", \"value_known_ones\": 0" +
                        ", \"value_known_zeroes\": 0}");
                }
            }
            w.println();
            w.println("      ],");
            w.println("      \"pcode_op_count\": " + opCount + ",");
            w.println("      \"pcode_truncated\": " + truncated + ",");
            w.println("      \"fixpoint_converged\": " + fx.converged + ",");
            w.println("      \"mmio_accesses\": [");
            for (int i = 0; i < mmio.size(); i++) {
                if (i > 0) w.println(",");
                w.print("        " + mmio.get(i));
            }
            w.println();
            w.println("      ],");
            w.println("      \"mmio_access_count\": " + mmio.size() + ",");
            w.println("      \"may_accesses\": [");
            for (int i = 0; i < may.size(); i++) {
                if (i > 0) w.println(",");
                w.print("        " + may.get(i));
            }
            w.println();
            w.println("      ],");
            w.println("      \"may_access_count\": " + may.size() + ",");
            w.println("      \"port_io_accesses\": [");
            for (int i = 0; i < portIo.size(); i++) {
                if (i > 0) w.println(",");
                w.print("        " + portIo.get(i));
            }
            w.println();
            w.println("      ],");
            w.println("      \"port_io_access_count\": " + portIo.size() + ",");
            w.println("      \"msr_accesses\": [");
            for (int i = 0; i < msr.size(); i++) {
                if (i > 0) w.println(",");
                w.print("        " + msr.get(i));
            }
            w.println();
            w.println("      ],");
            w.println("      \"msr_access_count\": " + msr.size() + ",");
            w.println("      \"bar_relative_accesses\": [");
            for (int i = 0; i < barRel.size(); i++) {
                if (i > 0) w.println(",");
                w.print("        " + barRel.get(i));
            }
            w.println();
            w.println("      ],");
            w.println("      \"bar_relative_access_count\": " +
                barRel.size() + ",");
            w.println("      \"may_fixpoint_converged\": " + my.converged + ",");
            w.println("      \"indirect_calls\": [");
            for (int i = 0; i < ind.sites.size(); i++) {
                if (i > 0) w.println(",");
                w.print("        " + ind.sites.get(i));
            }
            w.println();
            w.println("      ],");
            int indSucc = 0;
            for (List<Integer> s : ind.successors.values()) {
                indSucc += s.size();
            }
            PointsToResult pt;
            try {
                // Protocol-resolved sites are explained, not
                // unresolved: exclude them from the may/unresolved
                // counts (v2 item #3).
                Set<Integer> ptCertain =
                    new HashSet<Integer>(ind.certainCalls);
                ptCertain.addAll(protoResolved);
                pt = recoverPointsTo(ops, currentProgram.getMemory(),
                    currentProgram.getFunctionManager(), funcPtrByOffset,
                    funcPtrByAddr, ptCertain);
            } catch (Exception e) {
                pt = new PointsToResult(new ArrayList<String>(), 0, 0);
            }
            w.println("      \"indirect_call_count\": " + ind.sites.size() + ",");
            w.println("      \"indirect_call_edges\": " + ind.edges + ",");
            w.println("      \"indirect_successor_count\": " + indSucc + ",");
            w.println("      \"may_call_edges\": [");
            for (int i = 0; i < pt.maySites.size(); i++) {
                if (i > 0) w.println(",");
                w.print("        " + pt.maySites.get(i));
            }
            w.println();
            w.println("      ],");
            w.println("      \"may_call_site_count\": " + pt.maySites.size() + ",");
            w.println("      \"may_call_target_count\": " + pt.mayTargets + ",");
            w.println("      \"unresolved_indirect_count\": " + pt.unresolved + ",");
            w.println("      \"protocol_call_edges\": [");
            for (int i = 0; i < protoEdges.size(); i++) {
                if (i > 0) w.println(",");
                w.print("        " + protoEdges.get(i));
            }
            w.println();
            w.println("      ],");
            w.println("      \"protocol_call_edge_count\": " + protoEdges.size() + ",");
            // v3.6: tail-call recovery, computed in Phase A and reused
            // here (same data the entry guards used).
            TailCallResult tc = rec.tc;
            w.println("      \"may_tail_call_edges\": [");
            for (int i = 0; i < tc.sites.size(); i++) {
                if (i > 0) w.println(",");
                w.print("        " + tc.sites.get(i));
            }
            w.println();
            w.println("      ],");
            w.println("      \"may_tail_call_site_count\": " + tc.sites.size() + ",");
            w.println("      \"may_tail_call_target_count\": " + tc.targets + ",");
            w.println("      \"unresolved_tail_call_count\": " + tc.unresolved + ",");
            w.println("      \"copy_sites\": [");
            for (int ci = 0; ci < copySites.size(); ci++) {
                if (ci > 0) w.println(",");
                w.print("        " + copySites.get(ci).json);
            }
            w.println();
            w.println("      ],");
            w.println("      \"copy_site_count\": " + copySites.size() + ",");
            w.println("      \"bounds_flagged_count\": " + copyFlagged);
            totalIndirect += ind.edges;
            totalIndSucc += indSucc;
            totalMayCallSites += pt.maySites.size();
            totalMayCallTargets += pt.mayTargets;
            totalUnresolved += pt.unresolved;
            totalTailCallSites += tc.sites.size();
            totalTailCallTargets += tc.targets;
            totalUnresolvedTail += tc.unresolved;
            totalProtoEdges += protoEdges.size();
            totalBarRel += barRel.size();
            totalMmio += mmio.size();
            totalMay += may.size();
            totalPortIo += portIo.size();
            totalMsr += msr.size();
            totalCopySites += copySites.size();
            totalBoundsFlagged += copyFlagged;
            // Phase 4 V1: boundary judgment for this function.
            // A failure here must not lose the function's MMIO
            // findings (same discipline as the bounds scan).
            if (bndProfile != null) {
                try {
                    BoundaryEval ber = evaluateBoundary(
                        f.getName(), ops, bndAccesses, bndProfile);
                    totalBoundaryChecked += ber.checked;
                    totalBoundaryViolations += ber.violations;
                    totalBoundaryUnknownAgent += ber.unknownAgent;
                    totalBoundaryUnknownRegion += ber.unknownRegion;
                    allBoundarySites.addAll(ber.siteJsons);
                } catch (Exception e) {
                    println("[!] boundary eval failed for " +
                        f.getName() + ": " + e);
                }
            }
            for (BoundsSiteRec sr : copySites) {
                allCopySites.add(sr.json);
            }
            w.print("    }");
        }

        w.println();
        w.println("  ],");

        // Strings: defined data whose value is a String
        w.println("  \"strings\": [");
        boolean firstStr = true;
        int strCount = 0;
        boolean strTruncated = false;
        try {
            DataIterator dataIter = currentProgram.getListing().getDefinedData(true);
            while (dataIter.hasNext() && !monitor.isCancelled()) {
                Data d = dataIter.next();
                Object val = d.getValue();
                if (val instanceof String) {
                    if (strCount >= MAX_STRINGS) {
                        strTruncated = true;
                        break;
                    }
                    if (!firstStr) w.println(",");
                    firstStr = false;
                    w.print("    {\"address\": \"" + d.getAddress() +
                        "\", \"value\": \"" + esc((String) val) + "\"}");
                    strCount++;
                }
            }
        } catch (Exception e) {
        }
        w.println();
        w.println("  ],");
        w.println("  \"string_count\": " + strCount + ",");
        w.println("  \"strings_truncated\": " + strTruncated + ",");

        // Imports: external symbols (dynamic UND symbols, e.g. libc calls) +
        // external functions, merged by name. (PLT stubs appear as normal
        // functions, so Function.isExternal() alone yields an empty list.)
        w.println("  \"imports\": [");
        boolean firstImp = true;
        try {
            java.util.Set<String> seen = new java.util.HashSet<String>();
            SymbolIterator extSyms =
                currentProgram.getSymbolTable().getExternalSymbols();
            while (extSyms.hasNext() && !monitor.isCancelled()) {
                Symbol s = extSyms.next();
                String nm = s.getName();
                if (nm == null || !seen.add(nm)) continue;
                String lib = "";
                try {
                    Namespace ns = s.getParentNamespace();
                    if (ns != null && ns.getName() != null) lib = ns.getName();
                } catch (Exception e) {
                }
                if (!firstImp) w.println(",");
                firstImp = false;
                w.print("    {\"name\": \"" + esc(nm) +
                    "\", \"library\": \"" + esc(lib) +
                    "\", \"source\": \"symbol\"}");
            }
            FunctionIterator extFns =
                currentProgram.getFunctionManager().getExternalFunctions();
            while (extFns.hasNext() && !monitor.isCancelled()) {
                Function f = extFns.next();
                String nm = f.getName();
                if (nm == null || !seen.add(nm)) continue;
                String lib = "";
                try {
                    ExternalLocation loc = f.getExternalLocation();
                    if (loc != null && loc.getLibraryName() != null) {
                        lib = loc.getLibraryName();
                    }
                } catch (Exception e) {
                }
                if (!firstImp) w.println(",");
                firstImp = false;
                w.print("    {\"name\": \"" + esc(nm) +
                    "\", \"library\": \"" + esc(lib) +
                    "\", \"source\": \"function\"}");
            }
        } catch (Exception e) {
        }
        w.println();
        w.println("  ],");
        w.println("  \"function_count\": " + fnCount + ",");
        w.println("  \"mmio_access_total\": " + totalMmio + ",");
        w.println("  \"may_access_total\": " + totalMay + ",");
        w.println("  \"port_io_access_total\": " + totalPortIo + ",");
        w.println("  \"msr_access_total\": " + totalMsr + ",");
        w.println("  \"indirect_call_edges_total\": " + totalIndirect + ",");
        w.println("  \"indirect_successor_total\": " + totalIndSucc + ",");
        w.println("  \"may_call_site_total\": " + totalMayCallSites + ",");
        w.println("  \"may_call_target_total\": " + totalMayCallTargets + ",");
        w.println("  \"unresolved_indirect_total\": " + totalUnresolved + ",");
        w.println("  \"may_tail_call_site_total\": " + totalTailCallSites + ",");
        w.println("  \"may_tail_call_target_total\": " + totalTailCallTargets + ",");
        w.println("  \"unresolved_tail_call_total\": " + totalUnresolvedTail + ",");
        w.println("  \"protocol_call_edge_total\": " + totalProtoEdges + ",");
        w.println("  \"bar_relative_access_total\": " + totalBarRel + ",");
        w.println("  \"copy_sites\": [");
        for (int ci = 0; ci < allCopySites.size(); ci++) {
            if (ci > 0) w.println(",");
            w.print("    " + allCopySites.get(ci));
        }
        w.println();
        w.println("  ],");
        w.println("  \"copy_site_total\": " + totalCopySites + ",");
        w.println("  \"bounds_flagged_total\": " + totalBoundsFlagged + ",");
        w.println("  \"transfer_call_forms\": {");
        w.println("    \"total_transfer_calls\": " + totalTransferCalls + ",");
        {
            // Bounds Phase 1: "dma"/"cmdaddr" buckets count matched
            // sites only (no bounded callee set to census); the
            // other forms stay 0, explicit.
            String[] formKinds = new String[] { "memcpy", "memmove",
                "cache", "dma", "cmdaddr" };
            String[] forms = new String[] { "site", "plain_arg",
                "field_only", "const", "top", "other" };
            for (int ki = 0; ki < formKinds.length; ki++) {
                w.print("    \"" + formKinds[ki] + "\": {");
                for (int fi = 0; fi < forms.length; fi++) {
                    if (fi > 0) w.print(", ");
                    Integer cv = totalFormCounts.get(
                        formKinds[ki] + ":" + forms[fi]);
                    w.print("\"" + forms[fi] + "\": " +
                        (cv == null ? 0 : cv.intValue()));
                }
                w.println("}" + (ki + 1 < formKinds.length ? "," : ""));
            }
        }
        w.println("  },");
        // Phase 4 V1: boundary fields (design §7). Sites carry
        // violations ONLY; compliant accesses are not emitted
        // (same reason bounds emits sites but the verdict line
        // carries the count). boundary_checked_total is the one
        // additive field: without it, violations + unknown counts
        // cannot prove how much was actually judged.
        w.println("  \"boundary_regions\": [");
        if (bndProfile != null) {
            for (int bi = 0; bi < bndProfile.regions.size(); bi++) {
                if (bi > 0) w.println(",");
                w.print("    " + bndProfile.regions.get(bi).json());
            }
            w.println();
        }
        w.println("  ],");
        w.println("  \"boundary_region_count\": " +
            (bndProfile == null ? 0 : bndProfile.regions.size()) + ",");
        w.println("  \"boundary_sites\": [");
        for (int bi = 0; bi < allBoundarySites.size(); bi++) {
            if (bi > 0) w.println(",");
            w.print("    " + allBoundarySites.get(bi));
        }
        w.println();
        w.println("  ],");
        w.println("  \"boundary_violation_count\": " +
            totalBoundaryViolations + ",");
        w.println("  \"boundary_unknown_agent_total\": " +
            totalBoundaryUnknownAgent + ",");
        w.println("  \"boundary_unknown_region_total\": " +
            totalBoundaryUnknownRegion + ",");
        w.println("  \"boundary_checked_total\": " +
            totalBoundaryChecked + ",");
        if (bndProfile == null) {
            w.println("  \"boundary_profile\": null,");
        } else {
            w.println("  \"boundary_profile\": {");
            w.println("    \"source\": \"" + esc(bndProfile.source) + "\",");
            w.println("    \"image_security_state\": " +
                (bndProfile.imageSec == null ? "null" :
                    "\"" + bndProfile.imageSec + "\"") + ",");
            w.println("    \"image_privilege\": " +
                (bndProfile.imagePriv == null ? "null" :
                    "\"" + bndProfile.imagePriv + "\"") + ",");
            w.println("    \"boundary_precedence\": \"" +
                (bndProfile.highestWins ? "highest-wins" : "lowest-wins") +
                "\",");
            w.println("    \"mpu_privdefena\": " + bndProfile.mpuPrivdefena + ",");
            if (bndProfile.hasDefault) {
                w.println("    \"boundary_default_attribute\": " +
                    "{\"domain\": \"" + bndProfile.defDomain +
                    "\", \"min_privilege\": \"" + bndProfile.defPriv +
                    "\"}");
            } else {
                w.println("    \"boundary_default_attribute\": null");
            }
            w.println("  },");
        }
        // Phase 4 V1.5: learning diagnostics (additive; Lean
        // ignores them). Empty arrays / 0 when learning is off
        // or no profile is present.
        w.println("  \"boundary_table_learning\": [");
        if (bndProfile != null) {
            for (int bi = 0;
                bi < bndProfile.tableLearningJson.size(); bi++) {
                if (bi > 0) w.println(",");
                w.print("    " + bndProfile.tableLearningJson.get(bi));
            }
            w.println();
        }
        w.println("  ],");
        w.println("  \"boundary_thread_entries\": [");
        if (bndProfile != null) {
            boolean firstTe = true;
            for (Map.Entry<String, ThreadEntry> te :
                bndProfile.threadEntries.entrySet()) {
                if (!firstTe) w.println(",");
                firstTe = false;
                w.print("    {\"function\": \"" +
                    esc(te.getKey()) + "\", \"privilege\": " +
                    (te.getValue().priv == null ? "null" :
                        "\"" + te.getValue().priv + "\"") +
                    ", \"sites\": " + te.getValue().sites +
                    ", \"status\": \"" + te.getValue().status +
                    "\"}");
            }
            w.println();
        }
        w.println("  ],");
        w.println("  \"boundary_thread_unresolved_sites\": " +
            (bndProfile == null ? 0
                : bndProfile.threadUnresolvedSites) + ",");
        w.println("  \"literal_scan\": {");
        w.println("    \"literal_count\": " + litScan.literalCount + ",");
        w.print("    \"attributed\": {");
        {
            List<String> fields =
                new ArrayList<String>(litScan.attributions.keySet());
            java.util.Collections.sort(fields);
            boolean firstField = true;
            for (String fld : fields) {
                if (!firstField) w.print(",");
                firstField = false;
                List<String> names =
                    new ArrayList<String>(litScan.attributions.get(fld));
                java.util.Collections.sort(names);
                StringBuilder nb = new StringBuilder();
                for (int k = 0; k < names.size(); k++) {
                    if (k > 0) nb.append(", ");
                    nb.append("\"").append(esc(names.get(k))).append("\"");
                }
                w.print("\"" + esc(fld) + "\": [" + nb.toString() + "]");
            }
        }
        w.println("},");
        w.print("    \"unattributed\": [");
        for (int k = 0; k < litScan.unattributed.size(); k++) {
            if (k > 0) w.print(", ");
            w.print("\"" + esc(litScan.unattributed.get(k)) + "\"");
        }
        w.println("]");
        w.println("  }");
        w.println("}");
        w.close();
        println("[*] cfgspace: " + totalBarRel + " bar-relative findings");
        println("[*] persite: extra findings mmio=" +
            persiteExtraMmio + " port=" + persiteExtraPort +
            " msr=" + persiteExtraMsr + " bar=" + persiteExtraBar +
            ", skippedByIdentity=" + persiteSkippedIdent +
            ", replayMismatch=" + persiteReplayMismatch + ".");
        println("[*] boundary: checked=" + totalBoundaryChecked +
            " violations=" + totalBoundaryViolations +
            " unknown_agent=" + totalBoundaryUnknownAgent +
            " unknown_region=" + totalBoundaryUnknownRegion);
        println("[+] JSON Export Complete: " + outputJson +
            " (" + fnCount + " functions, " + strCount + " strings)");
    }
}
