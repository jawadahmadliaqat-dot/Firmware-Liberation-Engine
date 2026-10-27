import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.symbol.ExternalLocation;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
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
        /** The ISA's peripheral/MMIO bands as [start, end) pairs,
            in the same order isMmioAddress tests them (ARM: the single
            Cortex-M window; RISC-V/MIPS: the configured band list).
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
    }

    // Selected in run() from the program's processor (default ARM:
    // the pre-step-1 behaviour). RISC-V programs get a RiscVIsa,
    // MIPS programs a MipsIsa, x86 programs an X86Isa.
    private IsaAdapter isa = new ArmIsa();

    /** Per-callee Ghidra calling-convention names, keyed by
        function entry-point offset (ram space only). Built in
        run() before the function loop. A missing entry means
        "unknown callee" and falls back to the conservative union
        via clobberForConvention(null), never a guess. For
        single-convention adapters the name is ignored, so the
        map is semantically inert for ARM/RISC-V/MIPS. */
    private Map<Long, String> callConvMap =
        new HashMap<Long, String>();

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
            // ARM Cortex-M peripheral region.
            return addr >= 0x40000000L && addr < 0x60000000L;
        }
        public List<long[]> mmioWindows() {
            List<long[]> wins = new ArrayList<long[]>();
            wins.add(new long[] {0x40000000L, 0x60000000L});
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
        Bits(long ones, long zeroes) {
            this.ones = ones;
            this.zeroes = zeroes;
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
        if (b != null && (b.ones != 0 || b.zeroes != 0)) return b;
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

    private static Bits copyBits(Varnode in, Memory mem, Map<String, Bits> bvals,
        IsaAdapter isa) {
        if (in.isConstant()) {
            return Bits.exact(in.getOffset(), sizeMask(in.getSize()));
        }
        if (in.getAddress() != null &&
            "ram".equals(in.getAddress().getAddressSpace().getName())) {
            try {
                long val = isa.readPointer(mem, in.getAddress());
                return Bits.exact(val, sizeMask(in.getSize()));
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
        Long addr = resolveExact(ins[1], bvals);
        if (addr == null) return Bits.unknown();
        try {
            Address a = toAddr(addr.longValue());
            int sz = out.getSize();
            long val;
            if (sz == 4) val = mem.getInt(a) & 0xffffffffL;
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
        if (b.ones == 0 && b.zeroes == 0) {
            m.remove(key);
        } else {
            m.put(key, b);
        }
    }

    /** The transfer function: the v3 op-folding algebra, applied to a
        COPY of the incoming state. No MMIO recording here -- that happens
        once, after convergence, from the final states. */
    private void applyTransfer(Map<String, Bits> bvals, OpRec op, Memory mem) {
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
                putKnown(bvals, vkey(out), copyBits(ins[0], mem, bvals, isa));
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
            Bits a = resolveBits(ins[0], bvals);
            long outMask = sizeMask(out.getSize());
            long inMask = sizeMask(ins[0].getSize());
            putKnown(bvals, vkey(out), new Bits(a.ones & outMask,
                (a.zeroes | ~inMask) & outMask));
        } else if (mnem.equals("INT_SEXT") && ins.length == 1 && out != null) {
            Bits a = resolveBits(ins[0], bvals);
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
        } else if (mnem.equals("CALL") || mnem.equals("CALLIND")) {
            // Caller-saved registers are dead after the call (the
            // set comes from clobberForCall: the per-callee Ghidra
            // signature for x86, the adapter's single set otherwise).
            long[] clobber = clobberForCall(op);
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
            if (out != null) putKnown(bvals, vkey(out), Bits.unknown());
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
                            derive.put(k, new Bits(
                                (outBits.ones >>> sh) & m,
                                (outBits.zeroes >>> sh) & m));
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
            if (ones != 0 || zeroes != 0) {
                r.put(k, new Bits(ones, zeroes));
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
        Map<String, Bits> entry) {
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
                applyTransfer(out, ops.get(i), mem);
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

    /** Meet over ALL direct call sites of one callee: an argument
        register is bound only when every site has it exact AND all
        sites agree on the value. Anything else stays unknown
        (absent from the returned map). */
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
            Long agreed = null;
            boolean allExact = true;
            for (CallSite s : sites) {
                FixResult fx = s.caller.fx;
                Long v = null;
                if (fx != null && fx.inStates != null &&
                    s.opIdx < fx.inStates.length &&
                    fx.inStates[s.opIdx] != null) {
                    v = resolveExact(vn, fx.inStates[s.opIdx]);
                }
                if (v == null) {
                    allExact = false;
                    break;
                }
                if (agreed == null) {
                    agreed = v;
                } else if (!agreed.equals(v)) {
                    allExact = false;
                    break;
                }
            }
            if (allExact && agreed != null) {
                out.put(isa.registerSpaceName() + ":" + off + ":" +
                    ptrSize, Bits.exact(agreed.longValue(), mask));
            }
        }
        return out;
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

        w.println("{");
        w.println("  \"binary_name\": \"" + esc(currentProgram.getName()) + "\",");
        w.println("  \"language\": \"" +
            esc(currentProgram.getLanguage().getLanguageID().getIdAsString()) + "\",");
        w.println("  \"extractor_version\": \"v3.10\",");
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
        for (FuncRec rec : funcRecs) {
            List<OpRec> pops = rec.or.ops;
            for (int i = 0; i < pops.size(); i++) {
                OpRec op = pops.get(i);
                if (!op.mnem.equals("CALL") || op.ins.length < 1) {
                    continue;
                }
                Varnode t = op.ins[0];
                if (t == null || t.getAddress() == null ||
                    !"ram".equals(t.getAddress().getAddressSpace().
                        getName())) {
                    continue;
                }
                FuncRec callee = funcByEntry.get(t.getOffset());
                if (callee == null) {
                    callee = funcByEntry.get(
                        isa.stripInstructionTag(t.getOffset()));
                }
                if (callee == null) continue;
                List<CallSite> sl = sitesByCallee.get(callee.entryKey);
                if (sl == null) {
                    sl = new ArrayList<CallSite>();
                    sitesByCallee.put(callee.entryKey, sl);
                }
                sl.add(new CallSite(rec, i));
                Set<Long> cb = calleesByCaller.get(rec.entryKey);
                if (cb == null) {
                    cb = new HashSet<Long>();
                    calleesByCaller.put(rec.entryKey, cb);
                }
                cb.add(callee.entryKey);
                Set<Long> dc = directCallersByCallee.get(callee.entryKey);
                if (dc == null) {
                    dc = new HashSet<Long>();
                    directCallersByCallee.put(callee.entryKey, dc);
                }
                dc.add(rec.entryKey);
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
                        rec.branchTargets, e);
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
                        rec.branchTargets, entries.get(ek));
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
                        Long addr = resolveExact(op.ins[1], bvals);
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
                            Long port = resolveExactSlice(op.ins[1],
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
                            Long port = resolveExactSlice(op.ins[1],
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
                            Long idx = resolveExactSlice(op.ins[1],
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
                            Long idx = resolveExactSlice(op.ins[1],
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
            w.println("      \"unresolved_tail_call_count\": " + tc.unresolved);
            totalIndirect += ind.edges;
            totalIndSucc += indSucc;
            totalMayCallSites += pt.maySites.size();
            totalMayCallTargets += pt.mayTargets;
            totalUnresolved += pt.unresolved;
            totalTailCallSites += tc.sites.size();
            totalTailCallTargets += tc.targets;
            totalUnresolvedTail += tc.unresolved;
            totalProtoEdges += protoEdges.size();
            totalMmio += mmio.size();
            totalMay += may.size();
            totalPortIo += portIo.size();
            totalMsr += msr.size();
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
        println("[+] JSON Export Complete: " + outputJson +
            " (" + fnCount + " functions, " + strCount + " strings)");
    }
}
