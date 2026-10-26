import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.Memory;
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
 */
public class ExtractIR extends GhidraScript {

    private static final int MAX_PCODE_PER_FUNCTION = 5000;
    private static final int MAX_STRINGS = 10000;
    private static final int MAX_FIXPOINT_ROUNDS = 100;

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
        return b != null ? b : Bits.unknown();
    }

    private static Long resolveExact(Varnode v, Map<String, Bits> bvals) {
        if (v == null) return null;
        Bits b = resolveBits(v, bvals);
        return b.exactValue(sizeMask(v.getSize()));
    }

    private static Bits copyBits(Varnode in, Memory mem, Map<String, Bits> bvals) {
        if (in.isConstant()) {
            return Bits.exact(in.getOffset(), sizeMask(in.getSize()));
        }
        if (in.getAddress() != null &&
            "ram".equals(in.getAddress().getAddressSpace().getName())) {
            try {
                long val = mem.getInt(in.getAddress()) & 0xffffffffL;
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
        if (mnem.equals("COPY") && ins.length == 1) {
            if (out != null) {
                putKnown(bvals, vkey(out), copyBits(ins[0], mem, bvals));
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
            // AAPCS caller-saved registers are dead after the call.
            // Ghidra ARM offsets (rN = 0x20 + 4N): r0=32, r1=36, r2=40,
            // r3=44, r12=80. Callee-saved r4-r11 and sp are preserved;
            // lr is NOT clobbered: Ghidra's own P-Code models it.
            long[] clobber = {32L, 36L, 40L, 44L, 80L};
            Set<String> drop = new HashSet<String>();
            for (String k : bvals.keySet()) {
                for (long off : clobber) {
                    if (k.startsWith("register:" + off + ":")) {
                        drop.add(k);
                    }
                }
            }
            for (String k : drop) bvals.remove(k);
            if (out != null) putKnown(bvals, vkey(out), Bits.unknown());
        } else {
            if (out != null) putKnown(bvals, vkey(out), Bits.unknown());
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
        Map<Integer, List<Integer>> branchTargets) {
        int n = ops.size();
        Map<String, Bits>[] in = new Map[n];
        if (n == 0) return new FixResult(in, true);
        in[0] = new HashMap<String, Bits>();

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
                    Integer j = firstAt.get(String.format("%08x", t));
                    if (j == null) {
                        j = firstAt.get(String.format("%08x", t & ~1L));
                    }
                    if (j != null) succ.get(i).add(j);
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
                    if (i + 1 < n) succ.get(i).add(i + 1);
                }
            } else if (mnem.equals("RETURN")) {
                // No successors: RETURN ends the function.
            } else if (mnem.equals("BRANCHIND")) {
                // v3.3: recovered TBB/TBH targets; anything else
                // (pointer tables, bx reg) keeps no successors.
                List<Integer> bt = branchTargets.get(i);
                if (bt != null) succ.get(i).addAll(bt);
            } else if (mnem.equals("CALL") || mnem.equals("CALLIND")) {
                if (i + 1 < n) succ.get(i).add(i + 1);
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

    private static class MayResult {
        final Map<String, Set<Long>>[] inStates;
        final boolean converged;
        MayResult(Map<String, Set<Long>>[] inStates, boolean converged) {
            this.inStates = inStates;
            this.converged = converged;
        }
    }

    /** May-resolution: constant -> singleton; otherwise the map entry
        (missing key = TOP = unconstrained, e.g. a function argument). */
    private static Set<Long> mayResolve(Varnode v,
        Map<String, Set<Long>> m) {
        if (v == null) return null;
        if (v.isConstant()) {
            Set<Long> s = new HashSet<Long>();
            s.add(v.getOffset() & sizeMask(v.getSize()));
            return s;
        }
        return m.get(vkey(v));
    }

    /** COPY source resolution: like mayResolve, but a ram varnode reads
        the program-memory word (literal pool), mirroring copyBits. */
    private static Set<Long> mayCopyBits(Varnode v,
        Map<String, Set<Long>> m, Memory mem) {
        if (v == null) return null;
        if (v.isConstant()) {
            Set<Long> s = new HashSet<Long>();
            s.add(v.getOffset() & sizeMask(v.getSize()));
            return s;
        }
        if (v.getAddress() != null &&
            "ram".equals(v.getAddress().getAddressSpace().getName())) {
            try {
                long val = mem.getInt(v.getAddress()) & 0xffffffffL;
                Set<Long> s = new HashSet<Long>();
                s.add(val);
                return s;
            } catch (Exception e) {
                return null;
            }
        }
        return m.get(vkey(v));
    }

    private static void mayPut(Map<String, Set<Long>> m, String key,
        Set<Long> s) {
        if (s == null || s.size() > MAX_MAY_SET_SIZE) {
            m.remove(key);
        } else {
            m.put(key, s);
        }
    }

    private static Set<Long> mayCombine(Set<Long> a, Set<Long> b,
        java.util.function.BiFunction<Long, Long, Long> f, long mask) {
        if (a == null || b == null) return null;
        if ((long) a.size() * (long) b.size() > MAX_MAY_SET_SIZE) return null;
        Set<Long> r = new HashSet<Long>();
        for (long x : a) {
            for (long y : b) {
                r.add(f.apply(x, y) & mask);
            }
        }
        return r.size() > MAX_MAY_SET_SIZE ? null : r;
    }

    private static Set<Long> mayMap(Set<Long> a,
        java.util.function.Function<Long, Long> f, long mask) {
        if (a == null) return null;
        Set<Long> r = new HashSet<Long>();
        for (long x : a) r.add(f.apply(x) & mask);
        return r.size() > MAX_MAY_SET_SIZE ? null : r;
    }

    /** The may transfer function: the v3 op-folding algebra over sets. */
    private void applyMayTransfer(Map<String, Set<Long>> m, OpRec op,
        Memory mem) {
        String mnem = op.mnem;
        Varnode[] ins = op.ins;
        Varnode out = op.out;
        if (mnem.equals("COPY") && ins.length == 1) {
            if (out != null) {
                mayPut(m, vkey(out), mayCopyBits(ins[0], m, mem));
            }
        } else if (mnem.equals("INT_AND") || mnem.equals("INT_OR") ||
            mnem.equals("INT_XOR")) {
            if (ins.length == 2 && out != null) {
                Set<Long> a = mayResolve(ins[0], m);
                Set<Long> b = mayResolve(ins[1], m);
                long mask = sizeMask(out.getSize());
                Set<Long> r = null;
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
                Set<Long> a = mayResolve(ins[0], m);
                Set<Long> b = mayResolve(ins[1], m);
                long mask = sizeMask(out.getSize());
                Set<Long> r = null;
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
            Set<Long> a = mayResolve(ins[0], m);
            Set<Long> n = mayResolve(ins[1], m);
            long mask = sizeMask(out.getSize());
            Set<Long> r = null;
            if (a != null && n != null && n.size() == 1) {
                long sh = n.iterator().next();
                if (sh >= 0 && sh < 64) {
                    r = new HashSet<Long>();
                    int width = out.getSize() * 8;
                    for (long x : a) {
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
                        r.add(v & mask);
                    }
                    if (r.size() > MAX_MAY_SET_SIZE) r = null;
                }
            }
            mayPut(m, vkey(out), r);
        } else if (mnem.equals("INT_ZEXT") && ins.length == 1 && out != null) {
            // Zero-extension keeps the numeric value.
            mayPut(m, vkey(out), mayResolve(ins[0], m));
        } else if (mnem.equals("INT_SEXT") && ins.length == 1 && out != null) {
            Set<Long> a = mayResolve(ins[0], m);
            long outMask = sizeMask(out.getSize());
            long inMask = sizeMask(ins[0].getSize());
            long signBit = 1L << (ins[0].getSize() * 8 - 1);
            Set<Long> r = null;
            if (a != null) {
                r = new HashSet<Long>();
                for (long x : a) {
                    long v = ((x & signBit) != 0) ? ((x | ~inMask) & outMask)
                        : (x & outMask);
                    r.add(v);
                }
                if (r.size() > MAX_MAY_SET_SIZE) r = null;
            }
            mayPut(m, vkey(out), r);
        } else if (mnem.equals("SUBPIECE") && ins.length == 2 && out != null) {
            Set<Long> a = mayResolve(ins[0], m);
            Set<Long> off = mayResolve(ins[1], m);
            long mask = sizeMask(out.getSize());
            Set<Long> r = null;
            if (a != null && off != null && off.size() == 1) {
                long sh = off.iterator().next() * 8;
                if (sh >= 0 && sh < 64) {
                    r = new HashSet<Long>();
                    for (long x : a) r.add((x >>> sh) & mask);
                    if (r.size() > MAX_MAY_SET_SIZE) r = null;
                }
            }
            mayPut(m, vkey(out), r);
        } else if (mnem.equals("LOAD") && out != null) {
            Set<Long> r = null;
            if (ins.length >= 2) {
                Set<Long> addrs = mayResolve(ins[1], m);
                if (addrs != null) {
                    r = new HashSet<Long>();
                    boolean ok = true;
                    for (long a : addrs) {
                        try {
                            Address ad = toAddr(a);
                            int sz = out.getSize();
                            long val;
                            if (sz == 4) val = mem.getInt(ad) & 0xffffffffL;
                            else if (sz == 2) val = mem.getShort(ad) & 0xffffL;
                            else if (sz == 1) val = mem.getByte(ad) & 0xffL;
                            else { ok = false; break; }
                            r.add(val);
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
            long[] clobber = {32L, 36L, 40L, 44L, 80L};
            Set<String> drop = new HashSet<String>();
            for (String k : m.keySet()) {
                for (long off : clobber) {
                    if (k.startsWith("register:" + off + ":")) drop.add(k);
                }
            }
            for (String k : drop) m.remove(k);
            if (out != null) mayPut(m, vkey(out), null);
        } else {
            if (out != null) mayPut(m, vkey(out), null);
        }
    }

    /** May-join: a varnode keeps a finite set only if EVERY incoming
        path has a finite set for it; the set is the union. A missing
        key on any path means TOP (unconstrained) on that path, which
        poisons the join to TOP. */
    private static Map<String, Set<Long>> mayMeet(
        Map<String, Set<Long>> a, Map<String, Set<Long>> b) {
        if (a == null) return b;
        if (b == null) return a;
        Map<String, Set<Long>> r = new HashMap<String, Set<Long>>();
        for (Map.Entry<String, Set<Long>> e : a.entrySet()) {
            Set<Long> y = b.get(e.getKey());
            if (y == null) continue;
            Set<Long> u = new HashSet<Long>(e.getValue());
            u.addAll(y);
            if (u.size() <= MAX_MAY_SET_SIZE) r.put(e.getKey(), u);
        }
        return r;
    }

    private static boolean maySameState(Map<String, Set<Long>> a,
        Map<String, Set<Long>> b) {
        if (a == null || b == null) return a == b;
        if (a.size() != b.size()) return false;
        for (Map.Entry<String, Set<Long>> e : a.entrySet()) {
            Set<Long> o = b.get(e.getKey());
            if (o == null || !o.equals(e.getValue())) return false;
        }
        return true;
    }

    private static Map<String, Set<Long>> stripMayUniques(
        Map<String, Set<Long>> m) {
        Map<String, Set<Long>> r = new HashMap<String, Set<Long>>();
        for (Map.Entry<String, Set<Long>> e : m.entrySet()) {
            if (!e.getKey().startsWith("unique:")) {
                r.put(e.getKey(), e.getValue());
            }
        }
        return r;
    }

    @SuppressWarnings("unchecked")
    private MayResult runMayFixpoint(List<OpRec> ops, Memory mem,
        Map<Integer, List<Integer>> branchTargets) {
        int n = ops.size();
        Map<String, Set<Long>>[] in = new Map[n];
        if (n == 0) return new MayResult(in, true);
        in[0] = new HashMap<String, Set<Long>>();

        // Successors: duplicated from runFixpoint -- KEEP IN SYNC.
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
                    Integer j = firstAt.get(String.format("%08x", t));
                    if (j == null) {
                        j = firstAt.get(String.format("%08x", t & ~1L));
                    }
                    if (j != null) succ.get(i).add(j);
                }
                if (mnem.equals("CBRANCH")) {
                    if (i + 1 < n) succ.get(i).add(i + 1);
                }
            } else if (mnem.equals("RETURN")) {
                // No successors: RETURN ends the function.
            } else if (mnem.equals("BRANCHIND")) {
                // v3.3: recovered TBB/TBH targets; anything else
                // (pointer tables, bx reg) keeps no successors.
                List<Integer> bt = branchTargets.get(i);
                if (bt != null) succ.get(i).addAll(bt);
            } else if (mnem.equals("CALL") || mnem.equals("CALLIND")) {
                if (i + 1 < n) succ.get(i).add(i + 1);
            } else {
                if (i + 1 < n) succ.get(i).add(i + 1);
            }
        }

        boolean converged = false;
        for (int round = 0; round < MAX_FIXPOINT_ROUNDS && !converged; round++) {
            boolean changed = false;
            for (int i = 0; i < n; i++) {
                if (in[i] == null) continue;
                Map<String, Set<Long>> out =
                    new HashMap<String, Set<Long>>(in[i]);
                applyMayTransfer(out, ops.get(i), mem);
                for (int j : succ.get(i)) {
                    Map<String, Set<Long>> prop = out;
                    if (!ops.get(j).instrAddr.equals(ops.get(i).instrAddr)) {
                        prop = stripMayUniques(out);
                    }
                    Map<String, Set<Long>> merged = mayMeet(in[j], prop);
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
                in[i] = new HashMap<String, Set<Long>>();
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

    /** v3.3: recover TBB/TBH jump-table targets as CFG successors.
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
    private Map<Integer, List<Integer>> recoverTbbTargets(
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
                Integer j = firstAt.get(String.format("%08x", target));
                if (j == null) {
                    j = firstAt.get(String.format("%08x", target & ~1L));
                }
                if (j != null && !targets.contains(j)) targets.add(j);
            }
            if (!targets.isEmpty()) result.put(i, targets);
        }
        return result;
    }

    private static class IndirectResult {
        final List<String> sites;
        final int edges;
        final Map<Integer, List<Integer>> successors;
        IndirectResult(List<String> sites, int edges,
            Map<Integer, List<Integer>> successors) {
            this.sites = sites;
            this.edges = edges;
            this.successors = successors;
        }
    }

    /** Backward slice for pointer-table dispatch: from a CALLIND /
        BRANCHIND destination, unwrap an optional Thumb-bit AND and a
        4-byte LOAD, and return the table base if the LOAD address is
        INT_ADD [base, index*4] where base is a constant or a COPY of
        a constant (one hop, e.g. via `adr`). Null if no match. */
    private static Long findPtrTableBase(List<OpRec> ops, int brIdx) {
        OpRec br = ops.get(brIdx);
        if (br.ins.length < 1) return null;
        int cur = findDef(ops, vkey(br.ins[0]), brIdx);
        if (cur < 0) return null;
        OpRec d = ops.get(cur);
        if (d.mnem.equals("INT_AND") && d.ins.length == 2) {
            boolean unwrapped = false;
            for (int s = 0; s < 2; s++) {
                Varnode v = d.ins[s];
                if (v.isConstant() &&
                    (v.getOffset() & 0xFFFFFFFFL) == 0xFFFFFFFEL) {
                    cur = findDef(ops, vkey(d.ins[1 - s]), cur);
                    unwrapped = true;
                    break;
                }
            }
            if (!unwrapped || cur < 0) return null;
            d = ops.get(cur);
        }
        if (!d.mnem.equals("LOAD") || d.ins.length < 2 ||
            d.out == null || d.out.getSize() != 4) return null;
        int defAddr = findDef(ops, vkey(d.ins[1]), cur);
        if (defAddr < 0) return null;
        OpRec add = ops.get(defAddr);
        if (!add.mnem.equals("INT_ADD") || add.ins.length != 2) return null;
        // Try each side as the base (const, or COPY-of-const) with the
        // other side as the scaled index.
        for (int s = 0; s < 2; s++) {
            Varnode v = add.ins[s];
            Long base = null;
            if (v.isConstant()) {
                base = v.getOffset();
            } else {
                int defBase = findDef(ops, vkey(v), defAddr);
                if (defBase < 0) continue;
                OpRec cb = ops.get(defBase);
                if (!cb.mnem.equals("COPY") || cb.ins.length != 1 ||
                    !cb.ins[0].isConstant()) continue;
                base = cb.ins[0].getOffset();
            }
            String otherKey = vkey(add.ins[1 - s]);
            int defIdx = findDef(ops, otherKey, defAddr);
            if (defIdx < 0) continue;
            OpRec sc = ops.get(defIdx);
            boolean scaled = false;
            if (sc.mnem.equals("INT_LEFT") && sc.ins.length == 2 &&
                sc.ins[1].isConstant() &&
                sc.ins[1].getOffset() == 2L) {
                scaled = true;
            } else if (sc.mnem.equals("INT_MULT") && sc.ins.length == 2) {
                for (int t = 0; t < 2; t++) {
                    if (sc.ins[t].isConstant() &&
                        sc.ins[t].getOffset() == 4L) {
                        scaled = true;
                    }
                }
            }
            if (scaled) return base;
        }
        return null;
    }

    /** v3.4 (fixed): recover call-graph edges AND intra-function
        pointer-table successors. For each CALLIND/BRANCHIND (skipping
        TBB/TBH ones, which are already CFG successors):
          - single constant destination -> function-entry edge;
          - pointer table (see findPtrTableBase): each entry (& ~1)
            that is a function entry becomes an edge; each entry that
            is a real instruction start in THIS function becomes a
            CFG successor (BRANCHIND only -- a computed goto, not a
            call); the read stops at the first entry that is neither,
            or an unreadable address, capped at 64.
        Argument-dependent dispatch (vtable via object pointer) has no
        constant base and is left for points-to analysis. Every
        reported edge target is a real function entry by construction. */
    private IndirectResult recoverIndirect(List<OpRec> ops, Memory mem,
        FunctionManager fm, Set<Integer> tbbBranchInds) {
        List<String> out = new ArrayList<String>();
        Map<Integer, List<Integer>> succ =
            new HashMap<Integer, List<Integer>>();
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
                tbbBranchInds.contains(i)) continue;
            if (call.ins.length < 1) continue;
            List<String> targets = new ArrayList<String>();
            List<Integer> mySucc = new ArrayList<Integer>();
            int def = findDef(ops, vkey(call.ins[0]), i);
            if (def >= 0) {
                OpRec dd = ops.get(def);
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
                            Function fn = fm.getFunctionAt(toAddr(c & ~1L));
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
                        long entryAddr = base.longValue() + 4L * k;
                        long ptr;
                        try {
                            ptr = mem.getInt(toAddr(entryAddr)) & 0xffffffffL;
                        } catch (Exception e) {
                            break;
                        }
                        long t = ptr & ~1L;
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
                                String.format("%08x", t));
                            if (j == null) {
                                j = firstAt.get(
                                    String.format("%08x", t & ~1L));
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
            }
            if (!mySucc.isEmpty()) succ.put(i, mySucc);
        }
        return new IndirectResult(out, edges, succ);
    }

    @Override
    public void run() throws Exception {
        if (getScriptArgs().length < 1) {
            println("[!] ExtractIR needs an output JSON path argument.");
            return;
        }
        String outputJson = getScriptArgs()[0];
        PrintWriter w = new PrintWriter(new FileWriter(outputJson));

        w.println("{");
        w.println("  \"binary_name\": \"" + esc(currentProgram.getName()) + "\",");
        w.println("  \"language\": \"" +
            esc(currentProgram.getLanguage().getLanguageID().getIdAsString()) + "\",");
        w.println("  \"extractor_version\": \"v3.4-callgraph\",");
        w.println("  \"functions\": [");

        FunctionIterator functions = currentProgram.getFunctionManager().getFunctions(true);
        boolean firstFn = true;
        int fnCount = 0;
        int totalMmio = 0;
        int totalMay = 0;
        int totalIndirect = 0;
        int totalIndSucc = 0;
        while (functions.hasNext() && !monitor.isCancelled()) {
            Function f = functions.next();
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

            // Phase 1: collect this function's P-Code ops (capped).
            // Phase 2: CFG fixpoint over them (see header: must-analysis,
            // unique-strip at instruction boundaries, CALL clobber).
            // Phase 3: stream the P-Code JSON and record MMIO accesses
            // from the FINAL states -- never from a running linear scan.
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
            // v3.3: TBB/TBH jump-table targets, shared by both fixpoints.
            // On any recovery failure, fall back to no targets (same
            // behaviour as before v3.3 -- sound, just less recall).
            Map<Integer, List<Integer>> branchTargets;
            try {
                branchTargets = recoverTbbTargets(ops,
                    currentProgram.getMemory());
            } catch (Exception e) {
                branchTargets = new HashMap<Integer, List<Integer>>();
            }
            // v3.4: indirect recovery runs BEFORE the fixpoints, so
            // pointer-table intra-function successors join the shared
            // map (call-graph edges are printed, not successors).
            IndirectResult ind;
            try {
                ind = recoverIndirect(ops, currentProgram.getMemory(),
                    currentProgram.getFunctionManager(),
                    branchTargets.keySet());
            } catch (Exception e) {
                ind = new IndirectResult(new ArrayList<String>(), 0,
                    new HashMap<Integer, List<Integer>>());
            }
            for (Map.Entry<Integer, List<Integer>> e :
                ind.successors.entrySet()) {
                List<Integer> cur = branchTargets.get(e.getKey());
                if (cur == null) {
                    branchTargets.put(e.getKey(), e.getValue());
                } else {
                    for (Integer j : e.getValue()) {
                        if (!cur.contains(j)) cur.add(j);
                    }
                }
            }
            FixResult fx;
            try {
                fx = runFixpoint(ops, currentProgram.getMemory(),
                    branchTargets);
            } catch (Exception e) {
                Map<String, Bits>[] empty = new Map[ops.size()];
                for (int i = 0; i < empty.length; i++) {
                    empty[i] = new HashMap<String, Bits>();
                }
                fx = new FixResult(empty, false);
            }
            MayResult my;
            try {
                my = runMayFixpoint(ops, currentProgram.getMemory(),
                    branchTargets);
            } catch (Exception e) {
                Map<String, Set<Long>>[] emptyMay = new Map[ops.size()];
                for (int i = 0; i < emptyMay.length; i++) {
                    emptyMay[i] = new HashMap<String, Set<Long>>();
                }
                my = new MayResult(emptyMay, false);
            }

            w.println("      \"pcode\": [");
            boolean firstOp = true;
            List<String> mmio = new ArrayList<String>();
            List<String> may = new ArrayList<String>();
            Memory mem = currentProgram.getMemory();
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
                        if (addr != null && addr >= 0x40000000L &&
                            addr < 0x60000000L) {
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
                                (exact == null ? "null" : exact.toString()) +
                                ", \"value_known_ones\": " + valBits.ones +
                                ", \"value_known_zeroes\": " + valBits.zeroes + "}");
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
                if ((op.mnem.equals("LOAD") || op.mnem.equals("STORE")) &&
                    !mustRecorded && my.inStates[i] != null &&
                    op.ins.length >= 2) {
                    Set<Long> addrSet =
                        mayResolve(op.ins[1], my.inStates[i]);
                    if (addrSet != null) {
                        List<Long> win = new ArrayList<Long>();
                        for (long a : addrSet) {
                            if (a >= 0x40000000L && a < 0x60000000L) win.add(a);
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
                                (exact == null ? "null" : exact.toString()) +
                                ", \"value_known_ones\": " + valBits.ones +
                                ", \"value_known_zeroes\": " + valBits.zeroes + "}");
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
            w.println("      \"indirect_call_count\": " + ind.sites.size() + ",");
            w.println("      \"indirect_call_edges\": " + ind.edges + ",");
            w.println("      \"indirect_successor_count\": " + indSucc);
            totalIndirect += ind.edges;
            totalIndSucc += indSucc;
            totalMmio += mmio.size();
            totalMay += may.size();
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
        w.println("  \"indirect_call_edges_total\": " + totalIndirect + ",");
        w.println("  \"indirect_successor_total\": " + totalIndSucc);
        w.println("}");
        w.close();
        println("[+] JSON Export Complete: " + outputJson +
            " (" + fnCount + " functions, " + strCount + " strings)");
    }
}
