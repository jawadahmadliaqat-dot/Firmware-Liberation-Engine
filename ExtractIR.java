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
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * ExtractIR v3: exports functions + P-Code IR + strings + imports + XREFs as JSON.
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
 * capture exactly that, via the same linear scan (last definition wins)
 * already used for address resolution. Ops folded: COPY, LOAD (program
 * memory only), INT_ADD/SUB/MULT (exact-only), INT_AND/OR/XOR/NOT (mask
 * algebra, exact even on partial knowledge), INT_LEFT/RIGHT, INT_2COMP
 * (arithmetic negation), INT_NEGATE (bitwise NOT -- NOT arithmetic
 * negation; ARM BIC sleigh proves it: "Rd = rn&(~shift1)"), INT_ZEXT/SEXT,
 * SUBPIECE. Everything else yields unknown
 * bits (ones=0, zeroes=0), which mask algebra still handles safely.
 * LIMIT (same as v2): linear scan, not branch-sensitive -- fine for -O0.
 */
public class ExtractIR extends GhidraScript {

    private static final int MAX_PCODE_PER_FUNCTION = 5000;
    private static final int MAX_STRINGS = 10000;

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
        w.println("  \"extractor_version\": \"v3-value-export\",");
        w.println("  \"functions\": [");

        FunctionIterator functions = currentProgram.getFunctionManager().getFunctions(true);
        boolean firstFn = true;
        int fnCount = 0;
        int totalMmio = 0;
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

            // P-Code IR for this function (control flow + ops) plus an
            // MMIO resolver with VALUE EXPORT (v3): bare-metal code
            // reaches hardware registers INDIRECTLY (literal-pool load
            // into a register, then STORE/LOAD through it), so raw P-Code
            // never shows the address. We track known-bit masks linearly
            // (last definition wins) and resolve STORE/LOAD targets that
            // land in the MMIO window 0x40000000-0x60000000, capturing
            // the stored/loaded value bits alongside each access.
            w.println("      \"pcode\": [");
            int opCount = 0;
            boolean truncated = false;
            boolean firstInstr = true;
            Map<String, Bits> bvals = new HashMap<String, Bits>();
            List<String> mmio = new ArrayList<String>();
            Memory mem = currentProgram.getMemory();
            try {
                InstructionIterator instrs =
                    currentProgram.getListing().getInstructions(f.getBody(), true);
                while (instrs.hasNext() && !monitor.isCancelled()) {
                    Instruction instr = instrs.next();
                    PcodeOp[] ops = instr.getPcode();
                    for (PcodeOp op : ops) {
                        if (opCount >= MAX_PCODE_PER_FUNCTION) {
                            truncated = true;
                            break;
                        }
                        if (!firstInstr) w.println(",");
                        firstInstr = false;
                        String mnem = op.getMnemonic();
                        Varnode[] ins = op.getInputs();
                        Varnode out = op.getOutput();
                        w.print("        {\"addr\": \"" + instr.getAddress() +
                            "\", \"asm\": \"" + esc(instr.getMnemonicString()) +
                            "\", \"op\": \"" + esc(mnem) + "\", \"inputs\": [");
                        for (int i = 0; i < ins.length; i++) {
                            if (i > 0) w.print(", ");
                            w.print(varnodeJson(ins[i]));
                        }
                        w.print("], \"output\": " + varnodeJson(out) + "}");
                        opCount++;

                        // ---- MMIO resolver + value export (same op order) ----
                        if (mnem.equals("COPY") && ins.length == 1) {
                            if (out != null) {
                                bvals.put(vkey(out), copyBits(ins[0], mem, bvals));
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
                                bvals.put(vkey(out), r);
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
                                    bvals.put(vkey(out), Bits.exact(r, mask));
                                } else {
                                    bvals.put(vkey(out), Bits.unknown());
                                }
                            }
                        } else if ((mnem.equals("INT_NOT") || mnem.equals("INT_NEGATE")) &&
                            ins.length == 1 && out != null) {
                            // CAREFUL: Ghidra's INT_NEGATE is bitwise NOT (~),
                            // NOT arithmetic negation. Proof: the ARM sleigh
                            // defines BIC as "Rd = rn&(~shift1)" and it
                            // compiles to INT_NEGATE + INT_AND. (Arithmetic
                            // negation is INT_2COMP.) Getting this wrong
                            // flips the cleared-bit mask: -0xC00 clears
                            // 0xBFF, while ~0xC00 clears 0xC00.
                            Bits a = resolveBits(ins[0], bvals);
                            long mask = sizeMask(out.getSize());
                            bvals.put(vkey(out),
                                new Bits(a.zeroes & mask, a.ones & mask));
                        } else if (mnem.equals("INT_2COMP") &&
                            ins.length == 1 && out != null) {
                            Long a = resolveExact(ins[0], bvals);
                            long mask = sizeMask(out.getSize());
                            if (a != null) {
                                bvals.put(vkey(out), Bits.exact(-a, mask));
                            } else {
                                bvals.put(vkey(out), Bits.unknown());
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
                                bvals.put(vkey(out), r);
                            } else {
                                bvals.put(vkey(out), Bits.unknown());
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
                                bvals.put(vkey(out),
                                    Bits.exact(sa >> n.intValue(), mask));
                            } else {
                                bvals.put(vkey(out), Bits.unknown());
                            }
                        } else if (mnem.equals("INT_ZEXT") && ins.length == 1 && out != null) {
                            Bits a = resolveBits(ins[0], bvals);
                            long outMask = sizeMask(out.getSize());
                            long inMask = sizeMask(ins[0].getSize());
                            bvals.put(vkey(out), new Bits(a.ones & outMask,
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
                            bvals.put(vkey(out), r);
                        } else if (mnem.equals("SUBPIECE") && ins.length == 2 && out != null) {
                            Bits a = resolveBits(ins[0], bvals);
                            Long off = resolveExact(ins[1], bvals);
                            long mask = sizeMask(out.getSize());
                            if (off != null && off.longValue() >= 0) {
                                int sh = off.intValue() * 8;
                                bvals.put(vkey(out), new Bits((a.ones >>> sh) & mask,
                                    (a.zeroes >>> sh) & mask));
                            } else {
                                bvals.put(vkey(out), Bits.unknown());
                            }
                        } else if (mnem.equals("LOAD") || mnem.equals("STORE")) {
                            Bits valBits = Bits.unknown();
                            if (mnem.equals("LOAD") && out != null) {
                                valBits = loadBits(ins, out, bvals, mem);
                                bvals.put(vkey(out), valBits);
                            } else if (mnem.equals("STORE") && ins.length >= 3) {
                                valBits = resolveBits(ins[2], bvals);
                            }
                            if (ins.length >= 2) {
                                Long addr = resolveExact(ins[1], bvals);
                                if (addr != null && addr >= 0x40000000L &&
                                    addr < 0x60000000L) {
                                    int sz = (mnem.equals("STORE") && ins.length >= 3)
                                        ? ins[2].getSize()
                                        : (out != null ? out.getSize() : 0);
                                    Long exact = valBits.exactValue(
                                        sizeMask(sz == 0 ? 4 : sz));
                                    mmio.add("{\"instr\": \"" + instr.getAddress() +
                                        "\", \"op\": \"" + mnem +
                                        "\", \"address\": \"0x" + Long.toHexString(addr) +
                                        "\", \"size\": " + sz +
                                        ", \"value\": " +
                                        (exact == null ? "null" : exact.toString()) +
                                        ", \"value_known_ones\": " + valBits.ones +
                                        ", \"value_known_zeroes\": " + valBits.zeroes + "}");
                                }
                            }
                        } else {
                            if (out != null) bvals.put(vkey(out), Bits.unknown());
                        }
                    }
                    if (truncated) break;
                }
            } catch (Exception e) {
                // keep JSON valid even if P-Code walk fails for a function
            }
            w.println();
            w.println("      ],");
            w.println("      \"pcode_op_count\": " + opCount + ",");
            w.println("      \"pcode_truncated\": " + truncated + ",");
            w.println("      \"mmio_accesses\": [");
            for (int i = 0; i < mmio.size(); i++) {
                if (i > 0) w.println(",");
                w.print("        " + mmio.get(i));
            }
            w.println();
            w.println("      ],");
            w.println("      \"mmio_access_count\": " + mmio.size());
            totalMmio += mmio.size();
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
        w.println("  \"mmio_access_total\": " + totalMmio);
        w.println("}");
        w.close();
        println("[+] JSON Export Complete: " + outputJson +
            " (" + fnCount + " functions, " + strCount + " strings)");
    }
}
