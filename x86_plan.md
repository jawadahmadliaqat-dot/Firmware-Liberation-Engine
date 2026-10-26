# x86 adapter plan (Step 5, Part B)

Status: PLAN ONLY. No X86Isa code exists. Part A (MIPS) is verified on
the extractor side; its Lean-generic gate is blocked by the verifier's
hardcoded MMIO window (see §7) — the same blocker applies to x86, so
read §7 before promising a Lean PASS on any x86 report.

Design rule carried from steps 1–5: complexity lives INSIDE ExtractIR,
usage stays simple — same one-command pipeline, same JSON shape unless
a shape change is explicitly decided (§4), no new flags, no lean/
changes without separate authorization.

## 1. What x86 needs that ARM / RISC-V / MIPS do not

### 1.1 Overlapping registers (the biggest design decision)
ARM, RISC-V, and MIPS have one name per register width: a write to r0
is a write to all of r0. x86 does not. `al`, `ax`, `eax`, and `rax`
are the same storage at different widths and offsets (Ghidra's
`register` space: `rax` offset 0 size 8, `eax` offset 0 size 4, `ax`
offset 0 size 2, `al` offset 0 size 1, `ah` offset 1 size 1).
The current fixpoint keys a value by (space, offset, size), so a write
to `al` and a read of `eax` look like different registers today.
That is unsound for must-analysis (a partial write must NOT leave the
full register's old value intact) and incomplete for may-analysis.
Options, in order of preference:
  a. Conservative full-register invalidation: any write to a
     sub-register invalidates every overlapping varnode (the whole
     register becomes unknown). Sound, simple, loses precision on
     byte-wise code. Start here.
  b. Per-byte value tracking: track known bits per byte of each
     register. Precise, but a large change to the fixpoint state
     representation. Only if (a) measurably loses real findings on
     the OVMF corpus (§6).
Empirical check first: probe how Ghidra 11.4.2 names and offsets the
x86 register file (including `r8`–`r15`, `xmm` — vector registers
are out of scope for v1; the adapter must ignore them, not crash).

### 1.2 No link register — CALL pushes the return address on the stack
ARM/RISC-V/MIPS all COPY the return address into a link register
(`lr`/`ra`), which is why `ra` can be excluded from caller-saved
clobbers. x86 has no such register: `CALL` pushes the return address
onto the stack and `RET` pops it. Consequences:
  - `returnAddressRegisterOffset` has no x86 meaning. The interface
    needs a "no link register" case (e.g. return −1) instead of
    forcing a bogus register number.
  - The CALL P-Code includes a stack STORE + `rsp` adjustment. The
    fixpoint must not treat that stack write as a user store (it
    already doesn't — stack writes are not MMIO — but the `rsp`
    adjustment must not corrupt the caller's stack-frame reasoning).
  - Tail calls are `JMP <target>` (a BRANCH to another function),
    exactly like the MIPS direct-`j` tail-call open item: BRANCHIND
    recovery does not cover them, and extending BRANCH recovery to
    cross-function targets risks the BMP tail numbers (43/399).
    Keep tail-call recovery BRANCHIND-only for v1; document x86
    `JMP`-tail-calls as the same open item.

### 1.3 Multiple calling conventions in one binary (x86-32)
ARM has AAPCS, RISC-V has its ABI, MIPS has o32 — one convention per
adapter. x86-32 has several in the same binary: cdecl (args on stack,
caller cleans), stdcall (callee cleans), fastcall (first two args in
`ecx`/`edx`), thiscall (`this` in `ecx`). A single caller-saved set
is wrong for all of them at once.
Plan: v1 uses a conservative union — clobber `eax`/`ecx`/`edx` on
every CALL (the volatile set common to all three conventions) and
treat all stack-passed arguments as TOP (unknown). v2 (optional):
read the calling convention from Ghidra's function signature
(`Function.getSignature().getCallingConvention()`) and clobber per
convention; for unknown/stripped functions fall back to the union.
x86-64 is simpler: System V (args `rdi rsi rdx rcx r8 r9`, volatile
`rax rcx rdx rsi rdi r8-r11`, saved `rbx rbp r12-r15`) and Windows
(args `rcx rdx r8 r9`, volatile `rax rcx rdx r8-r11`, saved `rbx
rbp rsi rdi r12-r15`) — one convention per binary in practice, so
the adapter takes the convention as a property of the binary
(default System V; Windows selected by the PE subsystem or an
`abi=` script argument, mirroring the existing `mmio=` override).

### 1.4 Port I/O — a separate access class, not MMIO
`IN`/`OUT` address a 16-bit port space (0x0000–0xFFFF), disjoint
from memory. Folding port numbers into `mmio_accesses` would corrupt
every address-range check downstream (classifier profiles are memory
maps; the Lean window is a memory range). So:
  - New JSON access class: `port_io_accesses` (port number, direction
    IN/OUT, value known-bits, instruction, function). Shape change —
    needs an `extractor_version` bump decision (§4).
  - Empirical check first: determine how Ghidra 11.4.2 lifts IN/OUT
    (user-defined pcodeops vs memory-mapped pseudo-ops). Do not
    assume; the probe binary (§6) must contain `inb`/`outb`.
  - PCI config space falls out of port I/O for free at the raw level
    (0xCF8 address port, 0xCFC data port). Decoding a 0xCF8 value
    into bus/device/function/register is a second-order analysis
    (v2): v1 reports the raw port accesses; v2 optionally pairs
    CF8 writes with following CFC accesses.

### 1.5 MSRs — index-based, not address-based
`RDMSR`/`WRMSR` take the MSR index in `ECX` (value in `EDX:EAX`).
Like ports, MSRs are not memory: new JSON access class
`msr_accesses` (index, direction, value known-bits). The must-analysis
can recover constant MSR indices the same way it recovers MMIO
addresses (ECX is very often an immediate: e.g. 0x1B APIC base,
0xC0000080 EFER). Privileged-only: user-mode firmware (UEFI apps)
cannot execute them, but DXE drivers and SMM code can.

### 1.6 PE image format + UEFI scale
  - The ingest pipeline assumes ELF today only by habit — Ghidra
    auto-detects the loader, and PE32+ imports work. Verify: (a) a
    PE32+ DXE driver imports and analyzes end-to-end; (b) TE (Terse
    Executable, the stripped-PE variant most DXE drivers ship as)
    loader support in Ghidra 11.4.2 — if TE import fails, DXE-driver
    coverage is blocked until the image is converted to PE (a
    preprocessing step, not an extractor change).
  - Scale: UEFI firmware volumes are multi-MB (BMP is 1.2 MB).
    The per-function fixpoint should scale near-linearly, but the
    whole-program store map and points-to sets are the risk. Measure
    on OVMF (§6) before optimizing: report wall time, peak Ghidra
    memory (512 MB cap), and function count. If the store map
    blows up, the mitigation is per-module analysis (one DXE driver
    at a time) rather than whole-firmware-volume analysis.
  - SMM (System Management Mode) is DEFERRED, not v1: SMI handlers
    live in SMRAM, a separate address space, and are registered via
    SMM protocols — Ghidra will not discover them automatically
    (the same discovery problem as pointer-table dispatch, but
    worse, because the registration itself is protocol-based).
    v1 covers DXE drivers + UEFI applications; SMM is a separate
    research item.

### 1.7 Variable-length instructions
MIPS/ARM/RISC-V are fixed 4-byte; x86 is 1–15 bytes. The good news:
the CFG/fixpoint already work on op indices, not addresses, so
variable length needs no `fallthroughIndex` arithmetic (x86 has no
delay slots: `fallthroughIndex = i+1`, like ARM/RISC-V). The real
risks are elsewhere:
  - Disassembly reliability: x86 allows data embedded in code and
    jumps into the middle of an instruction; Ghidra's function
    boundaries are less certain than on fixed-width ISAs. Mitigation:
    trust Ghidra's analysis, report function counts, do not try to
    fix disassembly inside the extractor.
  - Jump tables use different idioms: SIB-indexed absolute tables
    (`mov eax, [table + eax*4]` → INT_ADD + INT_MULT/INT_LEFT),
    RIP-relative bases (64-bit `lea rax, [rip+disp]`), and
    relative-offset tables in PIC/PIE code. The existing
    `matchBranchTableFrom` (absolute + offset paths) should transfer,
    but the base computation needs a RIP check: determine empirically
    whether Ghidra folds RIP-relative LEA targets to constants
    (expected: yes, the decompiler knows RIP's value per
    instruction). If not, seed `rip` per instruction like the
    RISC-V `gp`-seeding open item.
  - x86-16 real mode (SEC phase, option ROMs, SeaBIOS) is OUT OF
    SCOPE for v1: the adapter's register/pointer model is 32/64-bit
    only. Say so explicitly; do not let a 16-bit test case expand
    the scope.

### 1.8 Flags and condition resolution
ARM/RISC-V/MIPS branches test a register directly. x86 branches test
EFLAGS set by a preceding CMP/TEST (which Ghidra lifts as SUB/AND
with flag-register outputs). The feasibility check (`resolveCond`)
and the may-taint condition logic assume a compare-then-branch shape
they can walk; x86 needs a flag-aware condition walk (CMP → flag
varnode → CBRANCH on that flag). This is a contained extension to
the condition resolver, gated on the ISA like `unwrapIndirectDef`:
X86Isa implements flag-chain resolution, the others return the input
unchanged. Prototype on the probe binary before wiring it in.

## 2. Ordered plan

  1. Empirical Ghidra probe (mirrors ProbeMIPS/ProbeRV, lives OUTSIDE
     the scriptPath dir): x86-64 + x86-32 test binaries from the
     system gcc (64-bit native; 32-bit only if multilib is present,
     else via a prebuilt 32-bit toolchain — do not fight apt for it).
     Record: language IDs (`x86:LE:64:default`,
     `x86:LE:32:default`), register-space layout and overlap
     offsets, how CALL/RET/IN/OUT/RDMSR/WRMSR lift, how RIP-relative
     LEA lifts, how a switch table lifts, how CMP+Jcc lifts.
  2. Register-overlap decision (§1.1): implement conservative
     full-register invalidation first; measure precision loss on the
     OVMF corpus before considering per-byte tracking.
  3. X86Isa, 64-bit first (UEFI is 64-bit; the toolchain is native),
     32-bit second. Interface additions, all ISA-gated so ARM /
     RISC-V / MIPS behavior is unchanged: no-link-register case,
     flag-chain condition resolution, port/MSR access classes.
  4. Port I/O + MSR extraction (§1.4, §1.5) with the JSON shape
     decision (§4) made explicitly before code is written.
  5. x86 jump-table recovery (§1.7): SIB-indexed absolute tables,
     RIP-relative bases, relative-offset tables.
  6. Calling-convention handling (§1.3): union-clobber + stack-args
     TOP for v1; signature-driven conventions as a v2 option.
  7. Test firmware from source (§6) + OVMF corpus run (§6).
  8. Lean profile-driven window (§7) — separate authorization,
     prerequisite for any Lean PASS on x86 addresses.
  9. Full regression suite: ARM blink byte-identical, BMP exactly
     v3.7, RISC-V generic PASS, MIPS BE/LE numbers unchanged.
     Any regression = FAIL, revert, report.

## 3. What does NOT change
`ingest_and_analyze.py` (Ghidra auto-detects PE/ELF; no language flag
is passed), `classify_mmio.py` (address-keyed; x86 profiles are a
future profile, not a classifier change), `svd_import.py`, the
generated STM32F1 profile, README (until a push is authorized),
`lean/` (until §7 is authorized). `ExtractIR.java` backup before
editing, name not ending in `.java`.

## 4. JSON shape decision (needed before step 4 above)
`port_io_accesses` and `msr_accesses` are new top-level fields.
That is a shape change, so it needs the same treatment as the open
`extractor_version` question (still `v3.7-mayfp` after steps 1–5):
either bump the version when the x86 adapter lands (recommended —
the version string is the honest signal that the schema grew), or
report ports/MSRs inside a clearly-marked sub-object of the existing
report with the version unchanged (not recommended — it hides the
change from consumers). Do not silently add fields without a version
decision.

## 5. Verification strategy (mirrors the RISC-V/MIPS bar)
  - End-to-end: no crash, valid JSON, on both the from-source test
    firmware and the OVMF corpus.
  - Spot-checks (≥3) against the x86 platform map, not against the
    tool's own output: e.g. LAPIC 0xFEE00000, HPET 0xFED00000, VGA
    0xB8000, PCI ports 0xCF8/0xCFC, serial 0x3F8 — each with the
    expected access kind (LOAD/STORE/IN/OUT) and value mask.
  - Recovery counts: jump-table cases recovered (all switch cases'
    side effects present), indirect-call edges (certain, via the
    table path), unresolved counts — reported, not just claimed.
  - Lean: generic PASS is BLOCKED by §7 until the window is
    profile-driven. Until then, report Lean generic honestly the way
    MIPS is reported (which invariants pass, which single check
    fails, and why) — never fake a PASS by moving test addresses
    into the ARM window.
  - Regression gates (§2 step 9) are mandatory and independent of
    the x86 result.

## 6. Test firmware and corpus
  - From source (preferred, mirrors riscv_blink/mips_blink): a
    freestanding x86-64 program built with the system gcc
    (`-ffreestanding -nostdlib`, custom entry, no libc): a loop
    writing to a fixed MMIO address (e.g. 0xFED00000 HPET or VGA
    0xB8000), an `outb` to a legacy port (0x3F8 or 0x80), a dense
    switch forcing a jump table, and a non-tail indirect call
    through a function-pointer table. The "chip map" is the x86
    platform map (public: Intel SDM + ACPI spec), not a vendor
    datasheet — no new trust assumption.
  - Real corpus: OVMF (EDK2, open source, PE32+/TE DXE drivers,
    multi-MB scale test). A single DXE driver first (bounded scope),
    then a full firmware volume if step 1's scale numbers allow.
  - Fallback if from-source proves infeasible: a public prebuilt
    x86 firmware ELF/PE from a trusted source (OVMF binary release),
    stated as such — same fallback rule as step 5.

## 7. The Lean window dependency (MIPS finding, applies to x86)
Lean generic hardcodes `checkWindow 0x40000000 0x60000000`
(`lean/Main.lean`, `printGeneric`; same window in
`lean/Verifier/Common.lean:151`). That is the ARM Cortex-M /
RISC-V-GD32 peripheral region. MIPS's AR9331 GPIO (0x18040000) is
outside it, so Lean generic FAILS on the MIPS report on exactly that
one check (trace non-empty: true, masks consistent: true, window:
false) — the extractor output is correct; the verifier's window is
ARM-centric. x86 platform addresses (0xFED00000, 0xFEE00000,
0xB8000, ports) are likewise outside it, so x86 Lean generic will
fail the same way. The fix is a profile-driven Lean window (window
from the profile or a report field, not a hardcoded constant) — a
lean/ change that needs its own authorization and its own
regression proof (ARM blink + BMP + RISC-V + MIPS must still PASS).
Until that lands, x86 (like MIPS) ships with an honest caveat, not
a faked PASS.

## 8. Open questions (for the parent / Jawad)
  1. 64-bit first, 32-bit second (§2 step 3) — confirm, or reverse
     if a 32-bit target (legacy BIOS, option ROM) matters more.
  2. JSON shape + version bump for port/MSR classes (§4) — bump on
     the x86 landing, or keep `v3.7-mayfp` and hide the fields?
  3. Corpus: OVMF (recommended) or a smaller target first (single
     EDK2 DXE driver, then volume)?
  4. SMM: deferred (§1.6) — confirm it stays out of v1, or is SMRAM
     coverage a requirement that changes the plan?
  5. Real mode (16-bit): out of scope (§1.7) — confirm.
  6. Lean window (§7): authorize the profile-driven window as a
     separate step before x86 Lean verification, or accept the
     MIPS-style caveat for x86 too?
  7. Calling conventions (§1.3): union-clobber for v1 — accept the
     precision loss, or is signature-driven convention handling a
     v1 requirement?
