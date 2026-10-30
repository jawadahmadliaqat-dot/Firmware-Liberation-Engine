/-
  Verifier/Common.lean — shared checker for the Formal Verifier.
  Pure defs only (no IO): MMIO trace type, blink spec, JSON extraction,
  blink-specific checks, and firmware-agnostic generic checks.
  Imported by Main (the exe) and by Verifier/BlinkProof (the theorem).
-/

import Lean

open Lean

/-- What address space a trace op lives in. -/
inductive TraceKind | mmio | port | msr
  deriving Repr, DecidableEq, Inhabited

/-- One trace op, as exported by ExtractIR v3 (MMIO) and v3.8 (port/MSR).
    The structure keeps its historical name; `kind` distinguishes the
    space. `addr` is the MMIO address, the I/O port number, or the MSR
    index, respectively. `isStore` is STORE for MMIO, OUT for ports,
    WRMSR for MSRs. Default kind is mmio, so pre-v3.8 literals (e.g.
    BlinkProof's badTrace) keep working unchanged. -/
structure MmioAccess where
  isStore : Bool
  func : String
  addr : Nat
  ones : Nat
  zeroes : Nat
  kind : TraceKind := .mmio
  deriving Repr, DecidableEq, Inhabited

/-- What "safe" means for one GPIO pin. -/
structure Spec where
  clockAddr : Nat
  clockBit : Nat
  modeAddr : Nat
  modeBits : Nat
  modeSetBit : Nat
  ledAddr : Nat
  ledBit : Nat
  deriving Repr

/-- STM32F4, GPIOA pin 5 (the blink firmware's LED). -/
def blinkSpec : Spec := {
  clockAddr := 0x40023830, clockBit := 0,
  modeAddr := 0x40020000, modeBits := 0xC00, modeSetBit := 10,
  ledAddr := 0x40020014, ledBit := 5
}

def hasBit (n bit : Nat) : Bool := (n >>> bit) % 2 == 1

/-- Hex string ("0x..." or plain) to Nat. -/
def hexVal (c : Char) : Option Nat :=
  if '0' ≤ c ∧ c ≤ '9' then some (c.toNat - '0'.toNat)
  else if 'a' ≤ c ∧ c ≤ 'f' then some (c.toNat - 'a'.toNat + 10)
  else if 'A' ≤ c ∧ c ≤ 'F' then some (c.toNat - 'A'.toNat + 10)
  else none

def parseHex (s : String) : Except String Nat := do
  let chars := match s.toList with
    | '0' :: 'x' :: rest => rest
    | cs => cs
  chars.foldlM (fun acc c =>
    match hexVal c with
    | some d => pure (acc * 16 + d)
    | none => throw s!"bad hex digit: {c}") 0

def extractAccess (func : String) (j : Json) : Except String MmioAccess := do
  let op ← j.getObjVal? "op" >>= Json.getStr?
  let addrS ← j.getObjVal? "address" >>= Json.getStr?
  let addr ← parseHex addrS
  let ones ← j.getObjVal? "value_known_ones" >>= Json.getNat?
  let zeroes ← j.getObjVal? "value_known_zeroes" >>= Json.getNat?
  pure { isStore := op == "STORE", func := func, addr := addr, ones := ones, zeroes := zeroes, kind := .mmio }

/-- One I/O-port access: the "port" hex string is the port number.
    OUT is the write direction (isStore), IN the read direction. -/
def extractPortAccess (func : String) (j : Json) : Except String MmioAccess := do
  let op ← j.getObjVal? "op" >>= Json.getStr?
  let portS ← j.getObjVal? "port" >>= Json.getStr?
  let port ← parseHex portS
  let ones ← j.getObjVal? "value_known_ones" >>= Json.getNat?
  let zeroes ← j.getObjVal? "value_known_zeroes" >>= Json.getNat?
  pure { isStore := op == "OUT", func := func, addr := port, ones := ones, zeroes := zeroes, kind := .port }

/-- One MSR access: the "index" hex string is the MSR index.
    WRMSR is the write direction (isStore), RDMSR the read direction. -/
def extractMsrAccess (func : String) (j : Json) : Except String MmioAccess := do
  let op ← j.getObjVal? "op" >>= Json.getStr?
  let idxS ← j.getObjVal? "index" >>= Json.getStr?
  let idx ← parseHex idxS
  let ones ← j.getObjVal? "value_known_ones" >>= Json.getNat?
  let zeroes ← j.getObjVal? "value_known_zeroes" >>= Json.getNat?
  pure { isStore := op == "WRMSR", func := func, addr := idx, ones := ones, zeroes := zeroes, kind := .msr }

/-- All trace ops of all functions, in file order. Per function the
    order is MMIO ops, then port ops, then MSR ops (the JSON carries
    three separate arrays, so no interleaved order exists to preserve).
    Port/MSR fields are optional: absent (pre-v3.8 reports) means no
    port/MSR ops, not an error — same policy as may_accesses. A
    present-but-malformed port/MSR field is an error, not silently
    ignored. The mmio_accesses field keeps its historical strict
    behavior (absent = error). -/
def extractTrace (j : Json) : Except String (List MmioAccess) := do
  let fns ← j.getObjVal? "functions" >>= Json.getArr?
  fns.toList.foldlM (fun acc fn => do
    let name ← fn.getObjVal? "name" >>= Json.getStr?
    let arr ← fn.getObjVal? "mmio_accesses" >>= Json.getArr?
    let accs ← arr.toList.mapM (extractAccess name)
    let parr ← match fn.getObjVal? "port_io_accesses" with
      | .ok v => Json.getArr? v
      | .error _ => pure #[]
    let paccs ← parr.toList.mapM (extractPortAccess name)
    let marr ← match fn.getObjVal? "msr_accesses" with
      | .ok v => Json.getArr? v
      | .error _ => pure #[]
    let maccs ← marr.toList.mapM (extractMsrAccess name)
    pure (acc ++ accs ++ paccs ++ maccs)) []

/-- All MAY-accesses, expanded: one MmioAccess per possible address.
Absent "may_accesses" (old reports) means no may data, not an error;
a present-but-malformed field is an error, not silently ignored. -/
def extractMayTrace (j : Json) : Except String (List MmioAccess) := do
  let fns ← j.getObjVal? "functions" >>= Json.getArr?
  fns.toList.foldlM (fun acc fn => do
    let name ← fn.getObjVal? "name" >>= Json.getStr?
    let arr ← match fn.getObjVal? "may_accesses" with
      | .ok v => Json.getArr? v
      | .error _ => pure #[]
    let accs ← arr.toList.foldlM (fun a2 m => do
      let op ← m.getObjVal? "op" >>= Json.getStr?
      let addrs ← m.getObjVal? "addresses" >>= Json.getArr?
      let ones ← m.getObjVal? "value_known_ones" >>= Json.getNat?
      let zeroes ← m.getObjVal? "value_known_zeroes" >>= Json.getNat?
      let expanded ← addrs.toList.mapM (fun aJson => do
        let addrS ← Json.getStr? aJson
        let addr ← parseHex addrS
        pure { isStore := op == "STORE", func := name, addr := addr,
               ones := ones, zeroes := zeroes, kind := .mmio })
      pure (a2 ++ expanded)) []
    pure (acc ++ accs)) []

/-- Check 1: clock + mode STOREs precede every LED STORE. -/
def goOrder (spec : Spec) : List MmioAccess → Bool → Bool → Bool
  | [], _, _ => true
  | a :: rest, sawClock, sawMode =>
    if a.isStore && a.addr == spec.ledAddr then
      (sawClock && sawMode) && goOrder spec rest sawClock sawMode
    else if a.isStore && a.addr == spec.clockAddr then
      goOrder spec rest true sawMode
    else if a.isStore && a.addr == spec.modeAddr then
      goOrder spec rest sawClock true
    else goOrder spec rest sawClock sawMode

def checkOrder (spec : Spec) (trace : List MmioAccess) : Bool :=
  goOrder spec trace false false

/-- Check 2: every LED STORE decides the LED bit (set or clear, never neither). -/
def checkLedBits (spec : Spec) (trace : List MmioAccess) : Bool :=
  trace.all fun a =>
    !(a.isStore && a.addr == spec.ledAddr) ||
    (hasBit a.ones spec.ledBit != hasBit a.zeroes spec.ledBit)

/-- Check 3: every clock STORE sets the clock-enable bit. -/
def checkClockBit (spec : Spec) (trace : List MmioAccess) : Bool :=
  trace.all fun a =>
    !(a.isStore && a.addr == spec.clockAddr) || hasBit a.ones spec.clockBit

/-- Check 4: mode field cleared, then output bit set, before the first LED STORE. -/
def goMode (spec : Spec) : List MmioAccess → Bool → Bool → Bool
  | [], sawClear, sawSet => sawClear && sawSet
  | a :: rest, sawClear, sawSet =>
    if a.isStore && a.addr == spec.ledAddr then
      sawClear && sawSet
    else if a.isStore && a.addr == spec.modeAddr then
      goMode spec rest
        (sawClear || Nat.land a.zeroes spec.modeBits == spec.modeBits)
        (sawSet || hasBit a.ones spec.modeSetBit)
    else goMode spec rest sawClear sawSet

def checkMode (spec : Spec) (trace : List MmioAccess) : Bool :=
  goMode spec trace false false

def checkAll (spec : Spec) (trace : List MmioAccess) : Bool :=
  checkOrder spec trace && checkLedBits spec trace &&
  checkClockBit spec trace && checkMode spec trace

/-- Generic invariants: hold for ANY correct extraction, no firmware spec needed. -/
def checkMasksConsistent (trace : List MmioAccess) : Bool :=
  trace.all fun a => Nat.land a.ones a.zeroes == 0

def checkWindow (lo hi : Nat) (trace : List MmioAccess) : Bool :=
  trace.all fun a => decide (lo ≤ a.addr) && decide (a.addr < hi)

/-- Window check against a band list, for MMIO ops only: an MMIO address
    passes if it falls in ANY band. The bands come from the report's
    "mmio_windows" field (the extractor adapter's own constants); see
    extractMmioWindows. Port/MSR ops pass vacuously here — they live in
    different spaces and are covered by checkPortMsrSanity instead, so
    a port number is never judged against MMIO bands. -/
def checkWindowBands (windows : List (Nat × Nat)) (trace : List MmioAccess) : Bool :=
  trace.all fun a => !decide (a.kind = .mmio) ||
    windows.any fun w => decide (w.1 ≤ a.addr) && decide (a.addr < w.2)

/-- Sanity for non-MMIO ops: a port number must fit the 16-bit I/O
    port space, an MSR index must fit 32 bits. MMIO ops pass vacuously
    (their window check is checkWindowBands). This is a sanity bound,
    NOT a confinement check: which ports/MSRs a driver may touch is
    checkPortMsrConfinement below (the v2-deferred item, added after
    the sanity check shipped). -/
def checkPortMsrSanity (trace : List MmioAccess) : Bool :=
  trace.all fun a =>
    if a.kind = .port then decide (a.addr ≤ 0xFFFF)
    else if a.kind = .msr then decide (a.addr < 2 ^ 32)
    else true

/-- MMIO bands claimed by the extractor, as [start, end) hex-string pairs
    in the report's top-level "mmio_windows" field. Absent (old reports)
    means the historical ARM window, not an error; a present-but-malformed
    field is an error, not silently ignored (same policy as may_accesses).
    TRUST NOTE: these bands are extractor-produced facts, same trust level
    as the trace itself (Lean already trusts extractor JSON). They are
    static adapter constants, NOT derived from the trace, so a
    mis-resolved wild address still fails the check. What this does NOT
    prove: that the bands equal the true platform map — that is the
    SVD-profile classifier's job, not the window check's. -/
def extractMmioWindows (j : Json) : Except String (List (Nat × Nat)) := do
  match j.getObjVal? "mmio_windows" with
  | .error _ => pure [(0x40000000, 0x60000000)]
  | .ok v => do
    let arr ← Json.getArr? v
    arr.toList.mapM (fun w => do
      let pair ← Json.getArr? w
      if pair.size != 2 then throw s!"bad mmio window (need [start, end]): {w}"
      else do
        let loS ← Json.getStr? pair[0]!
        let hiS ← Json.getStr? pair[1]!
        let lo ← parseHex loS
        let hi ← parseHex hiS
        if lo < hi then pure (lo, hi)
        else throw s!"bad mmio window (start >= end): {w}")

/-- Bmp mode only (its sole caller is printBmp; generic mode uses the
    report's bands via checkWindowBands). The hardcoded ARM window plus
    the ARM Private Peripheral Bus band [0xE0000000, 0xE0100000): the
    PPB is the processor core's own System Control Space (SysTick,
    NVIC, SCB), a fixed architectural band, not a platform
    peripheral window. Admitting the band here is a WINDOW fact only:
    WHICH family may touch it is still gated by checkBmpConfinement
    below (the core-family rule) — a named driver family touching
    the PPB still fails there. Added Oct 30, 2026 (Phase 4 core
    family fix): the Phase 4 PPB lens band made 20 genuine BMP core
    accesses visible, and the old single-window check rejected all
    of them. -/
def checkGeneric (trace : List MmioAccess) : Bool :=
  !trace.isEmpty && checkMasksConsistent trace &&
  trace.all fun a => (decide (0x40000000 ≤ a.addr) && decide (a.addr < 0x60000000)) ||
    (decide (0xE0000000 ≤ a.addr) && decide (a.addr < 0xE0100000))

def inRange (addr lo hi : Nat) : Bool :=
  decide (lo ≤ addr) && decide (addr < hi)

/-- Architectural x86 port allowlist: the PC platform's fixed I/O map
    entries that platform firmware touches during init and bring-up.
    PCI configuration mechanism 1 (0xCF8-0xCFF, address + data bytes);
    legacy interrupt/timer/DMA/keyboard/CMOS (PIC, PIT, DMA pages,
    keyboard controller, RTC); serial UARTs COM1-COM4. QEMU fw_cfg
    (0x510 selector, 0x511 data, 0x514 DMA address high, 0x518 DMA
    address low/trigger): identified from PciHostBridgeDxe (OVMF corpus,
    Oct 2026 — OUT 0x514/0x518 immediates feeding the generic IoWrite32
    helper, high-then-low 32-bit writes plus control poll, QEMU fw_cfg
    spec base 0x514) and conditioned on the OVMF-on-QEMU platform, like
    the COM/legacy entries are conditioned on the PC platform. Only the
    four documented ports are granted, not the 0x510-0x518 range: the
    in-between ports are unassigned padding. Device registers
    (parallel, VGA, IDE, floppy) are deliberately NOT included: firmware
    touching them extends this list with a justification comment (the
    allowlist path), it does not get a silent pass. -/
def x86PortAllowed (p : Nat) : Bool :=
  inRange p 0xCF8 0xD00 ||
  inRange p 0x20 0x22 || inRange p 0xA0 0xA2 ||
  inRange p 0x40 0x44 ||
  inRange p 0x00 0x10 || inRange p 0x80 0x90 || inRange p 0xC0 0xE0 ||
  p == 0x60 || p == 0x64 ||
  inRange p 0x70 0x72 ||
  inRange p 0x3F8 0x400 || inRange p 0x2F8 0x300 ||
  inRange p 0x3E8 0x3F0 || inRange p 0x2E8 0x2F0 ||
  p == 0x510 || p == 0x511 || p == 0x514 || p == 0x518

/-- Architectural x86 MSR allowlist: the firmware-init-relevant core.
    Intel SDM Vol 4 architectural MSRs (TSC, APIC_BASE, BIOS_SIGN_ID,
    MTRRCAP, SYSENTER, MISC_ENABLE, MTRR phys/fixed, PAT,
    MTRR_DEF_TYPE, EFER, STAR/LSTAR/CSTAR/FMASK, FS/GS bases, TSC_AUX)
    and AMD APM (SYSCFG, HWCR, GHCB, SEV_STATUS). Any MSR outside this
    list fails confinement until added here with a justification
    comment (the allowlist path).
    Additions (CpuDxe, P5 MSR gap — named entries only, SDM-justified):
    0x17 IA32_PLATFORM_ID (SDM Vol 4 Table 2-2, read-only; CPU
    identification for microcode-update targeting), 0x79
    IA32_BIOS_UPDT_TRIG (microcode-update trigger written by
    firmware to load a microcode update), 0x830 IA32_X2APIC_ICR
    (x2APIC interrupt-command register; IPI send for AP bring-up),
    0x982 IA32_TME_ACTIVATE (Intel TME spec 336907 Table 4-2;
    TME/MK-TME activation status read by firmware — bit 1 TME
    Enable, bits 35:32 MK_TME_KEYID_BITS). No x2APIC range was
    added: only the single named ICR entry, per the named-only
    rule. The list is index-granular, not direction-granular, so
    each entry permits both RDMSR and WRMSR; the observed CpuDxe
    accesses are 0x79/0x830 writes and 0x17/0x982 reads. -/
def x86MsrAllowed (m : Nat) : Bool :=
  m == 0x10 || m == 0x1B || m == 0x8B || m == 0xFE ||
  m == 0x17 || m == 0x79 || m == 0x830 || m == 0x982 ||
  inRange m 0x174 0x177 ||
  m == 0x1A0 ||
  inRange m 0x200 0x210 ||
  m == 0x250 || m == 0x258 || m == 0x259 || inRange m 0x268 0x270 ||
  m == 0x277 || m == 0x2FF ||
  inRange m 0xC0000080 0xC0000085 ||
  inRange m 0xC0000100 0xC0000104 ||
  m == 0xC0010010 || m == 0xC0010015 ||
  m == 0xC0010130 || m == 0xC0010131

/-- One trace op's confinement verdict under an architecture's
    allowlist. MMIO ops pass vacuously (their check is
    checkWindowBands). For x86 ("x86:..." language) the architectural
    sets above decide; for any other architecture — and for unknown
    architecture — there is no port/MSR allowlist, so a port/MSR op
    fails. There is deliberately no "everything passes" default. -/
def portMsrAllowed (lang : Option String) (a : MmioAccess) : Bool :=
  if a.kind = .mmio then true
  else match lang with
  | some l => if l.startsWith "x86" then
      if a.kind = .port then x86PortAllowed a.addr else x86MsrAllowed a.addr
    else false
  | none => false

/-- Port/MSR confinement: every non-MMIO op in the architectural
    allowlist for the report's architecture. This is the check
    checkPortMsrSanity deliberately deferred: sanity bounds the space
    (port ≤ 0xFFFF, MSR < 2^32); confinement bounds the set. A
    violation is a verification failure, reported by name in
    portMsrConfinementViolations — never silently dropped, never
    silently passed. Protocol-attributed ports need no exemption:
    Pci.Read/Write's CF8/CFC pass by the architectural PCI range,
    which is stronger than a kind-based exemption (a mis-attributed
    entry cannot ride it; and the trace carries no
    protocol-attributed marker on port entries, so an exemption could
    not even be implemented from the trace alone). -/
def checkPortMsrConfinement (lang : Option String) (trace : List MmioAccess) : Bool :=
  trace.all fun a => portMsrAllowed lang a

/-- Short kind name for the confinement-failure line. -/
def kindName : TraceKind → String
  | .mmio => "mmio"
  | .port => "port"
  | .msr => "msr"

def natToHex (n : Nat) : String :=
  if n == 0 then "0x0"
  else "0x" ++ ((Nat.toDigits 16 n).foldl (fun s d => s.push d) "")

/-- The offending entries, for the distinct confinement-failure line:
    (function, kind, address) of every op outside the allowlist. -/
def portMsrConfinementViolations (lang : Option String) (trace : List MmioAccess) : List MmioAccess :=
  trace.filter fun a => !portMsrAllowed lang a

/-- The report's "language" field (e.g. "x86:LE:64:default"), if
    present and well-formed. Absent or malformed means unknown
    architecture — the sound default for confinement (no allowlist),
    NOT an error: old reports carry no port/MSR entries, so the choice
    is vacuous for them, and a new report with port/MSR entries but
    no language must fail confinement rather than pass by default. -/
def extractLanguage (j : Json) : Option String :=
  match j.getObjVal? "language" with
  | .ok v => match Json.getStr? v with
    | .ok s => some s
    | .error _ => none
  | .error _ => none

/-- BMP confinement profile, OBSERVED from the v2.0.0 report (not assumed):
    every driver family touches only its own peripherals. This is the
    first firmware-specific property: it proves no driver family can
    scribble on another family's registers. Locked here so future
    pipeline runs must match the same profile (regression gate).
    CORE FAMILY RULE (Oct 30, 2026, Phase 4 fix): the PPB/SCS band
    [0xE0000000, 0xE0100000) is processor-INTERNAL ("core"), not a
    platform peripheral, so it is granted ONLY to the platform_
    bring-up functions — and to no other named family. Grounded in
    the 6 diagnosed BMP ops (fresh v3.19 report): platform_init
    STOREs SCB VTOR 0xE000ED08 (vector-table base) and LOAD/STOREs
    SCB DEMCR 0xE000EDFC (TRCENA bit 24 set, enabling DWT trace),
    and platform_request_boot LOADs SysTick CTRL 0xE000E010 twice
    (boot-request timing poll). Board bring-up configuring the core
    itself is not a cross-family scribble. This is NOT a blanket
    PPB allowance: jtagtap, rcc_, st_usbfs, swdptap and aux_serial
    keep their narrow ranges, so a USB driver (st_usbfs_*) touching
    SCB still FAILS here. Functions matching no branch (nvic_*,
    systick_*, scb_*, reset_handler — the other 14 PPB ops) still
    pass via else true: that pre-existing passthrough is UNCHANGED
    by this fix, not endorsed by it; constraining it is separate
    profile-tightening work. -/
def checkBmpConfinement (trace : List MmioAccess) : Bool :=
  trace.all fun a =>
    if a.func.startsWith "jtagtap" then
      inRange a.addr 0x40010000 0x40010400 || inRange a.addr 0x40010800 0x40011000
    else if a.func.startsWith "rcc_" then
      inRange a.addr 0x40021000 0x40021400
    else if a.func.startsWith "st_usbfs" then
      inRange a.addr 0x40005C00 0x40006000
    else if a.func.startsWith "swdptap" then
      inRange a.addr 0x40010800 0x40010C00
    else if a.func == "aux_serial_set_led" || a.func == "aux_serial_clear_led" then
      inRange a.addr 0x40010C00 0x40011000
    else if a.func.startsWith "platform_" then
      inRange a.addr 0x40010800 0x40011400 || inRange a.addr 0x40012400 0x40012800 ||
      inRange a.addr 0xE0000000 0xE0100000
    else true

/-- Clock-enable-before-use, v1 (generalization of the blink theorem).
    WHAT IT CHECKS: every MUST access (LOAD or STORE — a gated
    peripheral faults on any access) to a mapped peripheral's register
    block requires a MUST STORE to that peripheral's clock-gate
    register somewhere in the trace. The violation line names the
    peripheral, its gate register, and its gate bit.
    WHAT IT DOES NOT PROVE (honest limits, read before citing it):
    (1) ORDER-FREE, not must-precede. The Lean trace is flat file
    order, not execution order (Main's own comment: "no interleaved
    order exists to preserve"), so no temporal claim is made. Proof
    from BMP: a GPIOB use sits at flat position 4 while the first
    gate touch sits at position 302 — file order is not execution
    order, and any order claim over it would false-FAIL correct
    firmware. True must-precede (gate STORE dominates the use in the
    CFG) needs extractor dominance evidence that the report does not
    carry; that is phase 2, specified in v21-clockenable/design.
    (2) REGISTER granularity, not bit granularity. The gate bit is
    recorded for the message and for phase 2, but v1 only requires the
    gate REGISTER to be touched. Reason, measured on BMP: the
    libopencm3 generic rcc_periph_clock_enable helper resolves only
    3 gate bits in the must trace (AFIO, TIM3, DMA1) although the
    firmware correctly enables GPIOA/B/C, TIM1, USB, ADC1 — a
    bit-precise check would false-FAIL it. "Enabled the wrong bit in
    the same register" is therefore NOT caught by v1.
    (3) NO-RCC GAP: a firmware that uses STM32 blocks but never
    touches any RCC gate register is vacuous PASS, because the maps
    activate on gate touch (see below). The synthetic control works
    around this honestly: it touches one family's gate (APB1) and uses
    a peripheral from another family (APB2), which v1 does catch.
    (4) COVERAGE-BOUNDED: a peripheral the extractor never recovers
    (e.g. F4 USART2 via RAM handle-struct, the known Gap B) cannot
    fail this check — the check sees only must-extracted uses.
    CHIP ACTIVATION: reports carry no chip field (only language
    "ARM:LE:32:v8" and binary_name), so a chip's map is active iff any
    of its RCC gate registers is STORE-touched in the trace. This is
    what keeps non-STM32 ARM targets safe: RP2040, nRF52, Zephyr
    (nRF52840) and TinyUSB touch zero STM32 RCC gates, so they are
    vacuous PASS — verified by sweep, not assumed. (Without this
    gating, nRF52 UARTE0 at 0x40002000 would misread as F1 TIM14.)
    If both families are touched (never seen in practice), both maps
    apply and a use is covered if ANY matching gate is touched.
    EXCLUDED AS GRAY: EXTI, RTC, IWDG, FLASH, RCC itself, DBGMCU,
    ETH (multi-bit gates), USB OTG FS (AHB2 register) — their gating
    is variant-dependent or multi-bit, so mapping them risks false
    FAILs. They are unchecked, never failed. -/
structure ClockGate where
  name : String
  blockLo : Nat
  blockHi : Nat
  gateAddr : Nat
  gateBit : Nat
  deriving Repr, DecidableEq, Inhabited

/-- STM32F1 (RM0008) peripheral blocks and their RCC gates. -/
def f1ClockGates : List ClockGate := [
  { name := "AFIO",   blockLo := 0x40010000, blockHi := 0x40010400, gateAddr := 0x40021018, gateBit := 0 },
  { name := "GPIOA",  blockLo := 0x40010800, blockHi := 0x40010C00, gateAddr := 0x40021018, gateBit := 2 },
  { name := "GPIOB",  blockLo := 0x40010C00, blockHi := 0x40011000, gateAddr := 0x40021018, gateBit := 3 },
  { name := "GPIOC",  blockLo := 0x40011000, blockHi := 0x40011400, gateAddr := 0x40021018, gateBit := 4 },
  { name := "GPIOD",  blockLo := 0x40011400, blockHi := 0x40011800, gateAddr := 0x40021018, gateBit := 5 },
  { name := "GPIOE",  blockLo := 0x40011800, blockHi := 0x40011C00, gateAddr := 0x40021018, gateBit := 6 },
  { name := "ADC1",   blockLo := 0x40012400, blockHi := 0x40012800, gateAddr := 0x40021018, gateBit := 9 },
  { name := "ADC2",   blockLo := 0x40012800, blockHi := 0x40012C00, gateAddr := 0x40021018, gateBit := 10 },
  { name := "TIM1",   blockLo := 0x40012C00, blockHi := 0x40013000, gateAddr := 0x40021018, gateBit := 11 },
  { name := "SPI1",   blockLo := 0x40013000, blockHi := 0x40013400, gateAddr := 0x40021018, gateBit := 12 },
  { name := "TIM8",   blockLo := 0x40013400, blockHi := 0x40013800, gateAddr := 0x40021018, gateBit := 13 },
  { name := "USART1", blockLo := 0x40013800, blockHi := 0x40013C00, gateAddr := 0x40021018, gateBit := 14 },
  { name := "ADC3",   blockLo := 0x40014000, blockHi := 0x40014400, gateAddr := 0x40021018, gateBit := 15 },
  { name := "TIM2",   blockLo := 0x40000000, blockHi := 0x40000400, gateAddr := 0x4002101C, gateBit := 0 },
  { name := "TIM3",   blockLo := 0x40000400, blockHi := 0x40000800, gateAddr := 0x4002101C, gateBit := 1 },
  { name := "TIM4",   blockLo := 0x40000800, blockHi := 0x40000C00, gateAddr := 0x4002101C, gateBit := 2 },
  { name := "TIM5",   blockLo := 0x40000C00, blockHi := 0x40001000, gateAddr := 0x4002101C, gateBit := 3 },
  { name := "TIM6",   blockLo := 0x40001000, blockHi := 0x40001400, gateAddr := 0x4002101C, gateBit := 4 },
  { name := "TIM7",   blockLo := 0x40001400, blockHi := 0x40001800, gateAddr := 0x4002101C, gateBit := 5 },
  { name := "TIM12",  blockLo := 0x40001800, blockHi := 0x40001C00, gateAddr := 0x4002101C, gateBit := 6 },
  { name := "TIM13",  blockLo := 0x40001C00, blockHi := 0x40002000, gateAddr := 0x4002101C, gateBit := 7 },
  { name := "TIM14",  blockLo := 0x40002000, blockHi := 0x40002400, gateAddr := 0x4002101C, gateBit := 8 },
  { name := "WWDG",   blockLo := 0x40002C00, blockHi := 0x40003000, gateAddr := 0x4002101C, gateBit := 11 },
  { name := "SPI2",   blockLo := 0x40003800, blockHi := 0x40003C00, gateAddr := 0x4002101C, gateBit := 14 },
  { name := "SPI3",   blockLo := 0x40003C00, blockHi := 0x40004000, gateAddr := 0x4002101C, gateBit := 15 },
  { name := "USART2", blockLo := 0x40004400, blockHi := 0x40004800, gateAddr := 0x4002101C, gateBit := 17 },
  { name := "USART3", blockLo := 0x40004800, blockHi := 0x40004C00, gateAddr := 0x4002101C, gateBit := 18 },
  { name := "UART4",  blockLo := 0x40004C00, blockHi := 0x40005000, gateAddr := 0x4002101C, gateBit := 19 },
  { name := "UART5",  blockLo := 0x40005000, blockHi := 0x40005400, gateAddr := 0x4002101C, gateBit := 20 },
  { name := "I2C1",   blockLo := 0x40005400, blockHi := 0x40005800, gateAddr := 0x4002101C, gateBit := 21 },
  { name := "I2C2",   blockLo := 0x40005800, blockHi := 0x40005C00, gateAddr := 0x4002101C, gateBit := 22 },
  { name := "USB",    blockLo := 0x40005C00, blockHi := 0x40006000, gateAddr := 0x4002101C, gateBit := 23 },
  { name := "CAN1",   blockLo := 0x40006400, blockHi := 0x40006800, gateAddr := 0x4002101C, gateBit := 25 },
  { name := "BKP",    blockLo := 0x40006C00, blockHi := 0x40007000, gateAddr := 0x4002101C, gateBit := 27 },
  { name := "PWR",    blockLo := 0x40007000, blockHi := 0x40007400, gateAddr := 0x4002101C, gateBit := 28 },
  { name := "DAC",    blockLo := 0x40007400, blockHi := 0x40007800, gateAddr := 0x4002101C, gateBit := 29 },
  { name := "DMA1",   blockLo := 0x40020000, blockHi := 0x40020400, gateAddr := 0x40021014, gateBit := 0 },
  { name := "DMA2",   blockLo := 0x40020400, blockHi := 0x40020800, gateAddr := 0x40021014, gateBit := 1 },
  { name := "CRC",    blockLo := 0x40023000, blockHi := 0x40023400, gateAddr := 0x40021014, gateBit := 6 },
  { name := "SDIO",   blockLo := 0x40018000, blockHi := 0x40018400, gateAddr := 0x40021014, gateBit := 10 }
]

/-- STM32F4 (RM0090) peripheral blocks and their RCC gates. -/
def f4ClockGates : List ClockGate := [
  { name := "TIM2",   blockLo := 0x40000000, blockHi := 0x40000400, gateAddr := 0x40023840, gateBit := 0 },
  { name := "TIM3",   blockLo := 0x40000400, blockHi := 0x40000800, gateAddr := 0x40023840, gateBit := 1 },
  { name := "TIM4",   blockLo := 0x40000800, blockHi := 0x40000C00, gateAddr := 0x40023840, gateBit := 2 },
  { name := "TIM5",   blockLo := 0x40000C00, blockHi := 0x40001000, gateAddr := 0x40023840, gateBit := 3 },
  { name := "TIM6",   blockLo := 0x40001000, blockHi := 0x40001400, gateAddr := 0x40023840, gateBit := 4 },
  { name := "TIM7",   blockLo := 0x40001400, blockHi := 0x40001800, gateAddr := 0x40023840, gateBit := 5 },
  { name := "TIM12",  blockLo := 0x40001800, blockHi := 0x40001C00, gateAddr := 0x40023840, gateBit := 6 },
  { name := "TIM13",  blockLo := 0x40001C00, blockHi := 0x40002000, gateAddr := 0x40023840, gateBit := 7 },
  { name := "TIM14",  blockLo := 0x40002000, blockHi := 0x40002400, gateAddr := 0x40023840, gateBit := 8 },
  { name := "WWDG",   blockLo := 0x40002C00, blockHi := 0x40003000, gateAddr := 0x40023840, gateBit := 11 },
  { name := "SPI2",   blockLo := 0x40003800, blockHi := 0x40003C00, gateAddr := 0x40023840, gateBit := 14 },
  { name := "SPI3",   blockLo := 0x40003C00, blockHi := 0x40004000, gateAddr := 0x40023840, gateBit := 15 },
  { name := "USART2", blockLo := 0x40004400, blockHi := 0x40004800, gateAddr := 0x40023840, gateBit := 17 },
  { name := "USART3", blockLo := 0x40004800, blockHi := 0x40004C00, gateAddr := 0x40023840, gateBit := 18 },
  { name := "UART4",  blockLo := 0x40004C00, blockHi := 0x40005000, gateAddr := 0x40023840, gateBit := 19 },
  { name := "UART5",  blockLo := 0x40005000, blockHi := 0x40005400, gateAddr := 0x40023840, gateBit := 20 },
  { name := "I2C1",   blockLo := 0x40005400, blockHi := 0x40005800, gateAddr := 0x40023840, gateBit := 21 },
  { name := "I2C2",   blockLo := 0x40005800, blockHi := 0x40005C00, gateAddr := 0x40023840, gateBit := 22 },
  { name := "I2C3",   blockLo := 0x40005C00, blockHi := 0x40006000, gateAddr := 0x40023840, gateBit := 23 },
  { name := "CAN1",   blockLo := 0x40006400, blockHi := 0x40006800, gateAddr := 0x40023840, gateBit := 25 },
  { name := "CAN2",   blockLo := 0x40006800, blockHi := 0x40006C00, gateAddr := 0x40023840, gateBit := 26 },
  { name := "PWR",    blockLo := 0x40007000, blockHi := 0x40007400, gateAddr := 0x40023840, gateBit := 28 },
  { name := "DAC",    blockLo := 0x40007400, blockHi := 0x40007800, gateAddr := 0x40023840, gateBit := 29 },
  { name := "TIM1",   blockLo := 0x40010000, blockHi := 0x40010400, gateAddr := 0x40023844, gateBit := 0 },
  { name := "TIM8",   blockLo := 0x40010400, blockHi := 0x40010800, gateAddr := 0x40023844, gateBit := 1 },
  { name := "USART1", blockLo := 0x40011000, blockHi := 0x40011400, gateAddr := 0x40023844, gateBit := 4 },
  { name := "USART6", blockLo := 0x40011400, blockHi := 0x40011800, gateAddr := 0x40023844, gateBit := 5 },
  { name := "ADC1",   blockLo := 0x40012000, blockHi := 0x40012400, gateAddr := 0x40023844, gateBit := 8 },
  { name := "ADC2",   blockLo := 0x40012400, blockHi := 0x40012800, gateAddr := 0x40023844, gateBit := 9 },
  { name := "ADC3",   blockLo := 0x40012800, blockHi := 0x40012C00, gateAddr := 0x40023844, gateBit := 10 },
  { name := "SDIO",   blockLo := 0x40012C00, blockHi := 0x40013000, gateAddr := 0x40023844, gateBit := 11 },
  { name := "SPI1",   blockLo := 0x40013000, blockHi := 0x40013400, gateAddr := 0x40023844, gateBit := 12 },
  { name := "SYSCFG", blockLo := 0x40013800, blockHi := 0x40013C00, gateAddr := 0x40023844, gateBit := 14 },
  { name := "TIM9",   blockLo := 0x40014000, blockHi := 0x40014400, gateAddr := 0x40023844, gateBit := 16 },
  { name := "TIM10",  blockLo := 0x40014400, blockHi := 0x40014800, gateAddr := 0x40023844, gateBit := 17 },
  { name := "TIM11",  blockLo := 0x40014800, blockHi := 0x40014C00, gateAddr := 0x40023844, gateBit := 18 },
  { name := "GPIOA",  blockLo := 0x40020000, blockHi := 0x40020400, gateAddr := 0x40023830, gateBit := 0 },
  { name := "GPIOB",  blockLo := 0x40020400, blockHi := 0x40020800, gateAddr := 0x40023830, gateBit := 1 },
  { name := "GPIOC",  blockLo := 0x40020800, blockHi := 0x40020C00, gateAddr := 0x40023830, gateBit := 2 },
  { name := "GPIOD",  blockLo := 0x40020C00, blockHi := 0x40021000, gateAddr := 0x40023830, gateBit := 3 },
  { name := "GPIOE",  blockLo := 0x40021000, blockHi := 0x40021400, gateAddr := 0x40023830, gateBit := 4 },
  { name := "GPIOF",  blockLo := 0x40021400, blockHi := 0x40021800, gateAddr := 0x40023830, gateBit := 5 },
  { name := "GPIOG",  blockLo := 0x40021800, blockHi := 0x40021C00, gateAddr := 0x40023830, gateBit := 6 },
  { name := "GPIOH",  blockLo := 0x40021C00, blockHi := 0x40022000, gateAddr := 0x40023830, gateBit := 7 },
  { name := "CRC",    blockLo := 0x40023000, blockHi := 0x40023400, gateAddr := 0x40023830, gateBit := 12 },
  { name := "DMA1",   blockLo := 0x40026000, blockHi := 0x40026400, gateAddr := 0x40023830, gateBit := 21 },
  { name := "DMA2",   blockLo := 0x40026400, blockHi := 0x40026800, gateAddr := 0x40023830, gateBit := 22 }
]

/-- The RCC gate registers per chip (STOREs to these activate the map). -/
def f1GateAddrs : List Nat := [0x40021014, 0x40021018, 0x4002101C]
def f4GateAddrs : List Nat := [0x40023830, 0x40023840, 0x40023844]

/-- A gate register counts as touched only by an MMIO STORE to it
    (a LOAD of the gate register enables nothing). -/
def gateTouched (trace : List MmioAccess) (gate : Nat) : Bool :=
  trace.any fun a => a.isStore && decide (a.kind = .mmio) && a.addr == gate

/-- Active maps, by gate touch (see the header comment for why this
    gating exists and what it costs). -/
def activeClockGates (trace : List MmioAccess) : List ClockGate :=
  (if f1GateAddrs.any fun g => gateTouched trace g then f1ClockGates else []) ++
  (if f4GateAddrs.any fun g => gateTouched trace g then f4ClockGates else [])

/-- All mapped gates covering one address (usually exactly one; more
    only when both chips' maps are active). -/
def gatesFor (gates : List ClockGate) (addr : Nat) : List ClockGate :=
  gates.filter fun g => decide (g.blockLo ≤ addr) && decide (addr < g.blockHi)

/-- One clock-enable violation: the first use of a peripheral whose
    gate register is never STORE-touched, with the gate that should
    have been touched. Only the first use per (peripheral, block) is
    reported, so the line stays readable when a peripheral is used
    hundreds of times. -/
structure ClockViolation where
  access : MmioAccess
  gate : ClockGate
  deriving Repr, DecidableEq, Inhabited

def clockViolationsGo : List MmioAccess → List MmioAccess → List (String × Nat) → List ClockGate → List ClockViolation
  | [], _, _, _ => []
  | a :: rest, trace, seen, gates =>
    if decide (a.kind = .mmio) then
      match gatesFor gates a.addr with
      | [] => clockViolationsGo rest trace seen gates
      | g :: gs =>
        if (g :: gs).any fun gg => gateTouched trace gg.gateAddr then
          clockViolationsGo rest trace seen gates
        else if seen.contains (g.name, g.blockLo) then
          clockViolationsGo rest trace seen gates
        else
          { access := a, gate := g } ::
            clockViolationsGo rest trace ((g.name, g.blockLo) :: seen) gates
    else clockViolationsGo rest trace seen gates

/-- The clock-enable violations of a must trace (empty = pass). -/
def clockEnableViolations (trace : List MmioAccess) : List ClockViolation :=
  clockViolationsGo trace trace [] (activeClockGates trace)

/-- Clock-enable check: true iff no violation. -/
def checkClockEnable (trace : List MmioAccess) : Bool :=
  (clockEnableViolations trace).isEmpty

/-- Bounds (computed-pointer copy) evidence, v3.15. One entry per
    memcpy/memmove call site whose dst or src argument the extractor
    proved to be ADD(struct-field, function-argument offset).
    `unsoundCheck` = the function also contains, before the call, an
    unsigned comparison of (offset + size) against the same struct's
    size field -- the CVE-2026-11743 check shape, which a negative
    offset wraps past. `soundGuard` = the extractor found a candidate
    sound guard before the call: "signed-check" (signed offset-vs-0
    comparison), "wide-check" (ZEXT-past-pointer-size range check;
    v3 refinement: SEXT does NOT count -- a sign-extending widening
    alone does not reject negative offsets), "guard-call" (a call
    to a helper containing a signed ARG-vs-0 check, with a branch
    between it and the copy), or "multiword-check" (bounds v3: a
    64-bit range check lowered to 32-bit ARM as low-word unsigned
    compare + SBCS with carry + carry-tested branch gating the
    transfer; v3 refinement: the widening must be zero-extending
    -- a sign-extending ASR widening alone is NOT sound); "none"
    otherwise. A site is FLAGGED iff unsoundCheck && soundGuard ==
    "none": the function tried to validate and did it in exactly the
    wrapping way, with no candidate sound guard anywhere before the
    copy. PASS on this line means "no proven-bad shape in the traced
    copies" -- never "all copies proven safe": copies the extractor
    could not track (stack-spilled offsets, DMA transfers,
    command-address programming via integer offsets, indirect
    calls) are simply absent, and a site with no in-function check
    at all is emitted unflagged because a caller-side validation
    cannot be excluded. Since v3.16 the site set also covers
    cache-range transfers (address argument = computed pointer).
    Since Phase 1 (extractor v3.18) the site set also
    covers direct DMA transfers (role "dma": any callee that
    programs a computed-pointer argument into a constant address)
    and direct command-address programming (role "cmdaddr": any
    callee that programs a bare offset argument into a constant
    address or uses it as a store address; `baseField` is none
    when the callee never re-derives base+offset, so the field is
    `Option Nat` since Phase 1), and a flagged site is suppressed
    with soundGuard "caller-check" when every known direct caller
    validates the same (base, offset, size) triple (signed,
    ZEXT-wide, or multi-word guard in the caller; unsigned-only
    caller validation does not count). Indirect calls (CALLIND,
    e.g. through a driver ops struct) are still not sites: the
    callee cannot be resolved from inside the caller scan. Verdict
    logic is unchanged: only `flagged` decides, and `baseField` is
    never read by it.
    The top-level "copy_sites" field is optional: absent
    (pre-v3.15 reports) means no bounds data, not an error -- the
    line then passes vacuously and the site count (0) shows it. A
    present-but-malformed field is an error, like port/MSR. -/
structure BoundsSite where
  func : String
  instr : Nat
  kind : String
  role : String
  offsetArg : Nat
  baseField : Option Nat
  sizeField : Option Nat
  unsoundCheck : Bool
  soundGuard : String
  flagged : Bool
deriving Repr

def extractBoundsSite (j : Json) : Except String BoundsSite := do
  let func ← j.getObjVal? "func" >>= Json.getStr?
  let instrS ← j.getObjVal? "instr" >>= Json.getStr?
  let instr ← parseHex instrS
  let kind ← j.getObjVal? "kind" >>= Json.getStr?
  let role ← j.getObjVal? "role" >>= Json.getStr?
  let offsetArg ← j.getObjVal? "offset_arg" >>= Json.getNat?
  let baseField ← match j.getObjVal? "base_field" with
    | .ok .null => pure none
    | .ok v => some <$> Json.getNat? v
    | .error e => Except.error e
  let sizeField ← match j.getObjVal? "size_field" with
    | .ok .null => pure none
    | .ok v => some <$> Json.getNat? v
    | .error _ => pure none
  let unsoundCheck ← j.getObjVal? "unsound_check" >>= Json.getBool?
  let soundGuard ← j.getObjVal? "sound_guard" >>= Json.getStr?
  let flagged ← j.getObjVal? "flagged" >>= Json.getBool?
  pure { func := func, instr := instr, kind := kind, role := role,
         offsetArg := offsetArg, baseField := baseField,
         sizeField := sizeField, unsoundCheck := unsoundCheck,
         soundGuard := soundGuard, flagged := flagged }

def extractBoundsSites (j : Json) : Except String (List BoundsSite) := do
  match j.getObjVal? "copy_sites" with
  | .ok v => do
    let arr ← Json.getArr? v
    arr.toList.mapM extractBoundsSite
  | .error _ => pure []

/-- The bounds violations: flagged copy sites (empty = pass). -/
def boundsViolations (sites : List BoundsSite) : List BoundsSite :=
  sites.filter fun s => s.flagged

/-- Bounds check: true iff no flagged copy site. -/
def checkBounds (sites : List BoundsSite) : Bool :=
  (boundsViolations sites).isEmpty

/-- Phase 4 V1: security-boundary property (design-phase4.md).
    The extractor emits only VIOLATIONS in "boundary_sites"
    (compliant accesses are not emitted), plus the two unknown
    counts and the checked total. A violation is a NECESSARY
    condition for privilege escalation, never proof of an exploit.
    Unknown agents / unknown regions are miss + count on the
    extractor side: they never appear here as violations, and the
    counts are surfaced by Main so a report that covers little
    says so out loud. Absent fields (pre-Phase-4 reports) mean
    no boundary data, not an error -- the line then passes
    vacuously with 0 sites, same policy as bounds. -/
structure BoundarySite where
  func : String
  addr : Nat
  agent : String
  region : String
  kind : String
  leg : String
deriving Repr

def extractBoundarySite (j : Json) : Except String BoundarySite := do
  let func ← j.getObjVal? "function" >>= Json.getStr?
  let addrS ← j.getObjVal? "address" >>= Json.getStr?
  let addr ← parseHex addrS
  let agent ← j.getObjVal? "agent" >>= Json.getStr?
  let region ← j.getObjVal? "region" >>= Json.getStr?
  let kind ← j.getObjVal? "kind" >>= Json.getStr?
  let leg ← j.getObjVal? "leg" >>= Json.getStr?
  pure { func := func, addr := addr, agent := agent, region := region,
         kind := kind, leg := leg }

def extractBoundarySites (j : Json) : Except String (List BoundarySite) := do
  match j.getObjVal? "boundary_sites" with
  | .ok v => do
    let arr ← Json.getArr? v
    arr.toList.mapM extractBoundarySite
  | .error _ => pure []

/-- One boundary count field, absent = 0 (pre-Phase-4 reports). -/
def extractBoundaryCount (j : Json) (field : String) : Nat :=
  match j.getObjVal? field with
  | .ok v => match Json.getNat? v with
    | .ok n => n
    | .error _ => 0
  | .error _ => 0

/-- The boundary violations: the emitted sites ARE the violations. -/
def boundaryViolations (sites : List BoundarySite) : List BoundarySite :=
  sites

/-- Boundary check: true iff no emitted violation site. -/
def checkBoundary (sites : List BoundarySite) : Bool :=
  (boundaryViolations sites).isEmpty


/-- Non-vacuity: a GPIOA use with only an APB1 gate touched (APB2 never
    touched) fails — the synthetic-control shape. -/
example : checkClockEnable [
  { isStore := true, func := "main", addr := 0x4002101C, ones := 2, zeroes := 0 },
  { isStore := true, func := "main", addr := 0x4001080C, ones := 1, zeroes := 0 }
] = false := rfl

/-- ... and the same use with its own family's gate touched passes. -/
example : checkClockEnable [
  { isStore := true, func := "main", addr := 0x40021018, ones := 4, zeroes := 0 },
  { isStore := true, func := "main", addr := 0x4001080C, ones := 1, zeroes := 0 }
] = true := rfl
