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

def checkGeneric (trace : List MmioAccess) : Bool :=
  !trace.isEmpty && checkMasksConsistent trace &&
  checkWindow 0x40000000 0x60000000 trace

def inRange (addr lo hi : Nat) : Bool :=
  decide (lo ≤ addr) && decide (addr < hi)

/-- Architectural x86 port allowlist: the PC platform's fixed I/O map
    entries that platform firmware touches during init and bring-up.
    PCI configuration mechanism 1 (0xCF8-0xCFF, address + data bytes);
    legacy interrupt/timer/DMA/keyboard/CMOS (PIC, PIT, DMA pages,
    keyboard controller, RTC); serial UARTs COM1-COM4. Device registers
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
  inRange p 0x3E8 0x3F0 || inRange p 0x2E8 0x2F0

/-- Architectural x86 MSR allowlist: the firmware-init-relevant core.
    Intel SDM Vol 4 architectural MSRs (TSC, APIC_BASE, BIOS_SIGN_ID,
    MTRRCAP, SYSENTER, MISC_ENABLE, MTRR phys/fixed, PAT,
    MTRR_DEF_TYPE, EFER, STAR/LSTAR/CSTAR/FMASK, FS/GS bases, TSC_AUX)
    and AMD APM (SYSCFG, HWCR, GHCB, SEV_STATUS). Any MSR outside this
    list fails confinement until added here with a justification
    comment (the allowlist path). -/
def x86MsrAllowed (m : Nat) : Bool :=
  m == 0x10 || m == 0x1B || m == 0x8B || m == 0xFE ||
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
    pipeline runs must match the same profile (regression gate). -/
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
      inRange a.addr 0x40010800 0x40011400 || inRange a.addr 0x40012400 0x40012800
    else true
