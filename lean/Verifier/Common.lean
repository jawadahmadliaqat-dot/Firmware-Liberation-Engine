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
    NOT a confinement check: port/MSR confinement (which ports/MSRs a
    driver may touch) is future work, deliberately not added here. -/
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
