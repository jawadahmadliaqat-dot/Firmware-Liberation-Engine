/-
  Verifier/Common.lean — shared checker for the Formal Verifier.
  Pure defs only (no IO): MMIO trace type, blink spec, JSON extraction,
  blink-specific checks, and firmware-agnostic generic checks.
  Imported by Main (the exe) and by Verifier/BlinkProof (the theorem).
-/

import Lean

open Lean

/-- One MMIO access, as exported by ExtractIR v3. -/
structure MmioAccess where
  isStore : Bool
  func : String
  addr : Nat
  ones : Nat
  zeroes : Nat
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
  pure { isStore := op == "STORE", func := func, addr := addr, ones := ones, zeroes := zeroes }

/-- All MMIO accesses of all functions, in file order. -/
def extractTrace (j : Json) : Except String (List MmioAccess) := do
  let fns ← j.getObjVal? "functions" >>= Json.getArr?
  fns.toList.foldlM (fun acc fn => do
    let name ← fn.getObjVal? "name" >>= Json.getStr?
    let arr ← fn.getObjVal? "mmio_accesses" >>= Json.getArr?
    let accs ← arr.toList.mapM (extractAccess name)
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
