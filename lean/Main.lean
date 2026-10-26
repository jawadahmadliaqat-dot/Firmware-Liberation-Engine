/-
  Main.lean — ingest_check executable.
  Usage: lake exe ingest_check <report.json> [blink|generic|bmp]
  Default mode is blink (the PA5 spec); generic runs only the
  firmware-agnostic invariants (non-empty trace, consistent masks,
  addresses inside the MMIO bands).
  Generic-mode bands: the report's top-level "mmio_windows" field
  (emitted by ExtractIR from the ISA adapter's own constants).
  Reports without the field (old reports) fall back to the historical
  ARM window 0x40000000-0x60000000, so old verdicts are unchanged.
  Bmp mode keeps its own hardcoded ARM window via checkGeneric.
-/

import Verifier.Common

open Lean

def printBlink (trace : List MmioAccess) : IO Bool := do
  let order := checkOrder blinkSpec trace
  let led := checkLedBits blinkSpec trace
  let clock := checkClockBit blinkSpec trace
  let mode := checkMode blinkSpec trace
  IO.println s!"order (clock+mode before LED): {order}"
  IO.println s!"led bit decided on every LED store: {led}"
  IO.println s!"clock bit set on every clock store: {clock}"
  IO.println s!"mode clear-then-set before LED: {mode}"
  pure (order && led && clock && mode)

def printGeneric (windows : List (Nat × Nat)) (trace : List MmioAccess) : IO Bool := do
  let nonempty := !trace.isEmpty
  let masks := checkMasksConsistent trace
  let window := checkWindowBands windows trace
  IO.println s!"trace non-empty: {nonempty}"
  IO.println s!"masks consistent (ones & zeroes == 0): {masks}"
  IO.println s!"all addresses in MMIO window: {window}"
  pure (nonempty && masks && window)

def printBmp (trace : List MmioAccess) (mayTrace : List MmioAccess) : IO Bool := do
  let generic := checkGeneric trace
  let confined := checkBmpConfinement trace
  let mayConfined := checkBmpConfinement mayTrace
  IO.println s!"generic invariants: {generic}"
  IO.println s!"driver confinement (each family touches only its own peripherals): {confined}"
  IO.println s!"may confinement (every possible address within its family): {mayConfined}"
  pure (generic && confined && mayConfined)

def main (args : List String) : IO UInt32 := do
  let path := (args.head?).getD "report.json"
  let mode := (args.drop 1 |>.head?).getD "blink"
  let content ← IO.FS.readFile path
  match Json.parse content with
  | .error e => IO.println s!"JSON parse failed: {e}"; pure 1
  | .ok j =>
    match extractTrace j with
    | .error e => IO.println s!"extract failed: {e}"; pure 1
    | .ok trace => do
      IO.println s!"trace ops: {trace.length}"
      match extractMayTrace j with
      | .error e => IO.println s!"may extract failed: {e}"; pure 1
      | .ok mayTrace => do
        IO.println s!"may trace ops: {mayTrace.length}"
        match extractMmioWindows j with
        | .error e => IO.println s!"mmio windows extract failed: {e}"; pure 1
        | .ok windows => do
          let ok ← if mode == "generic" then printGeneric windows trace
            else if mode == "bmp" then printBmp trace mayTrace
            else printBlink trace
          if ok then IO.println "VERDICT: PASS"; pure 0
          else IO.println "VERDICT: FAIL"; pure 1
