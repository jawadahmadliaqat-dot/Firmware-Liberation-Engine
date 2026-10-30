/-
  Main.lean — ingest_check executable.
  Usage: lake exe ingest_check <report.json> [blink|generic|bmp]
  Default mode is blink (the PA5 spec); generic runs only the
  firmware-agnostic invariants (non-empty trace, consistent masks,
  MMIO addresses inside the bands, port/MSR sanity, port/MSR
  confinement against the architectural allowlist for the report's
  language) plus the clock-enable check (every used STM32
  peripheral's gate register touched; vacuous unless an STM32 RCC
  gate register is STORE-touched, so non-STM32 reports are
  unaffected). Bmp and blink modes are untouched by confinement: their
  reports (ARM) carry no port/MSR entries, so the check would be
  vacuous there, and their code paths do not call it.
  The trace is unified: "trace ops" counts MMIO + port + MSR ops
  (the breakdown line right after it splits the count by kind).
  Reports without port/MSR fields (pre-v3.8) yield the same trace
  as before — the breakdown is then (N, 0, 0) and every pre-existing
  output line is unchanged.
  Generic-mode bands: the report's top-level "mmio_windows" field
  (emitted by ExtractIR from the ISA adapter's own constants).
  Reports without the field (old reports) fall back to the historical
  ARM window 0x40000000-0x60000000, so old verdicts are unchanged.
  Bmp mode keeps its own hardcoded ARM window via checkGeneric.
  Generic mode also runs the bounds check (v3.15; v3.16 extends
  the site set from memcpy/memmove copies to cache-range
  transfers): the report's top-level "copy_sites" field, absent
  on pre-v3.15 reports (then the bounds line passes vacuously
  with 0 sites -- visible, not hidden).
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

def printGeneric (lang : Option String) (windows : List (Nat × Nat)) (trace : List MmioAccess) (sites : List BoundsSite) (bsites : List BoundarySite) (bUnknownAgent bUnknownRegion bRegionCount : Nat) : IO Bool := do
  let nonempty := !trace.isEmpty
  let masks := checkMasksConsistent trace
  let window := checkWindowBands windows trace
  let sanity := checkPortMsrSanity trace
  let confined := checkPortMsrConfinement lang trace
  IO.println s!"trace non-empty: {nonempty}"
  IO.println s!"masks consistent (ones & zeroes == 0): {masks}"
  IO.println s!"all addresses in MMIO window: {window}"
  IO.println s!"port/MSR sanity (port ≤ 0xFFFF, MSR index < 2^32): {sanity}"
  IO.println s!"port/MSR confinement (every port/MSR in the architectural allowlist): {confined}"
  let violations := portMsrConfinementViolations lang trace
  if !violations.isEmpty then
    let names := violations.map fun a =>
      s!"{a.func} {kindName a.kind} {natToHex a.addr}"
    IO.println s!"confinement violations: {names}"
  let clock := checkClockEnable trace
  IO.println s!"clock-enable (every used peripheral's gate register touched): {clock}"
  let clockVios := clockEnableViolations trace
  if !clockVios.isEmpty then
    let names := clockVios.map fun v =>
      s!"{v.access.func} {kindName v.access.kind} {natToHex v.access.addr} ({v.gate.name} needs {natToHex v.gate.gateAddr} bit {v.gate.gateBit})"
    IO.println s!"clock-enable violations: {names}"
  let bounds := checkBounds sites
  IO.println s!"bounds (no computed-pointer copy/transfer with unsound-only guard): {bounds}"
  IO.println s!"bounds sites: {sites.length}"
  let boundsVios := boundsViolations sites
  if !boundsVios.isEmpty then
    let names := boundsVios.map fun s =>
      let bfs := match s.baseField with | some n => toString n | none => "none"
      s!"{s.func} {s.kind} {natToHex s.instr} (role {s.role}, offset arg {s.offsetArg}, base field {bfs}, no sound guard)"
    IO.println s!"bounds violations: {names}"
  let boundary := checkBoundary bsites
  IO.println s!"boundary (no must-proven access crossing a configured security boundary): {boundary}"
  IO.println s!"boundary regions: {bRegionCount}"
  let boundaryVios := boundaryViolations bsites
  if !boundaryVios.isEmpty then
    let names := boundaryVios.map fun s =>
      s!"{s.func} {if s.kind == "write" then "write" else "read"} {natToHex s.addr} ({s.agent}, {s.region}, {s.kind}, {s.leg})"
    IO.println s!"boundary violations: {names}"
  IO.println s!"boundary unknown-agent accesses: {bUnknownAgent}"
  IO.println s!"boundary unknown-region accesses: {bUnknownRegion}"
  pure (nonempty && masks && window && sanity && confined && clock && bounds && boundary)

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
  let content ← try IO.FS.readFile path catch e => do
    IO.println s!"cannot read report: {path} ({e})"
    IO.Process.exit 1
  match Json.parse content with
  | .error e => IO.println s!"JSON parse failed: {e}"; pure 1
  | .ok j =>
    match extractTrace j with
    | .error e => IO.println s!"extract failed: {e}"; pure 1
    | .ok trace => do
      IO.println s!"trace ops: {trace.length}"
      let mmioN := (trace.filter fun a => decide (a.kind = .mmio)).length
      let portN := (trace.filter fun a => decide (a.kind = .port)).length
      let msrN := (trace.filter fun a => decide (a.kind = .msr)).length
      IO.println s!"trace ops by kind (mmio, port, msr): ({mmioN}, {portN}, {msrN})"
      match extractMayTrace j with
      | .error e => IO.println s!"may extract failed: {e}"; pure 1
      | .ok mayTrace => do
        IO.println s!"may trace ops: {mayTrace.length}"
        match extractMmioWindows j with
        | .error e => IO.println s!"mmio windows extract failed: {e}"; pure 1
        | .ok windows => do
          match extractBoundsSites j with
          | .error e => IO.println s!"bounds extract failed: {e}"; pure 1
          | .ok sites => do
          match extractBoundarySites j with
          | .error e => IO.println s!"boundary extract failed: {e}"; pure 1
          | .ok bsites => do
          let lang := extractLanguage j
          let bUnknownAgent := extractBoundaryCount j "boundary_unknown_agent_total"
          let bUnknownRegion := extractBoundaryCount j "boundary_unknown_region_total"
          let bRegionCount := extractBoundaryCount j "boundary_region_count"
          let ok ← if mode == "generic" then printGeneric lang windows trace sites bsites bUnknownAgent bUnknownRegion bRegionCount
            else if mode == "bmp" then printBmp trace mayTrace
            else printBlink trace
          if ok then IO.println "VERDICT: PASS"; pure 0
          else IO.println "VERDICT: FAIL"; pure 1
