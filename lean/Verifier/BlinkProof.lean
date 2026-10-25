/-
  Verifier/BlinkProof.lean — theorem over the live blink report.
  The report is embedded at compile time via include_str (relative to
  this file: up to firmware_workspace, then analysis_reports).
  NOTE: Lake does not track include_str'd data files, so after the
  pipeline writes a new report, force a rebuild with:
    touch Verifier/BlinkProof.lean && lake build
-/

import Verifier.Common

open Lean

def embeddedReport : String :=
  include_str "../../analysis_reports/stm32_blink.elf_report.json"

def ingestedTrace : Except String (List MmioAccess) :=
  match Json.parse embeddedReport with
  | .error e => .error e
  | .ok j => extractTrace j

/-- Bool verdict over the ingested trace (false on any ingest failure). -/
def ingestedVerdict : Bool :=
  match ingestedTrace with
  | .ok trace => checkAll blinkSpec trace
  | .error _ => false

/-- THE THEOREM: the real extracted blink trace passes every safety check. -/
theorem ingested_blink_safe : ingestedVerdict = true := by native_decide

/-- Negative control: an LED store with no setup is rejected by the same checker. -/
def badTrace : List MmioAccess :=
  [{ isStore := true, func := "test", addr := 0x40020014, ones := 32, zeroes := 0 }]

theorem checker_rejects_led_first :
    checkAll blinkSpec badTrace = false := rfl

#print axioms ingested_blink_safe
#print axioms checker_rejects_led_first
