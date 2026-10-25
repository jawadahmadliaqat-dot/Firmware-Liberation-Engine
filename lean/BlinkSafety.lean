/-
  BlinkSafety.lean — Formal Verifier SMOKE TEST (Lean 4, core only, no Mathlib)
  ---------------------------------------------------------------------------
  Source of truth: /home/hatch/firmware_workspace/analysis_reports/
                     stm32_blink.elf_report.json
  (Ghidra 11.4.2 headless + ExtractIR MMIO resolver, ARM:LE:32:v8)

  The extracted trace for `main` (in order, with instruction addresses):
    LOAD  0x40023830  (08000026)   -- read RCC_AHB1ENR  (GPIO clock register)
    STORE 0x40023830  (0800002e)   -- enable GPIOA clock
    LOAD  0x40020000  (08000032)   -- read GPIOA_MODER  (pin mode register)
    STORE 0x40020000  (0800003a)   -- set pin mode (step 1)
    LOAD  0x40020000  (0800003e)
    STORE 0x40020000  (08000046)   -- set pin mode (step 2)
    LOAD  0x40020014  (0800004a)   -- read GPIOA_ODR    (LED output register)
    STORE 0x40020014  (08000052)   -- LED ON
    LOAD  0x40020014  (0800005c)
    STORE 0x40020014  (08000064)   -- LED OFF

  SAFETY CONSTRAINT (the proof): no STORE to the LED register (ODR) may
  occur before BOTH a clock-enable STORE (RCC_AHB1ENR) and an output-mode
  STORE (GPIOA_MODER) have been seen.

  LIMIT (honest): this checker verifies the ORDER of accesses only.
  Value-aware modelling (LED actually ON vs OFF) needs the stored VALUES,
  which ExtractIR does not yet export — a future pipeline upgrade.
-/

/-- STM32F4 GPIOA hardware register addresses. -/
def RCC_AHB1ENR : Nat := 0x40023830
def GPIOA_MODER : Nat := 0x40020000
def GPIOA_ODR   : Nat := 0x40020014

/-- The hardware state the safety rule tracks. -/
structure HwState where
  clockEnabled : Bool
  pinIsOutput  : Bool
  deriving Repr, DecidableEq

/-- One MMIO operation, as exported by ExtractIR. -/
inductive MmioOp where
  | load  : Nat → MmioOp
  | store : Nat → MmioOp
  deriving Repr, DecidableEq

/-- The exact extracted trace of `main`, in order. -/
def blinkTrace : List MmioOp := [
  MmioOp.load  RCC_AHB1ENR,
  MmioOp.store RCC_AHB1ENR,
  MmioOp.load  GPIOA_MODER,
  MmioOp.store GPIOA_MODER,
  MmioOp.load  GPIOA_MODER,
  MmioOp.store GPIOA_MODER,
  MmioOp.load  GPIOA_ODR,
  MmioOp.store GPIOA_ODR,
  MmioOp.load  GPIOA_ODR,
  MmioOp.store GPIOA_ODR
]

/-- Safety checker: walks the trace, tracking clock/mode flags.
    An ODR STORE is allowed only when both flags are already true,
    otherwise the whole trace is rejected (false). -/
def checkTrace : List MmioOp → HwState → Bool
  | [], _ => true
  | MmioOp.store a :: rest, s =>
      if a == GPIOA_ODR then
        (s.clockEnabled && s.pinIsOutput) && checkTrace rest s
      else if a == RCC_AHB1ENR then
        checkTrace rest { s with clockEnabled := true }
      else if a == GPIOA_MODER then
        checkTrace rest { s with pinIsOutput := true }
      else
        checkTrace rest s
  | MmioOp.load _ :: rest, s => checkTrace rest s

/-- Power-on reset state: clock off, pin not in output mode. -/
def initialState : HwState := { clockEnabled := false, pinIsOutput := false }

/-- THE SAFETY THEOREM: the real extracted blink trace satisfies the rule. -/
theorem blink_safe : checkTrace blinkTrace initialState = true := rfl

/-- The checker is not vacuous: an LED STORE with no setup is rejected. -/
theorem checker_rejects_unsafe :
    checkTrace [MmioOp.store GPIOA_ODR] initialState = false := rfl

/-- A trace with clock enabled but pin mode never set is also rejected. -/
theorem checker_rejects_no_mode :
    checkTrace [MmioOp.store RCC_AHB1ENR, MmioOp.store GPIOA_ODR]
      initialState = false := rfl
