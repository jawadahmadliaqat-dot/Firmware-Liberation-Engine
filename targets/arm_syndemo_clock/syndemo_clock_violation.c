/*
 * syndemo_clock_violation.c — SYNTHETIC Clock-Enable Negative Control.
 *
 * PURPOSE-BUILT SYNTHETIC firmware. This is NOT a real firmware, NOT
 * a real driver, and NOT a vulnerability in any real product. It
 * exists only to demonstrate what a Lean generic-mode clock-enable
 * FAIL looks like when firmware touches a peripheral whose clock
 * gate register was never touched.
 *
 * Mechanism (read from lean/Verifier/Common.lean, checkClockEnable):
 * v1 requires a MUST STORE to a peripheral's clock-gate REGISTER
 * somewhere in the trace. This firmware touches one family's gate
 * (APB1, for TIM3) and then uses a peripheral from another family
 * (GPIOA, gated by APB2ENR 0x40021018, bit 2) — so the F1 map is
 * active (an APB1 gate is touched) and the GPIOA use has no gate
 * touch, and Lean generic MUST fail clock-enable. The APB1 touch is
 * deliberate: a control with NO RCC touch at all would be vacuous
 * PASS (the map never activates), which would prove nothing — see
 * the design doc's no-RCC gap.
 *
 * Build (Task B recipe):
 *   arm-none-eabi-gcc -mcpu=cortex-m3 -mthumb -g -O0 -nostdlib \
 *       -Ttext=0x08000000 -Wl,-e,main -o syndemo_clock_violation.elf \
 *       syndemo_clock_violation.c
 * No libc, no startup code: Ghidra only needs the ELF + symbols.
 */

#define RCC_APB1ENR (*(volatile unsigned int *)0x4002101C) /* TIM3 clock gate */
#define GPIOA_ODR  (*(volatile unsigned int *)0x4001080C) /* GPIOA output, APB2 family */

int main(void) {
    RCC_APB1ENR |= 0x2u; /* enable TIM3 clock ONLY — APB1 family touched */
    GPIOA_ODR |= 0x1u;   /* GPIOA use, but APB2ENR never touched -> FAIL */
    while (1) {
        /* never returns; the loop itself is control flow for the IR */
    }
    return 0;
}
