/*
 * syndemo_arm_violation.c — SYNTHETIC Confinement Demo, SHAPE 1.
 *
 * PURPOSE-BUILT SYNTHETIC firmware. This is NOT a real firmware, NOT a
 * real driver, and NOT a vulnerability in any real product. It
 * exists only to demonstrate what a Lean bmp-mode driver-confinement
 * FAIL looks like when a function touches a peripheral outside its
 * own driver family.
 *
 * Mechanism (read from lean/Verifier/Common.lean, checkBmpConfinement):
 * bmp mode assigns a driver family by FUNCTION-NAME PREFIX. A function
 * whose name starts with "rcc_" belongs to the rcc family, whose only
 * allowed range is 0x40021000-0x40021400 (STM32F1 RCC block).
 *
 * The function rcc_syndemo_touch below deliberately performs a
 * LOAD + STORE on 0x4001080C (GPIOA output data, STM32F1) — outside
 * the rcc family's allowed range — so Lean bmp MUST fail driver
 * confinement. The name reuse is deliberate and labeled: the demo
 * borrows the family-name mechanism, it does not pretend to be BMP.
 *
 * Build:
 *   arm-none-eabi-gcc -mcpu=cortex-m3 -mthumb -g -O0 -nostdlib \
 *       -Ttext=0x08000000 -Wl,-e,main -o syndemo_arm_violation.elf \
 *       syndemo_arm_violation.c
 * No libc, no startup code: Ghidra only needs the ELF + symbols.
 */

#define RCC_CR    (*(volatile unsigned int *)0x40021000) /* in rcc range */
#define GPIOA_ODR (*(volatile unsigned int *)0x4001080C) /* NOT in rcc range */

/* rcc-family function by name prefix — deliberately touches GPIOA. */
void rcc_syndemo_touch(void) {
    GPIOA_ODR |= 0x1u; /* violating LOAD + STORE: GPIOA from rcc family */
}

int main(void) {
    RCC_CR |= 0x1u; /* in-family access, fine on its own */
    rcc_syndemo_touch();
    while (1) {
        /* never returns; the loop itself is control flow for the IR */
    }
    return 0;
}
