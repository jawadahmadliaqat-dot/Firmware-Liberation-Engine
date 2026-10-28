/*
 * syndemo_clock_control.c — SYNTHETIC Clock-Enable Positive Control.
 *
 * PURPOSE-BUILT SYNTHETIC firmware, the passing counterpart of
 * syndemo_clock_violation.c. It enables the GPIOA clock
 * (APB2ENR bit 2) and then uses GPIOA, so Lean generic MUST pass
 * clock-enable. Same build recipe as the violation control.
 *
 * Build:
 *   arm-none-eabi-gcc -mcpu=cortex-m3 -mthumb -g -O0 -nostdlib \
 *       -Ttext=0x08000000 -Wl,-e,main -o syndemo_clock_control.elf \
 *       syndemo_clock_control.c
 */

#define RCC_APB2ENR (*(volatile unsigned int *)0x40021018) /* GPIOA clock gate, bit 2 */
#define GPIOA_ODR  (*(volatile unsigned int *)0x4001080C) /* GPIOA output */

int main(void) {
    RCC_APB2ENR |= 0x4u; /* enable GPIOA clock (APB2ENR bit 2) */
    GPIOA_ODR |= 0x1u;   /* GPIOA use, gate touched -> PASS */
    while (1) {
        /* never returns; the loop itself is control flow for the IR */
    }
    return 0;
}
