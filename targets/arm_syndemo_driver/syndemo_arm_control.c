/*
 * syndemo_arm_control.c — SYNTHETIC Confinement Demo, SHAPE 1 CONTROL.
 *
 * Identical to syndemo_arm_violation.c except the violating access is
 * replaced with an IN-FAMILY access: rcc_syndemo_touch now touches
 * 0x40021004 (RCC_CFGR, inside the rcc family's 0x40021000-0x40021400
 * range) instead of GPIOA. This control MUST PASS Lean bmp mode.
 * If it does not PASS, the Shape 1 FAIL is not attributable to the
 * out-of-family address and the demo is void.
 *
 * Build:
 *   arm-none-eabi-gcc -mcpu=cortex-m3 -mthumb -g -O0 -nostdlib \
 *       -Ttext=0x08000000 -Wl,-e,main -o syndemo_arm_control.elf \
 *       syndemo_arm_control.c
 */

#define RCC_CR   (*(volatile unsigned int *)0x40021000) /* in rcc range */
#define RCC_CFGR (*(volatile unsigned int *)0x40021004) /* in rcc range */

/* Same name prefix (rcc family), same shape — but in-family only. */
void rcc_syndemo_touch(void) {
    RCC_CFGR |= 0x1u; /* in-family LOAD + STORE: no violation */
}

int main(void) {
    RCC_CR |= 0x1u;
    rcc_syndemo_touch();
    while (1) {
    }
    return 0;
}
