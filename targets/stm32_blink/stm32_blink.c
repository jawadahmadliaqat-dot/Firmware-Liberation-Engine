/*
 * stm32_blink.c — minimal bare-metal blink firmware (STM32F4, Cortex-M4).
 * Ground-truth MMIO map for pipeline verification:
 *   RCC_AHB1ENR = 0x40023830  (enable GPIOA clock, bit 0)
 *   GPIOA_MODER = 0x40020000  (PA5 = output: bits 11:10 = 01)
 *   GPIOA_ODR   = 0x40020014  (LED bit: PA5 = bit 5)
 * Build:
 *   arm-none-eabi-gcc -mcpu=cortex-m4 -mthumb -g -O0 -nostdlib \
 *       -Ttext=0x08000000 -Wl,-e,main -o stm32_blink.elf stm32_blink.c
 * No libc, no startup code: Ghidra only needs the ELF + symbols + debug info.
 */

#define RCC_AHB1ENR (*(volatile unsigned int *)0x40023830)
#define GPIOA_MODER (*(volatile unsigned int *)0x40020000)
#define GPIOA_ODR   (*(volatile unsigned int *)0x40020014)

static void delay(volatile unsigned int n) {
    while (n--) {
        /* busy wait: the loop itself is control flow for the IR */
    }
}

int main(void) {
    /* 1. Enable GPIOA clock */
    RCC_AHB1ENR |= 0x1u;

    /* 2. PA5 as general-purpose output */
    GPIOA_MODER &= ~(0x3u << 10);
    GPIOA_MODER |= (0x1u << 10);

    /* 3. Blink forever: LED on -> delay -> LED off -> delay */
    while (1) {
        GPIOA_ODR |= (1u << 5);   /* LED ON  (MMIO STORE) */
        delay(1000000u);
        GPIOA_ODR &= ~(1u << 5);  /* LED OFF (MMIO STORE) */
        delay(1000000u);
    }

    return 0;
}
