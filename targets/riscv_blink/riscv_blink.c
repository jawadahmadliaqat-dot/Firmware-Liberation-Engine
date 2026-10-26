/* RV32 blink ground truth, GD32VF103-style map (STM32F1-compatible regs).
 * RCU_APB2EN  0x40021018 (IOPAEN = bit 2)
 * GPIOA_CTL0  0x40010800 (pin mode, 4 bits per pin)
 * GPIOA_OCTL  0x4001080C (output data)
 * Mode input is volatile so GCC cannot fold the switch / indirect call away.
 * Each switch case calls a distinct function so -O2 emits a real jump table.
 */
#define RCU_APB2EN (*(volatile unsigned int *)0x40021018u)
#define GPIOA_CTL0 (*(volatile unsigned int *)0x40010800u)
#define GPIOA_OCTL (*(volatile unsigned int *)0x4001080Cu)

static volatile unsigned int mode_in;

static void delay(void) {
    volatile unsigned int i;
    for (i = 0; i < 100000; i++) { }
}

static void led_on(void)  { GPIOA_OCTL |=  (1u << 5); }
static void led_off(void) { GPIOA_OCTL &= ~(1u << 5); }

static void pat0(void) { GPIOA_OCTL = 0x01u; }
static void pat1(void) { GPIOA_OCTL = 0x02u; }
static void pat2(void) { GPIOA_OCTL = 0x04u; }
static void pat3(void) { GPIOA_OCTL = 0x08u; }
static void pat4(void) { GPIOA_OCTL = 0x10u; }
static void pat5(void) { GPIOA_OCTL = 0x20u; }

/* Dense switch -> jump table at -O2 (exercises RiscVIsa table recovery). */
__attribute__((noinline))
static void dispatch_switch(unsigned int mode) {
    switch (mode) {
        case 0: pat0(); break;
        case 1: pat1(); break;
        case 2: pat2(); break;
        case 3: pat3(); break;
        case 4: pat4(); break;
        case 5: pat5(); break;
        default: led_off(); break;
    }
}

typedef void (*led_fn)(void);
static led_fn table[2] = { led_on, led_off };

/* Indirect call, non-tail (exercises CALLIND handling via jalr). */
__attribute__((noinline))
static unsigned int call_via_ptr(unsigned int i) {
    table[i & 1u]();
    return i + 1u;
}

void main(void) {
    RCU_APB2EN |= (1u << 2);                    /* GPIOA clock on */
    GPIOA_CTL0 &= ~(0xFu << 20);                /* PA5 mode clear */
    GPIOA_CTL0 |=  (0x3u << 20);                /* PA5 out push-pull */
    for (;;) {
        dispatch_switch(mode_in);               /* volatile: cannot fold */
        mode_in = call_via_ptr(mode_in);
        delay();
    }
}

void _start(void) {
    __asm__ volatile ("li sp, 0x20008000");
    main();
    for (;;) { }
}
