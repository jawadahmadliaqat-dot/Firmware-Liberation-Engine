/* MIPS32 blink ground truth, AR9331-style GPIO map (verified against
 * AR9331 datasheet/OpenWrt headers: GPIO base 0x18040000, OE at +0x00
 * (1 = output), IN at +0x04, OUT at +0x08, SET at +0x0C, CLEAR at +0x10).
 * Mode input is volatile so GCC cannot fold the switch / indirect call away.
 * Each switch case calls a distinct function so -O2 emits a real jump table.
 */
#define GPIO_OE  (*(volatile unsigned int *)0x18040000u)
#define GPIO_OUT (*(volatile unsigned int *)0x18040008u)

static volatile unsigned int mode_in;

static void delay(void) {
    volatile unsigned int i;
    for (i = 0; i < 100000; i++) { }
}

static void led_on(void)  { GPIO_OUT |=  (1u << 5); }
static void led_off(void) { GPIO_OUT &= ~(1u << 5); }

static void pat0(void) { GPIO_OUT = 0x01u; }
static void pat1(void) { GPIO_OUT = 0x02u; }
static void pat2(void) { GPIO_OUT = 0x04u; }
static void pat3(void) { GPIO_OUT = 0x08u; }
static void pat4(void) { GPIO_OUT = 0x10u; }
static void pat5(void) { GPIO_OUT = 0x20u; }

/* Dense switch -> jump table at -O2 (exercises MipsIsa table recovery). */
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
    GPIO_OE |= (1u << 5);                       /* GPIO5 as output */
    for (;;) {
        dispatch_switch(mode_in);               /* volatile: cannot fold */
        mode_in = call_via_ptr(mode_in);
        delay();
    }
}

void _start(void) {
    __asm__ volatile ("li $sp, 0x80008000");
    main();
    for (;;) { }
}
