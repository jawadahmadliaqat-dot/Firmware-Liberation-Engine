// Freestanding x86-64 test firmware (no libc): MMIO, port I/O, MSR,
// jump table, indirect call, flag-based branch, sub-register writes.
// Mirrors the riscv_blink / mips_blink ground-truth pattern: the source
// is the map the extractor's output is spot-checked against.
typedef unsigned char u8;
typedef unsigned int u32;
typedef unsigned long long u64;

static inline void outb(unsigned short port, u8 v) {
    __asm__ volatile ("outb %0, %1" : : "a"(v), "Nd"(port));
}
static inline u8 inb(unsigned short port) {
    u8 v;
    __asm__ volatile ("inb %1, %0" : "=a"(v) : "Nd"(port));
    return v;
}
static inline u64 rdmsr(u32 idx) {
    u32 lo, hi;
    __asm__ volatile ("rdmsr" : "=a"(lo), "=d"(hi) : "c"(idx));
    return ((u64)hi << 32) | lo;
}
static inline void wrmsr(u32 idx, u64 v) {
    __asm__ volatile ("wrmsr" : : "c"(idx), "a"((u32)v), "d"((u32)(v >> 32)));
}

volatile u32 mode_in;
volatile u64 *hpet = (volatile u64 *)0xFED00000ULL; // HPET base
volatile u8 *vga = (volatile u8 *)0xB8000ULL;       // VGA text memory

__attribute__((noinline)) void led_on(void)  { *vga = 0x41; } // 'A'
__attribute__((noinline)) void led_off(void) { *vga = 0x20; } // ' '

__attribute__((noinline)) void dispatch_switch(u32 m) {
    switch (m) {
        case 0: *hpet = 1; break;
        case 1: *hpet = 2; break;
        case 2: *hpet = 4; break;
        case 3: *hpet = 8; break;
        case 4: *hpet = 16; break;
        case 5: *hpet = 32; break;
        default: *hpet = 0; break;
    }
}

typedef void (*fn_t)(void);
static fn_t table[2] = { led_on, led_off };
__attribute__((noinline)) void call_via_ptr(u32 i) { table[i & 1](); }

__attribute__((noinline)) u32 flag_check(u32 x) {
    if (x == 5) return 1;
    return 0;
}

__attribute__((noinline)) u64 subreg_test(u64 x) {
    u8 b = (u8)x;
    b = b + 1;
    return (u64)b;
}

// Clobber spot-checks (x86 v1): prove caller-saved handling
// directly. rbx is callee-saved in System V, so the HPET store
// after the call MUST appear; rax is volatile, so its HPET store
// after the call MUST NOT appear (address unknown after clobber).
// dummy_fn is also called normally from _start so it survives.
__attribute__((noinline)) void dummy_fn(void) { }
__attribute__((noinline)) void clobber_rbx_check(void) {
    __asm__ volatile (
        "mov $0xFED00000, %%rbx\n\t"
        "call dummy_fn\n\t"
        "movq $0x77, (%%rbx)"
        : : : "rbx", "memory");
}
__attribute__((noinline)) void clobber_rax_check(void) {
    __asm__ volatile (
        "mov $0xFED00000, %%rax\n\t"
        "call dummy_fn\n\t"
        "movq $0x77, (%%rax)"
        : : : "rax", "memory");
}

void _start(void) {
    outb(0x3F8, 0x55);           // serial port
    u8 s = inb(0x3F8);
    (void)s;
    wrmsr(0x1B, 0xFEE00900ULL);  // IA32_APIC_BASE
    u64 apic = rdmsr(0x1B);
    (void)apic;
    wrmsr(0xC0000080, 0x500ULL); // IA32_EFER
    u32 m = mode_in;
    dispatch_switch(m);
    call_via_ptr(m);
    u32 f = flag_check(m);
    if (f) led_on(); else led_off();
    u64 r = subreg_test(0x1122334455667788ULL);
    (void)r;
    dummy_fn();
    clobber_rbx_check();
    clobber_rax_check();
    for (;;) { *vga = 0x42; }    // 'B'
}
