// Freestanding x86-64 test firmware for global seeds, stage 2
// (program-wide all-stores-agree). NO unknown stores in this binary:
// every round-1 store address is exact (COPY-to-ram, or MMIO-skipped),
// which is what makes seeding possible at all.
// g_seed_addr init 0xDEADBEEF (.data decoy, readable, non-MMIO): the
// round-1 store through it is exact (not unknown), while the seeded
// value 0xFED00030 differs from the image value -- so old code, which
// can only use the image, cannot reproduce the finding.
// Expected (new code):
//   seed_use     -> MUST MMIO STORE 0xfed00030 value 0x77 (address seed)
//   seed_use_val -> MUST MMIO STORE 0xfed00038 value 0x1234 (value seed)
//   multi_use    -> MMIO STORE 0xfed00034 value NEVER 0x1111/0x2222
//     (disagreeing stores block the seed)
// Expected (old code): no STORE at 0xfed00030; seed_use_val value
// unknown; multi_use value unknown (old code never seeds).
typedef unsigned long long u64;

volatile u64 g_seed_addr = 0xDEADBEEFu;
volatile u64 g_seed_val = 0;
volatile u64 g_multi = 0;
volatile u64 g_out_seed_val = 0xFED00038u; // .data init, never stored
volatile u64 g_out_multi = 0xFED00034u;   // .data init, never stored

__attribute__((noinline)) void seed_init(void) {
    g_seed_addr = 0xFED00030u;
}

__attribute__((noinline)) void seed_use(void) {
    *(volatile u64 *)g_seed_addr = 0x77u;
}

__attribute__((noinline)) void seed_init_val(void) {
    g_seed_val = 0x1234u;
}

__attribute__((noinline)) void seed_use_val(void) {
    *(volatile u64 *)g_out_seed_val = g_seed_val;
}

__attribute__((noinline)) void multi_a(void) {
    g_multi = 0x1111u;
}

__attribute__((noinline)) void multi_b(void) {
    g_multi = 0x2222u;
}

__attribute__((noinline)) void multi_use(void) {
    *(volatile u64 *)g_out_multi = g_multi;
}

void _start(void) {
    seed_init();
    seed_use();
    seed_init_val();
    seed_use_val();
    multi_a();
    multi_b();
    multi_use();
    for (;;) { }
}
