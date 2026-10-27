// Freestanding x86-64 test firmware for memory propagation, stage 1
// (intra-procedural memState). All globals volatile (real STORE/LOAD
// and COPY-to/from-ram ops). All globals u64: 32-bit addressing
// lifts as INT_SEXT, which sign-extends MMIO addresses out of the
// bands -- a separate pre-existing gap, not what this tests.
// g_flag/g_alias_a init 0x7777 (.data, readable) so the negatives
// show the image-fallback value, not just unknown.
// Expected (new code):
//   poke_via_global  -> MUST MMIO STORE 0xfed00000 value 0x42
//   value_via_global -> MUST MMIO STORE 0xfed00018 value 0x1234
//   alias_test_store -> MMIO STORE 0xfed00010 value 0x7777 (NEVER 0xAAAA)
//   branch_test_store-> MMIO STORE 0xfed00014 value 0x7777 (NEVER 0xCCCC)
// Expected (old code): poke absent; value value unknown; negatives same
// 0x7777 (old code never propagated, so it cannot show a false must).
// The MMIO LOAD at 0xfed00020 supplies the opaque pointer for the
// alias test (a hardware input, hence unknown -- never a constant).
typedef unsigned long long u64;

volatile u64 g_mmio_addr = 0;
volatile u64 g_flag = 0x7777u;
volatile u64 g_alias_a = 0x7777u;
// Output-address globals: .data init, NEVER stored, so the load yields
// the image value and the MMIO store is register-indirect (a STORE op).
volatile u64 g_out_value = 0xFED00018u;
volatile u64 g_out_alias = 0xFED00010u;
volatile u64 g_out_branch = 0xFED00014u;

__attribute__((noinline)) void poke_via_global(void) {
    g_mmio_addr = 0xFED00000u;
    *(volatile u64 *)g_mmio_addr = 0x42u;
}

__attribute__((noinline)) void value_via_global(void) {
    g_flag = 0x1234u;
    *(volatile u64 *)g_out_value = g_flag;
}

__attribute__((noinline)) void alias_test_store(volatile u64 *p) {
    g_alias_a = 0xAAAAu;
    *p = 0xBBBBu;
    *(volatile u64 *)g_out_alias = g_alias_a;
}

__attribute__((noinline)) void branch_test_store(int cond) {
    if (cond) g_flag = 0xCCCCu;
    *(volatile u64 *)g_out_branch = g_flag;
}

void _start(void) {
    u64 opaque = *(volatile u64 *)0xFED00020u;
    poke_via_global();
    value_via_global();
    alias_test_store((volatile u64 *)opaque);
    branch_test_store((int)opaque);
    for (;;) { }
}
