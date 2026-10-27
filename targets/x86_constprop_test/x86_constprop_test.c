// Freestanding x86-64 test firmware for inter-procedural constant
// propagation (v2 item #2). The source is the map the extractor's
// output is spot-checked against. All helpers are noinline so the
// call graph is exactly what the source shows.
//
// Expected results under sound meet-over-all-call-sites propagation:
//   poke_single  -> MUST MMIO 0xfed00000 (one site, constant args)
//   poke_two     -> NO must (two sites, DIFFERENT addresses -> unknown)
//   poke_mixed   -> NO must (one constant site + one unknown-arg site)
//   poke_chain_inner -> MUST MMIO 0xfed00010 (transitive, one site each)
//   outb_single  -> MUST OUT port 0x3f8 (one site, constant port)
//   wrmsr_single -> MUST WRMSR index 0x1b (exploratory: value split
//                   through EDX:EAX may or may not fold exactly)
typedef unsigned char u8;
typedef unsigned int u32;
typedef unsigned long long u64;

static inline void outb(unsigned short port, u8 v) {
    __asm__ volatile ("outb %0, %1" : : "a"(v), "Nd"(port));
}

__attribute__((noinline)) void poke_single(u64 addr, u64 val) {
    *(volatile u64 *)addr = val;
}

__attribute__((noinline)) void poke_two(u64 addr, u64 val) {
    *(volatile u64 *)addr = val;
}

volatile u64 runtime_addr;

/* Volatile so the compiler MUST load it fresh immediately before
   the call (a plain literal gets hoisted into RAX at the top of
   _start and reused across calls -- see the note in _start). The
   analyzer reads the image value, so the site argument is exact. */
volatile u64 addr_single = 0xFED00000ULL;

__attribute__((noinline)) void poke_mixed(u64 addr, u64 val) {
    *(volatile u64 *)addr = val;
}

__attribute__((noinline)) void poke_chain_inner(u64 addr, u64 val) {
    *(volatile u64 *)addr = val;
}

__attribute__((noinline)) void poke_chain(u64 addr, u64 val) {
    poke_chain_inner(addr, val);
}

__attribute__((noinline)) void outb_single(unsigned short port, u8 v) {
    outb(port, v);
}

__attribute__((noinline)) void wrmsr_single(u32 idx, u64 v) {
    __asm__ volatile ("wrmsr" : : "c"(idx), "a"((u32)v), "d"((u32)(v >> 32)));
}

void _start(void) {
    /* NOTE on the compiler: GCC reuses RAX across calls for the
       same address constant (it can prove the callee preserves
       it). The ABI-conservative analysis correctly kills RAX
       after a CALL, so a site relying on such reuse reads
       unknown -- that is the analysis being right, not a
       propagation bug: a caller-saved register does not survive
       a call unless the caller reloads it. Each positive case
       therefore uses a DISTINCT address constant, forcing the
       compiler to reload it fresh before the call. */
    poke_chain(0xFED00010ULL, 0xBBULL);
    poke_single(addr_single, 0xAAULL);
    poke_two(0xFED00000ULL, 0x11ULL);
    poke_two(0xB8000ULL, 0x22ULL);
    poke_mixed(0xFED00000ULL, 0x33ULL);
    /* Second site passes a value loaded from MMIO (unmapped in the
       image, so the analysis sees it as unknown): constant vs
       unknown -> meet is unknown -> NO must. */
    poke_mixed(*(volatile u64 *)0xFED00000ULL, 0x44ULL);
    outb_single(0x3F8, 0x55);
    wrmsr_single(0x1B, 0xFEE00900ULL);
    for (;;) { }
}
