// Freestanding x86-64 test firmware for the seed leak guard (stage 2).
// g_leak stored 0xFED00040 in leak_init, BUT its address is passed to
// leak_sink -> address-taken leak blocks the seed. Decoy init
// 0xDEADBEEF (.data) keeps round-1 stores exact, so the ONLY thing
// blocking the seed is the leak (diagnostic: blockedLeak=1).
// Expected (new AND old code): NO MMIO STORE at 0xfed00040.
// The load yields the image value 0xDEADBEEF -> STORE [0xDEADBEEF],
// not MMIO.
typedef unsigned long long u64;

volatile u64 g_leak = 0xDEADBEEFu;

// Observable MMIO side effect so GCC's IPA cannot eliminate the call
// (an empty sink gets DCE'd, and then no leak ever happens). The
// pointer itself is never dereferenced: the ONLY leak is the call
// argument RDI = &g_leak. The MMIO store is absolute (COPY-to-ram),
// so it neither sets hasUnknownStore nor leaks a candidate address.
__attribute__((noinline)) void leak_sink(volatile u64 *p) {
    (void)p;
    *(volatile u64 *)0xFED00048u = 0x1u;
}

__attribute__((noinline)) void leak_init(void) {
    g_leak = 0xFED00040u;
    leak_sink(&g_leak);
}

__attribute__((noinline)) void leak_use(void) {
    *(volatile u64 *)g_leak = 0x99u;
}

void _start(void) {
    leak_init();
    leak_use();
    for (;;) { }
}
