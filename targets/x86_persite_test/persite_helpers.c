// Helpers for per-site transfer tests (x86-64, freestanding).
// Kept in a SEPARATE translation unit from the callers on purpose:
// with LTO off, GCC cannot do inter-procedural constant propagation
// across TUs, so every call below survives as a real CALL and every
// call-site argument stays exactly what the caller source shows.
// All helpers are noinline, and the build uses
// -fno-optimize-sibling-calls so forwarding calls are not turned
// into tail jumps (a tail jump would delete the CALL+RETURN pair
// the analysis reasons about).
typedef unsigned int u32;
typedef unsigned long long u64;

static inline void outl(unsigned short port, u32 v) {
    __asm__ volatile ("outl %0, %1" : : "a"(v), "Nd"(port));
}

// Helper taking an MMIO address as parameter: the STORE address
// is exactly the caller's argument, so two sites with different
// addresses disagree under all-sites-agree (merged: nothing)
// but resolve per-site (one STORE per site).
__attribute__((noinline)) void poke_addr(u64 addr, u64 val) {
    *(volatile u64 *)addr = val;
}

// Helper taking a port as parameter: same shape for port I/O.
__attribute__((noinline)) void poke_port(unsigned short port, u32 val) {
    outl(port, val);
}

// Nested chain: mid forwards its arguments to inner unchanged.
// Per-site must propagate through the chain: mid's clones give
// inner's sites their bindings (L2 clones), or nothing resolves.
__attribute__((noinline)) void inner_poke(u64 addr, u64 val) {
    *(volatile u64 *)addr = val;
}

__attribute__((noinline)) void mid_poke(u64 addr, u64 val) {
    inner_poke(addr, val);
}

// Helper taking a masked BAR base as parameter: the STORE address
// is base + off, so two sites passing DIFFERENT devices' BAR
// symbols disagree under all-sites-agree (merged: nothing) but
// resolve per-site (one BAR finding per device).
__attribute__((noinline)) void bar_poke(u64 base, u64 off, u32 val) {
    *(volatile u32 *)(base + off) = val;
}

// Recursion: the recursive call inside must NOT spawn further
// clones (self-sites keep merged behaviour) and must NOT
// produce a finding for a wrong site. Each top-level site's
// own n==0 STORE is real and must appear with its own
// address/value only.
__attribute__((noinline)) void rec_poke(u64 addr, u64 val, u64 n) {
    if (n == 0) {
        *(volatile u64 *)addr = val;
        return;
    }
    rec_poke(addr, val, n - 1);
}
