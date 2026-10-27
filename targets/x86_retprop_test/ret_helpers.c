// Helpers for return-value propagation tests (x86-64, freestanding).
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

static inline u32 inl(unsigned short port) {
    u32 v;
    __asm__ volatile ("inl %1, %0" : "=a"(v) : "Nd"(port));
    return v;
}

__attribute__((noinline)) u64 ret_const_addr(void) {
    return 0xFED00000ULL;
}

__attribute__((noinline)) u64 ret_const_addr2(void) {
    return 0xFED00080ULL;
}

__attribute__((noinline)) u64 ret_nested(void) {
    return ret_const_addr2();
}

__attribute__((noinline)) u64 ret_id(u64 x) {
    return x;
}

__attribute__((noinline)) u64 ret_id2(u64 x) {
    return x;
}

__attribute__((noinline)) u64 ret_add(u64 x) {
    return x + 0x10ULL;
}

__attribute__((noinline)) u64 ret_add_sym(u64 x) {
    return x + 0x10ULL;
}

__attribute__((noinline)) u64 ret_pathvar(u64 x) {
    if (x) return 0xFED00050ULL;
    return 0xFED00060ULL;
}

__attribute__((noinline)) u64 ret_rec(u64 n) {
    if (n == 0) return 0xFED00070ULL;
    return ret_rec(n - 1);
}

/* Reads BAR0 of bus 0 / dev 31 / fn 0 (config addr 0x8000F810)
   and returns the MASKED base. The caller gets a BASE symbol
   only if return-value propagation carries it across the call. */
__attribute__((noinline)) u64 ret_bar(void) {
    outl(0xCF8, 0x8000F810U);
    u64 bar = inl(0xCFC);
    bar &= ~0xFULL;
    return bar;
}
