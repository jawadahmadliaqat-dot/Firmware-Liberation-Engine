// Helpers for STRUCT return summaries (x86-64, dynamic link).
// Kept in a SEPARATE translation unit from the callers on purpose:
// with LTO off, GCC cannot do inter-procedural propagation across
// TUs, so every call below survives as a real CALL.
// All helpers are noinline, and the build uses
// -fno-optimize-sibling-calls so forwarding calls are not turned
// into tail jumps.
// The makers allocate with real malloc (external): its return is
// a genuinely unknown pointer, exactly like UEFI AllocatePool.
// The analysis must track fields of that pointer through the
// maker's stores and hand the caller a per-call-site object whose
// fields resolve. Compile at -O1 so the device pointer stays in
// a register (at -O0 GCC spills it to the stack, and the
// analysis does not track values through stack slots -- the same
// documented limitation as memState).
#include <stdlib.h>

typedef unsigned int u32;
typedef unsigned long long u64;

struct Dev {
    u64 regs;  // offset 0: MMIO base (exact) or BAR base (symbol)
    u64 val;   // offset 8: scratch value
    u64 ctrl;  // offset 16: control value
};

static inline void outl(unsigned short port, u32 v) {
    __asm__ volatile ("outl %0, %1" : : "a"(v), "Nd"(port));
}

static inline u32 inl(unsigned short port) {
    u32 v;
    __asm__ volatile ("inl %1, %0" : "=a"(v) : "Nd"(port));
    return v;
}

// Fresh object, constant fields (device A).
__attribute__((noinline)) struct Dev *make_dev_a(void) {
    struct Dev *d = malloc(sizeof *d);
    d->regs = 0xFED00000ULL;
    d->val = 0x1111ULL;
    d->ctrl = 0x42ULL;
    return d;
}

// Fresh object, constant fields (device B, different BAR).
__attribute__((noinline)) struct Dev *make_dev_b(void) {
    struct Dev *d = malloc(sizeof *d);
    d->regs = 0xFED00010ULL;
    d->val = 0x2222ULL;
    d->ctrl = 0x43ULL;
    return d;
}

// Fresh object, BAR field from config space (bus 0, dev 31, fn 0,
// BAR0 -- the same dance as the cfgspace fixture, but the BASE
// symbol is stored into a struct field and returned).
__attribute__((noinline)) struct Dev *make_pci_dev(void) {
    struct Dev *d = malloc(sizeof *d);
    outl(0xCF8, 0x8000F810U);
    u32 raw = inl(0xCFC);
    d->regs = (u64)(raw & 0xFFFFFFF0U);
    d->val = 0x55ULL;
    d->ctrl = 0x56ULL;
    return d;
}

// Fresh object, one field set on one path only (negative ii).
// regs is stored only when c != 0; ctrl is always stored.
__attribute__((noinline)) struct Dev *make_partial(int c) {
    struct Dev *d = malloc(sizeof *d);
    if (c) d->regs = 0xFED00050ULL;
    d->ctrl = 0x44ULL;
    return d;
}

// Global object (case b): the device struct lives in .data with
// initialized fields, and the maker returns its address through
// a global pointer variable. The fields are global cells read
// from image bytes -- no object summary is involved, and the
// global must never be confused with a fresh object.
struct Dev gdev_init = { 0xFED000A0ULL, 0x66ULL, 0x44ULL };
struct Dev *gdev_ptr = &gdev_init;

__attribute__((noinline)) struct Dev *make_global_dev(void) {
    return gdev_ptr;
}

// Wrapper (nested summary): returns make_dev_a's object unchanged.
// Its own summary forms only in a second Phase S round, once
// make_dev_a's summary is installed at the inner call site.
__attribute__((noinline)) struct Dev *make_wrap(void) {
    return make_dev_a();
}

// Recursive maker (negative iv): one RETURN yields make_dev_a's
// object, the other yields the recursive result. The RETURNs
// disagree, so no summary may form.
__attribute__((noinline)) struct Dev *make_rec(int n) {
    if (n == 0) return make_dev_a();
    return make_rec(n - 1);
}
