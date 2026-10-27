/* Callee clobber refinement fixture, TU 2 (probes + main).
 * Each probe sets DX to a port, calls one helper, then executes IN.
 * The emitted bytes are what matters (the fixture is never run):
 * the CALL sits between the DX setup and the IN, so only a refined
 * clobber lets the port value survive to the IN.
 * Compile: gcc -O1 -fno-optimize-sibling-calls -c clobber_main.c
 */

long touch_rax_only(void);
long nested_ok(void);
long cond_call(long flag, long a, long b, long c, long d);
long mixed_call(long flag, long a, long b, long c, long d);
long pushpop_only(void);
long call_through(long (*f)(void));

/* Probe macro: mov port -> DX, CALL helper, IN DX -> AL. */
#define PROBE(name, call_expr) \
__attribute__((noinline)) unsigned char name(unsigned short port) { \
    unsigned char v; \
    __asm__ volatile( \
        "mov %1, %%edx\n\t" \
        call_expr "\n\t" \
        "in %%dx, %%al\n\t" \
        : "=a" (v) \
        : "r" ((unsigned int)port) \
        : "edx", "memory"); \
    return v; \
}

/* POSITIVE (direct): touch_rax_only writes RAX only, so DX survives.
 * Called with 0xCF8 and 0xCFC from main: per-site clones (one per
 * port) composed with refinement => two port findings. */
PROBE(probe_raxonly, "call touch_rax_only")

/* POSITIVE (transitive): nested_ok's may-write set is {RAX} via
 * transitivity, so DX survives the nested call too. */
PROBE(probe_nested, "call nested_ok")

/* NEGATIVE (i): cond_call writes DX on its flag path => DX dies. */
__attribute__((noinline)) unsigned char probe_cond(unsigned short port) {
    unsigned char v;
    __asm__ volatile(
        "mov %1, %%edx\n\t"
        "call cond_call\n\t"
        "in %%dx, %%al\n\t"
        : "=a" (v)
        : "r" ((unsigned int)port)
        : "edx", "memory");
    return v;
}

/* NEGATIVE (ii): mixed_call writes DX on both paths (push/pop on
 * one, inner4 argument setup on the other) => DX dies. */
__attribute__((noinline)) unsigned char probe_mixed(unsigned short port) {
    unsigned char v;
    __asm__ volatile(
        "mov %1, %%edx\n\t"
        "call mixed_call\n\t"
        "in %%dx, %%al\n\t"
        : "=a" (v)
        : "r" ((unsigned int)port)
        : "edx", "memory");
    return v;
}

/* DOCUMENTED LIMIT: pushpop_only truly preserves DX, but the pop
 * counts as a write under the may-write rule => DX dies here too.
 * Expected: NO finding (conservative, sound, documented). */
__attribute__((noinline)) unsigned char probe_pushpop(unsigned short port) {
    unsigned char v;
    __asm__ volatile(
        "mov %1, %%edx\n\t"
        "call pushpop_only\n\t"
        "in %%dx, %%al\n\t"
        : "=a" (v)
        : "r" ((unsigned int)port)
        : "edx", "memory");
    return v;
}

/* NEGATIVE (iii): call_through contains an indirect call => tainted
 * => DX dies. */
__attribute__((noinline)) unsigned char probe_indirect(unsigned short port) {
    unsigned char v;
    __asm__ volatile(
        "mov %1, %%edx\n\t"
        "call call_through\n\t"
        "in %%dx, %%al\n\t"
        : "=a" (v)
        : "r" ((unsigned int)port)
        : "edx", "memory");
    return v;
}

/* CONTROL: no intervening call => resolves under old and new code. */
__attribute__((noinline)) unsigned char probe_plain(unsigned short port) {
    unsigned char v;
    __asm__ volatile(
        "mov %1, %%edx\n\t"
        "in %%dx, %%al\n\t"
        : "=a" (v)
        : "r" ((unsigned int)port)
        : "edx", "memory");
    return v;
}

/* CONTROL: plain MMIO store, resolves under old and new code. */
__attribute__((noinline)) void plain_mmio(void) {
    *(volatile unsigned char *)(unsigned long)0xFED00098UL = 0x55;
}

int main(void) {
    /* The cond/mixed/pushpop/indirect probes pass their helper's
     * arguments via the C calls below (these C calls are separate
     * from the asm CALLs inside the probes; they only set up the
     * helpers to exist as callees with the right shapes). */
    (void)cond_call(1, 1, 2, 3, 4);
    (void)mixed_call(1, 1, 2, 3, 4);
    (void)pushpop_only();
    (void)call_through(touch_rax_only);
    probe_raxonly(0xCF8);
    probe_raxonly(0xCFC);
    probe_nested(0x3E8);
    probe_cond(0xCF8);
    probe_mixed(0xCF8);
    probe_pushpop(0xCF8);
    probe_indirect(0xCF8);
    probe_plain(0x2F8);
    plain_mmio();
    return 0;
}
