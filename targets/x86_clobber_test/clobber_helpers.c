/* Callee clobber refinement fixture, TU 1 (helpers).
 * Every helper is global + noinline so GCC cannot fold across calls
 * and the calls survive into the ELF exactly as written.
 * Compile: gcc -O1 -fno-optimize-sibling-calls -c clobber_helpers.c
 */

/* Writes RAX only. The refinement case: callers keep DX across this. */
__attribute__((noinline)) long touch_rax_only(void) {
    return 0x42;
}

/* Transitive case: calls touch_rax_only, so its may-write set is
 * {RAX} by transitivity. Callers keep DX across this too. */
__attribute__((noinline)) long nested_ok(void) {
    return touch_rax_only();
}

/* Four-arg helper: callers set up RDI/RSI/RDX/RCX to call it, so any
 * function that calls inner4 writes RDX (among others) itself. */
__attribute__((noinline)) long inner4(long a, long b, long c, long d) {
    return a + b + c + d;
}

/* NEGATIVE (i): writes RDX on ONE path only (the flag path, via
 * inner4 argument setup). Union over paths => RDX is may-written
 * => callers must still lose DX across this call. The flag path
 * RETURNS inner4's value so GCC cannot dead-code-eliminate the
 * call (a discarded pure call would vanish at -O1 and the
 * negative would be vacuous -- caught by objdump inspection). */
__attribute__((noinline)) long cond_call(long flag, long a, long b,
        long c, long d) {
    if (flag) return inner4(a, b, c, d);
    return 0;
}

/* NEGATIVE (ii): saves/restores RDX on one path (balanced push/pop)
 * but writes RDX on the other path (inner4 argument setup). Either
 * path alone puts RDX in the may-write set => callers lose DX. */
__attribute__((noinline)) long mixed_call(long flag, long a, long b,
        long c, long d) {
    if (flag) {
        __asm__ volatile("push %%rdx\n\tpop %%rdx\n\t" ::: "memory");
        return 0;
    } else {
        return inner4(a, b, c, d);
    }
}

/* DOCUMENTED LIMIT (not a negative): balanced push/pop of RDX on
 * ALL paths. The value truly survives, but the pop IS a write, so
 * the may-write rule still clobbers RDX. Recovering this needs a
 * save/restore analysis (future work). Expected: NO finding. */
__attribute__((noinline)) long pushpop_only(void) {
    __asm__ volatile("push %%rdx\n\tpop %%rdx\n\t" ::: "memory");
    return 0;
}

/* NEGATIVE (iii): contains an indirect call, so its behavior is
 * unknown => tainted => callers lose every caller-saved register
 * across this call, exactly as before refinement. */
__attribute__((noinline)) long call_through(long (*f)(void)) {
    return f();
}
