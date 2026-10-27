// Helpers for the u32/INT_SEXT MMIO gap (x86-64, dynamic link).
// Kept in a SEPARATE translation unit from the callers on purpose:
// with LTO off, GCC cannot do inter-procedural propagation across
// TUs, so every call below survives as a real CALL, and the u32
// globals cannot be constant-folded at the use site.
// All helpers are noinline, and the build uses
// -fno-optimize-sibling-calls so forwarding calls are not turned
// into tail jumps. Compile at -O1 so values stay in registers
// (at -O0 GCC spills to the stack, which the analysis does not
// track -- the same documented limitation as memState).
//
// The bug: a 32-bit MMIO address held in a u32 (bit 31 set) is
// widened to 64 bits through a SIGNED int, so Ghidra lifts an
// INT_SEXT and the address becomes 0xFFFFFFFFFED00000 -- outside
// every MMIO band, so the access is missed (and the STORE even
// pollutes memState at the bogus address). The sound fix recovers
// the low 32 bits ONLY when the Bits prove bits 63..32 are all
// copies of bit 31.
typedef unsigned int u32;
typedef unsigned long long u64;

// u32 globals holding MMIO addresses (bit 31 set -> SEXT widens).
u32 g_base_a = 0xFED00000u;  // device A base
u32 g_base_b = 0xFED00010u;  // device B base
u32 g_plain  = 0x80000000u;  // NOT in any band (negative ii)

// STORE through a u32 global, widened through a signed int.
// P-Code: LOAD 4 bytes (global) -> INT_SEXT -> STORE.
// Expected AFTER fix: STORE 0xFED00000 val 0x42. BEFORE: missed.
__attribute__((noinline)) void poke_a(u32 v) {
    *(volatile u32 *)(u64)(int)g_base_a = v;
}

// LOAD through a u32 global, widened through a signed int.
// Expected AFTER fix: LOAD 0xFED00010. BEFORE: missed.
__attribute__((noinline)) u32 peek_b(void) {
    return *(volatile u32 *)(u64)(int)g_base_b;
}

// STORE to a compile-time-constant sign-extended address.
// GCC folds (u64)(int)0xFED00020u to the constant
// 0xFFFFFFFFFED00020 (movabs), so the address varnode itself is
// the sign-extended constant -- the fix must handle the constant
// path too, not just the INT_SEXT transfer path.
// Expected AFTER fix: STORE 0xFED00020 val 0x44. BEFORE: missed.
__attribute__((noinline)) void poke_const(u32 v) {
    *(volatile u32 *)(u64)(int)0xFED00020u = v;
}

// STORE through a u32 global, widened through UNSIGNED u64.
// Zero-extension: the address is 0xFED00000 already, no SEXT.
// CONTROL: present AFTER the fix (it was ALSO missed before, by
// the old pointer-sized image read in copyBits -- a 4-byte global
// at the end of .data -- which this slice fixes alongside SEXT).
// Expected: STORE 0xFED00000 val 0x43 after the fix.
__attribute__((noinline)) void poke_zext(u32 v) {
    *(volatile u32 *)(u64)g_base_a = v;
}

// STORE through a GENUINE 64-bit address with meaningful upper
// bits (0x00007F00...). Bit 31 is 1, but bits 63..32 are 0x00007F00,
// NOT all copies of bit 31, so truncation is UNSOUND here.
// NEGATIVE (i): NO finding before AND after.
__attribute__((noinline)) void poke_genuine(u32 v) {
    *(volatile u32 *)0x00007F00FED00000ULL = v;
}

// STORE through a u32 global whose low 32 bits are NOT in any
// band (0x80000000 -> sext 0xFFFFFFFF80000000). Truncation would
// recover 0x80000000, which is still non-MMIO.
// NEGATIVE (ii): NO finding before AND after.
__attribute__((noinline)) void poke_plain32(u32 v) {
    *(volatile u32 *)(u64)(int)g_plain = v;
}

// STORE through a u32 PARAMETER, widened through a signed int.
// Called from main with TWO different addresses, so the v3.9
// all-sites-agree discipline binds nothing: the parameter stays
// unknown, INT_SEXT of unknown stays unknown.
// NEGATIVE (iii): NO store at 0xFED00000 val 0x77, NO store at
// 0xFED00010 val 0x78, before AND after. (A truncation of an
// unknown value would be a guess, and is forbidden.)
__attribute__((noinline)) void poke_param(u32 a, u32 v) {
    *(volatile u32 *)(u64)(int)a = v;
}
