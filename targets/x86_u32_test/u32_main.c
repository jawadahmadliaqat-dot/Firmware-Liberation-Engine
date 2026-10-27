// Callers for the u32/INT_SEXT MMIO gap (x86-64, dynamic link).
// Expected results AFTER the fix:
//   SEXT-STORE: STORE 0xFED00000 val 0x42 (poke_a, INT_SEXT path)
//   ZEXT-CTRL:  STORE 0xFED00000 val 0x43 (poke_zext, before AND after)
//   CONST:      STORE 0xFED00020 val 0x44 (poke_const, constant path)
//   SEXT-LOAD:  LOAD 0xFED00010 (peek_b, INT_SEXT path)
//   PLAIN-1:    STORE 0xFED00030 value null (plain u64 literal, before AND after)
//   PLAIN-2:    STORE 0xFED00098 val 0x55 (plain u64 literal, before AND after)
// Expected BEFORE the fix: only the 2 plain findings
// (PLAIN-1, PLAIN-2). The SEXT/CONST findings are missed (the
// SEXT result is out of band), AND the ZEXT control is missed too
// (the 4-byte global load at the end of .data fails the old
// pointer-sized image read) -- both are fixed by this slice.
// Negatives, absent before AND after:
//   NO store through 0x00007F00FED00000 (genuine 64-bit, upper bits
//     are meaningful, not sign copies)
//   NO store at 0x80000000 / 0xFFFFFFFF80000000 (sext, not in band)
//   NO store at 0xFED00000 val 0x77, NO store at 0xFED00010 val 0x78
//     (parameter unknown: two disagreeing call sites)
typedef unsigned int u32;
typedef unsigned long long u64;

void poke_a(u32 v);
u32 peek_b(void);
void poke_const(u32 v);
void poke_zext(u32 v);
void poke_genuine(u32 v);
void poke_plain32(u32 v);
void poke_param(u32 a, u32 v);

int main(int argc, char **argv) {
    (void)argc;
    (void)argv;
    poke_a(0x42);
    poke_zext(0x43);
    poke_const(0x44);
    u32 x = peek_b();
    *(volatile u32 *)0xFED00030ULL = x;
    *(volatile u32 *)0xFED00098ULL = 0x55;
    poke_genuine(0x56);
    poke_plain32(0x66);
    // Disagreeing sites: constprop binds nothing for poke_param's
    // address parameter, so it stays unknown.
    poke_param(0xFED00000u, 0x77);
    poke_param(0xFED00010u, 0x78);
    return 0;
}
