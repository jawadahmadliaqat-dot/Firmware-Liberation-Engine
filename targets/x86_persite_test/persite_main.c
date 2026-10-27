// Callers for per-site transfer tests (x86-64, freestanding).
// Expected results under the sound rules (all helpers noinline,
// in the companion TU, so calls survive exactly as written):
//
//   P1 MMIO-HELPER: poke_addr called with 0xFED00000/0x42 and
//       0xFED00010/0x43 -> 2 MMIO STOREs (merged: 0, the
//       addresses disagree under all-sites-agree).
//   P2 PORT-HELPER: poke_port called with 0xCF8 and 0xCFC ->
//       2 port OUT findings (merged: 0).
//   P3 NESTED: mid_poke called with 0xFED00020/0x44 and
//       0xFED00030/0x45 -> 2 MMIO STOREs via inner_poke
//       (needs L2 clones: mid's clones give inner its sites).
//   P4 BAR-HELPER: bar_poke called with dev31 BAR0 + 0x100 and
//       dev30 BAR0 + 0x100 -> 2 BAR findings, one per device
//       (merged: 0, the BAR symbols disagree).
//   N1 UNKNOWN-SITE: poke_addr called with an unknown address
//       (IN from CFC with NO prior OUT, so the config latch
//       is empty and the read-back value is unknown) and
//       value 0x48 -> NO MMIO finding with value 72, while
//       P1/P2/P3/P4 findings are unaffected. The IN 0xCFC
//       itself IS a genuine port finding (constant port).
//   N2 RECURSION: rec_poke called with 0xFED00070/0x4B and
//       0xFED00078/0x4C (both n==0) -> exactly those 2 MMIO
//       STOREs, no others, and no clone spawned from the
//       recursive inner site (bounded: rec_poke groups == 2).
//   PLAIN: direct STORE 0xFED00090 val 0x55 (keeps the old-code
//       control non-empty and the Lean trace non-empty).
//
// Totals, new code: mmio 7 (P1 2 + P3 2 + N2 2 + PLAIN 1),
// port 3 (P2 2 + N1's IN 0xCFC 1), bar 2 (P4).
// Totals, old code: mmio 1 (PLAIN), port 1 (IN 0xCFC), bar 0.
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

void poke_addr(u64 addr, u64 val);
void poke_port(unsigned short port, u32 val);
void mid_poke(u64 addr, u64 val);
void bar_poke(u64 base, u64 off, u32 val);
void rec_poke(u64 addr, u64 val, u64 n);

void _start(void) {
    // N1 FIRST: IN from CFC with no prior OUT, so the config
    // latch is empty and the value is unknown (not a symbol).
    u32 unk = inl(0xCFC);
    poke_addr((u64)unk, 0x48ULL);

    // P1: MMIO helper, two sites, different addresses.
    poke_addr(0xFED00000ULL, 0x42ULL);
    poke_addr(0xFED00010ULL, 0x43ULL);

    // P2: port helper, two sites, different ports.
    poke_port(0xCF8, 0x11111111U);
    poke_port(0xCFC, 0x22222222U);

    // P3: nested chain, two sites.
    mid_poke(0xFED00020ULL, 0x44ULL);
    mid_poke(0xFED00030ULL, 0x45ULL);

    // P4: BAR helper, two devices, same offset (groups differ
    // ONLY on the base symbol, isolating symbol grouping).
    // PCI config address: 0x80000000 | (bus << 16) |
    // (dev << 11) | (fn << 8) | (reg & 0xFC).
    // dev 31 BAR0 = 0x8000F810, dev 30 BAR0 = 0x8000F010.
    outl(0xCF8, 0x8000F810U);
    u64 bar31 = inl(0xCFC);
    bar31 &= ~0xFULL;
    bar_poke(bar31, 0x100, 0x46U);
    outl(0xCF8, 0x8000F010U);
    u64 bar30 = inl(0xCFC);
    bar30 &= ~0xFULL;
    bar_poke(bar30, 0x100, 0x47U);

    // N2: recursion, two sites, both n==0.
    rec_poke(0xFED00070ULL, 0x4BULL, 0);
    rec_poke(0xFED00078ULL, 0x4CULL, 0);

    // PLAIN: direct MMIO.
    *(volatile u64 *)0xFED00090ULL = 0x55ULL;
    for (;;) { }
}
