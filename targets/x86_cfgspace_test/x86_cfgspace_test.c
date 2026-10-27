// Freestanding x86-64 test firmware for config-space-read value
// tracking (symbolic BAR sources). The source is the map the
// extractor's output is spot-checked against. All helpers are
// noinline so the call graph is exactly what the source shows.
//
// PCI config address format (mechanism 1):
//   0x80000000 | (bus << 16) | (dev << 11) | (fn << 8) | (reg & 0xFC)
// Device under test: bus 0, dev 31, fn 0  ->  BAR0 = 0x8000F810,
// BAR1 = 0x8000F814. BAR registers are 0x10..0x24 step 4.
//
// Expected results under the sound rules:
//   bar_use (BAR0 + 0x100 STORE)  -> BAR-relative finding
//       {bus 0, dev 31, fn 0, bar 0, offset 0x100, size 4}
//   bar_load (BAR0 + 0x200 LOAD)  -> BAR-relative finding
//       {bus 0, dev 31, fn 0, bar 0, offset 0x200, size 4}
//   bar1_use (BAR1 + 0x40 STORE)  -> BAR-relative finding
//       {bus 0, dev 31, fn 0, bar 1, offset 0x40, size 4}
//   plain_mmio (exact 0xFED00000)  -> plain MMIO STORE (keeps the
//       Lean trace non-empty, proving Lean ignores the additive
//       bar_relative class: generic must still PASS)
//   unmasked_use (BAR0, NO mask)  -> NO finding (raw BAR symbols
//       never yield findings; only masked BASE symbols do)
//   var_offset_use (BAR0 + variable offset) -> NO finding
//       (offset not constant -> symbol dropped)
//   sizing_use (OUT CFC 0xFFFFFFFF then IN CFC) -> NO finding
//       (a CFC write dirties the config address; the read-back is
//       a size mask, not a BAR base)
//   param_cfg (helper, config address from a parameter loaded
//       from MMIO = unknown) -> NO finding (config address unknown)
//   NOTE: BAR symbols do not cross function boundaries in this
//   slice (return values are unknown after CALL), so a helper that
//   reads a BAR and returns it yields no symbol in the caller;
//   that needs return-value propagation (a later slice).
typedef unsigned char u8;
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

/* Config address comes from a parameter: with an unknown argument
   the OUT value is unknown, so no config address is ever known
   inside this helper and no symbol can form. */
__attribute__((noinline)) void param_cfg(u32 cfgaddr) {
    outl(0xCF8, cfgaddr);
    u32 bar = inl(0xCFC);
    bar &= ~0xFU;
    *(volatile u32 *)(u64)(bar + 0x100) = 0x77U;
}

void _start(void) {
    /* Positive 1: BAR0 + 0x100 STORE. u64 bar forces 64-bit flow
       (32-bit addressing would sign-extend and drop the symbol,
       the known u32 gap -- same reason the constprop test uses
       distinct u64 constants). */
    outl(0xCF8, 0x8000F810U);
    u64 bar0 = inl(0xCFC);
    bar0 &= ~0xFULL;
    *(volatile u32 *)(bar0 + 0x100) = 0x1234U;
    /* Positive 2: BAR0 + 0x200 LOAD. */
    outl(0xCF8, 0x8000F810U);
    u64 bar0b = inl(0xCFC);
    bar0b &= ~0xFULL;
    volatile u32 sink = *(volatile u32 *)(bar0b + 0x200);
    (void)sink;
    /* Positive 3: BAR1 + 0x40 STORE (proves the BAR index is
       tracked, not just BAR0). */
    outl(0xCF8, 0x8000F814U);
    u64 bar1 = inl(0xCFC);
    bar1 &= ~0xFULL;
    *(volatile u32 *)(bar1 + 0x40) = 0x5678U;
    /* Plain exact MMIO (keeps the Lean trace non-empty). */
    *(volatile u32 *)0xFED00000ULL = 0x55U;
    /* Negative: unmasked BAR use -> NO finding. */
    outl(0xCF8, 0x8000F810U);
    u64 raw = inl(0xCFC);
    *(volatile u32 *)(raw + 0x100) = 0x99U;
    /* Negative: variable offset -> NO finding. */
    outl(0xCF8, 0x8000F810U);
    u64 barv = inl(0xCFC);
    barv &= ~0xFULL;
    u64 off = *(volatile u64 *)0xFED00000ULL;
    *(volatile u32 *)(barv + off) = 0xAAU;
    /* Negative: BAR sizing (write all-ones, read back size). */
    outl(0xCF8, 0x8000F810U);
    outl(0xCFC, 0xFFFFFFFFU);
    u64 sized = inl(0xCFC);
    sized &= ~0xFULL;
    *(volatile u32 *)(sized + 0x100) = 0xBBU;
    /* Negative: parameter config address (unknown). */
    param_cfg(*(volatile u32 *)0xFED00000ULL);
    for (;;) { }
}
