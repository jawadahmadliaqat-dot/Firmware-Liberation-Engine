// Callers for return-value propagation tests (x86-64, freestanding).
// Expected results under the sound rules (all helpers noinline, in
// the companion TU, so calls survive exactly as written):
//   CONST:  STORE 0xFED00000 val 0x42 (ret_const_addr)
//   NESTED: STORE 0xFED00080 val 0x43 (ret_nested -> ret_const_addr2,
//           needs a second summary round)
//   ARG-AGREE: two STOREs 0xFED00020 val 0x44 / 0x45 (ret_id, both
//           sites pass the same address, so sites agree)
//   ARG-DISAGREE: NO stores at 0xFED00030 / 0xFED00040 (ret_id2,
//           sites disagree -> no summary, never one of them)
//   ARG-OFFSET: two STOREs 0xFED00010 val 0x48 / 0x49 (ret_add,
//           both sites pass 0xFED00000, +0x10 transfer)
//   PATHVAR: NO store at 0xFED00050 / 0xFED00060 (ret_pathvar
//           returns different constants on different paths)
//   RECURSION: NO store at 0xFED00070 (ret_rec; a recursive
//           summary must never be guessed)
//   BAR-SYM: BAR-relative STORE bar0 offset 0x100 val 0x4C
//           (ret_bar returns the masked BASE symbol)
//   BAR-SYM+ADD: BAR-relative STORE bar0 offset 0x110 val 0x4D
//           (ret_add_sym(ret_bar()) + 0x100: ARG transfer applied
//           to a symbol argument, then a constant offset)
//   PLAIN: STORE 0xFED00090 val 0x55 (keeps the Lean trace
//           non-empty; BAR findings stay out of the trace)
typedef unsigned int u32;
typedef unsigned long long u64;

u64 ret_const_addr(void);
u64 ret_const_addr2(void);
u64 ret_nested(void);
u64 ret_id(u64 x);
u64 ret_id2(u64 x);
u64 ret_add(u64 x);
u64 ret_add_sym(u64 x);
u64 ret_pathvar(u64 x);
u64 ret_rec(u64 n);
u64 ret_bar(void);

void _start(void) {
    *(volatile u64 *)ret_const_addr() = 0x42ULL;
    *(volatile u64 *)ret_nested() = 0x43ULL;
    *(volatile u64 *)ret_id(0xFED00020ULL) = 0x44ULL;
    *(volatile u64 *)ret_id(0xFED00020ULL) = 0x45ULL;
    *(volatile u64 *)ret_id2(0xFED00030ULL) = 0x46ULL;
    *(volatile u64 *)ret_id2(0xFED00040ULL) = 0x47ULL;
    *(volatile u64 *)ret_add(0xFED00000ULL) = 0x48ULL;
    *(volatile u64 *)ret_add(0xFED00000ULL) = 0x49ULL;
    *(volatile u64 *)ret_pathvar(1) = 0x4AULL;
    *(volatile u64 *)ret_rec(0) = 0x4BULL;
    *(volatile u32 *)(ret_bar() + 0x100) = 0x4C;
    *(volatile u32 *)(ret_add_sym(ret_bar()) + 0x100) = 0x4D;
    *(volatile u64 *)0xFED00090ULL = 0x55ULL;
    for (;;) { }
}
