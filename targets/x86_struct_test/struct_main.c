// Callers for STRUCT return summaries (x86-64, dynamic link).
// Expected results under the sound rules (all helpers noinline,
// in the companion TU, so calls survive exactly as written):
//   A:  STORE 0xFED00000 val 0xA1 (a->regs, device A only)
//   B:  STORE 0xFED00010 val 0xA2 (b->regs, device B only)
//   NO-LEAK: no STORE 0xFED00000 val 0xA2, no STORE 0xFED00010
//           val 0xA1 (devices must not leak into each other)
//   PCI: BAR-relative STORE bar0 offset 0x100 val 0x4C
//           (p->regs is the BASE symbol from make_pci_dev)
//   PARTIAL-CTRL: STORE 0xFED00090 val 0x44 (q->ctrl, always set)
//   PARTIAL-NO: NO store at 0xFED00050 (q->regs set on one path
//           only, so the field is unknown in the caller)
//   GLOBAL: STORE 0xFED000A0 val 0xA4 (g->regs via image bytes;
//           no object summary, no confusion with fresh objects)
//   REC-NO: NO store at 0xFED00000 val 0xA5 (make_rec's RETURNs
//           disagree, so no summary, never the A device's regs)
//   LOOP-NO: NO store at 0xFED00000 val 0xA6 (the loop call site
//           may produce many objects, so no summary is installed
//           there -- documented conservative limitation)
//   WRAP: STORE 0xFED00000 val 0xA7 (w->regs through the wrapper;
//           needs a second summary round)
//   PLAIN: STORE 0xFED00098 val 0x55 (keeps the Lean trace
//           non-empty; BAR findings stay out of the trace)
typedef unsigned int u32;
typedef unsigned long long u64;

struct Dev {
    u64 regs;
    u64 val;
    u64 ctrl;
};

struct Dev *make_dev_a(void);
struct Dev *make_dev_b(void);
struct Dev *make_pci_dev(void);
struct Dev *make_partial(int c);
struct Dev *make_global_dev(void);
struct Dev *make_rec(int n);
struct Dev *make_wrap(void);

int main(int argc, char **argv) {
    (void)argv;
    struct Dev *a = make_dev_a();
    struct Dev *b = make_dev_b();
    *(volatile u64 *)a->regs = 0xA1ULL;
    *(volatile u64 *)b->regs = 0xA2ULL;

    struct Dev *p = make_pci_dev();
    *(volatile u32 *)(p->regs + 0x100) = 0x4C;

    struct Dev *q = make_partial(1);
    *(volatile u64 *)q->regs = 0xA3ULL;
    *(volatile u64 *)0xFED00090ULL = q->ctrl;

    struct Dev *g = make_global_dev();
    *(volatile u64 *)g->regs = 0xA4ULL;

    struct Dev *r = make_rec(0);
    *(volatile u64 *)r->regs = 0xA5ULL;

    struct Dev *w = make_wrap();
    *(volatile u64 *)w->regs = 0xA7ULL;

    int i;
    for (i = 0; i < argc; i++) {
        struct Dev *L = make_dev_a();
        *(volatile u64 *)L->regs = 0xA6ULL;
    }

    *(volatile u64 *)0xFED00098ULL = 0x55ULL;
    return 0;
}
