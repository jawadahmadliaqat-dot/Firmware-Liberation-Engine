/*
 * Caller-check masking fixture, POSITIVE-CONTROL variant
 * (SYNTHETIC, not real firmware). Own names, slot-buffer driver
 * shape (not fc_signed_mask, not SiM3U, not flash_si32).
 *
 * Shape: identical callee to cm_caller_mask.c (unsound-only copy
 * site, no signed check of its own), but the caller
 * slot_caller_gate() performs a signed check that DOES genuinely
 * gate the call: off < 0 returns before the call, so the call is
 * reached only when off >= 0.
 *
 * Expectation, pre-fix AND post-fix: the callee site reports
 * sound_guard="caller-check", flagged=false, Lean bounds true —
 * a genuinely gating caller check must stay suppressed. If a fix
 * flips this variant, the fix is over-broad.
 *
 * Build (same as the masking variant):
 *   arm-none-eabi-gcc -mcpu=cortex-m4 -mthumb -g -O2 -fno-builtin \
 *       -nostdlib -Ttext=0x08000000 -Wl,-e,main \
 *       -o cm_caller_gate.elf cm_caller_gate.c
 */

volatile int cm_sink;

struct slotbuf {
    char *data;          /* field offset 0: pointer field */
    unsigned int cap;    /* field offset 4: size field */
};

/* Local memcpy so the call resolves to a function named "memcpy"
 * without needing libc (nostdlib build). */
__attribute__((noinline))
void *memcpy(void *d, const void *s, unsigned int n) {
    unsigned char *dd = (unsigned char *)d;
    const unsigned char *ss = (const unsigned char *)s;
    unsigned int i;
    for (i = 0; i < n; i++) dd[i] = ss[i];
    return d;
}

/* Callee: unsound-only guard, NO signed check of its own. */
__attribute__((noinline))
int slot_callee(struct slotbuf *b, int off, char *dst,
                unsigned int len) {
    /* UNSOUND guard: unsigned (off + len) vs b->cap. */
    if ((unsigned int)(off + (int)len) > b->cap) return -1;
    /* Copy site: src = b->data + off = ADD(FIELD, ARG off). */
    memcpy(dst, b->data + off, len);
    return 0;
}

/* Caller: signed check that DOES gate the call. */
__attribute__((noinline))
int slot_caller_gate(struct slotbuf *b, int off, char *dst,
                     unsigned int len) {
    if (off < 0) return -1;
    int r = slot_callee(b, off, dst, len);
    cm_sink = r;
    return r;
}

static char backing[256];
static char out[256];
static struct slotbuf the_buf;

int main(void) {
    the_buf.data = backing;
    the_buf.cap = sizeof(backing);
    slot_caller_gate(&the_buf, 4, out, 16);
    while (1) {
    }
    return 0;
}
