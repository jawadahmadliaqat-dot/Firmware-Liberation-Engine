/*
 * Finding C signed-masking fixture (SYNTHETIC, not real firmware).
 * Own names, slot-buffer driver shape (not SiM3U, not flash_si32).
 *
 * Shape: a memcpy copy site whose src is ADD(struct-field,
 * function-argument offset), guarded ONLY by an unsound unsigned
 * (offset + size) > FIELD(size) check (the wrapping shape), plus
 * an UNRELATED signed comparison on the same offset argument,
 * placed BEFORE the copy in listing order, on a branch that does
 * NOT gate the copy (a debug-only branch that falls through to
 * the copy regardless of the comparison's outcome).
 *
 * Pre-fix expectation (false negative): the site reports
 * sound_guard="signed-check", flagged=false, Lean bounds true.
 * Post-fix expectation: sound_guard="none", flagged=true, Lean
 * bounds false with the violation named.
 *
 * Build (Cortex-M4, -O2 needed: -O0 spills args to the stack,
 * which the extractor does not track; memcpy kept noinline so
 * the call resolves to a function named "memcpy"):
 *   arm-none-eabi-gcc -mcpu=cortex-m4 -mthumb -g -O2 -fno-builtin \
 *       -nostdlib -Ttext=0x08000000 -Wl,-e,main \
 *       -o fc_signed_mask.elf fc_signed_mask.c
 */

volatile int fc_sink;

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

__attribute__((noinline))
int slot_copy(struct slotbuf *b, int off, char *dst, unsigned int len,
              int debug) {
    /* UNRELATED signed check on the SAME offset argument, BEFORE
     * the copy in listing order, on a branch that does NOT gate
     * the copy: whether or not off < 0, and whether or not debug
     * is set, execution always falls through to the unsound
     * check + copy below. A negative off is recorded but NOT
     * rejected here. */
    if (debug) {
        if (off < 0) {
            fc_sink = off;
        }
    }
    /* UNSOUND guard: unsigned (off + len) vs b->cap. A negative
     * off wraps the unsigned sum past the size, so this check
     * cannot reject it. */
    if ((unsigned int)(off + (int)len) > b->cap) return -1;
    /* Copy site: src = b->data + off = ADD(FIELD, ARG off). */
    memcpy(dst, b->data + off, len);
    return 0;
}

static char backing[256];
static char out[256];
static struct slotbuf the_buf;

int main(void) {
    the_buf.data = backing;
    the_buf.cap = sizeof(backing);
    slot_copy(&the_buf, 4, out, 16, 1);
    while (1) {
    }
    return 0;
}
