/*
 * Caller-check masking fixture, MASKING variant (SYNTHETIC, not real
 * firmware). Own names, slot-buffer driver shape (not fc_signed_mask,
 * not SiM3U, not flash_si32).
 *
 * Shape, across the caller-callee boundary:
 *   - Callee slot_callee() holds a genuinely unsound copy site:
 *     memcpy(dst, b->data + off, len) guarded ONLY by the unsigned
 *     (off + len) > b->cap check (wrapping shape). The callee holds
 *     NO signed check of its own, so the site is flagged in the
 *     callee scan and only caller validation can suppress it.
 *   - Caller slot_caller_mask() performs a signed comparison
 *     (off < 0) on the SAME argument it passes through to the
 *     callee, but on a branch that does NOT gate the call: whether
 *     or not off < 0, and whether or not the debug flag is set,
 *     execution always falls through to the call. The check is
 *     recorded (debug-only) but never rejects.
 *
 * Pre-fix expectation (gap, if real): the callee site reports
 * sound_guard="caller-check", flagged=false, Lean bounds true —
 * the non-gating caller check suppresses a whole callee-side site
 * on existence alone.
 * Post-fix expectation: sound_guard="none", flagged=true, Lean
 * bounds false with the violation named.
 *
 * Build (Cortex-M4, -O2 needed: -O0 spills args to the stack,
 * which the extractor does not track; memcpy/callee/caller kept
 * noinline so calls resolve by name):
 *   arm-none-eabi-gcc -mcpu=cortex-m4 -mthumb -g -O2 -fno-builtin \
 *       -nostdlib -Ttext=0x08000000 -Wl,-e,main \
 *       -o cm_caller_mask.elf cm_caller_mask.c
 */

volatile int cm_sink;
volatile int cm_debug = 1;

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
    /* UNSOUND guard: unsigned (off + len) vs b->cap. A negative
     * off wraps the unsigned sum past the size, so this check
     * cannot reject it. */
    if ((unsigned int)(off + (int)len) > b->cap) return -1;
    /* Copy site: src = b->data + off = ADD(FIELD, ARG off). */
    memcpy(dst, b->data + off, len);
    return 0;
}

/* Caller: signed check that does NOT gate the call. Both the
 * debug-flag branch and the off < 0 branch fall through to the
 * call regardless of outcome; a negative off is recorded but
 * NOT rejected here. The same off argument is passed through
 * unchanged to the callee. */
__attribute__((noinline))
int slot_caller_mask(struct slotbuf *b, int off, char *dst,
                     unsigned int len) {
    if (cm_debug) {
        if (off < 0) {
            cm_sink = off;
        }
    }
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
    slot_caller_mask(&the_buf, 4, out, 16);
    while (1) {
    }
    return 0;
}
