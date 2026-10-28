/*
 * x86_syndemo_port.c — SYNTHETIC Confinement Demo, SHAPE 2.
 *
 * PURPOSE-BUILT SYNTHETIC firmware. This is NOT a real firmware and
 * NOT a vulnerability in any real product. It exists only to
 * demonstrate what a Lean generic-mode port/MSR-confinement FAIL looks
 * like when built firmware (not a hand-tampered report) performs port
 * I/O outside the architectural allowlist.
 *
 * The function below performs OUT to port 0x1234. Port 0x1234 is in
 * NO architectural range (not PCI config 0xCF8-0xCFF, not legacy
 * PIC/PIT/DMA/keyboard/CMOS, not COM1-COM4), so Lean generic MUST
 * fail with a confinement-violations line naming exactly 0x1234.
 * Port 0x1234 was previously proven only as a synthetic negative on
 * a tampered report; here it comes from BUILT firmware through the
 * real pipeline. The fixture is never executed — only analyzed.
 *
 * Compile: gcc -O1 -fno-optimize-sibling-calls -o x86_syndemo_port.elf
 *          x86_syndemo_port.c
 * (Pattern follows targets/x86_clobber_test: noinline probe + inline
 * asm port I/O; the OUT stays in its own function for attribution.)
 */

__attribute__((noinline)) unsigned char syndemo_bad_port(void) {
    unsigned char v = 0;
    __asm__ volatile(
        "mov $0x1234, %%edx\n\t"
        "out %%al, %%dx\n\t"
        : "+a"(v)
        :
        : "edx", "memory");
    return v;
}

int main(void) {
    (void)syndemo_bad_port();
    return 0;
}
