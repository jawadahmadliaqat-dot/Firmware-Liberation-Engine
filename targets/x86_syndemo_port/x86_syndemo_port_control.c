/*
 * x86_syndemo_port_control.c — SYNTHETIC Confinement Demo, SHAPE 2 CONTROL.
 *
 * Identical to x86_syndemo_port.c except the port is 0x3F8 (COM1,
 * inside the architectural allowlist) instead of 0x1234. This control
 * MUST PASS Lean generic mode. If it does not PASS, the Shape 2 FAIL
 * is not attributable to the out-of-allowlist port and the demo is
 * void.
 *
 * Compile: gcc -O1 -fno-optimize-sibling-calls \
 *          -o x86_syndemo_port_control.elf x86_syndemo_port_control.c
 */

__attribute__((noinline)) unsigned char syndemo_ok_port(void) {
    unsigned char v = 0;
    __asm__ volatile(
        "mov $0x3f8, %%edx\n\t"
        "out %%al, %%dx\n\t"
        : "+a"(v)
        :
        : "edx", "memory");
    return v;
}

int main(void) {
    (void)syndemo_ok_port();
    return 0;
}
