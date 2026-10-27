/* Synthetic ACPI MCFG carrier: table bytes live in .rodata. */
const unsigned char mcfg_table[] = {77, 67, 70, 71, 61, 0, 0, 0, 1, 166, 84, 69, 83, 84, 32, 32, 84, 69, 83, 84, 77, 67, 70, 71, 1, 0, 0, 0, 84, 69, 83, 84, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 224, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0};
int main(void) { return mcfg_table[0]; }
