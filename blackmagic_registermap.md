# Black Magic Probe v2.0.0 — Register Map (extracted, not assumed)

Source: `blackmagic-native-v2_0_0.elf_report.json` (213 MMIO accesses, 32 distinct registers).
Method: static Ghidra P-Code extraction (ExtractIR v3.1) + CFG fixpoint register tracking.
Register names come from the public STM32F1 reference map (RM0008).

## What changed vs the v3 map (226 accesses, 40 registers)

- `0x4136544A` (LOAD in `renesas_uid`) is GONE — proven cross-branch phantom in
  v3 (the list-order definition gave pool 0x800d890, the path-correct definition
  gives pool 0x800d888). The v3.1 fixpoint drops it. This was the big-pipeline
  step-1 case, now closed.
- 7 more registers dropped because v3.1 is a MUST-analysis: their addresses are
  path-dependent (jump-table dispatch in `rcc_is_osc_ready`/`rcc_osc_on` and
  `remote_packet_process`, predicated-move merges in `aux_serial_init`,
  `platform_nrst_get_val`, `exti15_10_isr`, `st_usbfs_endpoints_reset`). v3
  reported one path's value as if unconditional; v3.1 reports unknown instead.
  Recovering these as MAY-sets (all possible addresses per site) is a future step.
- `platform_nrst_set_val` moved from GPIOC BRR (v3) to GPIOA BSRR (v3.1, value
  exactly 4): v3's value leaked across a RETURN boundary in list order; the
  fixpoint correctly does not propagate past RETURN.
- New in v3.1: a CRC_DR STORE in `stm32_crc32` (v3 saw only the LOAD), and
  recovered jtagtap accesses (GPIOA BSRR/BRR counts grew: 33->44 and 38->45).
- All 213 remaining accesses pass the classifier (0 suspects against the
  STM32F1 profile) and the Lean `bmp` confinement check.

| Peripheral | Register | Address | Stores | Loads | Touched by | Notable exact values |
|---|---|---|---|---|---|---|
| TIM3 | SR | 0x40000410 | 0 | 1 | tim3_isr(1) | - |
| TIM3 | CCR1 | 0x40000434 | 0 | 1 | tim3_isr(1) | - |
| TIM3 | CCR2 | 0x40000438 | 0 | 1 | tim3_isr(1) | - |
| USB | +0x00 | 0x40005c00 | 1 | 1 | st_usbfs_ep_stall_set(2) | - |
| USB | CNTR | 0x40005c40 | 4 | 2 | st_usbfs_poll(4), st_usbfs_v1_usbd_init(2) | 0, 39936 |
| USB | ISTR | 0x40005c44 | 5 | 1 | st_usbfs_poll(5), st_usbfs_v1_usbd_init(1) | 0, 61439, 63487, 64511, 65023 |
| USB | DADDR | 0x40005c4c | 1 | 0 | st_usbfs_set_address(1) | - |
| USB | BTABLE | 0x40005c50 | 1 | 8 | st_usbfs_ep_read_packet(3), st_usbfs_ep_setup(2), st_usbfs_ep_write_packet(2) +2 more | 0 |
| AFIO | MAPR | 0x40010004 | 1 | 1 | gpio_primary_remap(2) | - |
| EXTI | IMR | 0x40010400 | 1 | 1 | exti_enable_request(2) | - |
| EXTI | EMR | 0x40010404 | 1 | 1 | exti_enable_request(2) | - |
| EXTI | RTSR | 0x40010408 | 2 | 3 | exti_set_trigger(5) | - |
| EXTI | FTSR | 0x4001040c | 1 | 2 | exti_set_trigger(3) | - |
| EXTI | PR | 0x40010414 | 1 | 0 | exti_reset_request(1) | - |
| GPIOA | CRL | 0x40010800 | 3 | 3 | swdptap_seq_in(2), swdptap_seq_in_parity(2), swdptap_seq_out(2) | - |
| GPIOA | IDR | 0x40010808 | 0 | 9 | platform_nrst_get_val(2), jtagtap_next(2), jtagtap_tdi_tdo_seq(2) +2 more | - |
| GPIOA | BSRR | 0x40010810 | 44 | 0 | jtagtap_tdi_tdo_seq(6), jtagtap_tdi_seq(6), swdptap_seq_out(6) +12 more | 2, 4, 16, 32, 256, 1024 |
| GPIOA | BRR | 0x40010814 | 45 | 0 | jtagtap_tdi_tdo_seq(9), jtagtap_tdi_seq(8), swdptap_seq_out(6) +9 more | 2, 4, 16, 32, 256, 6144 |
| GPIOB | IDR | 0x40010c08 | 0 | 3 | platform_init(2), platform_target_voltage(1) | - |
| GPIOB | BSRR | 0x40010c10 | 10 | 0 | platform_init(5), main(1), platform_target_set_power(1) +3 more | 2, 4, 96, 128, 224, 1024 |
| GPIOB | BRR | 0x40010c14 | 9 | 0 | main(2), platform_init(2), platform_target_set_power(1) +4 more | 1, 2, 4, 224, 1024, 2048 |
| GPIOC | BSRR | 0x40011010 | 1 | 0 | platform_target_clk_output_enable(1) | 32768 |
| GPIOC | BRR | 0x40011014 | 2 | 0 | platform_target_clk_output_enable(1), platform_init(1) | 32768 |
| ADC1 | SR | 0x40012400 | 2 | 2 | platform_target_voltage_sense(2), sys_tick_handler(2) | - |
| ADC1 | CR2 | 0x40012408 | 1 | 1 | adc_enable_temperature_sensor(2) | - |
| RCC | CFGR | 0x40021004 | 9 | 9 | rcc_set_sysclk_source(2), rcc_set_pll_multiplication_factor(2), rcc_set_pll_source(2) +6 more | - |
| RCC | APB2ENR | 0x40021018 | 0 | 1 | debug_serial_receive_callback(1) | - |
| RCC | APB1ENR | 0x4002101c | 0 | 1 | debug_serial_receive_callback(1) | - |
| RCC | +0x2C | 0x4002102c | 5 | 5 | rcc_set_pll2_multiplication_factor(2), rcc_set_pll3_multiplication_factor(2), rcc_set_prediv1(2) +2 more | - |
| FLASH | ACR | 0x40022000 | 1 | 1 | flash_set_ws(2) | - |
| CRC | DR | 0x40023000 | 1 | 1 | stm32_crc32(2) | - |
| CRC | CR | 0x40023008 | 1 | 1 | stm32_crc32(2) | - |

Total: 32 distinct registers, 213 accesses.
