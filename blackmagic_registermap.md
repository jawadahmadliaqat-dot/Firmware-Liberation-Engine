# Black Magic Probe v2.0.0 — Register Map (extracted, not assumed)

Source: `blackmagic-native-v2_0_0.elf_report.json` (226 MMIO accesses, 65 functions).
Method: static Ghidra P-Code extraction (ExtractIR v3) + linear register tracking.
Register names come from the public STM32F1 reference map (RM0008); offsets
not in that map are marked UNKNOWN — the address itself is still exact.

NOTE: `0x4136544A` (LOAD in `renesas_uid`) is a TARGET-side Renesas UID
address, not local STM32 MMIO — probe firmware passes target addresses through
the same code paths. The extractor does not yet separate local vs target
addresses; that classification is a big-pipeline upgrade (needs data-flow context).

| Peripheral | Register | Address | Stores | Loads | Touched by | Notable exact values |
|---|---|---|---|---|---|---|
| ADC1 | SR | 0x40012400 | 2 | 2 | platform_target_voltage_sense(2), sys_tick_handler(2) | - |
| ADC1 | CR2 | 0x40012408 | 1 | 1 | adc_enable_temperature_sensor(2) | - |
| AFIO | EVCR | 0x40010000 | 0 | 1 | jtagtap_cycle(1) | - |
| AFIO | MAPR | 0x40010004 | 1 | 1 | gpio_primary_remap(2) | - |
| AFIO | EXTICR1 | 0x40010008 | 1 | 1 | exti_select_source(2) | - |
| CRC | DR | 0x40023000 | 0 | 1 | stm32_crc32(1) | - |
| CRC | CR | 0x40023008 | 1 | 1 | stm32_crc32(2) | - |
| EXTI | IMR | 0x40010400 | 1 | 1 | exti_enable_request(2) | - |
| EXTI | EMR | 0x40010404 | 1 | 1 | exti_enable_request(2) | - |
| EXTI | RTSR | 0x40010408 | 2 | 3 | exti_set_trigger(5) | - |
| EXTI | FTSR | 0x4001040C | 1 | 2 | exti_set_trigger(3) | - |
| EXTI | PR | 0x40010414 | 1 | 0 | exti_reset_request(1) | - |
| FLASH | ACR | 0x40022000 | 1 | 1 | flash_set_ws(2) | - |
| GPIOA | CRL | 0x40010800 | 3 | 3 | swdptap_seq_in(2), swdptap_seq_in_parity(2), swdptap_seq_out(2) | - |
| GPIOA | IDR | 0x40010808 | 0 | 9 | platform_nrst_get_val(3), swdptap_seq_in(2), exti15_10_isr(1) | - |
| GPIOA | BSRR | 0x40010810 | 33 | 0 | swdptap_seq_out(6), jtagtap_tms_seq(5), jtagtap_next(3) | 32, 16, 2 |
| GPIOA | BRR | 0x40010814 | 38 | 0 | jtagtap_tdi_seq(8), jtagtap_tdi_tdo_seq(6), swdptap_seq_out(6) | 32, 16, 8 |
| GPIOB | IDR | 0x40010C08 | 0 | 4 | platform_init(2), platform_target_get_power(1), platform_target_voltage(1) | - |
| GPIOB | BSRR | 0x40010C10 | 13 | 0 | platform_init(6), remote_packet_process(2), main(1) | 2, 1024, 8192 |
| GPIOB | BRR | 0x40010C14 | 12 | 0 | remote_packet_process(3), main(2), platform_init(2) | 1024, 2, 4096 |
| GPIOC | BSRR | 0x40011010 | 2 | 0 | platform_nrst_set_val(1), platform_target_clk_output_enable(1) | 4, 32768 |
| GPIOC | BRR | 0x40011014 | 1 | 0 | platform_init(1) | 32768 |
| RCC | CR | 0x40021000 | 1 | 10 | rcc_osc_on(6), rcc_is_osc_ready(5) | - |
| RCC | CFGR | 0x40021004 | 9 | 9 | rcc_set_sysclk_source(2), rcc_set_pll_multiplication_factor(2), rcc_set_pll_source(2) | - |
| RCC | APB2ENR | 0x40021018 | 0 | 1 | debug_serial_receive_callback(1) | - |
| RCC | APB1ENR | 0x4002101C | 0 | 1 | debug_serial_receive_callback(1) | - |
| RCC | BDCR | 0x40021020 | 1 | 2 | rcc_osc_on(2), rcc_is_osc_ready(1) | - |
| RCC | CSR | 0x40021024 | 1 | 2 | rcc_osc_on(2), rcc_is_osc_ready(1) | - |
| RCC | +0x2C | 0x4002102C | 5 | 5 | rcc_set_pll2_multiplication_factor(2), rcc_set_pll3_multiplication_factor(2), rcc_set_prediv1(2) | - |
| TIM3 | SR | 0x40000410 | 0 | 1 | tim3_isr(1) | - |
| TIM3 | CCR1 | 0x40000434 | 0 | 1 | tim3_isr(1) | - |
| TIM3 | CCR2 | 0x40000438 | 0 | 1 | tim3_isr(1) | - |
| UNKNOWN | +0x04A | 0x4136544A | 0 | 1 | renesas_uid(1) | - |
| USART1 | CR1 | 0x4001380C | 1 | 1 | aux_serial_init(2) | - |
| USB | +0x00 | 0x40005C00 | 1 | 1 | st_usbfs_ep_stall_set(2) | - |
| USB | +0x04 | 0x40005C04 | 2 | 2 | st_usbfs_endpoints_reset(4) | - |
| USB | CNTR | 0x40005C40 | 3 | 1 | st_usbfs_v1_usbd_init(2), st_usbfs_poll(2) | 0, 39936 |
| USB | ISTR | 0x40005C44 | 5 | 1 | st_usbfs_poll(5), st_usbfs_v1_usbd_init(1) | 0, 64511, 63487 |
| USB | DADDR | 0x40005C4C | 1 | 0 | st_usbfs_set_address(1) | - |
| USB | BTABLE | 0x40005C50 | 1 | 8 | st_usbfs_ep_read_packet(3), st_usbfs_ep_setup(2), st_usbfs_ep_write_packet(2) | 0 |

Total: 40 distinct registers, 226 accesses.