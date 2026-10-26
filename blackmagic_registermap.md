# Black Magic Probe v2.0.0 — Register Map (extracted, not assumed)

Source: `blackmagic-native-v2_0_0.elf_report.json` (235 MMIO accesses, 35 distinct registers).
Method: static Ghidra P-Code extraction (ExtractIR v3.3) + CFG fixpoint register tracking.
Register names come from the public STM32F1 reference map (RM0008).

## What changed in v3.3 (TBB/TBH jump-table recovery)

- Must-accesses grew 213 -> 235 (0 dropped, 0 may-sites changed): the
  recovered TBB/TBH case blocks restored `rcc_is_osc_ready` (7 accesses:
  RCC CR/BDCR/CSR), `rcc_osc_on` (9), and `remote_packet_process`'s 5
  GPIOB stores, plus 19 jtagtap accesses v3's list-order scan had
  missed. 35 distinct registers (was 32): RCC CR, BDCR, CSR return.
- vs the original v3 (226): 15 claims are still absent, all explained
  -- 6 converted to honest MAY-accesses (one-sided v3 claims),
  1 phantom (`renesas_uid`) correctly gone, 1 v3 error corrected
  (`platform_nrst_set_val` GPIOC BRR -> GPIOA BSRR), and 7
  argument-dependent addresses that are TOP in both analyses
  (`exti_select_source` AFIO EXTICR1, `jtagtap_cycle` AFIO EVCR,
  `st_usbfs_endpoints_reset` USB+0x04).

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
| USB | ISTR | 0x40005c44 | 5 | 1 | st_usbfs_poll(5), st_usbfs_v1_usbd_init(1) | 0, 64511, 63487, 61439, 65023 |
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
| GPIOA | BSRR | 0x40010810 | 44 | 0 | jtagtap_tdi_tdo_seq(6), jtagtap_tdi_seq(6), swdptap_seq_out(6) +12 more | 32×18, 16×11, 2×4, 4, 256, 1024 |
| GPIOA | BRR | 0x40010814 | 45 | 0 | jtagtap_tdi_tdo_seq(9), jtagtap_tdi_seq(8), swdptap_seq_out(6) +9 more | 32×22, 16×12, 4, 6144, 256, 2 |
| GPIOB | IDR | 0x40010c08 | 0 | 3 | platform_init(2), platform_target_voltage(1) | - |
| GPIOB | BSRR | 0x40010c10 | 12 | 0 | platform_init(5), remote_packet_process(2), main(1) +4 more | 2×4, 1024×3, 96, 128, 224, 4 |
| GPIOB | BRR | 0x40010c14 | 12 | 0 | remote_packet_process(3), main(2), platform_init(2) +5 more | 1024×5, 2×2, 4096, 224, 1, 4 |
| GPIOC | BSRR | 0x40011010 | 1 | 0 | platform_target_clk_output_enable(1) | 32768 |
| GPIOC | BRR | 0x40011014 | 2 | 0 | platform_target_clk_output_enable(1), platform_init(1) | 32768×2 |
| ADC1 | SR | 0x40012400 | 2 | 2 | platform_target_voltage_sense(2), sys_tick_handler(2) | - |
| ADC1 | CR2 | 0x40012408 | 1 | 1 | adc_enable_temperature_sensor(2) | - |
| RCC | CR | 0x40021000 | 1 | 10 | rcc_osc_on(6), rcc_is_osc_ready(5) | - |
| RCC | CFGR | 0x40021004 | 9 | 9 | rcc_set_sysclk_source(2), rcc_set_pll_multiplication_factor(2), rcc_set_pll_source(2) +6 more | - |
| RCC | APB2ENR | 0x40021018 | 0 | 1 | debug_serial_receive_callback(1) | - |
| RCC | APB1ENR | 0x4002101c | 0 | 1 | debug_serial_receive_callback(1) | - |
| RCC | BDCR | 0x40021020 | 1 | 2 | rcc_osc_on(2), rcc_is_osc_ready(1) | - |
| RCC | CSR | 0x40021024 | 1 | 2 | rcc_osc_on(2), rcc_is_osc_ready(1) | - |
| RCC | +0x2C | 0x4002102c | 5 | 5 | rcc_set_pll2_multiplication_factor(2), rcc_set_pll3_multiplication_factor(2), rcc_set_prediv1(2) +2 more | - |
| FLASH | ACR | 0x40022000 | 1 | 1 | flash_set_ws(2) | - |
| CRC | DR | 0x40023000 | 1 | 1 | stm32_crc32(2) | - |
| CRC | CR | 0x40023008 | 1 | 1 | stm32_crc32(2) | - |

## MAY-accesses (v3.2): possible, not certain

Sites the must-analysis drops (path-dependent address) with a finite set
of possible MMIO addresses. The other path in each case reads RAM or
another listed address; jump-table (BRANCHIND) sites are NOT recovered
here. Verified against the ELF literal-pool words.

| Function | Instr | Op | Possible addresses |
|---|---|---|---|
| platform_nrst_get_val | 08015aca | LOAD | GPIOA IDR 0x40010808, GPIOC IDR 0x40011008 |
| platform_target_get_power | 08015b02 | LOAD | GPIOB IDR 0x40010c08 (other path: RAM) |
| exti15_10_isr | 08015e34 | LOAD | GPIOA IDR 0x40010808, GPIOB IDR 0x40010c08 |
| platform_init | 08016082 | STORE | GPIOA BSRR 0x40010810, GPIOB BSRR 0x40010c10 |
| platform_init | 080160d0 | STORE | GPIOA BSRR 0x40010810, GPIOC BRR 0x40011010 |
| aux_serial_init | 08016388 | LOAD | USART2 CR1 0x4000440c, USART1 CR1 0x4001380c |
| aux_serial_init | 08016396 | STORE | USART2 CR1 0x4000440c, USART1 CR1 0x4001380c |
| rcc_get_usart_clk_freq | 08018456 | LOAD | USART1 CR1 0x40013800 (other path: RAM) |

Note: `rcc_get_usart_clk_freq` → USART1 is the single may-confinement
flag (the rcc_ family is profiled RCC-only); adjudication open.

Total: 35 distinct registers, 235 accesses.
