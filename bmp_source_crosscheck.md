# BMP source cross-check — v3.5 may-sets vs v2.0.0 source ground truth

Date: 2026-10-26. Report: v3.5-pointsto
(`blackmagic-native-v2_0_0.elf_report.json`, 40,307,721 bytes).
Source: `blackmagic-debug/blackmagic` ref `v2.0.0`
(commit `1b3607bb7ac914cf608c7fe3de00798e40b2da07`), cloned locally.
Method: source truth = every `->field = func` / `.field = func`
assignment in `src/`, restricted to functions present in the binary
(hosted-only assignments — dap/ftdi/jlink/remote — drop out automatically).
Symbol anchors from the ELF: `jtag_proc` = `0x2000193c`,
`swd_proc` = `0x2000195c` (both `.bss`, confirming the RAM-struct model).

## Headline

- **Singletons: 44/44 EXACT, 0 mismatches.** Every one-target may-set
  names the true function for that call.
- **Field truth coverage: 99/116 (85%).** Every source-truth target
  function appears in at least one may-set, except 17 misses in three
  explained classes (below).
- **The open Lean may-confinement FAIL is a FALSE POSITIVE.**
  `rcc_get_usart_clk_freq` does not read USART1_CR1 (see §4).
  The profile stays strict; no widening needed. Adjudication: RESOLVED
  by measurement, not by policy.
- **Must side spot-check: clean.** `jtagtap_next`'s 9 accesses map
  exactly to GPIOA IDR/BSRR/BRR; `rcc_osc_on`'s map to RCC_CR/BDCR.

## 1. Singletons — 44/44 exact

38 proc/target singletons verified against their field truth, plus 6
DP-`abort` singletons (`adiv5_jtag_abort`) verified against
`adiv5_jtag.c:57` (`dp->abort = adiv5_jtag_abort`) and its call site at
`adiv5_jtag.c:146` (`dp->abort(dp, ADIV5_DP_ABORT_DAPABORT)`).

Why the proc-op singletons are exact, not lucky: this binary links ONE
platform. `jtag_proc.jtagtap_next` is assigned in 6 places in source,
but 5 are hosted-platform code (dap/ftdi/jlink/remote) that is not in
this binary; the only linked implementation is `jtagtap_next`
(`platforms/common/jtagtap.c:119`, assigned at `:47`). The store map
found exactly that one. Example: `cmd_tdi_low_reset` → `jtagtap_next`
matches `command.c:503-510` (`jtag_proc.jtagtap_next(true, false)`).

## 2. Field coverage — 99/116

| field family | covered / truth | misses |
|---|---|---|
| attach | 15/16 | `lpc43x0_attach` |
| detach | 11/12 | `lpc43x0_detach` |
| check_error, mem_read/write, regs_*, reg_*, breakwatch_* | all 1/1 or 2/2 | — |
| reset | 0/2 | `cortexm_reset`, `samd_reset` |
| extended_reset | 4/4 | — |
| halt_request / halt_poll / halt_resume | 0/1, 0/1, 0/2 | `cortexm_halt_request`, `cortexm_halt_poll`, `cortexm_halt_resume`, `samd20_revB_halt_resume` |
| mass_erase | 19/21 | `kinetis_mdm_mass_erase`, `nrf54l_ctrl_ap_mass_erase` |
| enter_flash_mode | 12/13 | `target_enter_flash_mode_stub` |
| exit_flash_mode | 8/8 | — |
| jtagtap_* (6), swd seq_* (4) | all 1/1 | — |
| DP write/read_no_check, dp_read | 0/1, 0/1, 0/2 | `adiv5_swd_write_no_check`, `adiv5_swd_read_no_check`, `adiv5_jtag_read`, `adiv5_swd_read` |
| DP error / abort | 1/2, 1/2 | `adiv5_swd_clear_error`, `adiv5_swd_abort` |
| DP low_access, ap_read/write | all 2/2 | — |

## 3. The 17 misses — three explained classes

### (a) Tail calls — 6 misses (systematic blind spot, v3.6 direction)

`target_reset`, `target_halt_request`, `target_halt_poll`,
`target_halt_resume` contain ZERO `CALLIND`s in the report
(16/16/17/16 pcode ops, 1 `BRANCHIND` each). The source dispatch
(`target.c:393`: `if (target->reset) target->reset(target)`) compiles
to a **tail call** (`bx`, modelled as `BRANCHIND`), not a `CALLIND`.
v3.5 only recovers `CALLIND`s, so the whole reset/halt family is
invisible. Fix direction (v3.6): run the same points-to resolution on
`BRANCHIND`s whose destination resolves to function entries via the
store map, and keep same-function destinations as CFG successors.

### (b) Store-visibility gap — 11 misses

`lpc43x0_attach/detach`, the DP init stores (`write_no_check`,
`read_no_check`, `dp_read`, `swd_clear_error`, `swd_abort`),
`kinetis_mdm_mass_erase`, `nrf54l_ctrl_ap_mass_erase`,
`target_enter_flash_mode_stub`. Evidence: the function-pointer
literals ARE in the image (e.g. `lpc43x0_attach` literal
`0x0800a3f9` at `.text` `0x0800a9bc`; DP literals at `0x080041c4`,
`0x08005b54`), but NO function in the report loads from them, and
there are ZERO pc-relative `LOAD`s anywhere in the report. So the
stores live outside Ghidra's recognized function pcodes — a
disassembly-coverage gap, not a resolver gap. Fix direction: a
whole-image literal scan as a supplementary store source
(every `.text` word that equals a function entry is a candidate
stored pointer; attribute it by the nearest store site).

Note the consequence for swd-path sites: `adiv5_swd_raw_access`'s
abort site resolves to `adiv5_jtag_abort` only — `swd_abort` is missing
from the set, so swd-path abort sets are currently INCOMPLETE
(sound for jtag DPs, incomplete for swd DPs).

### (c) — (b) includes the stub

The stub is the default no-op assigned by drivers without flash mode
(`efm32.c:959`, `kinetis.c:572`, `lpc55xx.c:623`, `nrf51.c:426`).
Missing it costs nothing semantically (it does nothing), but it is
counted honestly here.

## 4. rcc may-flag — FALSE POSITIVE (adjudication resolved)

The Lean may-confinement FAIL was `rcc_get_usart_clk_freq` may-reading
USART1_CR1 (`0x40013800`). Verification against the binary:

- The flagged `LOAD` is at `08018456`. Its address chain is
  `COPY [ram 0x08018460]` (eq path) or `COPY [ram 0x08018464]`
  (ne path), then `LOAD [that + 0]`.
- The literals at those addresses, read from the ELF, are
  `0x20001108` and `0x2000110c` — RAM variables (the
  `rcc_apb2_frequency` / `rcc_apb1_frequency` globals), NOT USART1.
- So the true behavior is a RAM read. The may-analysis's
  `0x40013800` does not come from this chain.
  (Hypothesis, not verified: the may value-set propagation leaks the
  `usart == USART1_BASE` comparison constant into the redefined return
  register across the predicated `ldr.eq`/`ldr.ne` copies — the fix is
  to audit may value-set killing for predicated defs.)

Current upstream libopencm3's f1 `rcc_get_usart_clk_freq` also reads
only those globals, consistent with this finding; the binary's pinned
version evidently behaves the same. **The Lean FAIL is a tool artifact.
The profile stays strict. No adjudication decision is needed anymore.**

## 5. Must-access spot check

- `jtagtap_next` (9 accesses): `0x40010810` STORE (GPIOA BSRR, set),
  `0x40010814` STORE (GPIOA BRR, clear), `0x40010808` LOAD
  (GPIOA IDR, TDO read) — exactly the STM32F1 GPIO map for the
  platform's JTAG pins, matching `platforms/common/jtagtap.c`.
- `rcc_osc_on` (10 accesses): `0x40021000` (RCC_CR),
  `0x40021020` (RCC_BDCR) — oscillator control, as expected.
- Top must-functions (`jtagtap_tdi_tdo_seq` 17, `jtagtap_tdi_seq` 14,
  `swdptap_seq_out` 14, `swdptap_seq_in` 11) all touch only the same
  GPIOA registers. No suspect address among them
  (classifier: 235 known / 0 suspects, unchanged).

## 6. The 19 unresolved — classified, none are tool failures

- libc/stdio internals (8): `_printf_common` (3), `_printf_i` (2),
  `__sflush_r`, `_fwalk_sglue`, `_raise_r` (the `0x16` constant —
  not a function at all).
- Parameter callbacks (7): `sfdp_read_parameters` (3, SFDP parser
  callbacks), `bmp_spi_read_status`, `usb_control_request_dispatch`,
  `usb_standard_set_interface`, `target_breakwatch_set`.
- Vector-table dispatch (3): `reset_handler`.
- Register-indexed dispatch (1): `st_usbfs_poll` (`[reg + reg]`).

None of the 19 is a BMP driver op the tool should have resolved.

## 7. Pollution, quantified honestly

99/159 may-sites are fully within field truth. The rest carry the
known same-offset merge (one field offset shared by several structs —
e.g. `spi_run_command` functions inside attach-family sets). The 16
libc targets (`__sread`/`__swrite`/`__sseek`) inside stdio sites are
TRUE targets for those sites (newlib FILE struct fields), not
pollution — the field-truth table above simply does not cover libc.

## 8. Limits of this check

- Truth is restricted to binary-present functions; a source-assigned
  function that the linker dropped is not counted as a miss.
- `mem_read`/`mem_write` truth merges target_s and DP fields
  (same name, different structs) — per-field numbers for those two
  are family-level, not struct-level.
- Must side is a spot check (top functions + `jtagtap_next` +
  `rcc_osc_on`), not a full 235-access audit; blink 10/10 remains the
  must ground truth.
- The may-FP mechanism (§4) is a hypothesis; the FP itself
  (literals are RAM, not USART1) is verified from the ELF.

## Next (proposed, not started)

- v3.6: tail-call (`BRANCHIND`) recovery + whole-image literal scan
  as a supplementary store source. Both are now evidence-backed,
  not speculative.
- Fix the may value-set killing for predicated defs (§4 hypothesis).
