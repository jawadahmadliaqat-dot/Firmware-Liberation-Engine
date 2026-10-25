# Firmware Liberation Engine — Verifier Pipeline

Take a closed firmware binary, extract **what hardware it really touches**,
and **prove** safety properties about it with Lean 4 — not guesswork, checked
proofs over the extracted facts.

```
firmware.elf ──► Ghidra headless + ExtractIR ──► MMIO JSON ──► Lean 4 checks
```

## What it proves today

- **Extraction**: Ghidra P-Code + a linear register-value tracker resolves
  ARM MMIO addresses that never appear literally in the code (literal-pool
  load → register → STORE/LOAD). Verified 10/10 on a ground-truth STM32F4
  blink firmware we built ourselves.
- **Value export (v3)**: every MMIO access carries `value` (exact or null)
  plus `value_known_ones` / `value_known_zeroes` bit masks, so
  read-modify-write stores still yield provable bit effects.
- **Lean checks** (`lean/` Lake project, exe `ingest_check`):
  - `blink` — clock+mode before LED, LED bit decided, clock bit set,
    mode clear-then-set (theorem version: `Verifier/BlinkProof.lean`)
  - `generic` — trace non-empty, masks consistent, all addresses in the
    MMIO window
  - `bmp` — **driver confinement**: each driver family touches only its
    own peripherals (see below)

## Real-firmware result: Black Magic Probe v2.0.0

`blackmagic-native-v2_0_0.elf` (1.23 MB, ARM, 1034 functions) through the
full pipeline under a 512 MB Ghidra heap:

| Check | Result |
|---|---|
| MMIO accesses extracted | 226 (0 truncated at the 5000-op cap) |
| Driver confinement | **PASS** — jtagtap 38 (GPIO/AFIO only), rcc 45 (RCC only), st_usbfs 26 (USB only), swdptap 37 (GPIOA only), LED 2 (GPIOB only), platform 31 (GPIO/ADC only) |
| Negative tests | Tampered reports **FAIL** as required (confinement violation, mask overlap) |
| Register map | [`blackmagic_registermap.md`](blackmagic_registermap.md) — 40 registers, 39 labelled from the public STM32F1 map |

## Quickstart (any Linux box)

```bash
./setup.sh                                   # JDK + Ghidra + Lean
python3 ingest_and_analyze.py targets/stm32_blink/stm32_blink.elf --no-upload
cd lean && lake exe ingest_check ../analysis_reports/stm32_blink.elf_report.json
```

Drive mode (optional): pass a binary *name* instead of a path and it syncs
via `rclone` (`gdrive:Firmware_DataLake/...`); `--no-upload` skips the
upload. `FIRMWARE_WORKSPACE` and `GHIDRA_HEADLESS` env vars override paths.

## Honest limits

- The resolver is a **linear last-definition-wins scan** — fine for `-O0`,
  may mis-resolve optimized/obfuscated code. Fix planned: High P-Code (SSA).
- Checks are **static per-function facts**, not runtime execution order.
- The extractor does not yet separate **local vs target-side addresses**
  (e.g. `renesas_uid` passes a Renesas target address through probe code).
- No QEMU/angr/HIL in this stage — those belong to the big pipeline.

## Roadmap

Perfect portfolio (this repo + write-up) → big pipeline: register-map
export (done for BMP) → P-Code→Lean deepening → typestate Rust + Kani →
path pruning → HIL (needs physical hardware) → boot shims (last).
