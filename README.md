# Firmware Liberation Engine — Verifier Pipeline

Take a closed firmware binary, extract **what hardware it really touches**,
and **prove** safety properties about it with Lean 4 — not guesswork, checked
proofs over the extracted facts.

```
firmware.elf ──► Ghidra headless + ExtractIR ──► MMIO JSON ──► Lean 4 checks
```

## What it proves today

- **Extraction**: Ghidra P-Code + a CFG fixpoint register tracker (v3.1)
  resolves ARM MMIO addresses that never appear literally in the code
  (literal-pool load → register → STORE/LOAD). States flow along CFG edges
  and merge on conflict (exact values become unknown, bit masks AND-merge),
  so one branch's value can no longer leak into another branch's access —
  the v3 linear scan was proven to do exactly that on BMP `renesas_uid`.
  Verified 10/10 on a ground-truth STM32F4 blink firmware we built ourselves.
- **MAY-analysis (v3.2)**: a second fixpoint over the same CFG whose join
  is UNION (finite value sets, capped at 16; argument-dependent values are
  TOP and claimed nowhere). A LOAD/STORE the must-analysis drops because
  its address is path-dependent is recorded as a MAY-access with the full
  set of possible MMIO addresses — an audit must know what a driver
  COULD touch, not only what it must touch. On BMP it recovers 8 sites
  (14 addresses), including `aux_serial_init`'s true pair
  {USART1_CR1, USART2_CR1} (v3 claimed USART1 alone) and the
  `platform_nrst_get_val` pair {GPIOA_IDR, GPIOC_IDR}. Jump-table
  (BRANCHIND) blocks stay unreachable — recovering those needs table
  recovery, a separate step.
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
| MMIO accesses extracted | 213 (0 truncated at the 5000-op cap, all functions fixpoint-converged) |
| Driver confinement | **PASS** — jtagtap 56 (GPIO/AFIO only), rcc 28 (RCC only), st_usbfs 24 (USB only), swdptap 37 (GPIOA only), LED 2 (GPIOB only), platform 29 (GPIO/ADC only) |
| MAY-accesses (possible, not certain) | 8 sites, 14 addresses — see the MAY section in the register map |
| MAY confinement (every possible address within its family) | **FLAGS one case**: `rcc_get_usart_clk_freq` may read USART1_CR1 (0x40013800) on one path (the other path reads RAM) — a genuine may-finding, not a must-violation; the profile question (allow it with justification, or keep it flagged) is open |
| Negative tests | Tampered reports **FAIL** as required (confinement violation, mask overlap) |
| Register map | [`blackmagic_registermap.md`](blackmagic_registermap.md) — 32 registers, all labelled from the public STM32F1 map |
| Local-vs-target classifier | [`classify_mmio.py`](classify_mmio.py) + chip profiles — BMP: 213 known / **0 suspects** (v3 had 1: the `renesas_uid` phantom, now eliminated), may addresses 14 known / **0 suspects** |

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

- The resolver is a **path-insensitive must-analysis**: where paths disagree
  on an address, it reports unknown instead of guessing. That costs recall
  on jump-table dispatch (TBB/BRANCHIND has no CFG successors — `rcc_*`
  oscillator polling and parts of `remote_packet_process` are missed) and
  on predicated-move merges. The v3.2 MAY-analysis recovers the
  predicated/branch-merge cases as possible-address sets, but jump-table
  blocks still need table recovery (the next step).
- Checks are **static per-function facts**, not runtime execution order.
- Local vs target separation is v1: the classifier flags addresses outside
  the chip's documented peripheral blocks (BMP now 0 suspects), but deciding
  target-side vs mis-resolution for a flagged address still needs review.
- The confinement profile is **family-observed, not vendor-blessed**: it was
  derived from the must-trace, so a may-finding outside it (currently
  `rcc_get_usart_clk_freq` → USART1) is a question to adjudicate, not an
  automatic bug — widening the profile to silence it without justification
  would be cooking the books.
- No QEMU/angr/HIL in this stage — those belong to the big pipeline.

## Roadmap

Perfect portfolio (this repo + write-up) → big pipeline: register-map
export (done for BMP) → CFG fixpoint resolver (done, v3.1) → local-vs-target
classifier v1 (done) → MAY-analysis (done, v3.2) → jump-table recovery
(BRANCHIND targets) → P-Code→Lean deepening → typestate Rust + Kani →
path pruning → HIL (needs physical hardware) → boot shims (last).
