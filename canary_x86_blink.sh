#!/usr/bin/env bash
# Post-reinstall smoke check: x86_blink MUST read 11 mmio accesses.
# This is the cheapest detector of the Oct 29 failure mode (Decompiler
# Switch Analysis silently absent -> switch cases orphaned -> 11 drops
# to 5). FAILS LOUDLY (non-zero exit, expected-vs-got message) on any
# mismatch — never warn-and-continue.
#
# Usage: canary_x86_blink.sh
# Env: GHIDRA_HEADLESS (passed through to ingest), JAVA_HOME (Temurin
# preferred, as in the regress scripts). Expects x86_blink.elf in
# regress/ (staged copy) or binaries/.
set -u
WS="${FIRMWARE_WORKSPACE:-/home/hatch/firmware_workspace}"
if [ -d ~/workspace/tools/jdk/jdk-21.0.13+9 ]; then
  export JAVA_HOME=~/workspace/tools/jdk/jdk-21.0.13+9
  export PATH="$JAVA_HOME/bin:$PATH"
fi
BIN=""
if [ -f "$WS/regress/x86_blink.elf" ]; then BIN="$WS/regress/x86_blink.elf";
elif [ -f "$WS/binaries/x86_blink.elf" ]; then BIN="$WS/binaries/x86_blink.elf";
elif [ -f "$WS/targets/x86_blink/x86_blink.elf.b64" ]; then
  # Decode to regress/, NOT binaries/: the ingest wrapper copies its input
  # into binaries/ itself, and decoding straight to binaries/ makes it crash
  # with SameFileError (proven by the scratch fresh-clone test, 2026-10-31).
  mkdir -p "$WS/regress"
  base64 -d "$WS/targets/x86_blink/x86_blink.elf.b64" > "$WS/regress/x86_blink.elf"
  BIN="$WS/regress/x86_blink.elf";
else echo "CANARY FAILED: x86_blink.elf not found in regress/, binaries/, or targets/x86_blink/x86_blink.elf.b64" >&2; exit 1; fi
mkdir -p "$WS/headless_logs"
LOG="$WS/headless_logs/canary_x86_blink_$(date +%Y%m%d-%H%M%S).log"
cd "$WS" || exit 1
REP="$WS/analysis_reports/x86_blink.elf_report.json"
# Remove any stale report first: the ingest wrapper returns success even
# when Ghidra fails, so a stale good report would otherwise mask a bad run.
rm -f "$REP"
python3 ingest_and_analyze.py "$BIN" --no-upload > "$LOG" 2>&1
if [ ! -f "$REP" ]; then
  echo "CANARY FAILED: no report at $REP (see $LOG)" >&2; exit 1
fi
GOT=$(python3 -c "import json;print(json.load(open('$REP')).get('mmio_access_total'))" 2>/dev/null)
if [ "$GOT" = "11" ]; then
  echo "CANARY PASSED: x86_blink mmio = 11 (expected 11). Log: $LOG"
  exit 0
else
  echo "CANARY FAILED: x86_blink mmio expected 11, got ${GOT:-<unreadable>}." >&2
  echo "  This is the Oct 29 signature of Decompiler Switch Analysis not running." >&2
  echo "  Do NOT trust this Ghidra install — reinstall and re-verify. Report: $REP, log: $LOG" >&2
  exit 1
fi
