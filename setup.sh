#!/usr/bin/env bash
# Public setup for the Firmware Liberation Engine (verifier pipeline).
# Installs: JDK 21, Ghidra 11.4.2 (512M heap patch), Lean 4.35.0 via elan.
# Run as root or with sudo. Tested on Ubuntu 24.04; paths are overridable:
#   FIRMWARE_WORKSPACE=/path/to/work ./setup.sh
set -e
export DEBIAN_FRONTEND=noninteractive
sudo apt-get update -qq
sudo apt-get install -y -qq openjdk-21-jdk unzip curl git

# --- Ghidra ---
if [ ! -x /opt/ghidra/support/analyzeHeadless ]; then
  if [ -f ~/workspace/tools/ghidra/ghidra_11.4.2_PUBLIC_20250826.zip ]; then
    sudo unzip -q -o ~/workspace/tools/ghidra/ghidra_11.4.2_PUBLIC_20250826.zip -d /opt/
  else
    cd /tmp
    curl -L -o ghidra.zip https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_11.4.2_build/ghidra_11.4.2_PUBLIC_20250826.zip
    sudo unzip -q -o ghidra.zip -d /opt/
  fi
  sudo mv /opt/ghidra_11.4.2_PUBLIC /opt/ghidra
fi
# analyzeHeadless hardcodes MAXMEM; the env var alone does NOT override it.
# 512M keeps small VMs alive (no swap). Bigger machines can raise this.
sudo sed -i 's/^MAXMEM=2G/MAXMEM=512M/' /opt/ghidra/support/analyzeHeadless || true
grep -q '^MAXMEM=512M' /opt/ghidra/support/analyzeHeadless || {
  echo "SETUP FAILED: analyzeHeadless MAXMEM is not 512M after patching." >&2
  exit 1
}

# Hardening (Oct 29, 2026): a launcher-exists check CANNOT catch a
# partial tree — a fresh install once ran analyzeHeadless fine while
# silently missing Decompiler Switch Analysis, and extraction numbers
# dropped with no error anywhere. So setup NEVER trusts the launcher
# alone: it always verifies the tree AND runs the x86_blink canary,
# and FAILS LOUDLY (non-zero exit, no "Setup complete") if either fails.
# (The install block above is unchanged; verification runs whether the
# install was skipped or performed, because a pre-existing launcher
# proves nothing about tree completeness.)
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
export FIRMWARE_WORKSPACE="${FIRMWARE_WORKSPACE:-$SCRIPT_DIR}"
# TE loader lives inside the Ghidra tree and verify_ghidra_tree.sh requires
# it: build it BEFORE verifying, or verification always fails on a fresh
# install (setup.sh previously never installed it; only reinstall did).
if [ -f "$SCRIPT_DIR/loaders/te/build.sh" ]; then
  GHIDRA_HOME=/opt/ghidra bash "$SCRIPT_DIR/loaders/te/build.sh" || exit 1
fi
if ! "$SCRIPT_DIR/verify_ghidra_tree.sh" /opt/ghidra; then
  echo "SETUP FAILED: Ghidra tree verification failed — this install is incomplete and its analysis cannot be trusted." >&2
  echo "  Delete /opt/ghidra and re-run setup.sh, or run reinstall_ghidra.sh, then re-run setup.sh." >&2
  exit 1
fi
if ! "$SCRIPT_DIR/canary_x86_blink.sh"; then
  echo "SETUP FAILED: x86_blink canary failed — this Ghidra install does not reproduce the expected 11 mmio accesses." >&2
  echo "  Do NOT trust analysis from it. Delete /opt/ghidra and re-run setup.sh, or run reinstall_ghidra.sh." >&2
  exit 1
fi

# --- Lean 4.35.0 via elan (elan.lean-lang.org 404s; GitHub raw script works) ---
if [ ! -x "$HOME/.elan/bin/lean" ]; then
  curl -sSfL https://raw.githubusercontent.com/leanprover/elan/master/elan-init.sh | sh -s -- -y --default-toolchain leanprover/lean4:v4.35.0
fi
export PATH="$HOME/.elan/bin:$PATH"
lean --version
lake --version
echo "Setup complete. Next: python3 ingest_and_analyze.py <firmware.elf> --no-upload"
