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
grep -n "^MAXMEM" /opt/ghidra/support/analyzeHeadless

# --- Lean 4.35.0 via elan (elan.lean-lang.org 404s; GitHub raw script works) ---
if [ ! -x "$HOME/.elan/bin/lean" ]; then
  curl -sSfL https://raw.githubusercontent.com/leanprover/elan/master/elan-init.sh | sh -s -- -y --default-toolchain leanprover/lean4:v4.35.0
fi
export PATH="$HOME/.elan/bin:$PATH"
lean --version
lake --version
echo "Setup complete. Next: python3 ingest_and_analyze.py <firmware.elf> --no-upload"
