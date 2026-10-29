#!/usr/bin/env bash
# Reinstall Ghidra + JDK 21 after a VM restart (/opt and apt packages are ephemeral).
# The Ghidra zip lives in persistent storage, so no re-download is needed.
#
# HARDENING (Oct 29, 2026 drift): NEVER trust "launcher exists" as proof of
# a good install. A partial tree can run analyzeHeadless while silently
# missing an analyzer (Decompiler Switch Analysis did not run on Oct 29;
# switch cases were orphaned; must counts dropped with NO error). So this
# script VERIFIES the tree (verify_ghidra_tree.sh) on EVERY run: if the
# tree verifies, the unzip is skipped; if not, a fresh unzip is forced,
# the TE loader is rebuilt, the tree is re-verified, and the x86_blink
# canary (must read 11) runs as a post-reinstall smoke check. Any failure
# exits non-zero LOUDLY — never warn-and-continue past a bad install.
#
# Env overrides (for testing): GHIDRA_DIR (default /opt/ghidra),
# GHIDRA_ZIP (default the persistent 11.4.2 zip), SKIP_CANARY=1.
set -e
WS="$(cd "$(dirname "$0")" && pwd)"
GHIDRA_DIR="${GHIDRA_DIR:-/opt/ghidra}"
GHIDRA_ZIP="${GHIDRA_ZIP:-$HOME/workspace/tools/ghidra/ghidra_11.4.2_PUBLIC_20250826.zip}"
case "$GHIDRA_DIR" in /opt/*) SUDO="sudo";; *) SUDO="";; esac

# JDK: apt first (as before); on failure warn and continue — the Temurin
# tarball in ~/workspace/tools/jdk/ and the regress scripts' JAVA_HOME
# cover JDK, and a failed apt must not block the Ghidra repair.
$SUDO DEBIAN_FRONTEND=noninteractive apt-get install -y -qq openjdk-21-jdk \
  || echo "WARN: apt JDK install failed; continuing with java on PATH / Temurin."
java -version 2>&1 | head -1

if "$WS/verify_ghidra_tree.sh" "$GHIDRA_DIR"; then
  echo "Ghidra tree verified intact — skipping unzip."
else
  echo "Ghidra tree missing or incomplete — forcing fresh install from $GHIDRA_ZIP ..."
  PARENT="$(dirname "$GHIDRA_DIR")"
  EXTRACTED="$PARENT/ghidra_11.4.2_PUBLIC"
  $SUDO rm -rf "$GHIDRA_DIR" "$EXTRACTED"
  $SUDO unzip -q -o "$GHIDRA_ZIP" -d "$PARENT/"
  $SUDO mv "$EXTRACTED" "$GHIDRA_DIR"
  # Keep the 512M heap permanent: fresh installs default to 2G, which
  # OOM-crashes this VM (no swap, ~490MB free). Env MAXMEM alone does
  # NOT override the file.
  $SUDO sed -i 's/^MAXMEM=2G/MAXMEM=512M/' "$GHIDRA_DIR/support/analyzeHeadless"
  grep -n "^MAXMEM" "$GHIDRA_DIR/support/analyzeHeadless"
  # TE loader lives inside the Ghidra tree, so a fresh unzip wipes it;
  # rebuild it or .te targets (QemuVideoDxe.te) cannot be imported.
  if [ -f "$WS/loaders/te/build.sh" ]; then
    TE_JAVA_HOME="$JAVA_HOME"
    if [ -z "$TE_JAVA_HOME" ] && [ -d "$HOME/workspace/tools/jdk/jdk-21.0.13+9" ]; then
      TE_JAVA_HOME="$HOME/workspace/tools/jdk/jdk-21.0.13+9"
    fi
    echo "Rebuilding TE loader into $GHIDRA_DIR ..."
    GHIDRA_HOME="$GHIDRA_DIR" JAVA_HOME="$TE_JAVA_HOME" bash "$WS/loaders/te/build.sh"
  else
    echo "ERROR: loaders/te/build.sh not found — cannot rebuild TE loader." >&2
    exit 1
  fi
  # Re-verify the fresh tree before trusting it.
  "$WS/verify_ghidra_tree.sh" "$GHIDRA_DIR" \
    || { echo "ERROR: fresh Ghidra install FAILED verification — aborting." >&2; exit 1; }
fi

ls -lh "$GHIDRA_DIR/support/analyzeHeadless"
if [ "${SKIP_CANARY:-0}" != "1" ]; then
  echo "Running post-reinstall canary (x86_blink must read 11) ..."
  FIRMWARE_WORKSPACE="$WS" bash "$WS/canary_x86_blink.sh" \
    || { echo "ERROR: canary FAILED after reinstall — install not trusted." >&2; exit 1; }
fi
echo "Ghidra reinstall complete and verified."
