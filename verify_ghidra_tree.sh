#!/usr/bin/env bash
# Verify a Ghidra install is COMPLETE for the firmware pipeline.
# Lesson (Oct 29, 2026 drift): a partial install can run analyzeHeadless
# fine while silently missing an analyzer — Decompiler Switch Analysis did
# not run, switch-case blocks were orphaned, and must counts dropped on
# switch-heavy targets only, with NO error anywhere. A launcher-exists
# check cannot catch that; this file/class check can.
#
# Usage: verify_ghidra_tree.sh [GHIDRA_DIR]   (default: $GHIDRA_DIR or /opt/ghidra)
# Exit 0 iff every check passes; otherwise exit 1 with FAIL lines.
# Cheap: file-existence + jar-content checks only, no JVM launch.
set -u
DIR="${1:-${GHIDRA_DIR:-/opt/ghidra}}"
FAIL=0
check() { # check <label> <test-command...>
  local label="$1"; shift
  if "$@" >/dev/null 2>&1; then echo "PASS: $label"; else echo "FAIL: $label"; FAIL=1; fi
}
jar_has() { # jar_has <jar> <class-substring>
  unzip -l "$1" 2>/dev/null | grep -q "$2"
}
echo "Verifying Ghidra tree at $DIR ..."
check "analyzeHeadless launcher executable" test -x "$DIR/support/analyzeHeadless"
check "analyzeHeadless MAXMEM patched to 512M (2G OOM-crashes this VM)" \
  grep -q '^MAXMEM=512M' "$DIR/support/analyzeHeadless"
check "Decompiler.jar present" test -f "$DIR/Ghidra/Features/Decompiler/lib/Decompiler.jar"
check "DecompilerSwitchAnalyzer class in Decompiler.jar (the Oct 29 miss)" \
  jar_has "$DIR/Ghidra/Features/Decompiler/lib/Decompiler.jar" 'DecompilerSwitchAnalyzer\.class'
check "SwitchAnalysisDecompileConfigurer class in Decompiler.jar" \
  jar_has "$DIR/Ghidra/Features/Decompiler/lib/Decompiler.jar" 'SwitchAnalysisDecompileConfigurer\.class'
check "DecompilerSwitchAnalysisCmd class in Decompiler.jar" \
  jar_has "$DIR/Ghidra/Features/Decompiler/lib/Decompiler.jar" 'DecompilerSwitchAnalysisCmd\.class'
check "Base.jar present" test -f "$DIR/Ghidra/Features/Base/lib/Base.jar"
check "Framework jars present (Generic.jar)" test -f "$DIR/Ghidra/Framework/Generic/lib/Generic.jar"
check "TE loader extension present (needed for QemuVideoDxe.te)" \
  test -f "$DIR/Ghidra/Extensions/TeLoader/lib/TeLoader.jar"
check "TE loader extension.properties present" \
  test -f "$DIR/Ghidra/Extensions/TeLoader/extension.properties"
check "TE loader Module.manifest present" \
  test -f "$DIR/Ghidra/Extensions/TeLoader/Module.manifest"
if [ "$FAIL" -eq 0 ]; then
  echo "VERIFICATION PASSED: $DIR is complete for the pipeline."
  exit 0
else
  echo "VERIFICATION FAILED: $DIR is incomplete — do NOT trust analysis from it." >&2
  exit 1
fi
