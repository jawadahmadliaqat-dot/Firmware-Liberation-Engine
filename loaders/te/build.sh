#!/usr/bin/env bash
# Builds the TeLoader Ghidra extension and installs it into the Ghidra
# installation's Extensions directory, where analyzeHeadless picks it up.
#
# Usage:
#   GHIDRA_HOME=/opt/ghidra JAVA_HOME=~/workspace/tools/jdk/jdk-21.0.13+9 bash build.sh
# Defaults: GHIDRA_HOME=/opt/ghidra, JAVA_HOME=$JAVA_HOME or `java` on PATH.
# Requires JDK 21 (Ghidra 11.4.2). The install target is wiped on VM restart
# together with /opt/ghidra itself — just re-run this script after reinstalling
# Ghidra (see firmware_workspace/reinstall_ghidra.sh, then this script).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
# Resolve symlinks: /opt/ghidra is typically a symlink to the versioned dir,
# and `find` (default -P) will not descend into a symlink given as its start
# point, which would silently produce an empty classpath.
GHIDRA_HOME="$(readlink -f "${GHIDRA_HOME:-/opt/ghidra}")"
JAVA_HOME="${JAVA_HOME:-$(dirname "$(dirname "$(readlink -f "$(command -v java)")")")}"
JAVAC="$JAVA_HOME/bin/javac"
JAR="$JAVA_HOME/bin/jar"

if [ ! -d "$GHIDRA_HOME/Ghidra" ]; then
	echo "ERROR: Ghidra not found at $GHIDRA_HOME (expected \$GHIDRA_HOME/Ghidra)" >&2
	exit 1
fi
if [ ! -x "$JAVAC" ]; then
	echo "ERROR: javac not found at $JAVAC — set JAVA_HOME to a JDK 21 install" >&2
	exit 1
fi

CP="$(find "$GHIDRA_HOME" -name '*.jar' | tr '\n' ':')"
WORK="$SCRIPT_DIR/.build"
rm -rf "$WORK"
mkdir -p "$WORK/classes" "$WORK/lib"

echo "[*] Compiling TeLoader.java ..."
"$JAVAC" -proc:none -cp "$CP" -d "$WORK/classes" "$SCRIPT_DIR/TeLoader.java"

echo "[*] Packaging lib/TeLoader.jar ..."
(cd "$WORK/classes" && "$JAR" cf "$WORK/lib/TeLoader.jar" .)

DEST="$GHIDRA_HOME/Ghidra/Extensions/TeLoader"
mkdir -p "$DEST/lib"
cp "$WORK/lib/TeLoader.jar" "$DEST/lib/TeLoader.jar"
cp "$SCRIPT_DIR/extension.properties" "$DEST/extension.properties"
# Module.manifest (may be empty) marks the directory as a Ghidra module;
# without it, Ghidra skips the directory during extension discovery.
cp "$SCRIPT_DIR/Module.manifest" "$DEST/Module.manifest"

echo "[+] Installed to $DEST"
echo "    Verify: analyzeHeadless <projdir> <proj> -import <file.te> -overwrite"
echo "    (the log must NOT say 'No load spec found for import file')"
