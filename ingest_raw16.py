#!/usr/bin/env python3
"""Raw-binary 16-bit real-mode import path (Phase 3 backlog item 6).

Usage:
  python3 ingest_raw16.py <raw.bin> <base-hex-no-0x, e.g. 7c00> <output.json>
      [--mmio=<bands>] [--project-name=<name>]

Contract (fail-closed):
  * The input is a RAW binary (no ELF/PE headers) containing 16-bit
    real-mode CODE whose entry point is the first byte, loaded at the
    given linear base address (e.g. 7c00 for an MBR-style image).
  * The import pins Ghidra to language x86:LE:16:Real Mode and the
    BinaryLoader with that base address. Nothing is auto-detected:
    a file the loader cannot place, or a program that yields no
    entry function, is a LOUD FAILURE (non-zero exit), never a
    vacuous empty report passed off as success.
  * Protected Mode is NOT accepted here: its segment userop is
    (selector << 16) + offset, which is not a physical address
    without a GDT, so the segmented adapter does not apply to it.
  * Data-only binaries must NOT be fed through this path: the
    entry-function contract treats the first block as code. A
    block that disassembles to zero instructions fails loudly.
  * This wrapper never touches the ELF pipeline
    (ingest_and_analyze.py) and never uploads anything.

Exit codes: 0 = report written and verified; 1 = usage/validation
error; 2 = Ghidra import/analysis failure or unverified report.
"""
import datetime
import json
import os
import subprocess
import sys

WS = os.environ.get("FIRMWARE_WORKSPACE", "/home/hatch/firmware_workspace")
GHIDRA_HEADLESS = os.environ.get(
    "GHIDRA_HEADLESS", "/opt/ghidra/support/analyzeHeadless")
LANGUAGE = "x86:LE:16:Real Mode"


def fail(msg, code=2):
    print(f"[!] ingest_raw16 FAILED: {msg}", file=sys.stderr)
    sys.exit(code)


def main(argv):
    args = [a for a in argv if not a.startswith("--mmio=")]
    mmio = None
    project_name = "Raw16_Project"
    for a in argv:
        if a.startswith("--mmio="):
            mmio = a
        elif a.startswith("--project-name="):
            project_name = a.split("=", 1)[1]
    if len(args) != 3:
        print(__doc__)
        sys.exit(1)
    raw_path, base_hex, out_path = args
    if not os.path.isfile(raw_path):
        fail(f"input file not found: {raw_path}", code=1)
    if os.path.getsize(raw_path) == 0:
        fail("input file is empty", code=1)
    try:
        base = int(base_hex, 16)
    except ValueError:
        fail(f"base address must be hex without 0x (got {base_hex!r})",
             code=1)
    if base < 0 or base > 0x10FFEF:
        fail(f"base address out of the 21-bit real-mode space: "
             f"{base_hex}", code=1)
    # Normalise (a leading 0x is tolerated on input but never
    # passed to the loader: its baseAddr form forbids 0x).
    base_hex = format(base, "x")
    if not os.path.isdir(WS):
        fail(f"firmware workspace not found: {WS}", code=1)

    java_home = os.environ.get("JAVA_HOME", "")
    if not java_home and os.path.isdir(
            os.path.expanduser("~/workspace/tools/jdk/jdk-21.0.13+9")):
        java_home = os.path.expanduser(
            "~/workspace/tools/jdk/jdk-21.0.13+9")
    env = os.environ.copy()
    if java_home:
        env["JAVA_HOME"] = java_home
        env["PATH"] = java_home + "/bin:" + env.get("PATH", "")
    env["MAXMEM"] = "512M"

    log_dir = os.path.join(WS, "headless_logs")
    os.makedirs(log_dir, exist_ok=True)
    stamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
    log_path = os.path.join(
        log_dir, f"raw16_{os.path.basename(raw_path)}_{stamp}.log")

    post_args = [os.path.join(WS, "ExtractIR.java"), out_path]
    if mmio:
        post_args.append(mmio)
    cmd = [
        GHIDRA_HEADLESS,
        os.path.join(WS, "projects"),
        project_name,
        "-import", os.path.abspath(raw_path),
        "-processor", LANGUAGE,
        "-loader", "BinaryLoader",
        "-loader-baseAddr", f"ram:{base_hex}",
        "-scriptPath", WS,
        "-postScript",
    ] + post_args + ["-overwrite"]
    print(f"[*] ingest_raw16: {raw_path} base=ram:{base_hex} "
          f"language={LANGUAGE}")
    try:
        proc = subprocess.run(cmd, env=env, capture_output=True,
                              text=True, timeout=300)
    except subprocess.TimeoutExpired:
        fail("Ghidra headless timed out after 300s")
    with open(log_path, "w") as f:
        f.write("=== STDOUT ===\n")
        f.write(proc.stdout or "")
        f.write("\n=== STDERR ===\n")
        f.write(proc.stderr or "")
    print(f"[*] Full headless log saved to {log_path}")
    tail = (proc.stdout or "")[-500:]
    print(tail)

    # ---- Fail-closed verification (never trust the wrapper) ----
    blob = (proc.stdout or "") + (proc.stderr or "")
    if "Import failed" in blob or "could not successfully load" in blob:
        fail("Ghidra import failed (see headless log)")
    if not os.path.isfile(out_path):
        fail(f"no report written at {out_path}")
    try:
        with open(out_path) as f:
            rep = json.load(f)
    except Exception as e:
        fail(f"report at {out_path} is not valid JSON: {e}")
    if rep.get("language") != LANGUAGE:
        fail(f"report language is {rep.get('language')!r}, "
             f"expected {LANGUAGE!r}")
    if rep.get("extractor_version") != "v3.23":
        fail(f"unexpected extractor_version: "
             f"{rep.get('extractor_version')!r}")
    if not rep.get("function_count"):
        fail("entry function was not created: the binary did not "
             "disassemble as code at the given base (data-only "
             "binaries must not use this path)")
    if "segmented adapter active" not in blob:
        fail("segmented-adapter line missing from headless log; "
             "the extractor did not run in Real-Mode adapter mode")
    print(f"[+] ingest_raw16 OK: {rep.get('function_count')} function(s), "
          f"mmio={rep.get('mmio_access_total')} "
          f"may={rep.get('may_access_total')} "
          f"ports={rep.get('port_io_access_total')} "
          f"msr={rep.get('msr_access_total')}")
    print(f"[+] Report: {out_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
