#!/usr/bin/env python3
"""Generate a firmware_manifest.json (AmbientOS Layer 3 contract) from a
firmware-engine report JSON. Reads existing reports only — it does NOT
change the extractor, the report shape, or any engine CLI.

Honesty rules (enforced mechanically, not by convention):
  1. Verified ranges come ONLY from MUST accesses in the report, mapped
     through the chip profile's blocks. A must access outside every
     profile block FAILS the run (never silently dropped).
  2. MAY accesses are NEVER included (may_access_total is reported, not used).
  3. A manifest is emitted ONLY if Lean generic mode PASSES on the report
     (the script runs `lake exe ingest_check <report> generic` itself and
     refuses on any other verdict). The verdict lines are embedded.
  4. Forbidden ranges must not overlap any verified range (address or
     name — the trust layer traps a verified peripheral whose name is
     forbidden). Overlap FAILS the run. In particular, a block the
     firmware legitimately uses (e.g. BMP's FLASH wait-state config)
     can NEVER be listed as forbidden.
  5. sha256_hash is computed from the actual firmware binary file, and
     the report's binary_name must match the file's basename.
  6. formal_proof_status states EXACTLY what Lean proved (generic PASS
     lines), never "fully certified". The verifier's .olean build
     artifacts are NOT firmware proof certificates and are never cited.

Manifest range ends are INCLUSIVE (trust-layer `contains` is
start <= addr <= end), so a profile half-open block [start, end)
becomes [start, end-1] in the manifest.

Usage:
  python3 manifest_gen.py --report <report.json> --profile <profile.json> \
    --binary <firmware.elf> --arch ARM_CORTEX_M3 \
    [--name-map GPIOB=GPIOB_LED] \
    [--forbid FLASH_CONTROLLER:0x40023C00:0x40023FFF] \
    --out <firmware_manifest.json>
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
from collections import Counter, defaultdict

LEAN_DIR = os.path.expanduser("~/firmware_workspace/lean")
REPO_ROOT = os.path.dirname(os.path.abspath(__file__))


def repo_rel(p: str) -> str:
    """Repo-relative path for provenance (no local absolute home paths
    leaking into published manifests)."""
    return os.path.relpath(os.path.abspath(p), REPO_ROOT)


def fail(msg: str) -> None:
    print(f"manifest_gen: ERROR: {msg}", file=sys.stderr)
    sys.exit(1)


def parse_int(s: str) -> int:
    return int(str(s), 0)


def run_lean_generic(report_path: str) -> list[str]:
    """Run the verifier's generic mode on the report; return verdict lines.
    Refuses (exit) unless VERDICT: PASS is present."""
    env = dict(os.environ)
    elan = os.path.expanduser("~/.elan/bin")
    env["PATH"] = elan + os.pathsep + env.get("PATH", "")
    try:
        proc = subprocess.run(
            ["lake", "exe", "ingest_check", report_path, "generic"],
            cwd=LEAN_DIR, env=env, capture_output=True, text=True, timeout=300,
        )
    except FileNotFoundError:
        fail("lake not found (Lean toolchain missing from ~/.elan/bin)")
    out = proc.stdout + proc.stderr
    lines = [ln.strip() for ln in out.splitlines() if ln.strip()]
    if "VERDICT: PASS" not in lines:
        fail("Lean generic did NOT PASS on this report; refusing to emit "
             f"a manifest. Output:\n{out}")
    keep = [ln for ln in lines if ln.startswith(
        ("trace ops", "may trace ops", "trace non-empty", "masks consistent",
         "all addresses in MMIO window", "port/MSR sanity",
         "port/MSR confinement", "clock-enable", "VERDICT"))]
    return keep


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--report", required=True)
    ap.add_argument("--profile", required=True)
    ap.add_argument("--binary", required=True)
    ap.add_argument("--arch", required=True,
                    help="e.g. ARM_CORTEX_M3 / ARM_CORTEX_M4")
    ap.add_argument("--name-map", default="",
                    help="comma list OLD=NEW peripheral renames (documented "
                         "in provenance; used so policy capability names "
                         "match the manifest, e.g. GPIOB=GPIOB_LED)")
    ap.add_argument("--forbid", action="append", default=[],
                    help="NAME:START:END forbidden range (repeatable); "
                         "START/END hex, END exclusive (converted to "
                         "inclusive like profile blocks)")
    ap.add_argument("--out", required=True)
    args = ap.parse_args()

    report = json.load(open(args.report))
    profile = json.load(open(args.profile))
    blocks = [(b["name"], parse_int(b["start"]), parse_int(b["end"]))
              for b in profile["blocks"]]

    def block_of(addr: int):
        for name, s, e in blocks:
            if s <= addr < e:
                return name, s, e
        return None

    # --- collect MUST accesses (never MAY) ---
    touched: dict[str, dict] = {}
    outside = []
    for fn in report.get("functions", []):
        for acc in fn.get("mmio_accesses", []):
            addr = parse_int(acc["address"])
            hit = block_of(addr)
            if hit is None:
                outside.append((fn.get("name"), acc["address"], acc["op"]))
            else:
                name, s, e = hit
                slot = touched.setdefault(
                    name, {"start": s, "end": e, "count": 0,
                           "ops": set(), "example_fn": fn.get("name")})
                slot["count"] += 1
                slot["ops"].add(acc["op"])
    if outside:
        fail(f"{len(outside)} MUST accesses fall outside every profile "
             f"block (refusing to drop them silently), e.g. {outside[:5]}")

    # --- name mapping (documented, policy-compat only) ---
    name_map = {}
    for pair in filter(None, args.name_map.split(",")):
        old, new = pair.split("=", 1)
        name_map[old.strip()] = new.strip()

    verified = []
    evidence = {}
    for name in sorted(touched, key=lambda n: touched[n]["start"]):
        slot = touched[name]
        ops = slot["ops"]
        atype = ("read_write" if ops == {"LOAD", "STORE"}
                 else "read" if ops == {"LOAD"} else "write")
        disp = name_map.get(name, name)
        verified.append([f"0x{slot['start']:08X}", f"0x{slot['end'] - 1:08X}",
                         disp, atype])
        evidence[disp] = {
            "profile_block": name,
            "must_access_count": slot["count"],
            "observed_ops": sorted(ops),
            "example_function": slot["example_fn"],
        }

    # --- forbidden ranges (explicit, overlap-checked) ---
    forbidden = []
    for spec in args.forbid:
        fname, s, e = spec.split(":", 2)
        s, e = parse_int(s), parse_int(e)  # half-open input
        for v in verified:
            vs, ve = parse_int(v[0]), parse_int(v[1])
            if not (e - 1 < vs or s > ve):
                fail(f"forbidden range {fname} [{hex(s)},{hex(e)}) overlaps "
                     f"verified range {v[2]} [{v[0]},{v[1]}]")
            if fname == v[2]:
                fail(f"forbidden name {fname} collides with verified "
                     f"peripheral name (trust layer traps it anyway)")
        forbidden.append([f"0x{s:08X}", f"0x{e - 1:08X}", fname])

    # --- binary hash + name check ---
    if os.path.basename(args.binary) != report.get("binary_name"):
        fail(f"binary basename {os.path.basename(args.binary)!r} does not "
             f"match report binary_name {report.get('binary_name')!r}; "
             f"refusing to hash the wrong binary")
    sha = hashlib.sha256(open(args.binary, "rb").read()).hexdigest()

    # --- Lean gate (mechanical, no escape hatch) ---
    lean_lines = run_lean_generic(os.path.abspath(args.report))

    manifest = {
        "target_architecture": args.arch,
        "verified_mmio_ranges": verified,
        "forbidden_regions": forbidden,
        # EXACT claim: generic-mode PASS lines only. This is not a full
        # functional certification, and no .olean artifact is cited.
        "formal_proof_status": (
            "LEAN4_GENERIC_PASS: confinement true, clock-enable true, "
            "all addresses in MMIO window, masks consistent "
            f"(extractor {report.get('extractor_version')}, must-trace "
            "only, may excluded)"
        ),
        "sha256_hash": sha,
        "provenance": {
            "generator": "firmware_workspace/manifest_gen.py (reads reports, "
                         "changes no engine code/shape/CLI)",
            "report": repo_rel(args.report),
            "report_binary_name": report.get("binary_name"),
            "extractor_version": report.get("extractor_version"),
            "report_mmio_total": report.get("mmio_access_total"),
            "report_may_total_excluded": report.get("may_access_total"),
            "profile": repo_rel(args.profile),
            "profile_chip": profile.get("chip"),
            "lean_generic_verdict_lines": lean_lines,
            "range_evidence": evidence,
            "name_mapping_applied": name_map,
            "range_semantics": "profile blocks (half-open) converted to "
                               "inclusive manifest ends; block granularity "
                               "(the engine proves block-level confinement, "
                               "not register-level); may accesses excluded",
            "forbidden_rationale": "explicit --forbid ranges only; a block "
                                   "the firmware uses can never be "
                                   "forbidden (overlap-checked)",
        },
    }
    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2, sort_keys=True)
        f.write("\n")
    print(f"wrote {args.out}: {len(verified)} verified ranges, "
          f"{len(forbidden)} forbidden, sha256 {sha[:16]}…, "
          f"Lean generic PASS ({len(lean_lines)} verdict lines)")


if __name__ == "__main__":
    main()
