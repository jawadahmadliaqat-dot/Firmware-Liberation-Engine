#!/usr/bin/env python3
"""Classify ExtractIR MMIO accesses against a chip peripheral profile.

Big-pipeline step 1 (local-vs-target classification, v1): the extractor
records every resolved address in the MMIO window, but that window is far
wider than any real chip's peripherals. A probe firmware also carries
TARGET-side addresses, and the linear resolver can mis-resolve across
branches (proven: BMP renesas_uid 0x4136544A came from a list-order
definition, while the path-correct definition gives 0x41365449).

This tool does NOT decide which of those two cases a suspect is — that
needs the CFG fixpoint scan (step 2). It draws the line that can be drawn
today: KNOWN = inside a documented peripheral block of the chip profile;
SUSPECT = outside every block, needs human review, must never silently
pass as local MMIO.

Usage: python3 classify_mmio.py <report.json> <profile.json>
Exit code: 0 = no suspects, 1 = suspects found.
"""
import json
import sys


def main():
    if len(sys.argv) != 3:
        print("Usage: python3 classify_mmio.py <report.json> <profile.json>")
        return 2
    report = json.load(open(sys.argv[1]))
    profile = json.load(open(sys.argv[2]))
    blocks = [(b["name"], int(b["start"], 16), int(b["end"], 16))
              for b in profile["blocks"]]

    def classify(addr):
        for name, lo, hi in blocks:
            if lo <= addr < hi:
                return name
        return None

    known = 0
    suspects = []
    for fn in report.get("functions", []):
        for a in fn.get("mmio_accesses", []):
            addr = int(a["address"], 16)
            blk = classify(addr)
            if blk:
                known += 1
            else:
                suspects.append((fn["name"], a.get("instr", "?"),
                                 a["op"], a["address"]))
    print(f"chip profile: {profile['chip']}")
    print(f"known local-MMIO accesses: {known}")
    print(f"SUSPECT accesses (outside every known block): {len(suspects)}")
    for fn_name, instr, op, addr in suspects:
        print(f"  SUSPECT {op} {addr} in {fn_name} @ {instr}")
    return 1 if suspects else 0


if __name__ == "__main__":
    sys.exit(main())
