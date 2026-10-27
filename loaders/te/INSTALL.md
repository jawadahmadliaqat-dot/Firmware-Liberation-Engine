# TE loader — installation and usage (TE loader v1, Ghidra 11.4.2)

## What this is

`TeLoader.java` is a custom Ghidra loader for UEFI TE (Terse Executable)
images — the "VZ" files that Ghidra 11.4.2 cannot import on its own
("No load spec found for import file"). It parses the TE header per the UEFI
PI spec, maps each section exactly from file bytes at
ImageBase + VirtualAddress, and registers the header entry point, so
auto-analysis and the existing ExtractIR pipeline run unchanged.

Loader version is separate from the extractor: this is **TE loader v1**;
`extractor_version` stays **v3.10** (the loader adds no extractor change).

## Install (VM and PC use the same script)

Requirements: Ghidra 11.4.2 installed, JDK 21.

```bash
cd firmware_workspace/loaders/te
GHIDRA_HOME=/opt/ghidra JAVA_HOME=~/workspace/tools/jdk/jdk-21.0.13+9 bash build.sh
```

On Jawad's PC (WSL), point the two variables at the PC paths instead, e.g.:

```bash
GHIDRA_HOME=~/ghidra_11.4.2_PUBLIC JAVA_HOME=/usr/lib/jvm/java-21-openjdk-amd64 bash build.sh
```

`build.sh` compiles `TeLoader.java` against the Ghidra jars, packages
`lib/TeLoader.jar`, and installs it to
`$GHIDRA_HOME/Ghidra/Extensions/TeLoader/` (jar + `extension.properties`).
That Extensions directory is where Ghidra — including `analyzeHeadless` —
discovers loaders, so no classpath flags are needed. (`build.sh` resolves
`GHIDRA_HOME` through symlinks first: `/opt/ghidra` is usually a symlink to
the versioned directory, and `find` will not descend into a bare symlink
start point, which would otherwise silently produce an empty classpath.)

Notes:

- On the VM, `/opt/ghidra` is wiped on VM restart. After reinstalling Ghidra
  (see `firmware_workspace/reinstall_ghidra.sh`, plus the MAXMEM=512M patch),
  just re-run `build.sh` — the loader source lives in the repo, the jar is
  rebuilt from it.
- `setup.sh` does NOT install the loader yet. Proposed addition (for the
  parent to approve, not done here): after the Ghidra/Lean setup steps, run
  `bash loaders/te/build.sh` with the same `GHIDRA_HOME`/`JAVA_HOME` the rest
  of setup used, and print the install path.
- The `.jar` is a build artifact and is NOT committed to the repo — only
  `TeLoader.java`, `extension.properties`, `build.sh`, and this file are.

## Use

Through the normal pipeline (no pipeline change needed):

```bash
python3 ingest_and_analyze.py /path/to/driver.te --no-upload
# report: analysis_reports/driver.te_report.json
```

Or directly with headless Ghidra:

```bash
/opt/ghidra/support/analyzeHeadless <project_dir> <project> \
  -import /path/to/driver.te -postScript ExtractIR.java <out.json> -overwrite
```

Verify in the headless log: the import must NOT say
"No load spec found for import file", and the loader prints a line like:

```
TE loader v1: 3 sections, image base 0x0, entry 0x2396, stripped size 0x1a0
```

## Behavior and limits (read before trusting output)

- Supported machines: x86-64 (`0x8664`) and x86-32 (`0x014c`) only. Any other
  machine in a VZ file is refused (loader does not claim the file) — no
  guessing, no fallback language.
- Compiler spec is `windows` for both machines: x86 languages have no
  `default` cspec (x86-64 offers windows/clangwindows/gcc/golang/swift), and
  `windows` is what Ghidra's PE loader picks for the PE twins of these
  drivers, so TE analysis matches PE analysis as closely as possible.
- The install directory must contain an (even empty) `Module.manifest`
  alongside `extension.properties` — without it, Ghidra skips the directory
  during extension discovery and the import fails with "No load spec found"
  even though the jar is present. `build.sh` copies it; do not omit it.
- Image base and entry point come from the TE header, never guessed. A
  header ImageBase of 0 loads at base 0 — exactly what Ghidra's PE loader
  does for the PE twin of the same driver, so TE and PE addresses match.
- Relocations are NOT applied: the image loads at its header ImageBase, so
  no relocation is needed (same as the PE loader when the load base matches).
  The `.reloc` section is still loaded as an ordinary section, like the PE
  twin.
- Sections map exactly from file bytes. Stripped fields (e.g. the debug
  directory) are absent, not invented. A section whose raw data would come
  from file offset 0, or that extends past end-of-file, fails the import.
- Load-into an existing program whose image base differs from the TE header
  base is refused with an error (loading there would misplace every section).
- Any structural problem (bad magic, unsupported machine, truncated section
  table, section past EOF, entry point outside every section) fails the
  import with a specific `LoadException` — never a partial or shifted program.
- TE strips headers, so a TE report can lose findings the PE twin has
  (header-derived symbols, header bytes). Any TE finding NOT in the PE twin
  is a red flag, not a win.
