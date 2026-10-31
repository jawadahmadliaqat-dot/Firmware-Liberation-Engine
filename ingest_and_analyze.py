import os
import subprocess
import json
import sys
import signal
import datetime

# System Parameters & Resource Limits
# Overridable so anyone can run this on their own Linux box:
#   FIRMWARE_WORKSPACE=/path/to/work GHIDRA_HEADLESS=/path/to/analyzeHeadless
# Ghidra subprocess timeout (seconds): INGEST_TIMEOUT overrides the 300s
# default WITHOUT changing the one-command usage (no new flag, no new
# step). Large real-world targets need more than 300s (a 28MB kernel
# runs for over an hour); set e.g. INGEST_TIMEOUT=7200 for those.
# An invalid value warns and falls back to 300.
GHIDRA_HEADLESS_PATH = os.environ.get("GHIDRA_HEADLESS", "/opt/ghidra/support/analyzeHeadless")
LOCAL_WORKSPACE = os.environ.get("FIRMWARE_WORKSPACE", "/home/hatch/firmware_workspace")
DEFAULT_GHIDRA_TIMEOUT = 300

def _ingest_timeout():
    """Timeout for the Ghidra subprocess, in seconds (default 300)."""
    raw = os.environ.get("INGEST_TIMEOUT")
    if raw is None or raw == "":
        return DEFAULT_GHIDRA_TIMEOUT
    try:
        value = int(raw)
    except ValueError:
        print(f"[!] WARNING: invalid INGEST_TIMEOUT={raw!r}; using default {DEFAULT_GHIDRA_TIMEOUT}s.")
        return DEFAULT_GHIDRA_TIMEOUT
    if value <= 0:
        print(f"[!] WARNING: invalid INGEST_TIMEOUT={raw!r}; using default {DEFAULT_GHIDRA_TIMEOUT}s.")
        return DEFAULT_GHIDRA_TIMEOUT
    return value

def _coerce_text(data):
    """Coerce subprocess output to str for log writing.

    HARDENING (v51 harness fix): on a timeout, CPython's
    TimeoutExpired.stdout/stderr are BYTES even when the subprocess
    ran with text=True (reproduced on Python 3.12.3) — writing them
    to a text-mode file raises TypeError and crashes the timeout
    handler itself, losing the partial log. Bytes decode as UTF-8
    with replacement, so any log content (bytes or str) saves.
    """
    if data is None:
        return ""
    if isinstance(data, bytes):
        return data.decode("utf-8", errors="replace")
    return data
GDRIVE_TARGET_DIR = "gdrive:Firmware_DataLake/raw_binaries"
GDRIVE_OUTPUT_DIR = "gdrive:Firmware_DataLake/analysis_reports"

# 1. Ensure Local Directories Exist
os.makedirs(LOCAL_WORKSPACE, exist_ok=True)
os.makedirs(f"{LOCAL_WORKSPACE}/projects", exist_ok=True)
os.makedirs(f"{LOCAL_WORKSPACE}/binaries", exist_ok=True)
os.makedirs(f"{LOCAL_WORKSPACE}/analysis_reports", exist_ok=True)

def sync_from_gdrive(filename):
    """Downloads target binary from Google Drive to Local Workspace"""
    print(f"[*] Downloading {filename} from Google Drive...")
    cmd = f"rclone copy {GDRIVE_TARGET_DIR}/{filename} {LOCAL_WORKSPACE}/binaries/"
    res = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    if res.returncode != 0:
        print(f"[!] Error syncing from GDrive: {res.stderr}")
        return False
    print("[+] Download complete.")
    return True

def save_headless_log(binary_name, stdout, stderr):
    """Saves the COMPLETE headless log for one target run.

    HARDENING (Oct 29, 2026 drift): the old code printed only the last
    500 chars of stdout and archived nothing, so the Oct 29 analyzer
    loss was un-diagnosable retroactively (a one-line
    "Decompiler Switch Analysis" presence check in a saved log would
    have caught it immediately). Every run now saves its full log to
    headless_logs/<binary>_<timestamp>.log; the console still shows
    only the short tail.
    """
    log_dir = f"{LOCAL_WORKSPACE}/headless_logs"
    os.makedirs(log_dir, exist_ok=True)
    stamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
    safe = os.path.basename(binary_name)
    log_path = f"{log_dir}/{safe}_{stamp}.log"
    with open(log_path, "w") as f:
        f.write("=== STDOUT ===\n")
        f.write(_coerce_text(stdout))
        f.write("\n=== STDERR ===\n")
        f.write(_coerce_text(stderr))
    print(f"[*] Full headless log saved to {log_path}")
    return log_path

def run_ghidra_analysis(binary_name, project_name="PoC_Project"):
    """Runs Ghidra Headless within strict -Xmx2G heap limits"""
    binary_path = f"{LOCAL_WORKSPACE}/binaries/{binary_name}"
    project_path = f"{LOCAL_WORKSPACE}/projects"

    print(f"[*] Launching Ghidra Headless with 512MB Heap Limit on {binary_name}...")

    # Heap limit set to 512M for the first test (RAM is tight, no swap).
    # NOTE: analyzeHeadless hardcodes its own MAXMEM in the script file, so the
    # file itself was also edited to MAXMEM=512M; this env var alone would not
    # take effect.
    env = os.environ.copy()
    env["MAXMEM"] = "512M"

    # Ghidra Headless Command Format
    # analyzeHeadless <project_location> <project_name> -import <file> -postScript <analysis_script>
    json_output_path = f"{LOCAL_WORKSPACE}/analysis_reports/{binary_name}_report.json"
    # STALE-REPORT GUARD (v51): a previous run's report must never
    # masquerade as this run's result — the canary already deleted
    # first for exactly this reason, and the java-missing case
    # proved the gap live (instant failure + old report present =
    # false success). Remove it before launching, so that after
    # the run, presence of the file proves THIS run produced it.
    # A failed run therefore leaves no report — the honest outcome,
    # not data loss: reports are regenerable artifacts, while the
    # headless log (the diagnostic evidence) is always preserved.
    if os.path.exists(json_output_path):
        print(f"[*] Removing stale report {json_output_path} (a run's report must come from that run).")
        os.remove(json_output_path)
    ghidra_cmd = [
        GHIDRA_HEADLESS_PATH,
        project_path,
        project_name,
        "-import", binary_path,
        "-scriptPath", LOCAL_WORKSPACE,
        "-postScript", f"{LOCAL_WORKSPACE}/ExtractIR.java", json_output_path,
        "-overwrite"
    ]

    timeout = _ingest_timeout()
    # Popen (not run) + its own session, so a timeout kill takes the
    # WHOLE Ghidra tree, not just the launcher. GROUP-KILL (v51):
    # subprocess.run's timeout kills only the direct child; the
    # analyzeHeadless JVM survived a 1s test kill, finished the
    # analysis anyway, wrote a report AFTER the wrapper had declared
    # failure, and meanwhile held the project lock so the next
    # canary run failed on initLock. A "killed" run that keeps
    # running is not a kill — kill the process group instead.
    proc = subprocess.Popen(ghidra_cmd, env=env, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, text=True,
                            start_new_session=True)
    try:
        stdout, stderr = proc.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        print(f"[!] FAILURE: Ghidra timed out after {timeout}s (killing the whole Ghidra process group; no report produced).")
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            pass
        stdout, stderr = proc.communicate()
        try:
            save_headless_log(binary_name, stdout, stderr)
        except Exception as save_err:
            print(f"[!] WARNING: could not save partial headless log: {save_err}")
        print("[!] Pipeline FAILED: Ghidra analysis did not complete (timeout). See the partial headless log above.")
        return False
    except KeyboardInterrupt:
        print("[!] FAILURE: interrupted (killing the whole Ghidra process group).")
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            pass
        proc.communicate()
        return False
    except Exception as e:
        print(f"[!] Analysis failed: {e}")
        return False
    print("[+] Ghidra Analysis Finished.")
    save_headless_log(binary_name, stdout, stderr)
    print(stdout[-500:]) # Print tail of log (console stays short)
    # REPORT CHECK (v51 harness fix, same fail-loud principle):
    # analyzeHeadless exits 0 even when the post-script fails to
    # load (verified: script-load error + "Import succeeded" +
    # exit 0, no report) and even when java is missing — so the
    # exit code proves nothing. The report file is the only
    # honest success signal, exactly as the canary already
    # checks. A run with no (or empty) report is a FAILURE,
    # never a success, whatever the subprocess exit code was.
    if not os.path.exists(json_output_path) or os.path.getsize(json_output_path) == 0:
        print(f"[!] FAILURE: Ghidra finished but no report was produced at {json_output_path} (see headless log above).")
        return False
    return True

def sync_results_to_gdrive(report_file):
    """Syncs analysis reports back to Google Drive Data Lake"""
    print(f"[*] Uploading {report_file} to Google Drive...")
    cmd = f"rclone copy {report_file} {GDRIVE_OUTPUT_DIR}/"
    subprocess.run(cmd, shell=True)
    print("[+] Sync to Cloud Complete.")

if __name__ == "__main__":
    args = [a for a in sys.argv[1:] if a != "--no-upload"]
    no_upload = "--no-upload" in sys.argv
    if len(args) < 1:
        print("Usage: python3 ingest_and_analyze.py <target_binary_name | /path/to/local_binary> [--no-upload]")
        print("  Drive name  -> downloads from gdrive:Firmware_DataLake/raw_binaries, uploads report")
        print("  Local path  -> uses the file directly, no Drive download (upload still on unless --no-upload)")
        sys.exit(1)

    target_file = args[0]

    # Local mode: an existing file path is used directly (portable, no Drive needed).
    if os.path.isfile(target_file):
        import shutil
        print(f"[*] Using local binary {target_file} (no Drive download).")
        base = os.path.basename(target_file)
        shutil.copy(target_file, f"{LOCAL_WORKSPACE}/binaries/{base}")
        target_file = base
        ready = True
    else:
        ready = sync_from_gdrive(target_file)

    if ready:
        if run_ghidra_analysis(target_file):
            json_report = f"{LOCAL_WORKSPACE}/analysis_reports/{target_file}_report.json"
            if os.path.exists(json_report) and not no_upload:
                sync_results_to_gdrive(json_report)
            print("[✓] Pipeline step executed successfully.")
        else:
            # FAIL LOUD (v51 harness fix): a killed/failed run must
            # never exit 0 as if it succeeded — the old code fell
            # through silently, which is how a timed-out kernel run
            # could look like a pass to any caller checking only the
            # exit code. The canary script is unaffected: it checks
            # the report file itself, not this exit code.
            print("[!] Pipeline FAILED: Ghidra analysis did not complete successfully. No valid report was produced.")
            sys.exit(1)
