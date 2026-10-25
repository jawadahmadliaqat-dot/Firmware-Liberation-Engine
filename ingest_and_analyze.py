import os
import subprocess
import json
import sys

# System Parameters & Resource Limits
# Overridable so anyone can run this on their own Linux box:
#   FIRMWARE_WORKSPACE=/path/to/work GHIDRA_HEADLESS=/path/to/analyzeHeadless
GHIDRA_HEADLESS_PATH = os.environ.get("GHIDRA_HEADLESS", "/opt/ghidra/support/analyzeHeadless")
LOCAL_WORKSPACE = os.environ.get("FIRMWARE_WORKSPACE", "/home/hatch/firmware_workspace")
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
    ghidra_cmd = [
        GHIDRA_HEADLESS_PATH,
        project_path,
        project_name,
        "-import", binary_path,
        "-scriptPath", LOCAL_WORKSPACE,
        "-postScript", f"{LOCAL_WORKSPACE}/ExtractIR.java", json_output_path,
        "-overwrite"
    ]

    try:
        process = subprocess.run(ghidra_cmd, env=env, capture_output=True, text=True, timeout=300)
        print("[+] Ghidra Analysis Finished.")
        print(process.stdout[-500:]) # Print tail of log
        return True
    except subprocess.TimeoutExpired:
        print("[!] Ghidra timed out.")
        return False
    except Exception as e:
        print(f"[!] Analysis failed: {e}")
        return False

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
