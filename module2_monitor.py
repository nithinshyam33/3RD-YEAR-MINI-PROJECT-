"""
========================================
  MODULE 2 — MONITORING MODULE (v2)
  Dynamic Deception-Based Cyber Defense System

  What it does:
  - Watches deception_network/ folder
  - Ignores file changes made by Module 1 (whitelist)
  - Alerts ONLY when an outsider touches a file
  - Logs all real events to monitor_log.txt

  How to run:
  - Keep module1_generator.py running in Terminal 1
  - Run this file in Terminal 2
========================================
"""

import os
import hashlib
import time
import json
from datetime import datetime

# ─── CONFIG ───────────────────────────────────────────
WATCH_FOLDER       = "deception_network"    # Module 1's output folder
SYSTEM_UPDATE_LOG  = "system_updates.log"   # Module 1 writes here (root folder)
MONITOR_LOG        = "monitor_log.txt"      # Module 2 writes real alerts here
POLL_INTERVAL      = 5                      # Seconds between scans
# ──────────────────────────────────────────────────────

# Memory: stores last known state of every file
file_state = {}


# ─── UTILITIES ────────────────────────────────────────

def get_file_hash(filepath):
    """MD5 hash of file contents. Hash changes = file was modified."""
    try:
        with open(filepath, "rb") as f:
            return hashlib.md5(f.read()).hexdigest()
    except Exception:
        return None


def timestamp_now():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def log_event(event_type, filepath, extra=""):
    """
    Logs a REAL alert (not system update) to console + monitor_log.txt.
    JSON format so Module 3 can easily read and score it.
    """
    event = {
        "timestamp"  : timestamp_now(),
        "event_type" : event_type,
        "file"       : filepath,
        "note"       : extra
    }

    icons = {
        "INTRUDER_ACCESS" : "[!!!] INTRUDER ACCESS",
        "NEW_FILE"        : "[NEW] FILE APPEARED",
        "DELETED"         : "[DEL] FILE DELETED",
        "SYSTEM_UPDATE"   : "[ - ] system update"
    }
    icon = icons.get(event_type, event_type)

    print(f"[{event['timestamp']}]  {icon:<28}  ->  {filepath}")
    if extra:
        print(f"    -> {extra}")

    # Only write real threats to monitor_log (not system updates)
    if event_type != "SYSTEM_UPDATE":
        with open(MONITOR_LOG, "a") as f:
            f.write(json.dumps(event) + "\n")


# ─── WHITELIST CHECK ──────────────────────────────────

def was_updated_by_system(filepath):
    """
    Checks system_updates.log to see if Module 1 just updated this file.

    Module 1 writes a line like:
        {"file": "deception_network/credentials/admin_backup_credentials.txt", "timestamp": "..."}

    If the filepath appears in the last 60 seconds of log entries -> system update (ignore).
    If NOT found -> real intruder access (alert).
    """
    if not os.path.exists(SYSTEM_UPDATE_LOG):
        return False

    try:
        with open(SYSTEM_UPDATE_LOG, "r") as f:
            lines = f.readlines()

        now = datetime.now()

        for line in reversed(lines):   # Read newest entries first
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            try:
                entry = json.loads(line)
                entry_time = datetime.strptime(entry["timestamp"], "%Y-%m-%d %H:%M:%S")
                age_seconds = (now - entry_time).total_seconds()

                # Only trust entries from the last 60 seconds
                if age_seconds > 60:
                    break

                # Normalize paths before comparing
                if os.path.normpath(entry["file"]) == os.path.normpath(filepath):
                    return True   # Module 1 updated this — ignore

            except (json.JSONDecodeError, KeyError, ValueError):
                continue

    except Exception:
        pass

    return False   # Not found in system log -> real access


# ─── CORE SCAN LOGIC ──────────────────────────────────

def scan_folder():
    """
    Walks deception_network/ every POLL_INTERVAL seconds.
    For each changed file:
      - If Module 1 logged it -> IGNORE (system update)
      - If NOT in log         -> ALERT (real intruder)
    """
    current_files = set()

    for root, dirs, files in os.walk(WATCH_FOLDER):
        for filename in files:
            filepath = os.path.join(root, filename)
            current_files.add(filepath)

            current_hash = get_file_hash(filepath)

            if filepath not in file_state:
                # First scan — record baseline, no alert
                file_state[filepath] = {"hash": current_hash}
                log_event("NEW_FILE", filepath, "Discovered on startup — recording baseline")
                continue

            last_hash = file_state[filepath]["hash"]

            if current_hash != last_hash:
                # File changed — check WHO changed it
                if was_updated_by_system(filepath):
                    # Module 1 did this — safe to ignore
                    log_event("SYSTEM_UPDATE", filepath, "Routine rotation by Module 1")
                else:
                    # NOT in system log — real intruder
                    log_event(
                        "INTRUDER_ACCESS", filepath,
                        "Hash changed but NO system log entry — THREAT DETECTED"
                    )

                # Update stored hash either way
                file_state[filepath]["hash"] = current_hash

    # Check for deleted files
    deleted = set(file_state.keys()) - current_files
    for filepath in deleted:
        log_event("DELETED", filepath, "File removed — possible evidence tampering")
        del file_state[filepath]


# ─── MAIN LOOP ────────────────────────────────────────

def main():
    print("=" * 60)
    print("   MODULE 2 — DECEPTION NETWORK MONITOR v2")
    print(f"   Watching     : {WATCH_FOLDER}/")
    print(f"   System log   : {SYSTEM_UPDATE_LOG}  (written by Module 1)")
    print(f"   Alert log    : {MONITOR_LOG}  (real threats only)")
    print(f"   Poll rate    : every {POLL_INTERVAL} seconds")
    print("=" * 60)
    print()

    if not os.path.exists(WATCH_FOLDER):
        print(f"[ERROR] '{WATCH_FOLDER}' folder not found.")
        print("  -> Start module1_generator.py first, then run this.")
        return

    if not os.path.exists(SYSTEM_UPDATE_LOG):
        print(f"[WARN] '{SYSTEM_UPDATE_LOG}' not found yet.")
        print("  -> Module 1 will create it on first run. Continuing...\n")

    # Create/reset monitor log with header
    with open(MONITOR_LOG, "w") as f:
        f.write(f"# Module 2 Monitor started: {timestamp_now()}\n")
        f.write(f"# Real intrusion events only — system updates filtered out\n")

    print("  [*] Initial scan — building baseline...\n")

    scan_count = 0

    while True:
        scan_count += 1
        scan_folder()
        print(f"\n  [Scan #{scan_count} done] — next scan in {POLL_INTERVAL}s...\n")
        time.sleep(POLL_INTERVAL)


if __name__ == "__main__":
    main()
