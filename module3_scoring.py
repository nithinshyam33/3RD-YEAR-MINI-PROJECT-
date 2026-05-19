"""
========================================
  MODULE 3 — THREAT SCORING MODULE
  Dynamic Deception-Based Cyber Defense System

  What it does:
  - Reads monitor_log.txt (written by Module 2)
  - Scores attacker behavior from 0 to 100
  - Checks every 10 seconds for new events
  - Passes final score to Module 4 (alert_trigger.json)

  Scoring rules:
  - First decoy file accessed        : +20
  - Each additional file accessed    : +10
  - Rapid access (within 30 seconds) : +30
  - High-value file accessed         : +15 bonus
  - Deleted file (evidence tampering): +25

  Score ranges:
  - 0        : No threat
  - 1 - 30   : LOW
  - 31 - 60  : MEDIUM
  - 61 - 85  : HIGH
  - 86 - 100 : CRITICAL

  How to run:
  - Module 1 and Module 2 must already be running
  - Run this in Terminal 3
========================================
"""

import json
import os
import time
from datetime import datetime

# ─── CONFIG ───────────────────────────────────────────
MONITOR_LOG   = "monitor_log.txt"       # Input  — written by Module 2
SCORE_OUTPUT  = "alert_trigger.json"    # Output — read by Module 4
CHECK_INTERVAL = 10                     # Seconds between scans
RAPID_WINDOW   = 30                     # Seconds — accesses within this = rapid

# High value files — accessing these adds bonus points
HIGH_VALUE_PATHS = ["devops", "credentials"]
# ──────────────────────────────────────────────────────

# Scoring weights
SCORE_FIRST_ACCESS  = 20
SCORE_EXTRA_ACCESS  = 10
SCORE_RAPID_ACCESS  = 30
SCORE_HIGH_VALUE    = 15
SCORE_DELETED       = 25
SCORE_MAX           = 100


# ─── UTILITIES ────────────────────────────────────────

def timestamp_now():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def get_score_label(score):
    if score == 0:
        return "NONE"
    elif score <= 30:
        return "LOW"
    elif score <= 60:
        return "MEDIUM"
    elif score <= 85:
        return "HIGH"
    else:
        return "CRITICAL"


def is_high_value(filepath):
    """Returns True if the accessed file is in a high-value folder."""
    for keyword in HIGH_VALUE_PATHS:
        if keyword in filepath:
            return True
    return False


# ─── LOG READER ───────────────────────────────────────

def read_events():
    """
    Reads monitor_log.txt and returns only INTRUDER_ACCESS and DELETED events.
    Skips comment lines (starting with #).
    Returns a list of event dicts sorted by timestamp.
    """
    events = []

    if not os.path.exists(MONITOR_LOG):
        return events

    with open(MONITOR_LOG, "r") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            try:
                event = json.loads(line)
                # Only score real threat events
                if event.get("event_type") in ("INTRUDER_ACCESS", "DELETED"):
                    events.append(event)
            except json.JSONDecodeError:
                continue

    # Sort by timestamp oldest first
    events.sort(key=lambda e: e.get("timestamp", ""))
    return events


# ─── SCORING ENGINE ───────────────────────────────────

def calculate_score(events):
    """
    Applies scoring rules to the list of events.
    Returns:
      - total score (capped at 100)
      - breakdown dict (for display)
    """
    if not events:
        return 0, {}

    score = 0
    breakdown = {}

    # ── Rule 1: First access ──
    first_access_events = [e for e in events if e["event_type"] == "INTRUDER_ACCESS"]

    if first_access_events:
        score += SCORE_FIRST_ACCESS
        breakdown["First file accessed"] = f"+{SCORE_FIRST_ACCESS}"

    # ── Rule 2: Each additional file accessed ──
    extra = len(first_access_events) - 1
    if extra > 0:
        extra_score = extra * SCORE_EXTRA_ACCESS
        score += extra_score
        breakdown[f"Additional files accessed ({extra})"] = f"+{extra_score}"

    # ── Rule 3: Rapid access check ──
    # If any two accesses happened within RAPID_WINDOW seconds → rapid access
    rapid_detected = False
    for i in range(len(first_access_events) - 1):
        try:
            t1 = datetime.strptime(first_access_events[i]["timestamp"],     "%Y-%m-%d %H:%M:%S")
            t2 = datetime.strptime(first_access_events[i+1]["timestamp"],   "%Y-%m-%d %H:%M:%S")
            gap = (t2 - t1).total_seconds()
            if gap <= RAPID_WINDOW:
                rapid_detected = True
                break
        except (ValueError, KeyError):
            continue

    if rapid_detected:
        score += SCORE_RAPID_ACCESS
        breakdown[f"Rapid access (within {RAPID_WINDOW}s)"] = f"+{SCORE_RAPID_ACCESS}"

    # ── Rule 4: High value file accessed ──
    hv_count = sum(1 for e in first_access_events if is_high_value(e.get("file", "")))
    if hv_count > 0:
        hv_score = hv_count * SCORE_HIGH_VALUE
        score += hv_score
        breakdown[f"High-value files accessed ({hv_count})"] = f"+{hv_score}"

    # ── Rule 5: Deleted files (evidence tampering) ──
    deleted_events = [e for e in events if e["event_type"] == "DELETED"]
    if deleted_events:
        del_score = len(deleted_events) * SCORE_DELETED
        score += del_score
        breakdown[f"Files deleted ({len(deleted_events)})"] = f"+{del_score}"

    # Cap at 100
    score = min(score, SCORE_MAX)

    return score, breakdown


# ─── DISPLAY ──────────────────────────────────────────

def print_score_report(score, breakdown, event_count):
    label = get_score_label(score)

    # Visual bar (50 chars wide)
    filled = int((score / 100) * 50)
    bar = "#" * filled + "-" * (50 - filled)

    print("\n" + "=" * 55)
    print(f"  MODULE 3 — THREAT SCORE REPORT")
    print(f"  Time     : {timestamp_now()}")
    print(f"  Events   : {event_count} threat event(s) detected")
    print("=" * 55)
    print(f"\n  SCORE  : {score} / 100   [{label}]")
    print(f"  [{bar}]")
    print()

    if breakdown:
        print("  Breakdown:")
        for reason, points in breakdown.items():
            print(f"    {reason:<45} {points}")
    else:
        print("  No threat events found.")

    print()


# ─── SCORE OUTPUT (for Module 4) ──────────────────────

def save_score(score, breakdown, events):
    """
    Saves current score to alert_trigger.json.
    Module 4 reads this file and decides what alert to fire.
    """
    accessed_files = [
        e.get("file", "") for e in events
        if e.get("event_type") == "INTRUDER_ACCESS"
    ]
    output = {
        "timestamp"   : timestamp_now(),
        "score"       : score,
        "label"       : get_score_label(score),
        "event_count" : len(events),
        "files"       : accessed_files,
        "breakdown"   : breakdown
    }
    with open(SCORE_OUTPUT, "w") as f:
        json.dump(output, f, indent=2)


# ─── MAIN LOOP ────────────────────────────────────────

def main():
    print("=" * 55)
    print("   MODULE 3 — THREAT SCORING ENGINE")
    print(f"   Reading from : {MONITOR_LOG}")
    print(f"   Output to    : {SCORE_OUTPUT}")
    print(f"   Recalculates : every {CHECK_INTERVAL} seconds")
    print("=" * 55)

    if not os.path.exists(MONITOR_LOG):
        print(f"\n[WARN] '{MONITOR_LOG}' not found.")
        print("  -> Make sure Module 2 is running first.\n")

    scan_count = 0

    while True:
        scan_count += 1
        print(f"\n  [Scan #{scan_count}] Reading {MONITOR_LOG}...")

        events    = read_events()
        score, breakdown = calculate_score(events)

        print_score_report(score, breakdown, len(events))
        save_score(score, breakdown, events)

        print(f"  Score saved to {SCORE_OUTPUT} — Module 4 will read this.")
        print(f"  Next recalculation in {CHECK_INTERVAL}s...")

        time.sleep(CHECK_INTERVAL)


if __name__ == "__main__":
    main()
