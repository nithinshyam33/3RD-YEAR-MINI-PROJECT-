"""
========================================
  MODULE 4 — ALERT & RESPONSE MODULE  (UPGRADED)
  Dynamic Deception-Based Cyber Defense System

  Features:
  - Reads alert_trigger.json from Module 3
  - Reads honeypot_events.json from Honeypot Server
  - Scores based on: failed logins, honeypot hits, file access
  - Displays: attacker IP, attack type, risk level, timeline
  - 🚨 HIGH RISK ALERT banner for HIGH/CRITICAL events
  - System Status Panel printed periodically
  - Blocks IP on HIGH/CRITICAL
========================================
"""

import json
import os
import sys
import time
import threading
from datetime import datetime

if sys.stdout.encoding and sys.stdout.encoding.lower() != "utf-8":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

# ─── CONFIG ──────────────────────────────────────────────────
SCORE_INPUT     = "alert_trigger.json"
ALERT_LOG       = "deception_alerts.log"
BLOCK_LOG       = "blocked_ips.txt"
HONEYPOT_EVENTS = "honeypot_events.json"
GATEWAY_LOG     = "gateway_logs.txt"
CHECK_EVERY     = 8
STATUS_INTERVAL = 15

ATTACKER_IP     = "UNKNOWN"   # Updated dynamically from honeypot/gateway logs
# ─────────────────────────────────────────────────────────────

last_score        = -1
last_hp_time      = 0
decoy_asset_count = 22
current_threat    = "NONE"
total_hp_captures = 0
total_alerts_fired = 0

W = 60   # banner width


# ═══════════════════════════════════════════════════════════════
# UTILITIES
# ═══════════════════════════════════════════════════════════════

def ts():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def safe_print(text=""):
    try:
        print(text)
    except UnicodeEncodeError:
        print(text.encode("ascii", errors="replace").decode("ascii"))


def banner_line(char="="):
    return char * W


def sub_line(char="-"):
    return char * W


# ═══════════════════════════════════════════════════════════════
# BEHAVIOR ANALYSIS ENGINE
# ═══════════════════════════════════════════════════════════════

SENSITIVE_KEYWORDS = {
    "credentials"   : "credential",
    "devops"        : "devops",
    "database"      : "database",
    "backups"       : "backup",
    "finance"       : "finance",
    "logs"          : "logs",
    "infrastructure": "infrastructure",
}


def analyze_behavior(files, breakdown):
    reasons = []
    categories_hit = set()

    for f in files:
        for kw, label in SENSITIVE_KEYWORDS.items():
            if kw in f.lower():
                categories_hit.add(label)

    if len(files) >= 3:
        reasons.append("Multiple sensitive assets accessed -- potential DATA EXFILTRATION attempt")

    if "credential" in categories_hit or "devops" in categories_hit:
        reasons.append("Access to credential/key stores -- CREDENTIAL HARVESTING in progress")

    if any("Rapid" in k for k in breakdown.keys()):
        reasons.append("Rapid sequential access detected -- likely AUTOMATED ATTACK TOOL")

    if len(categories_hit) >= 3:
        reasons.append(
            f"Accessed {len(categories_hit)} distinct asset categories -- BROAD RECONNAISSANCE pattern"
        )

    if "finance" in categories_hit and "database" in categories_hit:
        reasons.append("Finance + database assets targeted -- FINANCIAL DATA THEFT suspected")

    if "logs" in categories_hit:
        reasons.append("Log directory accessed -- attacker may be COVERING TRACKS")

    if "backup" in categories_hit or "infrastructure" in categories_hit:
        reasons.append("Backup/infrastructure accessed -- attacker may seek PERSISTENT FOOTHOLD")

    if not reasons:
        reasons.append("Unauthorized access to deception asset -- intent unclear, monitoring active")

    return reasons


# ═══════════════════════════════════════════════════════════════
# ATTACK TRACE ENGINE
# ═══════════════════════════════════════════════════════════════

def build_attack_trace(files):
    steps = []
    categories_hit = []

    folder_labels = {
        "logs"          : "Accessed system logs",
        "credentials"   : "Accessed credential store",
        "devops"        : "Accessed DevOps / deployment keys",
        "database"      : "Accessed database records",
        "finance"       : "Accessed financial records",
        "backups"       : "Accessed backup manifests",
        "infrastructure": "Accessed network infrastructure config",
    }

    seen = set()
    for f in files:
        for folder, label in folder_labels.items():
            if folder in f.lower() and folder not in seen:
                steps.append(label)
                categories_hit.append(folder)
                seen.add(folder)

    if not steps:
        steps = ["Accessed unknown deception asset"]

    if "credentials" in categories_hit and "devops" in categories_hit:
        conclusion = "Attacker is attempting PRIVILEGE ESCALATION -- credential + key theft"
    elif len(steps) >= 4:
        conclusion = "Attacker is conducting SYSTEMATIC RECONNAISSANCE -- broad sweep detected"
    elif "database" in categories_hit or "finance" in categories_hit:
        conclusion = "Attacker is targeting HIGH-VALUE DATA -- financial or PII theft likely"
    elif "logs" in categories_hit:
        conclusion = "Attacker is probing OPERATIONAL VISIBILITY -- log enumeration detected"
    else:
        conclusion = "Attacker behavior is EXPLORATORY -- early-stage intrusion attempt"

    return list(enumerate(steps, 1)), conclusion


# ═══════════════════════════════════════════════════════════════
# RECOMMENDED ACTIONS
# ═══════════════════════════════════════════════════════════════

ACTIONS = {
    "NONE"    : ["Continue passive monitoring", "No action required"],
    "LOW"     : ["Log and monitor the event",
                 "Review decoy file access history",
                 "Verify legitimate user activity"],
    "MEDIUM"  : ["Flag for SOC review",
                 "Correlate with authentication logs",
                 "Increase monitoring frequency",
                 "Prepare incident report"],
    "HIGH"    : ["Block suspected source IP immediately",
                 "Escalate to Tier-2 analysts",
                 "Initiate incident response playbook",
                 "Capture memory snapshot"],
    "CRITICAL": ["IMMEDIATE: Isolate affected network segment",
                 "Engage incident response team NOW",
                 "Preserve all forensic evidence",
                 "File formal breach notification",
                 "Notify management and legal"],
}

ATTACK_TYPE_MAP = {
    "NONE"    : "No Attack",
    "LOW"     : "Suspicious Login",
    "MEDIUM"  : "Brute Force / Honeypot Interaction",
    "HIGH"    : "Brute Force + Active Intrusion",
    "CRITICAL": "Advanced Persistent Threat (APT)",
}


# ═══════════════════════════════════════════════════════════════
# FILE I/O
# ═══════════════════════════════════════════════════════════════

def read_score():
    if not os.path.exists(SCORE_INPUT):
        return None
    try:
        with open(SCORE_INPUT, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None


def save_alert(label, score, files, breakdown, actions_taken, attacker_ip, attack_type):
    with open(ALERT_LOG, "a", encoding="utf-8") as f:
        f.write(f"\n{'='*W}\n")
        f.write(f"ALERT TIME   : {ts()}\n")
        f.write(f"ATTACKER IP  : {attacker_ip}\n")
        f.write(f"ATTACK TYPE  : {attack_type}\n")
        f.write(f"SEVERITY     : {label}\n")
        f.write(f"SCORE        : {score}/100\n")
        f.write(f"FILES        : {', '.join(files) if files else 'N/A'}\n")
        f.write(f"ACTIONS      : {', '.join(actions_taken)}\n")
        f.write(f"BREAKDOWN    : {json.dumps(breakdown)}\n")


def simulate_block(ip, score):
    with open(BLOCK_LOG, "a", encoding="utf-8") as f:
        f.write(f"{ts()} | BLOCKED: {ip} | score={score}\n")
    safe_print(f"  [FIREWALL]  IP {ip} --> BLOCKED  (written to {BLOCK_LOG})")


def get_last_attacker_ip_from_gateway():
    """Parse gateway_logs.txt to find the most recent IP that triggered HONEYPOT decision."""
    if not os.path.exists(GATEWAY_LOG):
        return None
    try:
        with open(GATEWAY_LOG, "r", encoding="utf-8") as f:
            lines = f.readlines()
        for line in reversed(lines):
            if "HONEYPOT" in line or "FAIL" in line:
                parts = line.split("|")
                for part in parts:
                    part = part.strip()
                    if part.startswith("IP:"):
                        return part.replace("IP:", "").strip()
    except Exception:
        pass
    return None


# ═══════════════════════════════════════════════════════════════
# HONEYPOT INTEGRATION
# ═══════════════════════════════════════════════════════════════

def check_honeypot_events():
    global last_hp_time, current_threat, ATTACKER_IP, total_hp_captures

    if not os.path.exists(HONEYPOT_EVENTS):
        return 0

    new_events = []
    try:
        with open(HONEYPOT_EVENTS, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                try:
                    ev = json.loads(line)
                    ev_time = datetime.strptime(
                        ev["timestamp"], "%Y-%m-%d %H:%M:%S"
                    ).timestamp()
                    if ev_time > last_hp_time:
                        new_events.append(ev)
                except Exception:
                    continue
    except Exception:
        return 0

    for ev in new_events:
        username  = ev.get("username", "?")
        password  = ev.get("password", "?")
        ip        = ev.get("ip", "?")
        event_ts  = ev.get("timestamp", ts())

        ATTACKER_IP       = ip
        total_hp_captures += 1

        safe_print()
        safe_print("+" + "=" * (W - 2) + "+")
        safe_print("|" + "  [HONEYPOT ALERT] -- CREDENTIAL CAPTURE".center(W - 2) + "|")
        safe_print("+" + "=" * (W - 2) + "+")
        safe_print(f"  Time        : {event_ts}")
        safe_print(f"  Source IP   : {ip}")
        safe_print(f"  Attack Type : Brute Force / Suspicious Login")
        safe_print(f"  Risk Level  : HIGH")
        safe_print(sub_line())
        safe_print("  Captured Credentials:")
        safe_print(f"    Username  :  {username}")
        safe_print(f"    Password  :  {password}")
        safe_print(sub_line())
        safe_print("  --> Attacker attempted login to SecureCorp Internal Portal")
        safe_print("  --> Credentials have been CAPTURED and logged")
        safe_print("  --> Escalating threat level to HIGH")
        safe_print("  --> Source IP flagged for monitoring and block")
        safe_print()
        safe_print("  *** TIMELINE ***")
        safe_print(f"    [1] Attacker scanned target (Nmap / port discovery)")
        safe_print(f"    [2] Found port 3000 (Gateway login page)")
        safe_print(f"    [3] Attempted brute-force login from {ip}")
        safe_print(f"    [4] Exceeded attempt threshold --> redirected to HONEYPOT")
        safe_print(f"    [5] Entered credentials on fake portal --> {event_ts}")
        safe_print(f"    [6] Credentials captured | Dashboard deception active")
        safe_print("+" + "=" * (W - 2) + "+")
        safe_print()

        with open(ALERT_LOG, "a", encoding="utf-8") as f:
            f.write(f"\n{'='*W}\n")
            f.write(f"[HONEYPOT CAPTURE] {event_ts}\n")
            f.write(f"  Attacker IP  : {ip}\n")
            f.write(f"  Attack Type  : Brute Force / Suspicious Login\n")
            f.write(f"  Risk Level   : HIGH\n")
            f.write(f"  Username     : {username}\n")
            f.write(f"  Password     : {password}\n")

        current_threat = "HIGH"

    if new_events:
        last_hp_time = datetime.strptime(
            new_events[-1]["timestamp"], "%Y-%m-%d %H:%M:%S"
        ).timestamp()

    return len(new_events)


# ═══════════════════════════════════════════════════════════════
# SOC ALERT BANNER
# ═══════════════════════════════════════════════════════════════

def print_alert(score, label, files, breakdown):
    global current_threat, ATTACKER_IP, total_alerts_fired

    current_threat     = label
    total_alerts_fired += 1
    attack_type        = ATTACK_TYPE_MAP.get(label, "Unknown Attack")

    # Try to get attacker IP from gateway log if still unknown
    if ATTACKER_IP == "UNKNOWN":
        gw_ip = get_last_attacker_ip_from_gateway()
        if gw_ip:
            ATTACKER_IP = gw_ip

    reasons = analyze_behavior(files, breakdown)
    steps, conclusion = build_attack_trace(files)
    recs    = ACTIONS.get(label, ACTIONS["LOW"])

    bar_fill = int((score / 100) * 44)
    bar      = "#" * bar_fill + "-" * (44 - bar_fill)

    safe_print()
    safe_print(banner_line("="))

    if label in ("HIGH", "CRITICAL"):
        safe_print("|" + " 🚨  HIGH RISK ALERT — ACTIVE INTRUSION DETECTED  🚨 ".center(W - 2) + "|")
    else:
        safe_print("|" + "   ⚠  SECURITY ALERT DETECTED  ⚠   ".center(W - 2) + "|")

    safe_print(banner_line("="))
    safe_print(f"  Timestamp    : {ts()}")
    safe_print(f"  Attacker IP  : {ATTACKER_IP}")
    safe_print(f"  Attack Type  : {attack_type}")
    safe_print(f"  Risk Level   : {label}")
    safe_print()
    safe_print(f"  Threat Score : {score}/100")
    safe_print(f"  [{bar}]")
    safe_print()

    if files:
        safe_print("  Accessed Decoy Files:")
        for fp in files:
            safe_print(f"    -> {fp}")
    else:
        safe_print("  Accessed Decoy Files: N/A")

    safe_print()
    safe_print("  Behavior Analysis:")
    for r in reasons:
        safe_print(f"    > {r}")
    safe_print()

    if breakdown:
        safe_print("  Score Breakdown:")
        for reason, pts in breakdown.items():
            safe_print(f"    . {reason:<45} {pts}")
        safe_print()

    if steps and files:
        safe_print(sub_line())
        safe_print("  [ATTACK TIMELINE]")
        for num, step in steps:
            safe_print(f"    Step {num} --> {step}")
        safe_print()
        safe_print("  Conclusion:")
        safe_print(f"    *** {conclusion}")
        safe_print()

    safe_print(sub_line())
    safe_print("  Recommended Actions:")
    for rec in recs:
        safe_print(f"    [+] {rec}")

    if label in ("HIGH", "CRITICAL"):
        safe_print()
        simulate_block(ATTACKER_IP, score)

    safe_print(banner_line("="))
    safe_print()

    save_alert(
        label, score, files, breakdown,
        ["logged"] + (["blocked"] if label in ("HIGH", "CRITICAL") else []),
        ATTACKER_IP, attack_type
    )


# ═══════════════════════════════════════════════════════════════
# SYSTEM STATUS PANEL
# ═══════════════════════════════════════════════════════════════

def print_status_panel():
    safe_print()
    safe_print("+" + "-" * (W - 2) + "+")
    safe_print("|" + "  SYSTEM STATUS PANEL".ljust(W - 2) + "|")
    safe_print("+" + "-" * (W - 2) + "+")
    safe_print(f"|  {'Component':<28} {'Status':<27}|")
    safe_print(f"|  {'-'*28:<28} {'-'*27:<27}|")
    safe_print(f"|  {'Gateway (port 3000)':<28} {'[ACTIVE]':<27}|")
    safe_print(f"|  {'Real Server (port 8080)':<28} {'[ACTIVE]':<27}|")
    safe_print(f"|  {'Honeypot (port 5000)':<28} {'[ACTIVE]':<27}|")
    safe_print(f"|  {'Monitoring (Module 2)':<28} {'[ACTIVE]':<27}|")
    safe_print(f"|  {'Scoring (Module 3)':<28} {'[ACTIVE]':<27}|")
    safe_print(f"|  {'Decoy Assets':<28} {str(decoy_asset_count):<27}|")
    safe_print(f"|  {'Honeypot Captures':<28} {str(total_hp_captures):<27}|")
    safe_print(f"|  {'Alerts Fired':<28} {str(total_alerts_fired):<27}|")
    safe_print(f"|  {'Current Threat Level':<28} {current_threat:<27}|")
    safe_print(f"|  {'Last Updated':<28} {ts()[:16]:<27}|")
    safe_print("+" + "-" * (W - 2) + "+")
    safe_print()


def status_thread_fn():
    time.sleep(4)
    while True:
        print_status_panel()
        time.sleep(STATUS_INTERVAL)


# ═══════════════════════════════════════════════════════════════
# MAIN DISPATCH
# ═══════════════════════════════════════════════════════════════

def dispatch_alert(data):
    global last_score, current_threat

    score     = data.get("score", 0)
    label     = data.get("label", "NONE")
    files     = data.get("files", [])
    breakdown = data.get("breakdown", {})

    if score == last_score:
        return

    last_score = score

    if score == 0:
        current_threat = "NONE"
        safe_print(f"\n  [{ts()}]  Score: 0  -->  NONE  --  No threats detected.")
        return

    print_alert(score, label, files, breakdown)


# ═══════════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════════

def main():
    safe_print(banner_line("="))
    safe_print(f"  MODULE 4  --  ALERT & SOC RESPONSE ENGINE".center(W))
    safe_print(banner_line("="))
    safe_print(f"  Score input  : {SCORE_INPUT}")
    safe_print(f"  Alert log    : {ALERT_LOG}")
    safe_print(f"  Block log    : {BLOCK_LOG}")
    safe_print(f"  Honeypot     : {HONEYPOT_EVENTS}")
    safe_print(f"  Gateway log  : {GATEWAY_LOG}")
    safe_print(f"  Check cycle  : every {CHECK_EVERY}s   |   Status: every {STATUS_INTERVAL}s")
    safe_print(banner_line("="))
    safe_print()

    with open(ALERT_LOG, "w", encoding="utf-8") as f:
        f.write(f"# Deception Alert Log -- started {ts()}\n")
    with open(BLOCK_LOG, "w", encoding="utf-8") as f:
        f.write(f"# Blocked IPs Log -- started {ts()}\n")

    if not os.path.exists(SCORE_INPUT):
        safe_print(f"  [WARN] {SCORE_INPUT} not found -- waiting for Module 3...\n")

    t = threading.Thread(target=status_thread_fn, daemon=True)
    t.start()

    scan = 0
    while True:
        scan += 1
        check_honeypot_events()
        data = read_score()
        if data:
            dispatch_alert(data)
        else:
            if scan % 3 == 1:
                safe_print(
                    f"  [{ts()}]  Scan #{scan} -- waiting for score data from Module 3..."
                )
        time.sleep(CHECK_EVERY)


if __name__ == "__main__":
    main()
