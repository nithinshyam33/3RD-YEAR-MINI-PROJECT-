import os
import random
import time
import hashlib
import json
from datetime import datetime, timedelta

BASE = "deception_network"
INTERVAL = 30  # seconds — change this to whatever you want

folders = [
    "credentials", "backups", "finance",
    "infrastructure", "devops", "logs", "database"
]

usernames = [
    "admin", "root", "backup_admin", "vpn_admin",
    "sysops", "devops_lead", "finance_user", "db_admin",
    "network_ops", "sec_admin"
]

password_patterns = [
    "Admin@{year}!", "Secure#Key{num}", "Root{word}!{num}",
    "Server{word}#{num}", "Infra@{num}{word}"
]

words = ["Access", "Login", "Secure", "Net", "Ops", "Sys"]
departments = ["Finance", "HR", "Engineering", "Management", "IT", "Legal", "R&D"]

ALERT_LOG = "deception_alerts.log"
access_times = {}
cycle = 0


# --- Helpers ---

def rand_ip():
    return f"{random.randint(10,172)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"

def rand_money():
    return random.randint(50000, 500000)

def rand_token():
    raw = f"TOKEN_{random.randint(100000,999999)}_{datetime.now()}"
    return hashlib.sha256(raw.encode()).hexdigest()[:32].upper()

def rand_key_line():
    return hashlib.sha256(str(random.getrandbits(256)).encode()).hexdigest()[:64]

def rand_password():
    pattern = random.choice(password_patterns)
    return pattern.format(
        year=random.randint(2023, 2025),
        num=random.randint(10, 999),
        word=random.choice(words)
    )

def fake_timestamp(offset_minutes=0):
    t = datetime.now() - timedelta(minutes=offset_minutes)
    return t.strftime("%Y-%m-%d %H:%M:%S")

def fake_hash():
    return hashlib.md5(str(random.getrandbits(128)).encode()).hexdigest()


# --- Alert Detection ---

def check_access(filepath):
    try:
        atime = os.stat(filepath).st_atime
        if filepath in access_times and atime != access_times[filepath]:
            alert = {
                "timestamp": str(datetime.now()),
                "alert": "DECOY FILE ACCESSED",
                "file": filepath,
                "severity": "HIGH",
                "cycle": cycle
            }
            with open(ALERT_LOG, "a") as f:
                f.write(json.dumps(alert) + "\n")
            print(f"\n[!!!] ALERT — {filepath} accessed at {datetime.now()}\n")
        access_times[filepath] = atime
    except FileNotFoundError:
        pass

def monitor_all():
    for root, _, files in os.walk(BASE):
        for file in files:
            check_access(os.path.join(root, file))


# --- File Generators ---

def generate_credentials():
    lines = [
        "# INTERNAL ADMIN ACCESS - CONFIDENTIAL",
        f"# Generated   : {fake_timestamp()}",
        f"# Cycle       : {cycle}",
        f"# Backup ID   : {fake_hash()[:12].upper()}",
        ""
    ]
    for i in range(30):
        user = f"{random.choice(usernames)}_{random.randint(1,99)}"
        pw = rand_password()
        lines.append(f"{user} : {pw}")

    path = os.path.join(BASE, "credentials", "admin_backup_credentials.txt")
    with open(path, "w") as f:
        f.write("\n".join(lines))
    print(f"  [+] credentials updated")


def generate_database():
    rows = [
        "-- =============================",
        "-- DATABASE BACKUP - CONFIDENTIAL",
        f"-- Generated : {fake_timestamp()}",
        f"-- Cycle     : {cycle}",
        f"-- Server    : db-prod-{random.randint(1,5)}.internal",
        "-- =============================",
        "",
        "CREATE TABLE employees(",
        "  id INT PRIMARY KEY,",
        "  username TEXT NOT NULL,",
        "  password_hash TEXT,",
        "  department TEXT,",
        "  access_level INT",
        ");",
        ""
    ]
    for i in range(150):
        user = random.choice(usernames)
        pw_hash = fake_hash()
        dept = random.choice(departments)
        level = random.randint(1, 5)
        rows.append(f"INSERT INTO employees VALUES({i},'{user}','{pw_hash}','{dept}',{level});")

    path = os.path.join(BASE, "database", "employee_dump.sql")
    with open(path, "w") as f:
        f.write("\n".join(rows))
    print(f"  [+] database dump updated")


def generate_finance():
    lines = [
        "=" * 45,
        "   CONFIDENTIAL QUARTERLY FINANCE REPORT",
        f"   Generated : {fake_timestamp()}",
        f"   Cycle     : {cycle}",
        f"   Report ID : RPT-{random.randint(1000,9999)}",
        "=" * 45,
        ""
    ]
    total = 0
    for dept in departments:
        amount = rand_money()
        total += amount
        lines.append(f"  {dept:<20} ${amount:>10,}")

    lines += [
        "-" * 45,
        f"  {'TOTAL':<20} ${total:>10,}"
    ]

    path = os.path.join(BASE, "finance", "quarterly_finance_report.txt")
    with open(path, "w") as f:
        f.write("\n".join(lines))
    print(f"  [+] finance report updated")


def generate_server_config():
    lines = [
        "# INTERNAL INFRASTRUCTURE CONFIG - DO NOT SHARE",
        f"# Generated      : {fake_timestamp()}",
        f"# Cycle          : {cycle}",
        "",
        f"main_server_ip   = {rand_ip()}",
        f"database_primary = {rand_ip()}",
        f"database_replica = {rand_ip()}",
        f"backup_server    = {rand_ip()}",
        f"vpn_gateway      = {rand_ip()}",
        "",
        "ssh_enabled      = true",
        f"admin_port       = {random.randint(8000,9999)}",
        f"db_port          = {random.randint(3300,5500)}",
        f"ssl_cert_hash    = {fake_hash()}",
        "env              = production",
        f"build_version    = v{random.randint(1,5)}.{random.randint(0,9)}.{random.randint(0,99)}"
    ]

    path = os.path.join(BASE, "infrastructure", "server_config.conf")
    with open(path, "w") as f:
        f.write("\n".join(lines))
    print(f"  [+] server config updated")


def generate_devops_keys():
    lines = ["-----BEGIN RSA PRIVATE KEY-----"]
    for _ in range(24):
        lines.append(rand_key_line())
    lines += [
        "-----END RSA PRIVATE KEY-----",
        "",
        f"API_TOKEN        = {rand_token()}",
        f"DEPLOY_SECRET    = {rand_token()}",
        f"AWS_ACCESS_KEY   = AKIA{rand_token()[:16].upper()}",
        f"AWS_SECRET       = {rand_token()}",
        f"# Generated      : {fake_timestamp()}",
        f"# Cycle          : {cycle}"
    ]

    path = os.path.join(BASE, "devops", "deployment_keys.pem")
    with open(path, "w") as f:
        f.write("\n".join(lines))
    print(f"  [+] devops keys updated")


def generate_logs():
    lines = []
    for _ in range(100):
        offset = random.randint(0, 1440)
        ts = fake_timestamp(offset_minutes=offset)
        event = random.choice([
            f"connection from {rand_ip()} accepted",
            f"backup job started by {random.choice(usernames)}",
            f"backup completed — {random.randint(1,50)}GB written",
            f"authentication success: {random.choice(usernames)}@{rand_ip()}",
            f"scheduled task triggered: db_sync",
            f"SSL cert verified: hash={fake_hash()[:16]}",
            f"config reload by {random.choice(usernames)}",
            f"port scan detected from {rand_ip()} — blocked"
        ])
        lines.append(f"[{ts}] {event}")

    lines.sort()
    lines.append(f"[{fake_timestamp()}] === CYCLE {cycle} COMPLETE ===")

    path = os.path.join(BASE, "logs", "backup_server_logs.log")
    with open(path, "w") as f:
        f.write("\n".join(lines))
    print(f"  [+] logs updated")


def generate_backup_manifest():
    lines = [
        f"BACKUP MANIFEST",
        f"Generated  : {fake_timestamp()}",
        f"Job ID     : BKP-{random.randint(10000,99999)}",
        f"Cycle      : {cycle}",
        ""
    ]
    for i in range(20):
        size = random.randint(100, 9999)
        lines.append(f"  file_{i:03d}.tar.gz   {size:>6} MB   {fake_hash()}")

    path = os.path.join(BASE, "backups", "backup_manifest.txt")
    with open(path, "w") as f:
        f.write("\n".join(lines))
    print(f"  [+] backup manifest updated")


# --- Main ---

def generate_assets():
    global cycle
    cycle += 1
    print(f"\n{'='*45}")
    print(f"  CYCLE {cycle} — {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"  Next update in {INTERVAL} seconds")
    print(f"{'='*45}")
    generate_credentials()
    generate_database()
    generate_finance()
    generate_server_config()
    generate_devops_keys()
    generate_logs()
    generate_backup_manifest()


def main():
    os.makedirs(BASE, exist_ok=True)
    for folder in folders:
        os.makedirs(os.path.join(BASE, folder), exist_ok=True)

    print("=" * 45)
    print("   DECEPTION ASSET GENERATOR v2.0")
    print(f"   Interval : every {INTERVAL} seconds")
    print(f"   Output   : {BASE}/")
    print(f"   Alerts   : {ALERT_LOG}")
    print("=" * 45)

    while True:
        monitor_all()
        generate_assets()
        time.sleep(INTERVAL)


if __name__ == "__main__":
    main()
