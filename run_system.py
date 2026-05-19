import subprocess
import time
import sys
import os

BANNER = """
╔══════════════════════════════════════════════════╗
║     DYNAMIC DECEPTION-BASED CYBER DEFENSE        ║
║           SYSTEM STARTUP SEQUENCE                ║
╚══════════════════════════════════════════════════╝
"""

STATUS = """
╔══════════════════════════════════════════════════╗
║              SYSTEM ACTIVE                       ║
║                                                  ║
║   Gateway       : ON  (port 3000)                ║
║   Real Server   : ON  (port 8080)                ║
║   Honeypot      : ON  (port 5000)                ║
║   Monitoring    : ON  (Modules 1-4)              ║
║                                                  ║
║   Press Ctrl+C to shut down all components.      ║
╚══════════════════════════════════════════════════╝
"""

print(BANNER)

processes = []

def start(label, cmd, delay=1.5):
    print(f"  [*] Starting {label}...")
    p = subprocess.Popen(cmd)
    processes.append(p)
    time.sleep(delay)
    print(f"  [+] {label} — RUNNING (PID {p.pid})")
    return p

try:
    # ── 1. Gateway (port 3000) — must come first ──
    start("Gateway (app.py)          → port 3000",
          [sys.executable, "app.py"])

    # ── 2. Real Server (port 8080) — serves deception_network/ ──
    start("Real Server (HTTP)        → port 8080",
          [sys.executable, "-m", "http.server", "8080",
           "--directory", "deception_network"])

    # ── 3. Honeypot (port 5000) ──
    start("Honeypot (honeypot_server.py) → port 5000",
          [sys.executable, "honeypot_server.py"])

    # ── 4. Decoy Generator (Module 1) ──
    start("Module 1 — Decoy Generator",
          [sys.executable, "module1_generator.py"])

    # ── 5. Monitor (Module 2) ──
    start("Module 2 — File Monitor",
          [sys.executable, "module2_monitor.py"])

    # ── 6. Scoring Engine (Module 3) ──
    start("Module 3 — Threat Scoring",
          [sys.executable, "module3_scoring.py"])

    # ── 7. Alert Engine (Module 4) ──
    start("Module 4 — Alert & SOC Engine",
          [sys.executable, "module4_alert.py"])

    print(STATUS)

    # Keep alive — wait for any process to exit
    for p in processes:
        p.wait()

except KeyboardInterrupt:
    print("\n  [!] Ctrl+C received — shutting down all components...")
    for p in processes:
        try:
            p.terminate()
        except Exception:
            pass
    print("  [+] All processes terminated. System offline.\n")
    sys.exit(0)

except Exception as e:
    print(f"\n  [ERROR] Startup failed: {e}")
    for p in processes:
        try:
            p.terminate()
        except Exception:
            pass
    sys.exit(1)
