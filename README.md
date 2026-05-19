# Dynamic Deception-Based Cyber Defense System

## 📌 Project Overview
This project implements a **Dynamic Deception-Based Cyber Defense System** designed to detect, redirect, monitor, and analyze malicious activities using deception techniques such as honeypots, decoy assets, behavioral monitoring, and threat scoring.

Traditional security systems such as firewalls and intrusion detection systems are mostly reactive in nature. In contrast, this project uses a proactive approach where suspicious users are silently redirected into a controlled fake environment for monitoring and analysis.

The system combines:
- Gateway-based decision making
- Dynamic deception techniques
- Honeypot technology
- Behavioral monitoring
- Threat scoring and alert generation

---

# 🎯 Objective

The objective of this project is to:

- Detect suspicious login behavior
- Redirect attackers into a controlled honeypot environment
- Generate realistic decoy assets
- Monitor attacker interaction and behavior
- Store detailed forensic logs
- Improve proactive cyber defense using deception technology

---

# 🧠 Core Idea

The project works using two separate systems:

## 🖥️ System 1 — Main Defense System
Contains:
- Gateway login system
- Real production environment
- Internal deception assets
- Monitoring and alert modules

## 🎭 System 2 — Honeypot Server
Contains:
- Fake enterprise dashboard
- Fake users and credentials
- Fake databases
- Fake backup files
- Fake configuration secrets

If suspicious activity is detected, the attacker is redirected from System 1 to System 2 for observation.

---

# 🧱 System Architecture

```text
                    INTERNET
                        │
                        ▼
                 ATTACKER MACHINE
                (Nmap Port Scanning)
                        │
                        ▼
              ┌──────────────────┐
              │  GATEWAY SYSTEM  │
              │     (app.py)     │
              └──────────────────┘
                        │
         ┌──────────────┴──────────────┐
         │                             │
         ▼                             ▼

 VALID LOGIN                    SUSPICIOUS LOGIN
 (Correct Credentials)          (5–10 Wrong Attempts)

         │                             │
         ▼                             ▼

 ┌──────────────────┐       ┌─────────────────────┐
 │   REAL SYSTEM    │       │   HONEYPOT SERVER   │
 │  (Main Computer) │       │ (Second Computer)   │
 └──────────────────┘       └─────────────────────┘
         │                             │
         ▼                             ▼

 Internal Deception           Fake Dashboard
 Fake Assets                  Fake Users
 Fake Logs                    Fake Database
 Fake Config Files            Fake Backups

         │                             │
         └──────────────┬──────────────┘
                        ▼

             ┌──────────────────┐
             │ MONITORING MODULE │
             │  Threat Scoring   │
             │   Alert System    │
             └──────────────────┘
````

---

# 🔄 User Flow / Working Flow

```text
START
   │
   ▼
Attacker scans target using Nmap
   │
   ▼
Finds gateway open port
   │
   ▼
Opens login page
   │
   ▼
Attempts login
   │
   ├───────────────► Valid Credentials
   │                         │
   │                         ▼
   │                 Redirect to Real System
   │
   │
   └───────────────► Multiple Wrong Passwords
                             │
                             ▼
                    Redirect to Honeypot Server
                             │
                             ▼
                   Attacker interacts with
                     fake enterprise system
                             │
                             ▼
                 Monitoring module tracks:
                 - Page visits
                 - File access
                 - Downloads
                 - Suspicious activity
                             │
                             ▼
                   Threat score generated
                             │
                             ▼
                        Alert generated
                             │
                             ▼
                            END
```

---

# ⚙️ Modules

## 🔹 Module 1: Gateway & Decision Module

* Acts as the entry point of the system
* Validates login attempts
* Tracks failed login counts
* Uses a random threshold between 5–10 attempts
* Redirects suspicious users to honeypot system

### Features:

* Login validation
* Redirection logic
* Gateway logging
* Behavior classification

---

## 🔹 Module 2: Decoy Asset Generation Module

Generates realistic fake assets such as:

* Credentials
* Database dumps
* Financial reports
* Server configurations
* Logs and SSH keys

### Features:

* Dynamic file generation
* Realistic enterprise-style data
* Internal deception network

---

## 🔹 Module 3: Monitoring Module

Tracks attacker behavior inside the honeypot.

### Monitored Activities:

* Page visits
* Database access
* Backup downloads
* Sensitive file access
* Navigation behavior

### Logs:

* IP Address
* Timestamp
* Route accessed
* User agent

---

## 🔹 Module 4: Threat Scoring Module

* Calculates threat score based on attacker behavior
* Detects suspicious actions
* Assigns severity levels

### Severity Levels:

* LOW
* MEDIUM
* HIGH
* CRITICAL

---

## 🔹 Module 5: Alert & Response Module

Generates alerts whenever suspicious behavior is detected.

### Alert Conditions:

* Multiple failed logins
* Backup download attempts
* Rapid navigation
* Sensitive page access

### Output:

* Console alerts
* JSON logs
* Threat reports

---

# 🛠️ Technologies Used

* Python
* Flask
* JSON Logging
* File System Monitoring
* Random Data Generation
* Behavioral Analysis
* Threat Scoring
* Nmap (for attacker simulation)

---

# 📂 Project Structure

```text
project/
│
├── app.py
├── honeypot_server.py
├── run_system.py
├── module1_generator.py
├── module2_monitor.py
├── module3_scoring.py
├── module4_alert.py
│
├── gateway_logs.txt
├── honeypot_log.txt
├── honeypot_events.json
├── monitor_log.txt
├── deception_alerts.log
│
└── deception_network/
    ├── credentials/
    ├── database/
    ├── finance/
    ├── infrastructure/
    ├── devops/
    └── logs/
```

---

# 🚀 How It Works

1. The attacker scans the target system using Nmap
2. The attacker finds the gateway login page
3. The gateway analyzes login attempts
4. Legitimate users are redirected to the real system
5. Suspicious users are redirected to the honeypot server
6. The honeypot monitors every attacker action
7. Monitoring module tracks behavior
8. Threat scoring module evaluates risk
9. Alert module generates warnings and logs

---

# 🔐 Key Features

* Dynamic deception technology
* Gateway-based attacker classification
* Separate honeypot environment
* Behavioral monitoring
* Threat scoring
* Alert generation
* Realistic fake enterprise data
* Modular architecture
* Honeypot logging and analysis

---

# 📊 Log Files

| File                 | Purpose                               |
| -------------------- | ------------------------------------- |
| gateway_logs.txt     | Login attempts and redirect decisions |
| honeypot_log.txt     | Human-readable honeypot logs          |
| honeypot_events.json | Structured honeypot activity logs     |
| monitor_log.txt      | Behavior monitoring logs              |
| deception_alerts.log | Security alert logs                   |

---

# 📊 Use Cases

* Detect unauthorized access attempts
* Study attacker behavior
* Threat intelligence collection
* Cybersecurity research
* SOC monitoring simulation
* Honeypot analysis
* Deception-based defense research

---

# 🔮 Future Enhancements

* AI/ML-based anomaly detection
* SIEM integration
* Real-time dashboards
* Cloud deployment
* Automated response actions
* Multi-honeypot architecture
* Network-level deception

---

# 📌 Conclusion

This project demonstrates how deception technology can improve cybersecurity by misleading attackers and collecting valuable behavioral intelligence.

Instead of immediately blocking suspicious users, the system redirects them into a controlled honeypot environment where their activities can be monitored, analyzed, and logged safely.

The combination of gateway intelligence, deception techniques, behavioral monitoring, and threat scoring provides a proactive and adaptive cybersecurity defense mechanism.

---

# 👨‍💻 Author

NITHIN

```
```
