# Dynamic Deception-Based Cyber Defense System

## 📌 Project Overview
This project implements a Dynamic Deception-Based Cyber Defense System designed to detect and analyze malicious activities using deception techniques such as decoy assets.

Traditional security systems like firewalls and IDS are reactive, whereas this system proactively attracts attackers using fake but realistic assets and monitors their behavior.

---

## 🎯 Objective
To develop a system that:
- Generates realistic decoy assets
- Attracts attackers into a controlled environment
- Detects unauthorized access attempts
- Enhances cyber defense using deception techniques

---

## 🧱 System Architecture

```

Internet
|
Firewall
|
-

|                        |
Production Network   Deception Network
|
Decoy Assets
|
Monitoring
|
Threat Scoring
|
Alert System

```

---

## ⚙️ Modules

### 🔹 Module 1: Decoy Asset Generation
- Generates realistic fake assets such as:
  - Credentials
  - Database dumps
  - Server configurations
  - Financial records
  - Logs and keys
- Assets are dynamically updated at regular intervals
- Stored inside a simulated **deception network**

---

### 🔹 Module 2: Monitoring Module
- Tracks interaction with decoy assets
- Logs access details such as:
  - File accessed
  - Time
  - User/IP

---

### 🔹 Module 3: Threat Scoring Module
- Evaluates suspicious activity
- Assigns a threat score based on behavior

---

### 🔹 Module 4: Alert & Response Module
- Generates alerts when suspicious activity is detected
- Can trigger automated response actions

---

## 🛠️ Technologies Used
- Python
- File System Monitoring
- Random Data Generation
- Logging Mechanisms

---

## 📂 Project Structure

```

project/
│
├── decoy_generator.py
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

## 🚀 How It Works

1. The system generates realistic fake assets inside a deception environment
2. These assets mimic sensitive enterprise data
3. Assets are dynamically updated to maintain realism
4. Attackers interacting with these assets can be detected and analyzed

---

## 🔐 Key Features

- Dynamic decoy asset generation
- Realistic enterprise-like data
- Automated periodic updates
- Simulated deception network environment
- Scalable modular architecture

---

## 📊 Use Case

- Detect unauthorized access attempts
- Study attacker behavior
- Enhance proactive cybersecurity defense

---

## 📌 Conclusion

This project demonstrates how deception techniques can improve cybersecurity by misleading attackers and providing valuable insights into attack patterns.

---

## 👨‍💻 Author
   NITHIN 
