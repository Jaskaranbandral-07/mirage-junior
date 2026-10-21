<div align="center">

# 🛡️ MIRAGE Junior — Intelligent Deception Network
### *Next-Generation Lightweight Honeypot with Behavioral Threat Scoring & Auto-Quarantine*

[![Live Demo](https://img.shields.io/badge/Vercel-Live%20Demo-brightgreen?logo=vercel&style=for-the-badge)](https://mirage-junior.vercel.app)
[![Python](https://img.shields.io/badge/Python-3.10+-3776AB?logo=python&logoColor=white&style=for-the-badge)](https://python.org)
[![Framework](https://img.shields.io/badge/Flask-3.0-000000?logo=flask&logoColor=white&style=for-the-badge)](https://flask.palletsprojects.com/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg?style=for-the-badge)](https://opensource.org/licenses/MIT)
[![MITRE ATT&CK](https://img.shields.io/badge/MITRE%20ATT%26CK-Mapped-red?style=for-the-badge)](https://attack.mitre.org)

<p align="center">
  <b>A proactive cyber deception system that doesn't just passively log attacks — it scores, classifies, and auto-quarantines threats in real-time.</b>
</p>

[🌐 Live Showcase](https://mirage-junior.vercel.app) • [📖 Full PRD Document](College_PRD.md) • [👥 Contributors](CONTRIBUTORS.md) • [🚀 Quick Start](#-quick-start)

</div>

---

## 🌟 What Makes MIRAGE Junior Different?

Most undergraduate honeypots stop at *"log the attack and display it in a basic table"*. **MIRAGE Junior transforms passive logging into an active defense pipeline:**

| Feature | Standard Student Honeypot | 🛡️ MIRAGE Junior |
| :--- | :---: | :---: |
| **Attack Logging** | ✅ Basic IP and timestamp | ✅ Full protocol telemetry & details |
| **Analytics Dashboard** | ⚠️ Static HTML table | ✅ **Rich SOC dashboard with Chart.js & dark neon theme** |
| **Threat Scoring Engine** | ❌ Not implemented | ✅ **Real-time behavioral risk scoring (0–100 scale)** |
| **Honeytoken Tripwires** | ❌ None | ✅ **Fake `.env`, `.xlsx`, and DB dumps that alarm when touched** |
| **Automated Quarantine** | ❌ Zero auto-response | ✅ **Auto-blocks high-risk IPs via OS Firewall (`netsh`/`iptables`)** |
| **Attack Timeline Replay** | ❌ None | ✅ **Chronological visual narrative replay per attacker** |
| **MITRE ATT&CK Mapping** | ❌ None | ✅ **Every interaction mapped to real-world TTPs** |

---

## 🏗️ System Architecture

```
                    ┌──────────────────────────────┐
                    │      ATTACKER / BOTNET       │
                    └──────┬───────┬───────┬───────┘
                           │       │       │
                     SSH   │  HTTP │  FTP  │
                   (:2222) │(:8080)│(:2121)│
                           │       │       │
               ┌───────────▼───────▼───────▼───────────┐
               │         MIRAGE Junior Core            │
               │  ┌─────────────────────────────────┐  │
               │  │     Honeypot Trap Layer         │  │
               │  │  • HTTP Decoy (Flask)           │  │
               │  │  • SSH Trap (Paramiko Shell)    │  │
               │  │  • FTP Decoy (pyftpdlib)        │  │
               │  └────────────────┬────────────────┘  │
               │                   │ Telemetry         │
               │  ┌────────────────▼────────────────┐  │
               │  │     Intelligence Pipeline       │  │
               │  │  • Behavioral Scoring (0-100)   │  │
               │  │  • MITRE ATT&CK Auto-Tagger     │  │
               │  │  • GeoIP Enricher (ip-api)      │  │
               │  └────────────────┬────────────────┘  │
               │                   │ Score >= 76       │
               │  ┌────────────────▼────────────────┐  │
               │  │     Active Response Engine      │  │
               │  │  • OS Firewall Auto-Quarantine  │  │
               │  │  • Graded Telegram Push Alerts  │  │
               │  └────────────────┬────────────────┘  │
               └───────────────────┼───────────────────┘
                                   │
                     ┌─────────────▼─────────────┐
                     │   SQLite Database (WAL)   │
                     │    (mirage_junior.db)     │
                     └─────────────┬─────────────┘
                                   │
                     ┌─────────────▼─────────────┐
                     │   Flask Web Dashboard     │
                     │       (Port 5000)         │
                     │   mirage-junior.vercel.app│
                     └───────────────────────────┘
```

---

## 🎯 Key Features Breakdown

### 1. 🧠 Behavioral Threat Scoring Engine (0–100)
Every interaction dynamically accumulates threat points based on attacker intent:
- **Baseline Interaction:** `+5 pts` (Port scan, robots.txt visit)
- **Credential Brute-Force:** `+8 pts` per attempt (`root/admin`, `admin/admin`)
- **Lateral Scanning:** `+15 pts` (Attacking multiple trap protocols)
- **Targeted Reconnaissance:** `+20 pts` (Hitting `/.env`, `/api/config`, `/wp-login.php`)
- **Interactive Shell Access:** `+15 pts` (Gaining decoy SSH terminal)
- **Malicious Command Execution:** `+5 pts` (`whoami`, `cat /etc/passwd`, `id`)
- **Honeytoken Tripwire Touch:** `+25 pts` (Downloading fake credentials or database backups)

#### Attacker Classification & Automated Action:
- 🟢 **Scanner (`0–20 pts`):** Logged for reconnaissance tracking.
- 🟡 **Suspicious (`21–50 pts`):** Logged + Telegram warning dispatched.
- 🟠 **Active Threat (`51–75 pts`):** Logged + escalated Telegram push notification.
- 🔴 **Critical Threat (`76–100 pts`):** **Immediate Automated Firewall Quarantine + Telegram Alert!**

---

### 2. 🛡️ Active Auto-Quarantine (Firewall-Level Defense)
Moves from passive watching to **active system protection**:
- **Windows:** Adds active Windows Firewall rule:
  ```powershell
  netsh advfirewall firewall add rule name="MIRAGE_BLOCK_{IP}" dir=in action=block remoteip={IP}
  ```
- **Linux:** Adds immediate kernel drop rule:
  ```bash
  iptables -A INPUT -s {IP} -j DROP
  ```
- **CIDR Whitelist Protection:** Subnets (`127.0.0.1`, `192.168.0.0/16`, `10.0.0.0/8`) are immune to prevent accidental self-blocking.
- **Auto-Expiration:** Quarantines expire after 1 hour (3600s) to keep firewall tables clean.
- **Manual Override:** Admin can unblock any IP in 1-click directly from the dashboard.

---

### 3. 🪤 Honeytoken Tripwire System
Plants high-value fake digital bait that legitimate users never touch:
- **`/.env` Endpoint:** Decoy database and AWS credentials served on port 8080.
- **`credentials.xlsx`:** Planted fake employee passwords served via FTP on port 2121.
- **Local Bait Files:** Filesystem tripwires (`bait/backup_database.sql`, `bait/admin_passwords.txt`, `bait/ssh_keys/id_rsa`) actively monitored by Python's `watchdog` daemon.

---

### 4. 🗺️ MITRE ATT&CK Mapping
Every recorded event is automatically mapped to enterprise MITRE techniques:
- **T1046:** Network Service Scanning
- **T1110:** Brute Force Credential Access
- **T1078.001:** Default Accounts Usage
- **T1552.001:** Credentials in Files (`.env`, config)
- **T1033:** System Owner / User Discovery (`whoami`)
- **T1087.001:** Local Account Discovery (`cat /etc/passwd`)
- **T1005:** Data from Local System (FTP file download)
- **T1083:** File & Directory Discovery (Honeytoken triggers)

---

### 5. 📊 SOC Analytics Dashboard
- **Command Overview:** Live stat cards, Threat Distribution pie chart, Top Attacking Countries bar chart, 24h Attack Timeline, and live auto-updating event feeds.
- **Full Attack Log:** 10 records per page with protocol filters (`SSH`, `HTTP`, `FTP`, `Honeytokens`), search filters, MITRE tags, and CSV export.
- **Attacker Profile & Timeline Replay:** Deep-dive into individual attacker IPs with chronological narrative timeline replay.
- **Quarantine Manager:** Monitor currently jailed IPs, view historical auto-expiries, and unblock with confirmation.
- **Honeytokens Hub:** Audit trail of every bait interaction and process attribution.
- **Settings Panel:** Configure Telegram Bot alerts, quarantine sensitivity, and CIDR whitelist.

---

## 🚀 Quick Start

### 1. Clone & Install Dependencies
```bash
git clone https://github.com/Jaskaranbandral-07/mirage-junior.git
cd mirage-junior
pip install -r requirements.txt
```

### 2. Initialize Database & Run Traps
```bash
# Initialize SQLite database with indexes & WAL mode
python database/db_setup.py

# Start all honeypot services + watchdog + dashboard
python main.py
```

> **Demo Showcase Mode:**  
> To seed realistic multi-stage attacks and launch the dashboard immediately:
> ```bash
> python main.py --demo
> ```
> Then open your browser at **`http://localhost:5000`**.

---

## 🧪 Testing & Attack Simulation

Run the automated attack test suite to simulate multi-phase attacks:
```bash
# Run full unit test suite
pytest tests -v

# Run live multi-stage attack simulation (against active honeypots)
python tests/test_attack.py
```

---

## 📁 Repository Structure

```
mirage-junior/
├── config/
│   ├── settings.py           # Central configuration & environment variables
│   ├── scoring_rules.json    # Threat weights per attacker action
│   ├── mitre_mapping.json    # Behavior → MITRE ATT&CK mappings
│   └── whitelist.json        # Subnets immune from quarantine
│
├── honeypots/
│   ├── http_decoy.py         # Flask HTTP trap (Port 8080) with fake admin & .env
│   ├── ssh_trap.py           # Paramiko SSH trap (Port 2222) with interactive shell
│   ├── ftp_trap.py           # pyftpdlib FTP trap (Port 2121) with honeytoken serving
│   └── templates/            # Fake corporate site, admin login, and wp-login decoys
│
├── engine/
│   ├── scoring_engine.py     # Behavioral threat scoring calculator (0-100)
│   ├── quarantine.py         # OS Firewall auto-response & expiry checker
│   ├── alert_manager.py      # Graded Telegram push notification dispatcher
│   ├── geo_enricher.py       # IP geolocation caching & rate-limited lookups
│   ├── mitre_tagger.py       # MITRE technique classifier
│   └── honeytoken_monitor.py # File-system watchdog listener on bait directory
│
├── dashboard/
│   ├── app.py                # Flask application factory
│   ├── routes.py             # Route handlers & pagination (10 per page)
│   ├── demo_data.py          # Realistic attack telemetry generator
│   ├── templates/            # 7 dark-themed cyber UI views
│   └── static/               # Neon dark-mode stylesheet & Chart.js scripts
│
├── database/
│   ├── db_setup.py           # Schema DDL, indexes, and WAL configuration
│   └── db_manager.py         # Concurrency-safe CRUD operations
│
├── bait/                     # Planted honeytoken files (.sql, .txt, id_rsa)
├── tests/                    # Pytest test suite & attack simulator
├── main.py                   # Multi-threaded master orchestrator
├── vercel_app.py             # Serverless WSGI entry point for Vercel
├── vercel.json               # Vercel deployment specification
├── College_PRD.md            # Complete Product Requirements Document (v2.1)
└── CONTRIBUTORS.md           # Team roles & work division
```

---

## 👥 Contributors & Team Division

| Contributor | Role | Core Modules |
| :--- | :--- | :--- |
| **[Jaskaran Bandral](https://github.com/Jaskaranbandral-07)** | **Team Leader** (Backend & Core Engine) | Honeypot Traps (SSH/HTTP/FTP), Scoring Engine, Quarantine, GeoIP, DB Schema, PRD |
| **[Relish Sharma](https://github.com/2024A7R009)** | **Teammate** (Dashboard, UI & Deploy) | Analytics Dashboard, Dynamic Templates, Chart.js, Alerts, Vercel Deployment |

---

## 📜 License

This project is licensed under the **MIT License** — feel free to use, modify, and build upon for academic and research purposes.
