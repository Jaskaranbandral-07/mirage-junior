# Product Requirements Document (PRD)
## MIRAGE Junior — Intelligent Deception Network with Threat Scoring
### *A Next-Generation Lightweight Honeypot System for Proactive Cyber Defense*

---

## 1. Executive Summary

**Project Name:** MIRAGE Junior (Multi-layered Intelligent Response & Adaptive Gathering Engine — Junior Edition)

**Version:** 2.0 (Enhanced)

**Target Audience:** 3rd Year Cyber Security / Computer Science Students

**Institution Level:** Undergraduate College Project

**Objective:** Build an intelligent, lightweight deception network that doesn't just *capture* attacks — it **scores**, **classifies**, and **auto-responds** to attacker behavior in real-time, while maintaining a dead-simple single-machine deployment.

### What Makes This Different From Every Other Honeypot Project?

Most college honeypot projects stop at "log the attack and show it on a dashboard." **MIRAGE Junior goes three critical steps further:**

| Feature | Typical College Honeypot | MIRAGE Junior |
|---|---|---|
| Attack Logging | ✅ Logs IPs and credentials | ✅ Same |
| Dashboard | ✅ Basic table view | ✅ Rich interactive dashboard |
| **Threat Scoring Engine** | ❌ Not found in any student project | ✅ **Real-time attacker risk scoring (0-100)** |
| **Honeytoken Tripwire** | ❌ Not found in any student project | ✅ **Fake files that trigger alerts when touched** |
| **Auto-Quarantine** | ❌ Not found in any student project | ✅ **Auto-blocks high-risk IPs via firewall rules** |
| **Attack Timeline Replay** | ❌ Not found in any student project | ✅ **Step-by-step visual replay of an attack session** |
| **MITRE ATT&CK Mapping** | ❌ Not found in any student project | ✅ **Maps captured behavior to real-world TTPs** |

> **Why this matters for evaluation:** Evaluators see dozens of "honeypot + dashboard" projects every year. MIRAGE Junior demonstrates *threat intelligence thinking* — the same mindset used by Security Operations Centers (SOCs) in industry. This shows you understand not just *how* to capture attacks, but *what to do with the data*.

---

## 2. Problem Statement

### The Industry Gap
Traditional cybersecurity defenses (firewalls, IDS/IPS, antivirus) are purely **reactive** — they only block known, signature-based threats. Proactive defenses like enterprise deception networks (T-Pot, Cowrie, Dionaea) exist, but they are:
- **Resource-heavy** (T-Pot requires 8-16 GB RAM, Docker, ELK stack)
- **Complex to deploy** (requires DevOps knowledge, containerization)
- **Overkill for learning** (20+ honeypot daemons running simultaneously)

### The Student Gap
Existing student honeypot projects on GitHub share the same fundamental weakness:
- They **log** attacks but don't **analyze** them
- They show data in a table but don't **score** or **classify** attackers
- They have **zero automated response** — a human must manually review every log
- They don't connect captured behavior to any **real-world threat framework**

### Our Solution
MIRAGE Junior bridges both gaps by providing:
1. A **simple, single-machine** honeypot system (no Docker, no Kubernetes)
2. An **intelligent scoring engine** that automatically rates attacker severity
3. **Automated response** capabilities (IP quarantine, alert escalation)
4. **Threat framework mapping** that connects raw logs to the MITRE ATT&CK knowledge base

---

## 3. Core Features — Detailed Breakdown

### 3.1 The Traps (Honeypot Services)

#### 3.1.1 HTTP Decoy Server (Port 8080)
**Technology:** Python Flask
**What it emulates:** A vulnerable web application with fake admin panels

**Endpoints:**
| Route | Purpose | What Gets Logged |
|---|---|---|
| `/` | Landing page (fake corporate site) | IP, User-Agent, timestamp |
| `/admin` | Fake admin login panel | IP, credentials submitted |
| `/wp-login.php` | WordPress login decoy | IP, credentials submitted |
| `/phpmyadmin/` | phpMyAdmin decoy | IP, credentials submitted |
| `/api/config` | Fake exposed API endpoint | IP, User-Agent, headers |
| `/robots.txt` | Deliberate "disallow" bait entries | IP (shows attacker is scanning) |
| `/.env` | Fake exposed environment file | IP (high-severity indicator) |

**Behavior:**
- Every login attempt always returns "Invalid credentials, please try again" (never grants access)
- Responses include realistic HTTP headers (`X-Powered-By: PHP/7.4`, `Server: Apache/2.4.41`)
- Fake `.env` file contains planted honeytokens (see §3.3)
- Response times are artificially delayed by 200-500ms to mimic a real server

#### 3.1.2 SSH Trap (Port 2222)
**Technology:** Python `paramiko` library
**What it emulates:** A misconfigured SSH server with weak credentials

**Behavior:**
- Accepts connection → presents SSH banner (`SSH-2.0-OpenSSH_7.6p1 Ubuntu`)
- Prompts for username and password → logs all attempts
- After 3 failed attempts: simulates a "connection timeout" (mimics real server behavior)
- On "successful" login (if attacker tries `root`/`admin`): drops into a **fake shell** for 10 seconds, logs all commands typed, then disconnects with `Segmentation fault (core dumped)`
- The brief fake shell session captures attacker *intent* — what commands they try first reveals their objective

**Fake Shell Commands Supported:**
| Command | Fake Response |
|---|---|
| `whoami` | `root` |
| `id` | `uid=0(root) gid=0(root)` |
| `uname -a` | `Linux prod-server 4.15.0 #1 SMP x86_64 GNU/Linux` |
| `cat /etc/passwd` | Fake passwd file with planted usernames |
| `ls` | Fake directory listing |
| Any other | Logged as-is, returns empty output |

#### 3.1.3 FTP Trap (Port 2121) — *NEW*
**Technology:** Python `pyftpdlib` or raw socket
**What it emulates:** An FTP server with anonymous access enabled

**Behavior:**
- Allows anonymous login (logs it as low-severity)
- Credential attempts are logged (medium-severity)
- Lists fake directory with enticing filenames (`backup_db_2026.sql`, `credentials.xlsx`)
- Any download attempt of these files triggers high-severity alert + serves a honeytoken file

---

### 3.2 The Intelligence Engine — Attacker Threat Scoring 🧠

> **This is the #1 differentiator.** No student honeypot project implements behavioral threat scoring.

#### How It Works
Every attacker IP accumulates a **Threat Score** (0-100) based on their behavior across all honeypots. The score is calculated in real-time using a weighted point system:

#### Scoring Rules
| Behavior | Points | Rationale |
|---|---|---|
| First connection to any honeypot | +5 | Baseline — could be a scanner |
| Multiple login attempts (>3) | +10 | Indicates brute-force intent |
| Tries default credentials (`admin/admin`, `root/root`) | +8 | Common bot behavior |
| Hits multiple honeypot services | +15 | Lateral scanning — higher sophistication |
| Accesses `/.env` or `/api/config` | +20 | Targeted reconnaissance |
| Achieves "fake shell" access | +15 | Post-exploitation phase reached |
| Runs commands in fake shell | +5 per command | Active exploitation attempt |
| Triggers a honeytoken | +25 | High-confidence malicious intent |
| Repeat visit within 1 hour | +10 | Persistent threat |

#### Threat Classification
| Score Range | Classification | Dashboard Color | Action |
|---|---|---|---|
| 0-20 | 🟢 **Scanner** | Green | Log only |
| 21-50 | 🟡 **Suspicious** | Yellow | Log + Telegram alert |
| 51-75 | 🟠 **Active Threat** | Orange | Log + Telegram + escalated alert |
| 76-100 | 🔴 **Critical Threat** | Red | Log + Telegram + **Auto-Quarantine** |

#### Implementation
```python
# Simplified scoring logic (actual implementation in scoring_engine.py)
def calculate_threat_score(ip_address):
    score = 0
    events = db.get_events_by_ip(ip_address)
    
    for event in events:
        score += SCORING_RULES[event.type]
    
    # Cap at 100
    score = min(score, 100)
    
    # Classify
    if score >= 76:
        trigger_quarantine(ip_address)
        send_telegram_alert(ip_address, "CRITICAL", score)
    elif score >= 51:
        send_telegram_alert(ip_address, "ACTIVE_THREAT", score)
    elif score >= 21:
        send_telegram_alert(ip_address, "SUSPICIOUS", score)
    
    return score
```

---

### 3.3 Honeytoken Tripwire System 🪤

> **Second unique differentiator.** Combines file-system deception with network honeypots.

#### What Are Honeytokens?
Honeytokens are fake, deliberately planted "bait" data that no legitimate user would ever access. Any interaction with them is a **high-confidence indicator of compromise**.

#### Implementation
MIRAGE Junior plants three types of honeytokens:

**Type 1: Fake `.env` File (served by HTTP decoy)**
```
# .env - Server Configuration
DB_HOST=192.168.1.100
DB_USER=admin
DB_PASS=Str0ngP@ssw0rd!2026
AWS_ACCESS_KEY=AKIA3EXAMPLE7TOKEN
TELEGRAM_BOT_TOKEN=fake:AAF-token-here
```
When an attacker accesses this endpoint → +20 threat score + immediate alert

**Type 2: Fake Credential File (served by FTP decoy)**
A `credentials.xlsx` that when "downloaded" logs the attacker's IP and triggers an alert. The file contains fake but realistic-looking entries to waste attacker time.

**Type 3: Directory Tripwire (local file system)**
Using Python's `watchdog` library, monitors a local directory (`/opt/mirage/bait/`) containing enticing files:
- `backup_database.sql`
- `ssh_keys/id_rsa`
- `admin_passwords.txt`

Any access to these files (read, copy, modify) triggers:
- Immediate Telegram alert
- +25 threat score for the session
- Timestamped log of which file was accessed and by which process

---

### 3.4 Automated IP Quarantine (Auto-Response) 🛡️

> **Third unique differentiator.** Moves from passive logging to active defense.

When an attacker's Threat Score crosses the **Critical (76+)** threshold:

1. **Windows:** Adds a Windows Firewall rule to block the IP
   ```
   netsh advfirewall firewall add rule name="MIRAGE_BLOCK_{IP}" dir=in action=block remoteip={IP}
   ```
2. **Linux:** Adds an `iptables` rule
   ```
   iptables -A INPUT -s {IP} -j DROP
   ```

**Safety Features:**
- Quarantine is **temporary** (auto-expires after 1 hour by default)
- A **whitelist** prevents accidental blocking of your own IP, localhost, and LAN ranges
- All quarantine actions are logged and visible on the dashboard
- Manual override button on dashboard to unblock any IP instantly

---

### 3.5 Attack Timeline Replay 🔄

> **Fourth unique differentiator.** Visual storytelling of an attack — evaluators love this.

For each attacker session, the dashboard provides a **step-by-step timeline** showing:

```
TIMELINE: Attacker 45.33.32.156 (Russia, Moscow)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
11:02:03  🌐 HTTP scan on /robots.txt .................. [+5 pts → Score: 5]
11:02:05  🌐 HTTP GET /wp-login.php .................... [+5 pts → Score: 10]
11:02:08  🔑 HTTP login attempt (admin/password123) .... [+8 pts → Score: 18]
11:02:12  🌐 HTTP GET /.env ............................ [+20 pts → Score: 38]  ⚠️
11:03:44  🖥️  SSH connection attempt .................... [+15 pts → Score: 53] 🟠
11:03:47  🔑 SSH login (root/admin123) ................. [+8 pts → Score: 61]
11:03:48  🔑 SSH login (root/toor) ..................... [+8 pts → Score: 69]
11:03:50  💻 SHELL ACCESS - ran: whoami ................. [+15+5 → Score: 89] 🔴
11:03:51  💻 SHELL - ran: cat /etc/passwd .............. [+5 pts → Score: 94]
11:03:52  🔴 AUTO-QUARANTINE TRIGGERED — IP BLOCKED
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Total Session Duration: 1m 49s | Final Score: 94/100 | Class: CRITICAL
MITRE ATT&CK: T1190 (Exploit Public App), T1078 (Valid Accounts), T1059 (Command Exec)
```

This is rendered as an interactive component on the dashboard with color coding and expandable details for each event.

---

### 3.6 MITRE ATT&CK Mapping 🗺️

> **Fifth unique differentiator.** Bridges academic learning with industry-standard frameworks.

Each captured behavior is automatically tagged with its corresponding [MITRE ATT&CK](https://attack.mitre.org/) technique:

| Captured Behavior | MITRE Technique ID | Tactic |
|---|---|---|
| Port scanning (hits multiple services) | T1046 — Network Service Scanning | Discovery |
| Brute-force SSH/HTTP login | T1110 — Brute Force | Credential Access |
| Tries default credentials | T1078.001 — Default Accounts | Initial Access |
| Accesses `/.env` or config files | T1552.001 — Credentials in Files | Credential Access |
| Runs `whoami`, `id` in fake shell | T1033 — System Owner Discovery | Discovery |
| Runs `cat /etc/passwd` | T1087.001 — Local Account Discovery | Discovery |
| Attempts file download via FTP | T1005 — Data from Local System | Collection |
| Accesses honeytoken files | T1083 — File and Directory Discovery | Discovery |

This mapping is stored in a simple Python dictionary (no external API needed) and displayed both in the timeline view and as a summary chart on the dashboard.

---

### 3.7 Real-Time Alerts & Notifications 📱

**Telegram Bot Integration:**
- Instant push notifications graded by severity
- Format example:
  ```
  🔴 CRITICAL ALERT — MIRAGE Junior
  ━━━━━━━━━━━━━━━━━━━━━━━━━━
  🕐 Time: 2026-09-30 11:03:52
  🌍 IP: 45.33.32.156 (Russia, Moscow)
  📊 Threat Score: 94/100
  🎯 Classification: CRITICAL THREAT
  🛡️ Action: AUTO-QUARANTINED
  
  📋 Summary:
  • 3 HTTP scans (inc. /.env access)
  • 2 SSH brute-force attempts
  • Gained fake shell access
  • Ran: whoami, cat /etc/passwd
  
  🗺️ MITRE ATT&CK: T1190, T1078, T1059
  ```

**Alert Levels:**
| Level | Trigger | Notification |
|---|---|---|
| 🟢 Info | Score 0-20 | Dashboard only (no notification) |
| 🟡 Warning | Score 21-50 | Telegram message |
| 🟠 High | Score 51-75 | Telegram message + sound |
| 🔴 Critical | Score 76-100 | Telegram message + sound + quarantine confirmation |

### 3.8 IP Geolocation Enrichment 🌍
**Technology:** Free `ip-api.com` API (no API key required, 45 requests/min)

Each attacker IP is enriched with:
- Country & City
- ISP / Organization
- Latitude & Longitude (for map plotting)
- AS Number (Autonomous System)

Cached locally to avoid duplicate API calls for the same IP.

---

## 4. Analytics Dashboard

**Technology:** Flask (backend) + HTML/CSS/JS + Chart.js (frontend)
**Port:** 5000

### Dashboard Layout

```
┌─────────────────────────────────────────────────────────────────┐
│  MIRAGE Junior — Deception Network Command Center       [LIVE] │
├──────────┬──────────┬──────────┬──────────┬────────────────────┤
│ Total    │ Unique   │ Creds    │ Avg      │ IPs Quarantined    │
│ Hits     │ IPs      │ Captured │ Threat   │                    │
│  1,247   │   89     │   312    │ Score:47 │       12           │
├──────────┴──────────┴──────────┴──────────┴────────────────────┤
│                                                                 │
│  ┌─ THREAT DISTRIBUTION ──┐  ┌─ TOP ATTACKING COUNTRIES ─────┐ │
│  │  🟢 Scanner:    42%    │  │  🇷🇺 Russia      — 34 hits    │ │
│  │  🟡 Suspicious: 31%    │  │  🇨🇳 China       — 28 hits    │ │
│  │  🟠 Active:     19%    │  │  🇺🇸 USA         — 12 hits    │ │
│  │  🔴 Critical:    8%    │  │  🇧🇷 Brazil      —  8 hits    │ │
│  └────────────────────────┘  │  🇮🇳 India       —  7 hits    │ │
│                               └───────────────────────────────┘ │
│                                                                 │
│  ┌─ ATTACK TIMELINE (Last 24h) ─────────────────────────────┐  │
│  │  ▂▃▅▇█▇▅▃▂▁▁▂▃▄▅▇█▇▅▃▂▁▁▂▃▅ (hourly bar chart)         │  │
│  └───────────────────────────────────────────────────────────┘  │
│                                                                 │
│  ┌─ MITRE ATT&CK HEATMAP ───────────────────────────────────┐  │
│  │  T1110 Brute Force        ████████████████ 156            │  │
│  │  T1078 Default Accounts   ██████████ 98                   │  │
│  │  T1046 Network Scanning   ████████ 78                     │  │
│  │  T1552 Creds in Files     ██████ 45                       │  │
│  │  T1033 System Discovery   ████ 34                         │  │
│  └───────────────────────────────────────────────────────────┘  │
│                                                                 │
│  ┌─ LIVE ATTACK LOG ────────────────────────────────────────┐  │
│  │  Time   │ IP          │ Country │ Action     │ Score │ ⚡ │  │
│  │  11:03  │ 45.33.32.x  │ 🇷🇺 RU   │ SSH brute  │ 94 🔴│  │  │
│  │  11:01  │ 103.22.4.x  │ 🇨🇳 CN   │ HTTP scan  │ 38 🟡│  │  │
│  │  10:58  │ 192.168.1.x │ 🏠 LAN  │ FTP anon   │ 12 🟢│  │  │
│  └─────────────────────────────────────────────── [See All] ┘  │
│                                                                 │
│  ┌─ QUARANTINE LOG ─────────────────────────────────────────┐  │
│  │  45.33.32.156  │  Blocked at 11:03  │  Expires 12:03  │ 🔓│  │
│  └───────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
```

### Dashboard Pages
| Page | Route | Description |
|---|---|---|
| Overview | `/` | Stats cards, charts, live feed (shown above) |
| Attack Log | `/attacks` | Full paginated table of all events |
| Attacker Profile | `/attacker/<ip>` | Deep-dive on a single IP: timeline, score breakdown, MITRE tags |
| Quarantine | `/quarantine` | Active blocks, history, manual unblock button |
| Honeytokens | `/honeytokens` | Status of planted tokens, trigger history |
| Settings | `/settings` | Configure Telegram bot, scoring weights, whitelist |

---

## 5. System Architecture

```
                    ┌──────────────────────────────┐
                    │      ATTACKER / BOT          │
                    └──────┬───────┬───────┬───────┘
                           │       │       │
                     SSH   │  HTTP │  FTP  │
                   (:2222) │(:8080)│(:2121)│
                           │       │       │
              ┌────────────▼───────▼───────▼────────────┐
              │         MIRAGE Junior Core               │
              │  ┌─────────────────────────────────────┐ │
              │  │       Honeypot Service Layer         │ │
              │  │  ┌─────────┬──────────┬───────────┐ │ │
              │  │  │SSH Trap │HTTP Decoy│ FTP Trap  │ │ │
              │  │  │(paramiko│ (Flask)  │(pyftpdlib)│ │ │
              │  │  └────┬────┴────┬─────┴─────┬─────┘ │ │
              │  └───────┼─────────┼───────────┼───────┘ │
              │          │ Events  │           │          │
              │  ┌───────▼─────────▼───────────▼───────┐ │
              │  │      Event Processing Pipeline       │ │
              │  │  ┌──────────┐  ┌──────────────────┐ │ │
              │  │  │ Logger   │→ │ Scoring Engine   │ │ │
              │  │  └──────────┘  └────────┬─────────┘ │ │
              │  │                         │            │ │
              │  │  ┌──────────┐  ┌────────▼─────────┐ │ │
              │  │  │ GeoIP    │  │ MITRE ATT&CK     │ │ │
              │  │  │ Enricher │  │ Mapper            │ │ │
              │  │  └──────────┘  └──────────────────┘ │ │
              │  └─────────────────────────────────────┘ │
              │          │                               │
              │  ┌───────▼─────────────────────────────┐ │
              │  │      Response Engine                 │ │
              │  │  ┌──────────┐  ┌──────────────────┐ │ │
              │  │  │ Telegram │  │ Auto-Quarantine  │ │ │
              │  │  │ Alerter  │  │ (Firewall Rules) │ │ │
              │  │  └──────────┘  └──────────────────┘ │ │
              │  └─────────────────────────────────────┘ │
              └──────────────────┬───────────────────────┘
                                 │
                    ┌────────────▼────────────┐
                    │   SQLite Database       │
                    │   (mirage_junior.db)    │
                    └────────────┬────────────┘
                                 │
                    ┌────────────▼────────────┐
                    │   Flask Dashboard       │
                    │       (:5000)           │
                    └────────────────────────-┘
                                 │
              ┌──────────────────┼──────────────────┐
              │                  │                   │
     ┌────────▼───────┐ ┌───────▼────────┐ ┌───────▼────────┐
     │  ip-api.com    │ │ Telegram Bot   │ │ Honeytoken     │
     │  (Geolocation) │ │ API (Alerts)   │ │ Monitor        │
     └────────────────┘ └────────────────┘ │ (watchdog)     │
                                           └────────────────┘
```

---

## 6. Database Schema

**Technology:** SQLite 3 (serverless, zero-configuration)
**File:** `mirage_junior.db`

### Tables

#### `events` — Core event log
```sql
CREATE TABLE events (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp   DATETIME DEFAULT CURRENT_TIMESTAMP,
    ip_address  TEXT NOT NULL,
    port        INTEGER,
    protocol    TEXT CHECK(protocol IN ('SSH', 'HTTP', 'FTP', 'HONEYTOKEN')),
    event_type  TEXT NOT NULL,  -- 'connection', 'login_attempt', 'shell_command', 'file_access', 'scan'
    details     TEXT,           -- JSON blob with event-specific data
    threat_pts  INTEGER DEFAULT 0,
    mitre_id    TEXT            -- e.g., 'T1110'
);
```

#### `attackers` — Attacker profiles (aggregated)
```sql
CREATE TABLE attackers (
    ip_address    TEXT PRIMARY KEY,
    first_seen    DATETIME,
    last_seen     DATETIME,
    total_events  INTEGER DEFAULT 0,
    threat_score  INTEGER DEFAULT 0,
    classification TEXT CHECK(classification IN ('SCANNER', 'SUSPICIOUS', 'ACTIVE_THREAT', 'CRITICAL')),
    country       TEXT,
    city          TEXT,
    isp           TEXT,
    latitude      REAL,
    longitude     REAL,
    is_quarantined BOOLEAN DEFAULT 0
);
```

#### `credentials` — Captured login attempts
```sql
CREATE TABLE credentials (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp   DATETIME DEFAULT CURRENT_TIMESTAMP,
    ip_address  TEXT NOT NULL,
    protocol    TEXT,
    username    TEXT,
    password    TEXT,
    success     BOOLEAN DEFAULT 0   -- Always 0 (fake success for shell trap)
);
```

#### `quarantine_log` — Auto-response history
```sql
CREATE TABLE quarantine_log (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    ip_address  TEXT NOT NULL,
    blocked_at  DATETIME DEFAULT CURRENT_TIMESTAMP,
    expires_at  DATETIME,
    reason      TEXT,
    threat_score INTEGER,
    is_active   BOOLEAN DEFAULT 1,
    unblocked_by TEXT   -- 'auto_expire', 'manual', NULL
);
```

#### `honeytoken_triggers` — Token access log
```sql
CREATE TABLE honeytoken_triggers (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp   DATETIME DEFAULT CURRENT_TIMESTAMP,
    token_name  TEXT NOT NULL,  -- e.g., '.env', 'credentials.xlsx'
    token_type  TEXT,           -- 'http_endpoint', 'ftp_file', 'filesystem'
    ip_address  TEXT,
    process_name TEXT,          -- For filesystem tokens
    details     TEXT
);
```

---

## 7. Project File Structure

```
MIRAGE Junior/
├── config/
│   ├── settings.py           # Central configuration (ports, thresholds, API keys)
│   ├── scoring_rules.json    # Threat scoring weights (easily tunable)
│   ├── mitre_mapping.json    # Behavior → MITRE ATT&CK technique mapping
│   └── whitelist.json        # IPs to never quarantine
│
├── honeypots/
│   ├── http_decoy.py         # Flask-based HTTP honeypot
│   ├── ssh_trap.py           # Paramiko-based SSH honeypot
│   ├── ftp_trap.py           # FTP honeypot with file-serve capability
│   └── templates/            # HTML templates for fake web pages
│       ├── index.html        # Fake corporate landing page
│       ├── admin_login.html  # Fake admin panel
│       ├── wp_login.html     # WordPress login clone
│       └── env_file.txt      # Fake .env honeytoken content
│
├── engine/
│   ├── scoring_engine.py     # Threat score calculator
│   ├── mitre_tagger.py       # MITRE ATT&CK auto-tagger
│   ├── geo_enricher.py       # IP geolocation lookup + caching
│   ├── alert_manager.py      # Telegram bot integration
│   ├── quarantine.py         # Firewall rule management
│   └── honeytoken_monitor.py # File-system watchdog for tripwire tokens
│
├── dashboard/
│   ├── app.py                # Flask dashboard application
│   ├── routes.py             # Dashboard route handlers
│   ├── templates/
│   │   ├── base.html         # Base template with nav
│   │   ├── overview.html     # Main dashboard
│   │   ├── attacks.html      # Attack log table
│   │   ├── attacker.html     # Single attacker deep-dive + timeline
│   │   ├── quarantine.html   # Quarantine management
│   │   ├── honeytokens.html  # Honeytoken status page
│   │   └── settings.html     # Configuration page
│   └── static/
│       ├── css/
│       │   └── style.css     # Dashboard styling (dark theme)
│       └── js/
│           ├── charts.js     # Chart.js configurations
│           └── timeline.js   # Attack timeline renderer
│
├── database/
│   ├── db_setup.py           # Database initialization script
│   ├── db_manager.py         # CRUD operations wrapper
│   └── mirage_junior.db      # SQLite database (auto-created)
│
├── bait/                     # Honeytoken bait files (monitored directory)
│   ├── backup_database.sql
│   ├── admin_passwords.txt
│   └── ssh_keys/
│       └── id_rsa
│
├── tests/
│   ├── test_attack.py        # Simulated attack script for demos
│   ├── test_scoring.py       # Unit tests for scoring engine
│   └── test_honeytokens.py   # Unit tests for token triggers
│
├── main.py                   # Single entry point — starts everything
├── requirements.txt          # Python dependencies
└── README.md                 # Setup and usage instructions
```

---

## 8. Tech Stack & Dependencies

### Core
| Component | Technology | Why |
|---|---|---|
| Language | Python 3.10+ | Industry standard for security tooling |
| Database | SQLite 3 | Zero-config, serverless, single-file DB |
| Web Framework | Flask 3.x | Lightweight, perfect for dashboards |
| SSH Server | `paramiko` | Industry-standard Python SSH library |
| FTP Server | `pyftpdlib` | Lightweight, pure-Python FTP server |

### Supporting Libraries
| Library | Purpose |
|---|---|
| `requests` | HTTP calls to Telegram API and ip-api.com |
| `watchdog` | File system monitoring for honeytoken tripwires |
| `chart.js` (CDN) | Dashboard charts and visualizations |
| `threading` | Run multiple honeypots concurrently |
| `json` | Configuration file handling |
| `hashlib` | Honeytoken file integrity checks |
| `datetime` | Timestamp management |
| `subprocess` | Firewall rule execution for quarantine |

### `requirements.txt`
```
flask>=3.0.0
paramiko>=3.4.0
pyftpdlib>=1.5.9
requests>=2.31.0
watchdog>=4.0.0
```

### Hardware Requirements
- **Minimum:** Any machine with 4 GB RAM, Python 3.10+
- **No Docker, no containers, no cloud required**
- Runs on Windows, Linux, or macOS

---

## 9. API & Configuration Reference

### `config/settings.py`
```python
# === Network Configuration ===
HTTP_PORT = 8080
SSH_PORT = 2222
FTP_PORT = 2121
DASHBOARD_PORT = 5000

# === Telegram Configuration ===
TELEGRAM_BOT_TOKEN = "YOUR_BOT_TOKEN_HERE"
TELEGRAM_CHAT_ID = "YOUR_CHAT_ID_HERE"

# === Geolocation ===
GEO_API_URL = "http://ip-api.com/json/{ip}"
GEO_CACHE_DURATION = 3600  # seconds

# === Threat Scoring ===
QUARANTINE_THRESHOLD = 76
QUARANTINE_DURATION = 3600  # seconds (1 hour)
SCORING_RULES_FILE = "config/scoring_rules.json"

# === Whitelist (never quarantine) ===
IP_WHITELIST = ["127.0.0.1", "192.168.0.0/16", "10.0.0.0/8"]

# === Database ===
DATABASE_PATH = "database/mirage_junior.db"
```

---

## 10. Execution & Deployment

### One-Command Start
```bash
# Install dependencies
pip install -r requirements.txt

# Initialize database
python database/db_setup.py

# Start everything (honeypots + dashboard + monitors)
python main.py
```

`main.py` uses Python `threading` to spin up all services:
1. HTTP Decoy on `:8080`
2. SSH Trap on `:2222`
3. FTP Trap on `:2121`
4. Honeytoken File Monitor
5. Quarantine Expiry Checker
6. Flask Dashboard on `:5000`

### Testing / Demo Mode
```bash
# Run simulated attack (for demos and presentations)
python tests/test_attack.py
```
This script simulates a realistic multi-stage attack:
1. Scans HTTP endpoints → triggers low score
2. Attempts SSH brute-force → score rises
3. Gains "fake shell" → score spikes
4. Accesses honeytoken → triggers quarantine

Perfect for live demos during project evaluation.

---

## 11. Testing Strategy

| Test Type | What | How |
|---|---|---|
| **Unit Tests** | Scoring engine, MITRE mapper, GeoIP cache | `pytest` with mock data |
| **Integration Test** | Full attack simulation end-to-end | `test_attack.py` script |
| **Dashboard Test** | All pages render correctly | Manual browser testing |
| **Alert Test** | Telegram notifications fire correctly | Test with real Telegram bot |
| **Quarantine Test** | Firewall rules add/remove correctly | Test on local machine |

---

## 12. Implementation Phases

### Phase 1: Foundation (Week 1-2)
- [x] Set up project structure and Git repository
- [x] Create SQLite database with full schema
- [x] Build HTTP honeypot with all fake endpoints
- [x] Build SSH honeypot with credential logging
- [x] Basic event logging to database

### Phase 2: Intelligence Layer (Week 3-4)
- [x] Implement Threat Scoring Engine
- [x] Implement MITRE ATT&CK auto-tagging
- [x] Add IP Geolocation enrichment with caching
- [x] Build the fake shell for SSH (command capture)
- [x] Add FTP honeypot

### Phase 3: Response & Alerts (Week 5)
- [x] Telegram Bot integration with graded alerts
- [x] Auto-Quarantine system with whitelist protection
- [x] Honeytoken tripwire system (HTTP + filesystem)

### Phase 4: Dashboard (Week 6-7)
- [x] Overview page with stats cards and charts
- [x] Attack log with filtering and pagination
- [x] Attacker profile page with timeline replay
- [x] Quarantine management page
- [x] Honeytoken status page
- [x] Dark-themed styling

### Phase 5: Polish & Demo (Week 8)
- [x] `test_attack.py` demo script
- [x] Unit tests for scoring engine
- [x] README with setup instructions
- [x] Final bug fixes and edge cases
- [x] Prepare presentation with live demo

---

## 13. Deliverables for College Submission

| # | Deliverable | Description |
|---|---|---|
| 1 | **Source Code** | Well-commented Python codebase with clean structure |
| 2 | **Working Demo** | Live demo showing simulated attack → score → quarantine |
| 3 | **Database** | SQLite file with captured (simulated) attack data |
| 4 | **Project Report** | Full documentation: problem statement, architecture, MITRE mapping, results |
| 5 | **Presentation (PPT)** | Slides covering threat landscape, deception tech, architecture, live demo |
| 6 | **README.md** | Setup guide, architecture diagram, screenshots |
| 7 | **Test Results** | Screenshot/logs showing scoring accuracy and alert delivery |

---

## 14. Key Talking Points for Evaluation

Use these during your viva/presentation to impress evaluators:

1. **"We don't just log attacks — we score them."** Explain the behavioral threat scoring system and how it mirrors real SOC workflows.

2. **"Our system maps to MITRE ATT&CK."** Show that you understand industry-standard threat classification frameworks.

3. **"We have automated response, not just monitoring."** Demonstrate auto-quarantine — passive detection is table-stakes; active response is next-level.

4. **"Honeytokens provide high-fidelity alerts."** Explain the Attacker's Dilemma: no legitimate user would ever access `admin_passwords.txt`, so any trigger is guaranteed malicious.

5. **"The attack timeline tells a story."** Walk evaluators through a complete attack narrative — this demonstrates analytical thinking, not just coding.

---

## 15. Risk Mitigation

| Risk | Mitigation |
|---|---|
| Port conflicts on college network | Use high, non-standard ports (2222, 8080, 2121) |
| Accidental self-blocking | IP whitelist includes localhost and common LAN ranges |
| Rate limiting on GeoIP API | Local cache prevents duplicate lookups |
| Telegram API downtime | Alerts are always logged to DB regardless; Telegram is optional |
| Evaluator doesn't have Telegram | Demo mode works fully without Telegram configured |
| Firewall permissions for quarantine | Quarantine feature degrades gracefully — logs the action even if no admin rights |

---

> **Document Version:** 2.0 Enhanced
> **Last Updated:** September 30, 2026
> **Author:** Jaskaran Bandral
> **Status:** Ready for Implementation ✅
