# 👥 Project Contributors & Engineering Division

> **Project:** MIRAGE Junior — Intelligent Deception Network with Threat Scoring  
> **Course / Degree:** B.Tech / B.E. Cyber Security & Computer Science (3rd Year)  
> **Repository:** [`Jaskaranbandral-07/mirage-junior`](https://github.com/Jaskaranbandral-07/mirage-junior) • [`2024A7R009/mirage-junior`](https://github.com/2024A7R009/mirage-junior)  
> **Live Deployment:** [mirage-junior.vercel.app](https://mirage-junior.vercel.app)

---

## 👨‍💻 Team Structure & Responsibilities

```
                               ┌────────────────────────────────┐
                               │     MIRAGE JUNIOR PROJECT      │
                               └──────────────┬─────────────────┘
                                              │
                      ┌───────────────────────┴───────────────────────┐
                      │                                               │
        ┌─────────────▼──────────────┐                 ┌──────────────▼─────────────┐
        │     JASKARAN BANDRAL       │                 │       RELISH SHARMA        │
        │       Team Leader          │                 │         Teammate           │
        │   (Backend & Core Engine)  │                 │    (Dashboard & Deploy)    │
        └────────────────────────────┘                 └────────────────────────────┘
```

---

## 👤 1. Jaskaran Bandral — Team Leader (Backend & Core Engine)
* **GitHub Profile:** [@Jaskaranbandral-07](https://github.com/Jaskaranbandral-07)
* **Primary Git Branch:** `feature/backend-core`

### 🛠️ Key Modules & Contributions:
| Module | Primary Files | Description |
| :--- | :--- | :--- |
| **Honeypot Trap Layer** | `honeypots/http_decoy.py`<br>`honeypots/ssh_trap.py`<br>`honeypots/ftp_trap.py` | Multi-protocol decoys: Flask HTTP decoy with fake admin & `.env`, Paramiko SSH server with interactive fake shell (`whoami`, `cat /etc/passwd`), and pure-Python FTP trap with sensitive file downloads. |
| **Intelligence Engine** | `engine/scoring_engine.py`<br>`engine/mitre_tagger.py` | Real-time threat scoring algorithm (0–100 cap), lateral movement detection, attacker categorization, and MITRE ATT&CK technique mapping. |
| **Active Quarantine** | `engine/quarantine.py` | Automated OS firewall blocking (`netsh advfirewall` on Windows / `iptables` on Linux), CIDR subnet whitelisting (`ipaddress`), and auto-expiry manager. |
| **GeoIP Enrichment** | `engine/geo_enricher.py` | IP geolocation lookup, local/private IP bypass, and rate-limited JSON caching. |
| **Database Architecture** | `database/db_setup.py`<br>`database/db_manager.py` | SQLite schema design (5 relational tables), indexing for performance, WAL mode, and concurrency-safe CRUD operations. |
| **Honeytoken Monitor** | `engine/honeytoken_monitor.py` | Python `watchdog` daemon actively monitoring `/bait/` filesystem triggers. |
| **Orchestration** | `main.py` | Master multi-threaded service runner orchestrating 6 concurrent background threads. |
| **Documentation** | `College_PRD.md` (v2.1)<br>`README.md` | Author of the complete 800+ line Product Requirements Document and technical architecture specifications. |

---

## 👤 2. Relish Sharma — Teammate (Dashboard, Alerts & Integration)
* **GitHub Profile:** [@2024A7R009](https://github.com/2024A7R009)
* **Primary Git Branch:** `feature/dashboard-ui`

### 🛠️ Key Modules & Contributions:
| Module | Primary Files | Description |
| :--- | :--- | :--- |
| **Dashboard Backend** | `dashboard/app.py`<br>`dashboard/routes.py` | Flask application factory, pagination engine (10 records/page), protocol filters, CSV export streaming, and REST API endpoints. |
| **Dashboard UI Views** | `dashboard/templates/*.html`<br>(7 views) | Engineered 7 dark-themed cyber UI pages: Overview command center, Full Attack Log, Attacker Profile deep-dive, Quarantine Manager, Honeytoken Hub, and Settings. |
| **Frontend Styling** | `dashboard/static/css/style.css` | 600+ lines of custom dark-mode CSS with neon accents, responsive grid layouts, stat cards, and status badges. |
| **Data Visualizations** | `dashboard/static/js/charts.js`<br>`dashboard/static/js/timeline.js` | Chart.js integration (Threat Distribution, Top Countries, 24h Timeline), auto-refresh AJAX polling (5s), and chronological attack timeline replay. |
| **Alerting System** | `engine/alert_manager.py` | Graded Telegram Bot API push alerting (`CRITICAL`, `ACTIVE_THREAT`, `SUSPICIOUS`) with formatted Markdown notifications. |
| **Telemetry Generator** | `dashboard/demo_data.py` | Simulated attack telemetry seeder: 20 attacker profiles, 13 multi-stage scenarios, 33 credentials, and 6 honeytokens for evaluator demonstrations. |
| **Bait Decoys** | `bait/*`<br>`ftp_root/*` | Crafted authentic honeytoken decoy files: fake PostgreSQL database dump, internal credential cheat-sheet, and Excel password list. |
| **Testing Suite** | `tests/test_scoring.py`<br>`tests/test_honeytokens.py`<br>`tests/test_attack.py` | Full Pytest suite with isolated SQLite fixtures, behavioral scoring tests, watchdog tests, and multi-stage attack simulator. |
| **Cloud Deployment** | `vercel_app.py`<br>`vercel.json` | Vercel serverless WSGI configuration with `/tmp` SQLite storage compatibility for cloud showcase. |

---

## 🔀 Git Collaboration Workflow

```
feature/backend-core  (Jaskaran)  ──────────────────────┐
                                                         ├──▶ main (Merged & Production Verified)
feature/dashboard-ui  (Relish)    ──────────────────────┘
                                                         │
                                                         ▼
                                             Live Vercel Auto-Deploy
                                             mirage-junior.vercel.app
```

### Sprint Delivery Phases:
- [x] **Phase 1: Foundation (Traps & Database)** — HTTP decoy, SSH trap, FTP trap, and SQLite schema.
- [x] **Phase 2: Intelligence Layer** — Behavioral threat scoring engine, GeoIP enricher, and MITRE ATT&CK tagger.
- [x] **Phase 3: Active Response** — Firewall auto-quarantine, CIDR whitelisting, and Telegram push alerts.
- [x] **Phase 4: Dashboard & Analytics** — 10-per-page paginated attack logs, protocol filtering, Chart.js visualizations, and timeline replay.
- [x] **Phase 5: Polish & Deployment** — Pytest suite, Vercel serverless deployment, and evaluator presentation documentation.
