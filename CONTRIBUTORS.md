# 👥 Project Contributors & Engineering Division

> **Project:** MIRAGE Shield — Multi-Tenant Cyber Deception & Active WAF Platform  
> **Course / Degree:** B.Tech / B.E. Cyber Security & Computer Science (3rd Year)  
> **Repository:** [`Jaskaranbandral-07/mirage-junior`](https://github.com/Jaskaranbandral-07/mirage-junior) • [`2024A7R009/mirage-junior`](https://github.com/2024A7R009/mirage-junior)  
> **Live Deployment:** [mirage-junior.vercel.app](https://mirage-junior.vercel.app)

---

## 👨‍💻 Team Structure & Responsibilities

```
                               ┌────────────────────────────────┐
                               │      MIRAGE SHIELD PROJECT     │
                               └──────────────┬─────────────────┘
                                              │
                      ┌───────────────────────┴───────────────────────┐
                      │                                               │
        ┌─────────────▼──────────────┐                 ┌──────────────▼─────────────┐
        │     JASKARAN BANDRAL       │                 │       RELISH SHARMA        │
        │       Team Leader          │                 │         Teammate           │
        │  (Advanced Core, Shield    │                 │   (Dashboard UI, Charts,   │
        │   Proxy, SDKs & Multi-     │                 │    Alerts & Deployment)    │
        │        Tenancy)            │                 │                            │
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
| **Orchestration** | `main.py`<br>`run_shield.py` | Master multi-threaded service runner orchestrating 7 concurrent background threads plus standalone Shield CLI. |
| **MIRAGE Shield Proxy & Deception** | `mirage_shield/traffic_analyzer.py`<br>`mirage_shield/site_cloner.py`<br>`mirage_shield/honeypot_injector.py`<br>`mirage_shield/synthetic_deception.py`<br>`mirage_shield/shield_proxy.py` | Multi-tenant reverse proxy, website cloner, 6-factor scoring engine, and synthetic useless data engine that absorbs attacks before customer backends see them. |
| **Customer Backend SDKs** | `mirage_shield/sdk/python_shield.py`<br>`mirage_shield/sdk/node_shield.js` | Drop-in 2-line Python (Flask/WSGI) and Node.js (Express) middleware packages allowing startups to protect any backend and stream telemetry via Site API Key. |
| **Multi-Tenant Routes** | `dashboard/routes.py` | Tenant isolation (`/sites`, `/site/<site_id>`, `/api/ingest`, `/portal/<domain>`) and real-time web threat middleware. |
| **Chrome Extension** | `chrome_extension/manifest.json`<br>`chrome_extension/popup.html`<br>`chrome_extension/popup.css`<br>`chrome_extension/popup.js` | Manifest V3 browser extension for 1-click site provisioning, isolated per-site dashboard launch, and probe testing. |
| **Shield Integration Tests** | `tests/test_shield.py` | End-to-end tests for TrafficAnalyzer, SiteCloner, HoneypotInjector, `/portal/<domain>` routing, and live trap capture. |
| **Documentation & Branding** | `College_PRD.md` (v3.0)<br>`README.md`<br>`.github/CODEOWNERS` | Product Requirements Document, architecture specs, and GitHub module ownership configuration. |

---

## 👤 2. Relish Sharma — Teammate (Dashboard, Alerts & Integration)
* **GitHub Profile:** [@2024A7R009](https://github.com/2024A7R009)
* **Primary Git Branch:** `feature/dashboard-ui`

### 🛠️ Key Modules & Contributions:
| Module | Primary Files | Description |
| :--- | :--- | :--- |
| **Dashboard Backend** | `dashboard/app.py`<br>`dashboard/routes.py` | Flask application factory, pagination engine (10 records/page), protocol filters, CSV export streaming, and REST API endpoints. |
| **Dashboard UI Views** | `dashboard/templates/*.html`<br>(10 views incl. `sites.html` & `site_dashboard.html`) | Engineered dark-themed cyber UI pages: Global Overview, Protected Sites Directory, Personal Customer Site Dashboard, Attack Log, Attacker Deep-Dive, Quarantine, Honeytokens, and Settings. |
| **Frontend Styling** | `dashboard/static/css/style.css` | 1,100+ lines of custom dark-mode CSS with neon accents, responsive grid layouts, mobile cyber navigation dock, and status badges. |
| **Data Visualizations** | `dashboard/static/js/charts.js`<br>`dashboard/static/js/timeline.js` | Chart.js integration (Threat Distribution, Top Countries, 24h Timeline), auto-refresh AJAX polling (5s), and chronological attack timeline replay. |
| **Alerting System** | `engine/alert_manager.py` | Graded Telegram Bot API push alerting (`CRITICAL`, `ACTIVE_THREAT`, `SUSPICIOUS`) with formatted Markdown notifications. |
| **Telemetry Generator** | `dashboard/demo_data.py` | Simulated attack telemetry seeder: 20 attacker profiles, 13 multi-stage scenarios, 33 credentials, and 6 honeytokens for evaluator demonstrations. |
| **Bait Decoys** | `bait/*`<br>`ftp_root/*` | Crafted authentic honeytoken decoy files: fake PostgreSQL database dump, internal credential cheat-sheet, and Excel password list. |
| **Testing Suite** | `tests/test_scoring.py`<br>`tests/test_honeytokens.py`<br>`tests/test_attack.py` | Pytest suite with isolated SQLite fixtures, behavioral scoring tests, watchdog tests, and multi-stage attack simulator. |
| **Presentation & Guides** | `presentation.html`<br>`progress_tracker.html`<br>`MASTER_PROJECT_EXPLANATION.md`<br>`*.pdf` / `*.pptx` | Interactive 8-slide HTML/PPTX deck, live progress tracker, and evaluator project walkthrough guides. |
| **Cloud Deployment** | `vercel_app.py`<br>`vercel.json` | Vercel serverless WSGI configuration with `/tmp` SQLite storage compatibility for cloud showcase. |

---

## 🔀 Git Collaboration & Code Ownership Workflow

GitHub ownership is enforced via [`.github/CODEOWNERS`](.github/CODEOWNERS) and split cleanly across dedicated feature branches:

```
feature/backend-core  (@Jaskaranbandral-07) ──┐
                                              ├──▶ main (Merged & Production Verified)
feature/dashboard-ui  (@2024A7R009)         ──┘
                                              │
                                              ▼
                                  Live Vercel Auto-Deploy
                                  mirage-junior.vercel.app
```

| Ownership Area | Lead Owner | Co-Maintainer / Integration |
| :--- | :--- | :--- |
| **Advanced Core & Deception Engines:** `honeypots/`, `engine/` (`scoring_engine.py`, `quarantine.py`, `geo_enricher.py`, `mitre_tagger.py`, `honeytoken_monitor.py`), `database/`, `config/`, `mirage_shield/`, `chrome_extension/`, `main.py`, `run_shield.py`, `tests/test_shield.py`, `dashboard/templates/shield.html` | **@Jaskaranbandral-07** *(Lead)* | — |
| **UI, Alerts, Bait & Deployment:** `dashboard/` (`app.py`, views, CSS, Chart.js, `timeline.js`, `demo_data.py`), `engine/alert_manager.py`, `bait/`, `ftp_root/`, `tests/test_{scoring,honeytokens,attack}.py`, `vercel*`, Decks | **@2024A7R009** | — |
| **Live Threat Middleware & Docs:** `dashboard/routes.py`, `README.md`, `CONTRIBUTORS.md` | **@Jaskaranbandral-07** *(Lead)* | @2024A7R009 |

### Sprint Delivery Phases:
- [x] **Phase 1: Foundation (Traps & Database)** — HTTP decoy, SSH trap, FTP trap, and SQLite schema.
- [x] **Phase 2: Intelligence Layer** — Behavioral threat scoring engine, GeoIP enricher, and MITRE ATT&CK tagger.
- [x] **Phase 3: Active Response** — Firewall auto-quarantine, CIDR whitelisting, and Telegram push alerts.
- [x] **Phase 4: Dashboard & Analytics** — 10-per-page paginated attack logs, protocol filtering, Chart.js visualizations, and timeline replay.
- [x] **Phase 5: Polish & Deployment** — Pytest suite, Vercel serverless deployment, and evaluator presentation documentation.
- [x] **Phase 6: MIRAGE Shield & Chrome Extension** — Reverse-proxy website cloner, 6-factor traffic analyzer, live `/portal/<domain>` traps, Chrome extension, and clean real-time telemetry mode.
- [x] **Phase 7: Multi-Tenant Startup SaaS & Backend SDKs** — Per-website isolated customer dashboards (`/sites`, `/site/<site_id>`), Python/Node.js drop-in backend middleware (`/api/ingest`), synthetic useless data engine, and full rebrand to **MIRAGE Shield**.

---

## 🎓 College Evaluation & Viva Quick Guide (Who Explains What)

### How Jaskaran Explains the Core & Advanced Architecture (2 mins)
1. **Multi-Protocol Traps & Behavioral Scoring:** Incoming probes hit HTTP (`:8080`), SSH (`:2222`), FTP (`:2121`), or the Shield layer; `ScoringEngine` accumulates behavioral points (`0–100`), tags MITRE ATT&CK IDs, and triggers OS firewall `QuarantineManager` (`netsh` / `iptables`) automatically.
2. **MIRAGE Shield Absorption & Synthetic Deception:** Instead of forwarding hostile traffic to a customer's real server or returning a plain `403`, `TrafficAnalyzer` scores 6 dimensions and diverts threats into `SyntheticDeceptionEngine` + cloned traps, feeding attackers useless fake JSON/SQL/credential records.
3. **Multi-Tenant Isolation & Backend SDKs:** Every customer website receives an isolated `site_id`, `api_key` (`ms_live_...`), and private `dashboard_key`. Customer Flask/Express apps install our 2-line middleware (`python_shield.py` / `node_shield.js`) which absorbs attacks locally and posts async telemetry to `/api/ingest`.

### How Relish Explains UI, Alerts, Bait & Deployment (2 mins — Simple & Clear)
1. **SOC Dashboard & Per-Site Views:** Built the responsive dark-mode HTML/CSS UI (`dashboard/templates/` & `style.css`), Chart.js graphs (`charts.js`), 10-per-page attack log filtering, and customer workspace views (`sites.html`, `site_dashboard.html`) that poll `/api/stats` and `/api/site/<site_id>/stats` every 5 seconds.
2. **Telegram Alerts:** `engine/alert_manager.py` sends formatted push notifications to Telegram (`CRITICAL` / `ACTIVE_THREAT`) using the Bot API (`requests.post`).
3. **Bait Files, Demo Seeder & Cloud Hosting:** Created realistic static decoy files (`bait/*`, `ftp_root/*`), `demo_data.py` for offline showcase seeding, core unit tests, presentation slides (`presentation.html`), and Vercel serverless configuration (`vercel_app.py`, `vercel.json`).
