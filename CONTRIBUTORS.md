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
        │   Proxy, SDKs & Multi-     │                 │    Telegram & Deploy)      │
        │        Tenancy)            │                 │                            │
        └────────────────────────────┘                 └────────────────────────────┘
```

---

## 👤 1. Jaskaran Bandral — Team Leader (Advanced Core, SDKs & Multi-Tenancy)
* **GitHub Profile:** [@Jaskaranbandral-07](https://github.com/Jaskaranbandral-07)
* **Primary Git Branch:** `feature/backend-core`

### 🛠️ Key Modules & Contributions:
| Module | Primary Files | Description |
| :--- | :--- | :--- |
| **MIRAGE Shield Proxy & Cloner** | `mirage_shield/traffic_analyzer.py`<br>`mirage_shield/site_cloner.py`<br>`mirage_shield/honeypot_injector.py`<br>`mirage_shield/shield_proxy.py` | Multi-tenant reverse proxy, website cloner with pure-stdlib fallback, 6-factor traffic scoring engine (`ALLOW` / `REDIRECT` / `BLOCK`), and portal trap injector. |
| **Synthetic Fake-Data Engine** | `mirage_shield/synthetic_deception.py` | Absorbs SQLi, API scraping, RCE, and traversal attacks before customer backends see them, feeding attackers realistic yet useless decoy payloads. |
| **Customer Backend SDKs** | `mirage_shield/sdk/python_shield.py`<br>`mirage_shield/sdk/node_shield.js` | Drop-in 2-line Python (Flask/WSGI) and Node.js (Express) middleware packages allowing startups to protect any backend and stream telemetry via Site API Key. |
| **Multi-Tenant Database** | `database/db_setup.py`<br>`database/db_manager.py` | SQLite WAL schema with `sites`, `site_attackers`, and `site_id` workspace isolation per customer website. |
| **Intelligence & Quarantine** | `engine/scoring_engine.py`<br>`engine/mitre_tagger.py`<br>`engine/quarantine.py`<br>`engine/geo_enricher.py` | Behavioral threat scoring (0–100), MITRE ATT&CK auto-tagging, OS firewall auto-quarantine (`netsh`/`iptables`) with CIDR whitelist, and GeoIP lookup. |
| **Multi-Tenant Routes & Extension** | `dashboard/routes.py`<br>`chrome_extension/*`<br>`demo_target/shield_sdk.py` | Per-website dashboards (`/sites`, `/site/<site_id>`, `/portal/<domain>`, `/api/ingest`), extension `.zip` packager (`/api/extension/download`), Chrome extension, and NovaPay SDK middleware. |
| **Orchestration & Shield Tests** | `main.py`<br>`run_shield.py`<br>`tests/test_shield.py` | Service launcher plus end-to-end tests covering multi-tenant isolation, synthetic deception, and backend SDK absorption. |
| **Documentation & Ownership** | `College_PRD.md`<br>`README.md`<br>`.github/CODEOWNERS` | Technical architecture documentation and GitHub code ownership setup. |

---

## 👤 2. Relish Sharma — Teammate (Dashboard UI, Telegram Alerts & Deployment)
* **GitHub Profile:** [@2024A7R009](https://github.com/2024A7R009)
* **Primary Git Branch:** `feature/dashboard-ui`

### 🛠️ Key Modules & Contributions:
| Module | Primary Files | Description |
| :--- | :--- | :--- |
| **Dashboard Factory & UI Views** | `dashboard/app.py`<br>`dashboard/templates/*.html`<br>`demo_target/app.py`<br>`demo_target/templates/novapay.html` | Dark-themed cyber SaaS dashboard pages, Extension Download & Demo Hub (`/extension`), NovaPay FinTech Demo Target UI, Attack Log, Quarantine Manager, and Settings. |
| **Frontend Styling** | `dashboard/static/css/style.css` | Custom neon dark-mode CSS with responsive grid layouts, Chart.js wrappers, mobile cyber navigation dock, and status badges. |
| **Data Visualizations** | `dashboard/static/js/charts.js`<br>`dashboard/static/js/timeline.js` | Chart.js integration (Threat Distribution, Top Countries, 24h Timeline, MITRE Heatmap), 5-second auto-refresh polling, and attack timeline replay. |
| **Telegram Alerting & Settings** | `engine/alert_manager.py`<br>`dashboard/templates/settings.html` | Graded Telegram Bot API push alerting (`CRITICAL`, `ACTIVE_THREAT`, `SUSPICIOUS`) and user-configurable Telegram Bot Token / Chat ID / Whitelist panel. |
| **Core Scoring Tests** | `tests/test_scoring.py` | Unit tests verifying behavioral scoring thresholds, lateral scan bonuses, and auto-quarantine triggers. |
| **Presentation & Cloud Deploy** | `vercel_app.py`<br>`vercel.json`<br>`presentation.html`<br>`progress_tracker.html`<br>`MASTER_PROJECT_EXPLANATION.md`<br>`*.pdf` / `*.pptx` | Vercel serverless configuration, interactive 8-slide HTML/PPTX presentation deck, and evaluator walkthrough guides. |

---

## 🔀 Git Collaboration & Code Ownership

| Ownership Area | Lead Owner | Co-Maintainer |
| :--- | :--- | :--- |
| **Advanced Core, SDKs, Multi-Tenancy & Deception:** `mirage_shield/`, `chrome_extension/`, `engine/` (scoring, quarantine, MITRE, geo), `database/`, `config/`, `main.py`, `run_shield.py`, `tests/test_shield.py`, `dashboard/templates/shield.html` | **@Jaskaranbandral-07** *(Lead)* | — |
| **UI, Charts, Telegram Alerts & Deploy:** `dashboard/` (`app.py`, views, CSS, JS), `engine/alert_manager.py`, `tests/test_scoring.py`, `vercel*`, Decks | **@2024A7R009** | — |
| **Multi-Tenant APIs & Docs:** `dashboard/routes.py`, `README.md`, `CONTRIBUTORS.md` | **@Jaskaranbandral-07** *(Lead)* | @2024A7R009 |

---

## 🎓 College Evaluation & Viva Quick Guide (Who Explains What)

### How Jaskaran Explains the Core & Startup Architecture (2 mins)
1. **Clean SaaS Separation:** MIRAGE Shield's own dashboard has zero self-traps; all deception runs exclusively on protected customer websites (via cloned `/portal/<domain>` mirrors, Reverse Proxy `:8443`, or drop-in Python/Node backend SDKs).
2. **Attack Absorption & Synthetic Fake Data:** `TrafficAnalyzer` scores incoming HTTP requests across 6 factors (`0–100`). Suspicious/hostile traffic is absorbed before reaching the customer's real database and fed realistic yet 100% useless synthetic JSON/SQL/credential payloads from `SyntheticDeceptionEngine`.
3. **Multi-Tenant Isolation:** Every customer site receives an isolated `site_id`, `api_key` (`ms_live_...`), and private `dashboard_key`. Customer backends authenticate via `X-MIRAGE-Site-Key` to `POST /api/ingest`, keeping every website's personal dashboard completely isolated.

### How Relish Explains UI, Telegram Alerts & Deployment (2 mins — Simple & Clear)
1. **SaaS Dashboard & Per-Site UI:** Built the dark-mode HTML/CSS interface (`dashboard/templates/` & `style.css`), responsive Chart.js dashboards (`charts.js`), 10-per-page attack log filtering, and customer workspace views (`sites.html`, `site_dashboard.html`) polling live APIs every 5 seconds.
2. **Telegram Bot Notifications & Settings:** `engine/alert_manager.py` sends instant formatted Telegram push notifications via Bot API (`requests.post`), configured right from the `/settings` UI.
3. **Testing & Vercel Cloud Hosting:** Maintains core scoring tests (`test_scoring.py`), presentation decks (`presentation.html`), and Vercel serverless WSGI hosting (`vercel_app.py`, `vercel.json`).
