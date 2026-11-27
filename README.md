<div align="center">

<p align="center">
  <img src="dashboard/static/img/mirage-junior-logo.png" alt="MIRAGE Shield Logo" width="128" style="border-radius:16px;" />
  &nbsp;&nbsp;&nbsp;&nbsp;
  <img src="dashboard/static/img/mirage-shield-logo.png" alt="MIRAGE Shield Extension Logo" width="128" style="border-radius:16px;" />
</p>

# 🛡️ MIRAGE Shield — Multi-Tenant Cyber Deception & WAF Platform
### *Active Website Shielding, Backend SDK Middleware, Synthetic Fake-Data Traps & Per-Customer SOC Dashboards*

[![Live Demo](https://img.shields.io/badge/Vercel-Live%20Demo-brightgreen?logo=vercel&style=for-the-badge)](https://mirage-junior.vercel.app)
[![Python](https://img.shields.io/badge/Python-3.10+-3776AB?logo=python&logoColor=white&style=for-the-badge)](https://python.org)
[![Framework](https://img.shields.io/badge/Flask-3.0-000000?logo=flask&logoColor=white&style=for-the-badge)](https://flask.palletsprojects.com/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg?style=for-the-badge)](https://opensource.org/licenses/MIT)
[![MITRE ATT&CK](https://img.shields.io/badge/MITRE%20ATT%26CK-Mapped-red?style=for-the-badge)](https://attack.mitre.org)

<p align="center">
  <b>Installable website protection that absorbs attacks before they hit customer backends, feeds attackers useless synthetic decoy data, and isolates telemetry into each website's personal dashboard.</b>
</p>

[🌐 Live Platform](https://mirage-junior.vercel.app) • [🏢 Protected Sites](https://mirage-junior.vercel.app/sites) • [📄 Full PDF Guide](MIRAGE_Junior_Project_Explanation.pdf) • [📚 Master Docs](MASTER_PROJECT_EXPLANATION.md) • [📊 8-Slide Deck (HTML)](presentation.html) • [👥 Contributors & Viva Guide](CONTRIBUTORS.md)

</div>

---

## 🌟 What Makes MIRAGE Shield Different?

MIRAGE Shield keeps its own platform completely clean (zero self-traps) and focuses deception strictly on **protecting customer websites**:

| Feature | Traditional Firewall / Student Honeypot | 🛡️ MIRAGE Shield |
| :--- | :---: | :---: |
| **Per-Website Dashboards** | ❌ Single shared log | ✅ **Isolated personal dashboard + API key per customer site (`/site/<id>`)** |
| **Backend Integration** | ❌ Separate toy server only | ✅ **2-line installable Python (Flask/WSGI) & Node.js (Express) middleware** |
| **Attack Absorption** | ⚠️ Backend takes the hit | ✅ **Shield absorbs SQLi/XSS/RCE/recon before customer DB is touched** |
| **Fake Data Circulation** | ❌ Empty error page | ✅ **Feeds attackers convincing, 100% useless synthetic JSON/SQL/env decoys** |
| **Cloned Portal Traps** | ❌ None | ✅ **Live `/portal/<domain>` mirror with credential & `.env` tripwires** |
| **Threat Scoring & Telegram** | ❌ Basic log lines | ✅ **0–100 behavioral scoring, MITRE ATT&CK tagging, Quarantine & Telegram alerts** |

---

## 🏗️ System Architecture

```
            CUSTOMER WEBSITES / STARTUPS
     ┌────────────────────┬────────────────────┐
     │  2-Line Backend    │   Reverse Proxy    │
     │  SDK (Flask/Node)  │   (:8443 / Clone)  │
     └─────────┬──────────┴─────────┬──────────┘
               │                    │
               ▼                    ▼
     ┌─────────────────────────────────────────┐
     │      MIRAGE Shield Inspection Layer     │
     │  • 6-Factor Traffic Analyzer (0–100)    │
     │  • Synthetic Fake-Data Engine (SQL/API) │
     │  • Cloned Portal & Credential Traps     │
     └──────────────────┬──────────────────────┘
                        │ Clean → Pass to Real Site
                        │ Attack → Absorbed + POST /api/ingest
                        ▼
     ┌─────────────────────────────────────────┐
     │   Multi-Tenant Intelligence Pipeline    │
     │  • Per-Site Isolation (site_id/api_key) │
     │  • MITRE ATT&CK & GeoIP Enrichment      │
     │  • Firewall Auto-Quarantine & Telegram  │
     └──────────────────┬──────────────────────┘
                        ▼
     ┌─────────────────────────────────────────┐
     │   MIRAGE Shield SaaS Platform (:5000)   │
     │  • Global Overview & Quarantine         │
     │  • Personal Customer View (/site/<id>)  │
     │  • Telegram Settings (/settings)        │
     └─────────────────────────────────────────┘
```

---

## 🚀 Quick Start

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Initialize multi-tenant SQLite database
python database/db_setup.py

# 3. Start MIRAGE Shield SaaS Dashboard (:5000) + Reverse Proxy (:8443)
python main.py
```

- **Global Overview:** `http://localhost:5000`
- **Customer Site Workspaces:** `http://localhost:5000/sites`
- **Telegram Alerts & Whitelist Settings:** `http://localhost:5000/settings`
- **Standalone Reverse Proxy Mode:** `python run_shield.py --target https://your-site.com --port 8443`

---

## 📁 Repository Structure

```
mirage-shield/
├── config/
│   ├── settings.py           # Ports, Telegram settings, DB path & thresholds
│   ├── scoring_rules.json    # Threat weights per attacker action
│   ├── mitre_mapping.json    # Behavior → MITRE ATT&CK mappings
│   └── whitelist.json        # Subnets immune from quarantine
│
├── engine/
│   ├── scoring_engine.py     # Behavioral threat scoring calculator (0–100)
│   ├── quarantine.py         # OS Firewall auto-response & expiry checker
│   ├── alert_manager.py      # Graded Telegram push notification dispatcher
│   ├── geo_enricher.py       # IP geolocation caching & rate-limited lookups
│   └── mitre_tagger.py       # MITRE technique classifier
│
├── dashboard/
│   ├── app.py                # Flask application factory
│   ├── routes.py             # Multi-tenant routes, /api/ingest & portal proxy
│   ├── templates/            # Dark cyber UI (Overview, Sites, Site Dashboard, Settings)
│   └── static/               # Neon CSS, Chart.js scripts & sci-fi logos
│
├── mirage_shield/            # Core Website Deception & Backend SDK Layer
│   ├── config.py             # Shield proxy ports, thresholds & attack signatures
│   ├── site_cloner.py        # Clones target HTML/CSS/JS/images (with stdlib fallback)
│   ├── traffic_analyzer.py   # Thread-safe 6-factor scoring (ALLOW / REDIRECT / BLOCK)
│   ├── honeypot_injector.py  # Injects decoy admin, .env traps & JS beacons
│   ├── synthetic_deception.py# Useless synthetic fake JSON/SQL/RCE data circulation
│   ├── shield_proxy.py       # Multi-tenant reverse proxy server & Shield APIs
│   ├── sdk/                  # Customer drop-in middleware (python_shield.py, node_shield.js)
│   └── templates/            # Standalone Shield Command Center UI
│
├── chrome_extension/         # Manifest V3 Chrome Extension ("Protect Site & Open Dashboard")
├── .github/CODEOWNERS        # GitHub native 2-developer ownership rules
├── database/                 # Multi-tenant SQLite WAL schema & manager
├── tests/                    # Scoring, multi-tenant, SDK & Shield unit/integration tests
├── main.py                   # SaaS platform & Shield proxy launcher
├── run_shield.py             # Standalone CLI launcher for MIRAGE Shield
├── sync_and_deploy.bat       # One-click GitHub sync & Vercel deploy helper
├── vercel_app.py             # Serverless WSGI entry point for Vercel
├── College_PRD.md            # Complete Product Requirements Document
└── CONTRIBUTORS.md           # Team roles, work division & College Viva Guide
```

---

## 👥 Contributors & GitHub Build Division

Ownership is enforced in [`.github/CODEOWNERS`](.github/CODEOWNERS) and detailed with a **2-Minute College Viva Guide** in [`CONTRIBUTORS.md`](CONTRIBUTORS.md):

| Contributor | GitHub & Branch | Owned Modules & Files |
| :--- | :--- | :--- |
| **[Jaskaran Bandral](https://github.com/Jaskaranbandral-07)** *(Team Leader — Advanced Core)* | `@Jaskaranbandral-07`<br>`feature/backend-core` | **Multi-Tenant Core, SDKs & Deception:** `mirage_shield/` (proxy, cloner, analyzer, injector, synthetic deception, Python/Node SDKs), `chrome_extension/`, `engine/` (`scoring_engine.py`, `quarantine.py`, `geo_enricher.py`, `mitre_tagger.py`), `database/`, `config/`, `main.py`, `run_shield.py`, `dashboard/routes.py` (tenant & ingestion APIs), `tests/test_shield.py`, `College_PRD.md` |
| **[Relish Sharma](https://github.com/2024A7R009)** *(Teammate — UI, Telegram & Deploy)* | `@2024A7R009`<br>`feature/dashboard-ui` | **Dashboard UI, Alerts & Deployment:** `dashboard/` (`app.py`, HTML templates, CSS, `charts.js`, `timeline.js`), `engine/alert_manager.py` (Telegram Bot), `tests/test_scoring.py`, `vercel_app.py`, `vercel.json`, `presentation.html`, `progress_tracker.html`, `MASTER_PROJECT_EXPLANATION.md`, `*.pdf`, `*.pptx` |

---

## 📜 License

This project is licensed under the **MIT License** — feel free to use, modify, and build upon for academic and research purposes.
