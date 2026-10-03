# 👥 Contributors & Work Division

## 👤 Jaskaran Bandral — Team Leader (Backend & Core Engine)
**GitHub:** [@Jaskaranbandral-07](https://github.com/Jaskaranbandral-07)  
**Branch:** `feature/backend-core`

### Responsibilities:
| Module | Files | Description |
|---|---|---|
| **Configuration** | `config/settings.py`, `config/scoring_rules.json`, `config/mitre_mapping.json`, `config/whitelist.json` | Central configuration, scoring weights, MITRE ATT&CK mappings |
| **Database** | `database/db_setup.py`, `database/db_manager.py` | SQLite schema design, CRUD operations wrapper |
| **HTTP Honeypot** | `honeypots/http_decoy.py`, `honeypots/templates/*` | Flask-based web decoy with fake admin panels, WordPress clone |
| **SSH Honeypot** | `honeypots/ssh_trap.py` | Paramiko SSH server with interactive fake shell |
| **FTP Honeypot** | `honeypots/ftp_trap.py` | FTP trap with honeytoken file serving |
| **Scoring Engine** | `engine/scoring_engine.py` | Real-time behavioral threat scoring algorithm (0-100) |
| **MITRE Tagger** | `engine/mitre_tagger.py` | Automatic MITRE ATT&CK technique classification |
| **GeoIP Enrichment** | `engine/geo_enricher.py` | IP geolocation lookup with caching |
| **Quarantine System** | `engine/quarantine.py` | Automated IP blocking via OS firewall rules |
| **Honeytoken Monitor** | `engine/honeytoken_monitor.py` | File-system watchdog for tripwire detection |
| **Entry Point** | `main.py` | Multi-threaded service orchestrator |
| **Documentation** | `README.md`, `College_PRD.md` | Project documentation, algorithms, and PRD |

---

## 👤 Relish Sharma — Teammate (Dashboard, Alerts & Integration)
**GitHub:** [@2024A7R009](https://github.com/2024A7R009)  
**Branch:** `feature/dashboard-ui`

### Responsibilities:
| Module | Files | Description |
|---|---|---|
| **Dashboard Backend** | `dashboard/app.py`, `dashboard/routes.py` | Flask application factory, API endpoints, route handlers |
| **Dashboard Templates** | `dashboard/templates/base.html`, `overview.html`, `attacks.html`, `attacker.html`, `quarantine.html`, `honeytokens.html`, `settings.html` | 7 interactive HTML pages with dark cybersecurity theme |
| **Frontend Styling** | `dashboard/static/css/style.css` | Professional dark theme CSS with neon accents, responsive design |
| **Chart Visualizations** | `dashboard/static/js/charts.js` | Chart.js configurations, auto-refresh AJAX polling |
| **Timeline Renderer** | `dashboard/static/js/timeline.js` | Visual attack timeline replay component |
| **Alert System** | `engine/alert_manager.py` | Telegram Bot integration with graded notifications |
| **Demo Data** | `dashboard/demo_data.py` | Realistic attack data seeder for presentations |
| **Bait Files** | `bait/*` | Honeytoken decoy files (fake DB backups, SSH keys) |
| **Test Suite** | `tests/test_attack.py`, `tests/test_scoring.py`, `tests/test_honeytokens.py` | Simulated attack scripts and unit tests |
| **Deployment** | `vercel.json`, `vercel_app.py`, `requirements.txt` | Vercel deployment configuration |

---

## 🔀 Collaboration Workflow
```
feature/backend-core  (Jaskaran)  ──────────────────────┐
                                                         ├──▶ main (merged)
feature/dashboard-ui  (Relish)    ──────────────────────┘
```
