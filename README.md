# 🛡️ MIRAGE Junior — Intelligent Deception Network

![Python](https://img.shields.io/badge/python-3.10+-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)

## Overview
A next-generation lightweight honeypot system for proactive cyber defense, featuring real-time behavioral threat scoring and auto-quarantine.

## Features
- Intelligent Threat Scoring Engine (0-100)
- Auto-Quarantine of high-risk IPs
- Honeytoken tripwires
- Visual Attack Timeline Replay
- MITRE ATT&CK Mapping
- Rich Dashboard UI

## Quick Start
```bash
pip install -r requirements.txt
python database/db_setup.py
python main.py
```
*(To run with fake demo data, use `python main.py --demo`)*

## Testing Simulated Attack
```bash
python tests/test_attack.py
```

## Architecture
```
[Attacker] -> [SSH/HTTP/FTP Traps] -> [Scoring Engine] -> [Quarantine & Alerts]
                                          |
                                    [Dashboard]
```
