"""
MIRAGE Shield — Standalone CLI Launcher
Protects any target website by putting a cloning deception proxy in front of it.

Usage:
    python run_shield.py                              # Protects http://127.0.0.1:8080 on port 8443
    python run_shield.py --target https://example.com # Clones & protects example.com
    python run_shield.py --target https://example.com --port 9000
    python run_shield.py --target https://example.com --clone-only
    python run_shield.py --demo                       # Runs traffic simulation after startup
"""

import argparse
import os
import sys
import threading
import time
import logging

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from mirage_shield.shield_proxy import get_shield_instance
import mirage_shield.config as shield_cfg

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("MIRAGE.Shield")


def main():
    parser = argparse.ArgumentParser(
        description="MIRAGE Shield — Deception-as-a-Service Website Protector"
    )
    parser.add_argument(
        "--target",
        default=shield_cfg.TARGET_URL,
        help="Target website URL to protect and clone (default: %(default)s)",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=shield_cfg.SHIELD_PORT,
        help="Local port for the Shield proxy server (default: %(default)s)",
    )
    parser.add_argument(
        "--host",
        default=shield_cfg.SHIELD_HOST,
        help="Bind host address (default: %(default)s)",
    )
    parser.add_argument(
        "--clone-only",
        action="store_true",
        help="Only clone the target website into the honeypot cache and exit.",
    )
    parser.add_argument(
        "--demo",
        action="store_true",
        help="Run a brief simulated traffic mix (Allow/Redirect/Block) after starting.",
    )
    args = parser.parse_args()

    shield = get_shield_instance(target_url=args.target)
    shield.shield_port = args.port

    if args.clone_only:
        logger.info(f"🪞 Cloning {args.target}...")
        out_path = shield.cloner.clone(max_pages=8)
        logger.info(f"✅ Clone saved to: {out_path}")
        return

    if args.demo:
        def _run_demo_mix():
            time.sleep(2)
            logger.info("🎭 Running MIRAGE Shield demo traffic scenarios...")
            for scenario in ("legitimate", "recon_env", "cred_harvest", "sqli"):
                res = shield.run_simulation(scenario)
                logger.info(
                    f"   [{scenario}] {res['ip']} → {res['decision']} (Score: {res['score']}/100)"
                )
        threading.Thread(target=_run_demo_mix, daemon=True).start()

    print()
    logger.info("=" * 64)
    logger.info("🛡️  MIRAGE SHIELD — Website Deception Proxy Online")
    logger.info("=" * 64)
    logger.info(f"🎯 Protected Origin : {args.target}")
    logger.info(f"🌐 Shield Endpoint  : http://localhost:{args.port}/")
    logger.info(f"📊 Shield UI        : http://localhost:{args.port}/mirage-shield/dashboard")
    logger.info(f"👁️  Preview Clone    : http://localhost:{args.port}/mirage-shield/preview")
    logger.info("=" * 64)
    print()

    shield.run(host=args.host, port=args.port)


if __name__ == "__main__":
    main()
