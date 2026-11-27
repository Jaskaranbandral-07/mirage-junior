"""
NovaPay FinTech — Standalone Protected Demo Startup Website
Used for college viva & client demos to showcase MIRAGE Shield absorbing
real attacks at the backend SDK layer and circulating useless fake data.

Run locally:
    python demo_target/app.py
Or deploy `demo_target/` independently as a second Vercel project.
"""

import os
import sys
from flask import Flask, jsonify, render_template, request

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
if CURRENT_DIR not in sys.path:
    sys.path.insert(0, CURRENT_DIR)

from shield_sdk import NovaPayShieldMiddleware

# Safe fictional benign partner directory returned ONLY when traffic is clean
PUBLIC_MERCHANT_CATALOG = [
    {"merchant_id": "MCH-101", "company": "CloudScale Systems", "tier": "Enterprise", "region": "AP-South", "support_email": "ops@cloudscale.example"},
    {"merchant_id": "MCH-102", "company": "KitePay Retail", "tier": "Growth", "region": "EU-West", "support_email": "desk@kitepay.example"},
    {"merchant_id": "MCH-103", "company": "Orbit Logistics", "tier": "Enterprise", "region": "US-East", "support_email": "api@orbitlog.example"},
    {"merchant_id": "MCH-104", "company": "Verve Commerce", "tier": "Starter", "region": "AP-South", "support_email": "hello@verve.example"},
]


def create_demo_app(shield_url: str = None, site_key: str = None):
    app = Flask(__name__, template_folder=os.path.join(CURRENT_DIR, "templates"))
    default_shield = (
        shield_url
        if shield_url is not None
        else os.getenv(
            "MIRAGE_SHIELD_URL",
            "https://mirage-junior.vercel.app" if os.getenv("VERCEL") else "http://127.0.0.1:5000",
        )
    )
    active_key = site_key if site_key is not None else os.getenv("MIRAGE_SITE_KEY", "")

    shield = NovaPayShieldMiddleware(
        app.wsgi_app,
        shield_url=default_shield,
        site_key=active_key,
        domain="novapay-demo.local",
    )
    app.wsgi_app = shield
    app.shield_middleware = shield

    @app.route("/")
    def home():
        return render_template(
            "novapay.html",
            shield_url=shield.shield_url,
            site_id=shield.site_id,
            recent_absorbed=list(shield.recent_absorbed),
        )

    @app.route("/api/customers")
    def api_customers():
        query = (request.args.get("q") or "").strip().lower()
        matched = [
            m for m in PUBLIC_MERCHANT_CATALOG
            if not query or query in m["company"].lower() or query in m["tier"].lower()
        ]
        resp = jsonify({
            "status": "ok",
            "source": "NovaPay Real Partner Directory",
            "real_backend_executed": True,
            "query": query,
            "count": len(matched),
            "merchants": matched,
        })
        resp.headers["X-NovaPay-Real-Backend"] = "executed"
        return resp

    @app.route("/login", methods=["POST"])
    def employee_login():
        data = request.get_json(silent=True) or request.form.to_dict() or {}
        email = (data.get("email") or data.get("username") or "").strip()
        resp = jsonify({
            "status": "error",
            "real_backend_executed": True,
            "message": f"Invalid SSO credentials for {email or 'unknown user'}",
        })
        resp.status_code = 401
        resp.headers["X-NovaPay-Real-Backend"] = "executed"
        return resp

    @app.route("/api/shield-status")
    def api_shield_status():
        origin = os.getenv("NOVAPAY_PUBLIC_URL") or request.host_url.rstrip("/")
        if request.args.get("register") == "1" and shield.shield_url:
            shield.ensure_registered(origin)
        dash_url = f"{shield.shield_url}/site/{shield.site_id}" if (shield.shield_url and shield.site_id) else f"{shield.shield_url}/sites"
        return jsonify({
            "shield_url": shield.shield_url,
            "site_id": shield.site_id,
            "has_key": bool(shield.site_key),
            "dashboard_url": dash_url,
            "absorbed_count": len(shield.recent_absorbed),
            "recent_absorbed": list(shield.recent_absorbed),
        })

    @app.route("/api/shield-config", methods=["POST"])
    def api_shield_config():
        data = request.get_json(silent=True) or {}
        new_url = (data.get("shield_url") or "").strip().rstrip("/")
        new_key = (data.get("site_key") or "").strip()
        if new_url:
            if new_url != shield.shield_url:
                shield.site_key = new_key
                shield.site_id = ""
            shield.shield_url = new_url
        elif new_key:
            shield.site_key = new_key
        origin = os.getenv("NOVAPAY_PUBLIC_URL") or request.host_url.rstrip("/")
        if shield.shield_url and not shield.site_key:
            shield.ensure_registered(origin)
        dash_url = f"{shield.shield_url}/site/{shield.site_id}" if (shield.shield_url and shield.site_id) else f"{shield.shield_url}/sites"
        return jsonify({
            "success": True,
            "shield_url": shield.shield_url,
            "site_id": shield.site_id,
            "dashboard_url": dash_url,
        })

    return app


app = create_demo_app()

if __name__ == "__main__":
    port = int(os.getenv("DEMO_TARGET_PORT", 5050))
    print(f"NovaPay FinTech Demo Target running on http://localhost:{port}")
    app.run(host="0.0.0.0", port=port, debug=False, use_reloader=False)
