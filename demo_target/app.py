"""
NovaPay — Cloud Payroll, Invoicing & Merchant Payments Web App.
Completely standalone demo startup website with zero external security/monitoring
dependencies, built for realistic live product demonstrations.
"""

from collections import deque
import os
import secrets
import sys
from flask import Flask, jsonify, render_template, request

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
if CURRENT_DIR not in sys.path:
    sys.path.insert(0, CURRENT_DIR)

from waf_middleware import SilentBackendWAF

PUBLIC_MERCHANTS = [
    {"merchant_id": "NP-101", "company": "CloudScale Systems", "tier": "Enterprise", "region": "AP-South", "volume_usd": "$148,000/mo", "email": "ops@cloudscale.example"},
    {"merchant_id": "NP-102", "company": "KitePay Retail", "tier": "Growth", "region": "EU-West", "volume_usd": "$62,400/mo", "email": "desk@kitepay.example"},
    {"merchant_id": "NP-103", "company": "Orbit Logistics", "tier": "Enterprise", "region": "US-East", "volume_usd": "$210,500/mo", "email": "api@orbitlog.example"},
    {"merchant_id": "NP-104", "company": "Verve Commerce", "tier": "Starter", "region": "AP-South", "volume_usd": "$18,900/mo", "email": "hello@verve.example"},
    {"merchant_id": "NP-105", "company": "Northstar Freight", "tier": "Growth", "region": "US-West", "volume_usd": "$84,200/mo", "email": "billing@northstar.example"},
]

FX_RATES = {
    "USD": {"symbol": "$", "rate": 1.0, "settlement": "Same-Day ACH"},
    "INR": {"symbol": "₹", "rate": 84.15, "settlement": "Instant IMPS / NEFT"},
    "EUR": {"symbol": "€", "rate": 0.92, "settlement": "SEPA Instant"},
    "GBP": {"symbol": "£", "rate": 0.79, "settlement": "Faster Payments"},
}

RECENT_INVOICES = deque([
    {"invoice_id": "INV-2026-8410", "client": "CloudScale Systems", "email": "ap@cloudscale.example", "amount": 4200.00, "currency": "USD", "status": "Paid"},
    {"invoice_id": "INV-2026-8409", "client": "KitePay Retail", "email": "finance@kitepay.example", "amount": 1850.00, "currency": "EUR", "status": "Pending"},
], maxlen=12)

DEMO_INQUIRIES = deque(maxlen=15)


def create_demo_app(telemetry_url: str = None, site_key: str = None):
    app = Flask(__name__, template_folder=os.path.join(CURRENT_DIR, "templates"))
    default_telemetry = (
        telemetry_url
        if telemetry_url is not None
        else os.getenv(
            "TELEMETRY_INGEST_URL",
            "https://mirage-junior.vercel.app" if os.getenv("VERCEL") else "http://127.0.0.1:5000",
        )
    )
    active_key = site_key if site_key is not None else os.getenv("SITE_TELEMETRY_KEY", "")
    app.wsgi_app = SilentBackendWAF(
        app.wsgi_app,
        telemetry_url=default_telemetry,
        site_key=active_key,
    )

    @app.route("/")
    def home():
        return render_template(
            "novapay.html",
            merchants=PUBLIC_MERCHANTS,
            invoices=list(RECENT_INVOICES),
        )

    @app.route("/api/customers")
    def api_customers():
        query = (request.args.get("q") or "").strip().lower()
        tier = (request.args.get("tier") or "").strip().lower()
        matched = []
        for m in PUBLIC_MERCHANTS:
            if tier and tier != "all" and m["tier"].lower() != tier:
                continue
            if query and query not in m["company"].lower() and query not in m["region"].lower() and query not in m["merchant_id"].lower():
                continue
            matched.append(m)
        return jsonify({
            "status": "ok",
            "count": len(matched),
            "merchants": matched,
        })

    @app.route("/api/pricing/estimate", methods=["POST"])
    def api_pricing_estimate():
        data = request.get_json(silent=True) or {}
        try:
            monthly_volume = max(500.0, float(data.get("volume_usd") or 25000))
        except (ValueError, TypeError):
            monthly_volume = 25000.0
        try:
            headcount = max(1, int(data.get("employees") or 25))
        except (ValueError, TypeError):
            headcount = 25

        currency = (data.get("currency") or "USD").upper()
        fx = FX_RATES.get(currency, FX_RATES["USD"])
        fee_rate = 0.009 if monthly_volume >= 100000 else (0.014 if monthly_volume >= 25000 else 0.019)
        platform_fee = round(headcount * 4.0 + monthly_volume * fee_rate, 2)
        net_usd = round(max(0.0, monthly_volume - platform_fee), 2)
        converted_net = round(net_usd * fx["rate"], 2)

        return jsonify({
            "status": "ok",
            "currency": currency,
            "symbol": fx["symbol"],
            "fx_rate": fx["rate"],
            "settlement_rail": fx["settlement"],
            "effective_rate_pct": round(fee_rate * 100, 2),
            "platform_fee_usd": platform_fee,
            "net_payout_usd": net_usd,
            "net_payout_local": converted_net,
        })

    @app.route("/api/invoices", methods=["GET", "POST"])
    def api_invoices():
        if request.method == "GET":
            return jsonify({"status": "ok", "invoices": list(RECENT_INVOICES)})

        data = request.get_json(silent=True) or request.form.to_dict() or {}
        client_name = (data.get("client") or "").strip()
        email = (data.get("email") or "billing@client.example").strip()
        currency = (data.get("currency") or "USD").upper()
        if currency not in FX_RATES:
            currency = "USD"
        try:
            amount = round(max(1.0, float(data.get("amount") or 0)), 2)
        except (ValueError, TypeError):
            return jsonify({"status": "error", "message": "Enter a valid invoice amount."}), 400

        if not client_name:
            return jsonify({"status": "error", "message": "Client name is required."}), 400

        inv = {
            "invoice_id": f"INV-2026-{secrets.randbelow(9000) + 1000}",
            "client": client_name[:80],
            "email": email[:120],
            "amount": amount,
            "currency": currency,
            "status": "Payment Link Ready",
        }
        RECENT_INVOICES.appendleft(inv)
        return jsonify({
            "status": "ok",
            "invoice": inv,
            "payment_url": f"{request.host_url.rstrip('/')}/pay/{inv['invoice_id']}",
            "invoices": list(RECENT_INVOICES),
        })

    @app.route("/pay/<invoice_id>")
    def invoice_checkout_preview(invoice_id):
        inv = next((i for i in RECENT_INVOICES if i["invoice_id"] == invoice_id), None)
        if not inv:
            return render_template("novapay.html", merchants=PUBLIC_MERCHANTS, invoices=list(RECENT_INVOICES))
        return jsonify({
            "checkout_status": "open",
            "invoice_id": inv["invoice_id"],
            "merchant": "NovaPay Cloud Payroll",
            "billed_to": inv["client"],
            "amount_due": f"{inv['amount']:.2f} {inv['currency']}",
            "supported_methods": ["Card", "ACH Direct Debit", "SEPA", "UPI / IMPS"],
        })

    @app.route("/api/v1/rates")
    def api_v1_rates():
        return jsonify({"base": "USD", "updated": "live", "rails": FX_RATES})

    @app.route("/api/contact", methods=["POST"])
    def api_contact():
        data = request.get_json(silent=True) or request.form.to_dict() or {}
        name = (data.get("name") or "").strip()
        email = (data.get("email") or "").strip()
        company = (data.get("company") or "").strip()
        if not name or not email:
            return jsonify({"status": "error", "message": "Please fill in your name and work email."}), 400
        ticket = f"NP-{secrets.randbelow(90000) + 10000}"
        DEMO_INQUIRIES.appendleft({"ticket": ticket, "name": name, "email": email, "company": company})
        return jsonify({
            "status": "ok",
            "ticket_id": ticket,
            "message": f"Thanks {name}! Onboarding specialist assigned (Ticket {ticket}).",
        })

    @app.route("/login", methods=["POST"])
    def merchant_login():
        data = request.get_json(silent=True) or request.form.to_dict() or {}
        email = (data.get("email") or data.get("username") or "").strip().lower()
        password = (data.get("password") or "").strip()
        if email == "demo@novapay.io" and password == "NovaPay@2026":
            return jsonify({
                "status": "ok",
                "workspace": "NovaPay Sandbox Workspace",
                "role": "Finance Controller",
                "session_token": f"np_sess_{secrets.token_hex(8)}",
            })
        return jsonify({
            "status": "error",
            "message": f"Invalid credentials for {email or 'account'}.",
        }), 401

    return app


app = create_demo_app()

if __name__ == "__main__":
    port = int(os.getenv("DEMO_TARGET_PORT", 5050))
    print(f"NovaPay Cloud Payroll running on http://localhost:{port}")
    app.run(host="0.0.0.0", port=port, debug=False, use_reloader=False)
