/**
 * MIRAGE Shield — Zero-Dependency Node.js / Express Middleware
 *
 * Install on any Express backend so attacks are absorbed BEFORE reaching
 * your database/controllers, attackers receive useless synthetic decoy data,
 * and every incident streams to your private MIRAGE Shield customer dashboard.
 *
 * Usage:
 *   const mirageShield = require("./node_shield");
 *   app.use(mirageShield({ siteKey: "ms_live_YOUR_KEY", shieldUrl: "https://mirage-junior.vercel.app" }));
 */

const SCANNER_UAS = [
  "sqlmap", "nikto", "nmap", "masscan", "dirbuster", "gobuster",
  "wfuzz", "ffuf", "hydra", "nuclei", "wpscan", "acunetix",
  "curl/", "python-requests", "go-http-client",
];

const TRAP_PATHS = [
  "/.env", "/.git", "/wp-login.php", "/wp-admin", "/phpmyadmin",
  "/admin/login", "/api/config", "/api/keys", "/backup.sql", "/dump.sql",
  "/phpinfo.php", "/debug", "/etc/passwd",
];

function analyzeRequest(req) {
  let score = 0;
  const attackTypes = [];
  const ua = String(req.headers["user-agent"] || "").toLowerCase();
  const path = String(req.path || req.url || "/").toLowerCase();
  const bodyStr = req.body ? JSON.stringify(req.body) : "";
  const queryStr = req.originalUrl || req.url || "";
  const combined = decodeURIComponent(`${queryStr} ${bodyStr} ${path}`.replace(/\+/g, " ")).toUpperCase();

  if (SCANNER_UAS.some((t) => ua.includes(t))) score += 25;
  if (TRAP_PATHS.some((p) => path.includes(p))) {
    score += 45;
    attackTypes.push("targeted_recon");
  }
  if (/' OR |" OR |UNION SELECT|1=1|'; DROP |SLEEP\(|INFORMATION_SCHEMA/.test(combined)) {
    score += 50;
    attackTypes.push("sql_injection");
  }
  if (/\.\.\/|\.\.\\|%2E%2E\/|\/ETC\/PASSWD|WIN\.INI/.test(combined)) {
    score += 50;
    attackTypes.push("directory_traversal");
  }
  if (/; CAT |\| WHOAMI|&& WHOAMI|\$\(WHOAMI\)|\/BIN\/SH|POWERSHELL/.test(combined)) {
    score += 50;
    attackTypes.push("command_injection");
  }
  if (/<SCRIPT|JAVASCRIPT:|ONERROR=|ONLOAD=|ALERT\(|DOCUMENT\.COOKIE/.test(combined)) {
    score += 45;
    attackTypes.push("xss_probe");
  }

  const finalScore = Math.min(100, score);
  const decision = finalScore >= 80 ? "BLOCK" : finalScore >= 40 ? "REDIRECT" : "ALLOW";
  return { decision, score: finalScore, attackTypes };
}

function buildFakePayload(req, attackTypes) {
  if (attackTypes.includes("sql_injection")) {
    return {
      status: 200,
      fakeCount: 3,
      body: {
        query_status: "rows_returned",
        db_engine: "PostgreSQL 15.4 (Read-Replica)",
        rows: [
          { id: 1, email: "aarav.decoy@sandbox.invalid", password_bcrypt: "$2b$12$DECOY_HASH_INVALID_01", role: "ops" },
          { id: 2, email: "elena.decoy@sandbox.invalid", password_bcrypt: "$2b$12$DECOY_HASH_INVALID_02", role: "admin" },
          { id: 3, email: "marcus.decoy@sandbox.invalid", password_bcrypt: "$2b$12$DECOY_HASH_INVALID_03", role: "audit" },
        ],
      },
    };
  }
  return {
    status: 200,
    fakeCount: 2,
    body: {
      status: "ok",
      source: "replica-cache",
      data: [
        { id: "usr_decoy_101", email: "decoy.user1@sandbox.invalid", api_token: "sk_decoy_invalid_9981" },
        { id: "usr_decoy_102", email: "decoy.user2@sandbox.invalid", api_token: "sk_decoy_invalid_4412" },
      ],
      debug_links: ["/.env", "/api/config", "/backup.sql"],
    },
  };
}

module.exports = function mirageShield({ siteKey, shieldUrl = "https://mirage-junior.vercel.app" } = {}) {
  return function mirageShieldMiddleware(req, res, next) {
    const { decision, score, attackTypes } = analyzeRequest(req);
    if (decision === "ALLOW") return next();

    const ip =
      String(req.headers["x-forwarded-for"] || "").split(",")[0].trim() ||
      req.ip ||
      req.socket?.remoteAddress ||
      "127.0.0.1";

    let status = 200;
    let payload;
    let fakeCount = 0;

    if (decision === "BLOCK") {
      status = 403;
      payload = { error: "Forbidden — Blocked by MIRAGE Shield", score, ip };
    } else {
      const fake = buildFakePayload(req, attackTypes);
      status = fake.status;
      payload = fake.body;
      fakeCount = fake.fakeCount;
    }

    if (siteKey && typeof fetch === "function") {
      fetch(`${shieldUrl.replace(/\/+$/, "")}/api/ingest`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-MIRAGE-Site-Key": siteKey,
        },
        body: JSON.stringify({
          ip,
          path: req.path || req.url,
          method: req.method,
          user_agent: String(req.headers["user-agent"] || "").slice(0, 160),
          score,
          decision,
          attack_types: attackTypes,
          fake_records_served: fakeCount,
          source: "node_express_sdk",
        }),
      }).catch(() => {});
    }

    res.setHeader("X-Protected-By", "MIRAGE-Shield");
    return res.status(status).json(payload);
  };
};
