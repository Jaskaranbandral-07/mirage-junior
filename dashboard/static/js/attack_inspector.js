(function (global) {
    const METHOD_PROFILES = {
        sql_injection: {
            title: 'SQL Injection Absorption & Synthetic Row Dump',
            signature: "Match: (' OR | \" OR | UNION SELECT | 1=1 | 1' OR '1'='1 | '; DROP | SLEEP()",
            deceptionFn: 'SyntheticDeceptionEngine._fake_sqli_dump(domain, ip)',
            explanation: [
                'Intercepted at the WSGI Shield layer BEFORE the customer application route or SQL database could run.',
                'inspect_request_payload() scanned path, query string, and POST body and matched SQL injection tautology/UNION patterns (+50 detector / +25 risk points).',
                'SyntheticDeceptionEngine._fake_sqli_dump() built realistic PostgreSQL decoy rows with fake emails (@corp-sandbox.invalid) and invalid $2b$12$DECOY... hashes.',
                'ScoringEngine incremented the attacker IP profile toward auto-quarantine (25+ pts) and pushed telemetry strictly to this site workspace.'
            ],
            code: `# 1. Interception BEFORE real backend executes (mirage_shield/sdk/python_shield.py)
decision, score, attack_types = inspect_request_payload(path, method, ua, qs, body_text)
if decision == "ALLOW":
    return self.wsgi_app(environ, start_response)  # Never reached on attack

# 2. Match SQLi signatures & assign threat points
if any(s in combined_up for s in _SQLI_SIGS):  # "' OR ", "1=1", "UNION SELECT"
    score += 50
    attack_types.append("sql_injection")

# 3. Serve realistic yet 100% useless synthetic SQL rows (mirage_shield/synthetic_deception.py)
body_str, content_type, status_code, fake_count = self.deception.generate_response(
    path=path, attack_types=attack_types, ip=ip, domain=self.domain
)
# -> returns: {"db_engine": "PostgreSQL 15.4 (Read-Replica)", "rows": [{"password_bcrypt": "$2b$12$DECOY..."}]}

# 4. Score & Auto-Quarantine at >= 25 pts (engine/scoring_engine.py)
if score >= 25:
    self.quarantine_manager.block_ip(ip_address, threat_score=score, site_id=site_id)`
        },
        directory_traversal: {
            title: 'Directory Traversal Bait (/etc/passwd Decoy)',
            signature: 'Match: (../ | ..\\ | %2E%2E/ | /ETC/PASSWD | WIN.INI)',
            deceptionFn: 'SyntheticDeceptionEngine._fake_traversal_response(path)',
            explanation: [
                'Shield intercepted path-traversal sequence before filesystem or static file handlers ran.',
                'Signature scanner detected ../ and sensitive OS file targets (/etc/passwd or win.ini).',
                'Returned a harmless synthetic Linux passwd snippet pointing attackers toward fake internal backup paths.',
                'Logged MITRE T1083 telemetry and updated attacker score for auto-quarantine.'
            ],
            code: `# Path Traversal Signature Match & Fake File Response
if any(s in combined_up for s in ("../", "..\\\\", "/ETC/PASSWD", "WIN.INI")):
    score += 50
    attack_types.append("directory_traversal")

def _fake_traversal_response(self, path: str):
    body = (
        "root:x:0:0:root:/root:/bin/bash\\n"
        "www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\\n"
        "mirage_app:x:1001:1001:App Service:/home/mirage_app:/bin/bash\\n"
    )
    return body, "text/plain", 200, 5`
        },
        shell_command: {
            title: 'Command Injection (RCE) Shell Sandbox',
            signature: 'Match: (; CAT | | WHOAMI | && WHOAMI | $(WHOAMI) | /BIN/SH)',
            deceptionFn: 'SyntheticDeceptionEngine._fake_rce_response(domain)',
            explanation: [
                'WSGI/Proxy Shield blocked command injection tokens before any subprocess or handler executed.',
                'Returned plausible sandboxed Linux shell identity strings (uid=1001(deploy)) to keep attackers trapped.',
                'Assigned 25 threat points (MITRE T1059) triggering immediate quarantine at the 25-pt threshold.'
            ],
            code: `# Command Injection Signature Check & Decoy Linux Output
if any(s in combined_up for s in ("; CAT ", "| WHOAMI", "&& WHOAMI", "$(WHOAMI)", "/BIN/SH")):
    score += 50
    attack_types.append("command_injection")

def _fake_rce_response(self, domain: str):
    body = (
        f"Linux prod-node-02.{domain} 5.15.0-91-generic x86_64 GNU/Linux\\n"
        "uid=1001(deploy) gid=1001(deploy) groups=1001(deploy),27(sudo)\\n"
    )
    return body, "text/plain", 200, 4`
        },
        credential_harvest: {
            title: 'Decoy Admin Login & Credential Harvesting Trap',
            signature: 'Target: (/admin/login | /wp-login.php | POST /login SQLi or brute attempt)',
            deceptionFn: 'HoneypotInjector.serve_trap() + DatabaseManager.log_credential()',
            explanation: [
                'Intercepted unauthorized or hostile login attempt on trapped admin/SSO portal endpoint.',
                'Captured attacker username & password payload into the site-isolated credentials table for analyst visibility.',
                'Served deceptive invalid/replica response without exposing real authentication logic, and quarantined IP at >= 25 pts.'
            ],
            code: `# Credential Capture & Portal Trap Logging (dashboard/routes.py / mirage_shield/honeypot_injector.py)
captured_user, captured_pass = _extract_post_credentials(body_text)
db_mgr.log_credential(
    ip_address=ip,
    protocol="HTTP",
    username=captured_user,
    password=captured_pass,
    success=False,
    site_id=site_id,
)
ScoringEngine().calculate_threat_score(ip, site_id=site_id)  # Blocks IP at >= 25 pts`
        },
        targeted_recon: {
            title: 'Sensitive Endpoint Recon Trap (/.env, /api/config, Scraping)',
            signature: 'Target: (/.env | /.git | /api/v1/customers | /backup.sql | scanner UA)',
            deceptionFn: 'SyntheticDeceptionEngine._fake_env_response() / _fake_api_records()',
            explanation: [
                'Detected targeted reconnaissance against secret/config paths or automated API scraping endpoints.',
                'Instead of 404 or real customer records, returned fake sandbox tokens (sk_decoy_invalid_...) and canary .env keys.',
                'Incremented fake_records_served counter and evaluated attacker IP risk against 25-pt quarantine threshold.'
            ],
            code: `# Secret Recon & Synthetic API Bait (mirage_shield/synthetic_deception.py)
if any(tp in path_low for tp in ("/.env", "/.git", "/wp-login.php", "/api/config", "/backup.sql")):
    score += 45
    attack_types.append("targeted_recon")

def _fake_env_response(self, domain: str):
    body = (
        f"# Decoy Environment Snapshot ({domain})\\n"
        "DB_PASSWORD=decoy_not_a_real_password_991\\n"
        "STRIPE_SECRET_KEY=sk_decoy_invalid_0000000000\\n"
        "AWS_ACCESS_KEY_ID=AKIADECOYSANDBOX0000\\n"
    )
    return body, "text/plain; charset=utf-8", 200, 6`
        }
    };

    function parseDetails(raw) {
        if (!raw) return {};
        if (typeof raw === 'object') return raw;
        try {
            return JSON.parse(raw);
        } catch {
            return { raw_details: String(raw) };
        }
    }

    function ensureModal() {
        let overlay = document.getElementById('attack-inspector-modal');
        if (overlay) return overlay;

        overlay = document.createElement('div');
        overlay.id = 'attack-inspector-modal';
        overlay.style.cssText = 'position:fixed;inset:0;z-index:2000;background:rgba(5,9,17,0.82);backdrop-filter:blur(6px);display:none;align-items:center;justify-content:center;padding:18px;';
        overlay.innerHTML = `
            <div style="background:#0d1320;border:1px solid rgba(0,212,255,0.35);border-radius:14px;max-width:860px;width:100%;max-height:90vh;display:flex;flex-direction:column;overflow:hidden;box-shadow:0 24px 70px rgba(0,0,0,0.65);">
                <div style="padding:16px 22px;border-bottom:1px solid #1e293b;display:flex;justify-content:space-between;align-items:center;gap:12px;">
                    <div>
                        <div style="font-size:0.75rem;color:#00d4ff;font-weight:700;letter-spacing:0.6px;text-transform:uppercase;">MIRAGE Shield Execution Trace</div>
                        <h3 id="aim-title" style="margin:2px 0 0;color:#f8fafc;font-size:1.1rem;"></h3>
                    </div>
                    <button id="aim-close-btn" style="background:#1e293b;color:#e2e8f0;border:1px solid #334155;border-radius:8px;padding:6px 12px;cursor:pointer;font-weight:700;">&times; Close</button>
                </div>

                <div id="aim-badges" style="padding:12px 22px;background:#090d16;border-bottom:1px solid #1e293b;display:flex;gap:10px;flex-wrap:wrap;font-size:0.78rem;"></div>

                <div style="padding:10px 22px 0;border-bottom:1px solid #1e293b;display:flex;gap:8px;flex-wrap:wrap;">
                    <button class="btn btn-primary aim-tab" data-tab="flow" style="padding:6px 14px;font-size:0.8rem;">1. Method &amp; How It Worked</button>
                    <button class="btn aim-tab" data-tab="code" style="padding:6px 14px;font-size:0.8rem;background:#161e2e;color:#94a3b8;border:1px solid #263145;">2. Python Code Executed</button>
                    <button class="btn aim-tab" data-tab="payload" style="padding:6px 14px;font-size:0.8rem;background:#161e2e;color:#94a3b8;border:1px solid #263145;">3. Captured Request &amp; Response</button>
                </div>

                <div style="padding:18px 22px;overflow-y:auto;flex:1;">
                    <div id="aim-panel-flow"></div>
                    <div id="aim-panel-code" style="display:none;">
                        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px;">
                            <span id="aim-sig" style="font-size:0.8rem;color:#fbbf24;font-family:monospace;"></span>
                            <button id="aim-copy-code" class="btn" style="padding:4px 10px;font-size:0.75rem;background:rgba(0,255,65,0.12);color:#00ff41;border:1px solid rgba(0,255,65,0.35);">Copy Code</button>
                        </div>
                        <pre id="aim-code-pre" style="margin:0;padding:14px;background:#050811;border:1px solid #1e293b;border-radius:8px;color:#4ade80;font-size:0.78rem;line-height:1.5;overflow-x:auto;"></pre>
                    </div>
                    <div id="aim-panel-payload" style="display:none;">
                        <pre id="aim-payload-pre" style="margin:0;padding:14px;background:#050811;border:1px solid #1e293b;border-radius:8px;color:#38bdf8;font-size:0.78rem;line-height:1.5;overflow-x:auto;white-space:pre-wrap;"></pre>
                    </div>
                </div>
            </div>
        `;

        document.body.appendChild(overlay);
        overlay.addEventListener('click', (e) => {
            if (e.target === overlay) overlay.style.display = 'none';
        });
        overlay.querySelector('#aim-close-btn').addEventListener('click', () => {
            overlay.style.display = 'none';
        });
        document.addEventListener('keydown', (e) => {
            if (e.key === 'Escape' && overlay.style.display === 'flex') {
                overlay.style.display = 'none';
            }
        });
        overlay.querySelectorAll('.aim-tab').forEach((btn) => {
            btn.addEventListener('click', () => switchTab(overlay, btn.dataset.tab));
        });
        overlay.querySelector('#aim-copy-code').addEventListener('click', () => {
            const txt = overlay.querySelector('#aim-code-pre').textContent || '';
            if (navigator.clipboard) navigator.clipboard.writeText(txt).catch(() => {});
            const b = overlay.querySelector('#aim-copy-code');
            b.textContent = 'Copied!';
            setTimeout(() => { b.textContent = 'Copy Code'; }, 1500);
        });
        return overlay;
    }

    function switchTab(overlay, tabName) {
        overlay.querySelectorAll('.aim-tab').forEach((b) => {
            const active = b.dataset.tab === tabName;
            b.classList.toggle('btn-primary', active);
            b.style.background = active ? '' : '#161e2e';
            b.style.color = active ? '' : '#94a3b8';
            b.style.border = active ? '' : '1px solid #263145';
        });
        overlay.querySelector('#aim-panel-flow').style.display = tabName === 'flow' ? 'block' : 'none';
        overlay.querySelector('#aim-panel-code').style.display = tabName === 'code' ? 'block' : 'none';
        overlay.querySelector('#aim-panel-payload').style.display = tabName === 'payload' ? 'block' : 'none';
    }

    function esc(v) {
        return String(v ?? '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
    }

    function open(eventObj) {
        const overlay = ensureModal();
        const ev = eventObj || {};
        const details = parseDetails(ev.details);
        const profile = METHOD_PROFILES[ev.event_type] || METHOD_PROFILES.targeted_recon;
        const score = Number(ev.threat_score || ev.threat_pts || 0);
        const methodUsed = details.method || 'GET';
        const targetPath = details.path || '/';
        const sourceLayer = details.source || 'shield_middleware';
        const defenseFn = details.defense_method || profile.deceptionFn;
        const fakeCount = details.fake_records_served ?? 'decoy';

        overlay.querySelector('#aim-title').textContent = profile.title;
        overlay.querySelector('#aim-badges').innerHTML = `
            <span class="badge badge-scanner">Event: ${esc(ev.event_type || 'shield')}</span>
            <span class="badge badge-suspicious">MITRE: ${esc(ev.mitre_id || 'N/A')}</span>
            <span class="badge ${score >= 25 ? 'badge-critical' : 'badge-active'}">Score: ${score}/100 ${score >= 25 ? '(Auto-Quarantined)' : ''}</span>
            <span style="padding:4px 9px;background:#161e2e;border:1px solid #263145;border-radius:6px;color:#00d4ff;font-family:monospace;">IP: ${esc(ev.ip_address || '-')}</span>
            <span style="padding:4px 9px;background:#161e2e;border:1px solid #263145;border-radius:6px;color:#a5f3fc;font-family:monospace;">${esc(methodUsed)} ${esc(targetPath)}</span>
        `;

        const stepsHtml = profile.explanation.map((line, i) => `
            <div style="display:flex;gap:12px;align-items:flex-start;padding:10px 12px;background:#131b2b;border:1px solid #222e46;border-radius:8px;margin-bottom:8px;">
                <span style="min-width:24px;height:24px;border-radius:999px;background:rgba(0,212,255,0.16);color:#00d4ff;display:grid;place-items:center;font-weight:800;font-size:0.78rem;">${i + 1}</span>
                <div style="color:#cbd5e1;font-size:0.86rem;line-height:1.45;">${esc(line)}</div>
            </div>
        `).join('');

        overlay.querySelector('#aim-panel-flow').innerHTML = `
            <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:10px;margin-bottom:14px;">
                <div style="background:#090d16;border:1px solid #1e293b;border-radius:8px;padding:10px;">
                    <div style="font-size:0.72rem;color:#94a3b8;text-transform:uppercase;">Runtime Source</div>
                    <div style="color:#00ff41;font-family:monospace;font-size:0.85rem;margin-top:3px;">${esc(sourceLayer)}</div>
                </div>
                <div style="background:#090d16;border:1px solid #1e293b;border-radius:8px;padding:10px;">
                    <div style="font-size:0.72rem;color:#94a3b8;text-transform:uppercase;">Defense Function Called</div>
                    <div style="color:#00d4ff;font-family:monospace;font-size:0.82rem;margin-top:3px;">${esc(defenseFn)}</div>
                </div>
                <div style="background:#090d16;border:1px solid #1e293b;border-radius:8px;padding:10px;">
                    <div style="font-size:0.72rem;color:#94a3b8;text-transform:uppercase;">Fake Data Served</div>
                    <div style="color:#fbbf24;font-family:monospace;font-size:0.85rem;margin-top:3px;">${esc(fakeCount)} decoy records</div>
                </div>
            </div>
            ${stepsHtml}
        `;

        overlay.querySelector('#aim-sig').textContent = profile.signature;
        overlay.querySelector('#aim-code-pre').textContent = profile.code;
        overlay.querySelector('#aim-payload-pre').textContent = JSON.stringify({
            timestamp: ev.timestamp,
            site_id: ev.site_id,
            ip_address: ev.ip_address,
            protocol: ev.protocol,
            event_type: ev.event_type,
            mitre_id: ev.mitre_id,
            threat_pts: ev.threat_pts,
            threat_score: ev.threat_score,
            details: details,
        }, null, 2);

        switchTab(overlay, 'flow');
        overlay.style.display = 'flex';
    }

    global.MirageAttackInspector = { open };
})(window);
