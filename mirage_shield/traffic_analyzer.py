"""
MIRAGE Shield — Traffic Analyzer Engine
Real-time behavioral analysis of incoming HTTP requests.
Classifies traffic as ALLOW (real site), REDIRECT (fake honeypot clone),
or BLOCK (HTTP 403 + OS Firewall Quarantine).

Algorithm: Weighted Multi-Factor Risk Scoring
─────────────────────────────────────────────
Each request is scored across 6 behavioral dimensions:
  1. User-Agent Analysis     (0-25 pts)  — Attack scanners & bot signatures
  2. Request Rate Analysis   (0-20 pts)  — Sliding-window burst frequency
  3. Path Suspicion Analysis (0-45 pts)  — Probing .env, admin, backups, git
  4. Payload Inspection      (0-45 pts)  — URL-decoded SQLi, XSS, Traversal, RCE
  5. Header Anomaly Check    (0-10 pts)  — Missing browser headers / odd methods
  6. Behavioral History      (0-40 pts)  — Sticky deception & repeat violations

Decision Matrix:
  Score  0-39  → ALLOW     (proxy cleanly to real website)
  Score 40-79  → REDIRECT  (divert seamlessly into cloned honeypot)
  Score 80-100 → BLOCK     (HTTP 403 + quarantine IP)
"""

import time
import logging
import ipaddress
import threading
from collections import defaultdict
from urllib.parse import unquote_plus
from typing import Tuple

import mirage_shield.config as shield_cfg

logger = logging.getLogger("MIRAGE.Shield.Analyzer")

# Decision constants
ALLOW = "ALLOW"
REDIRECT = "REDIRECT"
BLOCK = "BLOCK"


class TrafficAnalyzer:
    """
    Real-time traffic analysis engine using multi-factor behavioral scoring.
    Maintains per-IP state to trap suspicious actors in a sticky honeypot session.
    """

    def __init__(self, inspect_localhost: bool = None):
        self.inspect_localhost = (
            shield_cfg.INSPECT_LOCALHOST
            if inspect_localhost is None
            else inspect_localhost
        )
        self.sticky_session = shield_cfg.STICKY_HONEYPOT_SESSION

        # Per-IP state (thread-safe across concurrent Flask worker threads)
        self._lock = threading.Lock()
        self.request_log = defaultdict(list)       # {ip: [timestamps]}
        self.ip_suspicion = defaultdict(float)     # {ip: cumulative_score}
        self.ip_paths = defaultdict(set)           # {ip: {paths}}
        self.trapped_ips = set()                   # IPs currently trapped in clone
        self.blocked_ips = set()                   # IPs blocked (403)
        self.custom_whitelist = set()              # Explicit admin-trusted IPs
        self.analysis_history = []                 # Recent telemetry records

        # Pre-parse whitelisted CIDRs (used when inspect_localhost is False)
        self.whitelisted_networks = []
        for cidr in shield_cfg.WHITELISTED_CIDRS:
            try:
                self.whitelisted_networks.append(ipaddress.ip_network(cidr, strict=False))
            except ValueError:
                pass

    def analyze(self, ip: str, path: str, method: str,
                user_agent: str, headers: dict,
                query_string: str = "", body: str = "",
                site_id: str = "global") -> Tuple[str, int, dict]:
        """
        Analyze an incoming HTTP request and decide ALLOW / REDIRECT / BLOCK.
        Returns: (decision, score, breakdown)
        """
        with self._lock:
            # Explicit admin whitelist or strict non-local CIDR check
            if self._is_whitelisted(ip):
                return ALLOW, 0, {"whitelisted": True, "total": 0}

            # Already hard-blocked
            if ip in self.blocked_ips:
                return BLOCK, 100, {"already_blocked": True, "total": 100}

            # Score all 6 behavioral dimensions
            ua_score = self._score_user_agent(user_agent)
            rate_score = self._score_request_rate(ip)
            path_score, path_flags = self._score_path(ip, path)
            payload_score, attack_types = self._score_payload(query_string, body, path)
            header_score = self._score_headers(headers, method)
            history_score = self._score_history(ip, path_score, payload_score)

            raw_score = ua_score + rate_score + path_score + payload_score + header_score + history_score

            # Sticky deception floor: once caught, keep attacker in the clone
            if self.sticky_session and ip in self.trapped_ips:
                raw_score = max(raw_score, shield_cfg.SUSPICION_THRESHOLD)

            final_score = min(100, int(raw_score))

            breakdown = {
                "user_agent": ua_score,
                "request_rate": rate_score,
                "suspicious_path": path_score,
                "payload_injection": payload_score,
                "header_anomaly": header_score,
                "behavioral_history": history_score,
                "attack_types": attack_types,
                "path_flags": path_flags,
                "total": final_score,
            }

            # Update cumulative IP memory (escalate on repeat hostile events or automated exploit payloads)
            if final_score > 0:
                prev_suspicion = self.ip_suspicion[ip]
                is_repeat = prev_suspicion > 0 and (path_score > 0 or payload_score > 0 or ua_score >= 20)
                is_automated_exploit = payload_score > 0 and ua_score >= 20
                if is_repeat or is_automated_exploit:
                    self.ip_suspicion[ip] = min(
                        100.0,
                        max(prev_suspicion, final_score) + (15 if payload_score > 0 else 10),
                    )
                    if self.ip_suspicion[ip] > final_score:
                        final_score = min(100, int(self.ip_suspicion[ip]))
                        breakdown["total"] = final_score
                else:
                    self.ip_suspicion[ip] = max(prev_suspicion, float(final_score))

            if len(self.ip_paths[ip]) < 200:
                self.ip_paths[ip].add(path)

            # Make routing decision
            if final_score >= shield_cfg.BLOCK_THRESHOLD:
                decision = BLOCK
                self.blocked_ips.add(ip)
                self.trapped_ips.discard(ip)
                logger.warning(f"🚫 BLOCKED: {ip} (score: {final_score}, types: {attack_types})")
            elif final_score >= shield_cfg.SUSPICION_THRESHOLD:
                decision = REDIRECT
                self.trapped_ips.add(ip)
                logger.info(f"🪤 DIVERTED TO CLONE: {ip} → {path} (score: {final_score})")
            else:
                decision = ALLOW

            # Store telemetry for dashboard
            self.analysis_history.append({
                "timestamp": time.time(),
                "site_id": site_id or "global",
                "ip": ip,
                "path": path,
                "method": method,
                "user_agent": (user_agent or "")[:120],
                "score": final_score,
                "decision": decision,
                "attack_types": attack_types,
                "breakdown": breakdown,
            })
            if len(self.analysis_history) > 1000:
                self.analysis_history = self.analysis_history[-500:]

            return decision, final_score, breakdown

    # ═══════════════════════════════════════════════════
    # Individual Scoring Functions
    # ═══════════════════════════════════════════════════

    def _score_user_agent(self, ua: str) -> int:
        if not ua:
            return 15
        ua_lower = ua.lower()
        for tool in shield_cfg.MALICIOUS_USER_AGENTS:
            if tool.lower() in ua_lower:
                return 25
        if len(ua) < 20:
            return 10
        if ua.startswith("Mozilla") and "compatible" not in ua_lower:
            return 0
        return 5

    def _score_request_rate(self, ip: str) -> int:
        now = time.time()
        self.request_log[ip].append(now)
        cutoff = now - shield_cfg.RATE_LIMIT_WINDOW
        self.request_log[ip] = [t for t in self.request_log[ip] if t > cutoff]
        count = len(self.request_log[ip])

        if count <= 8:
            return 0
        elif count <= shield_cfg.RATE_LIMIT_MAX_REQUESTS // 2:
            return 5
        elif count <= shield_cfg.RATE_LIMIT_MAX_REQUESTS:
            return 12
        return 20

    def _score_path(self, ip: str, path: str) -> Tuple[int, list]:
        path_lower = unquote_plus(path).lower()
        score = 0
        flags = []

        for high_risk in shield_cfg.HIGH_RISK_PATHS:
            if high_risk.lower() in path_lower:
                score = 40
                flags.append(f"high_risk:{high_risk}")
                break

        if score == 0:
            for recon in shield_cfg.RECON_PATHS:
                if recon.lower() in path_lower:
                    score = 20
                    flags.append(f"recon:{recon}")
                    break

        suspicious_count = sum(
            1 for p in self.ip_paths.get(ip, set())
            if any(s.lower() in p.lower() for s in shield_cfg.SUSPICIOUS_PATHS)
        )
        if suspicious_count >= 3:
            score = max(score, 45)
            flags.append("multi_path_recon")

        return score, flags

    def _score_payload(self, query: str, body: str, path: str) -> Tuple[int, list]:
        raw_combined = f"{query} {body} {path}"
        decoded = unquote_plus(raw_combined)
        combined_upper = f"{raw_combined} {decoded}".upper()

        score = 0
        attack_types = []

        for pattern in shield_cfg.SQLI_PATTERNS:
            if pattern.upper() in combined_upper:
                score = max(score, 45)
                attack_types.append("sql_injection")
                break

        for pattern in shield_cfg.CMD_INJECTION_PATTERNS:
            if pattern.upper() in combined_upper:
                score = max(score, 45)
                attack_types.append("command_injection")
                break

        for pattern in shield_cfg.TRAVERSAL_PATTERNS:
            if pattern.lower() in decoded.lower() or pattern.lower() in raw_combined.lower():
                score = max(score, 45)
                attack_types.append("directory_traversal")
                break

        for pattern in shield_cfg.XSS_PATTERNS:
            if pattern.upper() in combined_upper:
                score = max(score, 40)
                attack_types.append("xss_probe")
                break

        return score, attack_types

    def _score_headers(self, headers: dict, method: str) -> int:
        score = 0
        # Case-insensitive header lookup
        lower_headers = {str(k).lower(): v for k, v in (headers or {}).items()}
        if not lower_headers.get("accept"):
            score += 3
        if not lower_headers.get("accept-language"):
            score += 2
        if not lower_headers.get("accept-encoding"):
            score += 2
        if (method or "GET").upper() in ("DELETE", "PUT", "PATCH", "TRACE"):
            score += 3
        return min(10, score)

    def _score_history(self, ip: str, current_path_score: int, current_payload_score: int) -> int:
        prev = self.ip_suspicion.get(ip, 0)
        unique_paths = len(self.ip_paths.get(ip, set()))
        score = 0

        if prev >= shield_cfg.SUSPICION_THRESHOLD:
            # Repeated hostile requests escalate toward auto-block
            score += 20 if (current_path_score > 0 or current_payload_score > 0) else 10
        elif prev > 0:
            score += 10

        if unique_paths >= 10:
            score += 15
        elif unique_paths >= 4:
            score += 8

        return min(40, score)

    def _is_whitelisted(self, ip: str) -> bool:
        if ip in self.custom_whitelist:
            return True
        if self.inspect_localhost:
            return False
        try:
            addr = ipaddress.ip_address(ip)
            return any(addr in net for net in self.whitelisted_networks)
        except ValueError:
            return False

    # ═══════════════════════════════════════════════════
    # Management & Dashboard Telemetry Methods
    # ═══════════════════════════════════════════════════

    def set_inspect_localhost(self, enabled: bool):
        self.inspect_localhost = bool(enabled)

    def get_stats(self, site_id: str = None) -> dict:
        with self._lock:
            records = (
                [r for r in self.analysis_history if r.get("site_id") == site_id]
                if site_id and site_id != "global"
                else self.analysis_history
            )
            total = len(records)
            blocked = sum(1 for r in records if r["decision"] == BLOCK)
            redirected = sum(1 for r in records if r["decision"] == REDIRECT)
            allowed = sum(1 for r in records if r["decision"] == ALLOW)

            return {
                "total_analyzed": total,
                "allowed": allowed,
                "redirected_to_honeypot": redirected,
                "blocked": blocked,
                "currently_blocked_ips": len(self.blocked_ips),
                "currently_trapped_ips": len(self.trapped_ips),
                "tracked_ips": len(self.ip_suspicion),
                "blocked_ip_list": sorted(list(self.blocked_ips)),
                "trapped_ip_list": sorted(list(self.trapped_ips)),
                "inspect_localhost": self.inspect_localhost,
            }

    def get_recent_analysis(self, limit: int = 50, site_id: str = None) -> list:
        with self._lock:
            records = (
                [r for r in self.analysis_history if r.get("site_id") == site_id]
                if site_id and site_id != "global"
                else self.analysis_history
            )
            return records[-limit:][::-1]

    def unblock_ip(self, ip: str) -> bool:
        """Reset all suspicion/block state for an IP."""
        with self._lock:
            changed = (ip in self.blocked_ips) or (ip in self.trapped_ips) or (ip in self.ip_suspicion)
            self.blocked_ips.discard(ip)
            self.trapped_ips.discard(ip)
            self.ip_suspicion[ip] = 0
            self.ip_paths[ip].clear()
            self.request_log[ip].clear()
            if changed:
                logger.info(f"✅ Shield state reset / unblocked for IP: {ip}")
            return changed
