"""
Remediation & MITRE ATT&CK knowledge base.

Enriches attack reports with:
  • MITRE ATT&CK technique mappings per phase
  • Concrete, prioritized remediation advice derived from what ACTUALLY
    succeeded in the run (different advice per difficulty mode)

Pure data + pure functions — no dependencies.
"""

from typing import Any, Dict, List, Optional

# ---------------------------------------------------------------------------
# MITRE ATT&CK mapping (phase key -> techniques)
# ---------------------------------------------------------------------------

MITRE: Dict[str, List[Dict[str, str]]] = {
    "recon": [
        {"id": "T1595", "name": "Active Scanning"},
        {"id": "T1592", "name": "Gather Victim Host Info"},
        {"id": "T1580", "name": "Cloud Infrastructure Discovery"},
    ],
    "exploit": [
        {"id": "T1190", "name": "Exploit Public-Facing Application"},
        {"id": "T1134", "name": "Access Token Manipulation"},
        {"id": "T1068", "name": "Exploitation for Privilege Escalation"},
    ],
    "persistence": [
        {"id": "T1136", "name": "Create Account"},
        {"id": "T1098", "name": "Account Manipulation"},
        {"id": "T1053.005", "name": "Scheduled Task/Job: Cron"},
    ],
    "lateral_movement": [
        {"id": "T1552.001", "name": "Unsecured Credentials: Credentials In Files"},
        {"id": "T1046", "name": "Network Service Discovery"},
        {"id": "T1552.004", "name": "Unsecured Credentials: Private Keys"},
    ],
    "exfiltration": [
        {"id": "T1213", "name": "Data from Information Repositories"},
        {"id": "T1005", "name": "Data from Local System"},
    ],
    "cover_tracks": [
        {"id": "T1070", "name": "Indicator Removal"},
        {"id": "T1036", "name": "Masquerading"},
    ],
}

# ---------------------------------------------------------------------------
# Remediation rules
# ---------------------------------------------------------------------------
# key  -> (area, priority, title, fix)
# keys match exploited methods, backdoor types, credential types,
# exfiltration methods, and recon findings.

PRIORITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}

RULES: Dict[str, Dict[str, str]] = {
    # ---- exploitation methods
    "algorithm_confusion": {
        "area": "Authentication", "priority": "critical",
        "title": "JWT algorithm confusion accepted",
        "fix": "Pin accepted JWT algorithms server-side (allowlist HS256 or RS256 — never both). Reject tokens whose header algorithm differs from the configured one, and never derive the verification algorithm from the token itself.",
    },
    "signature_stripping": {
        "area": "Authentication", "priority": "critical",
        "title": "JWT signatures can be stripped (alg:none)",
        "fix": "Reject any token with an empty/absent signature or 'alg: none'. Enforce signature verification on every request — there is no 'public' path that should skip it.",
    },
    "jti_manipulation": {
        "area": "Authentication", "priority": "high",
        "title": "JWT ID (jti) manipulation bypasses revocation",
        "fix": "Implement a server-side revocation list / token blacklist checked on every request, keyed by jti, with the same TTL as the token.",
    },
    "subscription_race": {
        "area": "Business logic", "priority": "high",
        "title": "Race condition in subscription upgrade",
        "fix": "Add idempotency keys to all billing/upgrade endpoints and serialize upgrades per account (row lock or distributed lock). Never trust client-supplied tier values.",
    },
    "promo_bypass": {
        "area": "Business logic", "priority": "high",
        "title": "Promo code validation can be bypassed",
        "fix": "Validate promo codes strictly server-side against a signed, server-owned table. Reject malformed input (empty, null, glob, SQL fragments) before lookup, and never echo client-supplied discount values back as approved.",
    },
    "privesc": {
        "area": "Authorization", "priority": "critical",
        "title": "Privilege escalation via client-controlled role fields",
        "fix": "Never accept role/permission/admin flags from request bodies on profile endpoints. Derive authorization exclusively from the verified session/token server-side.",
    },
    # ---- persistence backdoors
    "hidden_admin": {
        "area": "Account management", "priority": "critical",
        "title": "Hidden admin accounts can be created via API",
        "fix": "Require re-authentication + MFA for privileged account creation, alert on new admin accounts, and audit 'created_by' provenance. Admin user management should not be reachable by ordinary API tokens.",
    },
    "api_key": {
        "area": "Account management", "priority": "high",
        "title": "Persistent API keys can be self-issued",
        "fix": "API key issuance must require an authorized admin flow with approval, scopes, and expiry. Alert on keys created with wildcard scopes ('*') or no expiry.",
    },
    "webhook": {
        "area": "Integrations", "priority": "high",
        "title": "Webhook endpoints allow attacker-controlled callbacks",
        "fix": "Restrict webhook registration to verified owners, allow-list callback domains, require signed payloads, and alert on webhooks pointing to unknown external hosts.",
    },
    "cron": {
        "area": "Automation", "priority": "critical",
        "title": "Scheduled tasks can be injected via API",
        "fix": "Scheduled-task creation must be an internal, admin-only operation — never exposed through the public API. Restrict allowed commands to a server-defined set.",
    },
    # ---- credential types
    "DATABASE_URL": {
        "area": "Secrets", "priority": "critical",
        "title": "Database credentials exposed in reachable config",
        "fix": "Move database credentials to a secrets manager or environment-only injection. Block serving of dotfiles and config files (.env, *.yml, config.json) at the proxy/WAF, and rotate the exposed credentials now.",
    },
    "MONGODB": {
        "area": "Secrets", "priority": "critical",
        "title": "MongoDB credentials exposed in reachable config",
        "fix": "Same as database URLs: secrets manager, block config file serving, rotate credentials.",
    },
    "REDIS": {
        "area": "Secrets", "priority": "high",
        "title": "Redis credentials exposed in reachable config",
        "fix": "Move to secrets manager, block config serving, rotate credentials, and ensure Redis is not reachable from the public network.",
    },
    "AWS_ACCESS_KEY": {
        "area": "Cloud", "priority": "critical",
        "title": "AWS access keys exposed",
        "fix": "Rotate the exposed keys immediately, restrict the IAM policy to least privilege, and switch workloads to short-lived roles (IRSA / instance profiles) instead of static keys.",
    },
    "AWS_SECRET": {
        "area": "Cloud", "priority": "critical",
        "title": "AWS secret keys exposed",
        "fix": "Rotate immediately; prefer short-lived credentials via roles.",
    },
    "GCP_KEY": {
        "area": "Cloud", "priority": "critical",
        "title": "GCP service-account key exposed",
        "fix": "Revoke the key, audit its activity in Cloud Logging, and use workload identity / attached service accounts instead of downloadable keys.",
    },
    "ssh_key": {
        "area": "Secrets", "priority": "critical",
        "title": "Private SSH keys exposed via web server",
        "fix": "Rotate the key pair everywhere it's trusted, remove key material from any web-served path, and require hardware-backed or short-lived certificates for SSH.",
    },
    "cert": {
        "area": "Secrets", "priority": "critical",
        "title": "TLS private keys exposed via web server",
        "fix": "Re-issue the certificate with a new key, restrict key file permissions, and ensure the web server cannot serve anything outside static/doc roots.",
    },
    # ---- exfiltration methods
    "user_export": {
        "area": "Data protection", "priority": "high",
        "title": "Bulk user export via unauthenticated pagination",
        "fix": "Require authorization on every export/list endpoint, cap page sizes, add anomaly alerts on high-volume sequential paging, and redact PII from list responses.",
    },
    "transaction_dump": {
        "area": "Data protection", "priority": "high",
        "title": "Transaction history readable at scale",
        "fix": "Scope financial queries to the authenticated account only. Require elevated auth for bulk/history endpoints and alert on unusual export volume.",
    },
    "file_extraction": {
        "area": "Data protection", "priority": "high",
        "title": "Sensitive files (.env, credentials) downloadable",
        "fix": "Deny all dotfile and config-path requests at the proxy. Keep secrets out of the web root entirely.",
    },
    "cache_poisoning": {
        "area": "Infrastructure", "priority": "high",
        "title": "Cache poisoning enables persistent data leakage",
        "fix": "Include authentication context in cache keys, disable caching for authenticated responses, and validate the 'origin' of cached data before serving.",
    },
    # ---- cover tracks
    "log_deletion": {
        "area": "Logging", "priority": "high",
        "title": "Logs and audit trails can be deleted via API",
        "fix": "Make logs append-only: ship them off-host in real time (syslog/SIEM) so deletion on the host has no effect. Remove any log-purge endpoints from the public API.",
    },
    # ---- recon findings
    "hidden_routes": {
        "area": "Attack surface", "priority": "medium",
        "title": "Hidden admin/internal routes are discoverable",
        "fix": "Return 404 (not 403) for unauthorized access to admin surfaces — 403 confirms existence. Move internal tooling to a separate network segment or VPN-only host.",
    },
    "debug_endpoints": {
        "area": "Attack surface", "priority": "high",
        "title": "Debug endpoints exposed in production",
        "fix": "Disable /debug, /debug/vars, /metrics-style endpoints in production or bind them to localhost only. They leak stack, config, and runtime detail.",
    },
}

EXPOSED_FILE_HINTS = (".env", "secrets.json", ".git/config", "config.json",
                      "docker-compose", "database.yml", "config.ts", "settings.py",
                      ".aws/credentials", "gcp-key", ".ssh/")


def _rule_for_cred_type(cred_type: str) -> Optional[str]:
    if cred_type in RULES:
        return cred_type
    if cred_type.startswith("AWS"):
        return "AWS_ACCESS_KEY"
    if cred_type in ("ssh_key", "cert"):
        return cred_type
    if cred_type in ("DATABASE_URL", "MONGODB", "REDIS", "GCP_KEY", "AZURE_SECRET"):
        return cred_type if cred_type in RULES else None
    return None


def build_recommendations(report: Dict[str, Any], events: List[Dict[str, Any]]) -> List[Dict[str, str]]:
    """Derive prioritized remediation advice from what actually succeeded."""
    seen: Dict[str, Dict[str, str]] = {}

    def add(key: str) -> None:
        if key in RULES and key not in seen:
            rule = RULES[key]
            seen[key] = {"area": rule["area"], "priority": rule["priority"],
                         "title": rule["title"], "fix": rule["fix"]}

    # exploitation methods that succeeded
    for method in (report.get("exploit_results", {}) or {}).get("methods", []) or []:
        add(method)
        if method in ("algorithm_confusion", "signature_stripping", "jti_manipulation"):
            add("jwt")  # no-op guard
    # any JWT method present at all (even partial success lists)
    methods = (report.get("exploit_results", {}) or {}).get("methods", []) or []
    if any("jwt" in str(m) or m in ("algorithm_confusion", "signature_stripping", "jti_manipulation")
           for m in methods):
        for m in ("algorithm_confusion", "signature_stripping", "jti_manipulation"):
            add(m)

    # persistence backdoor types
    for bd in (report.get("persistence_results", {}) or {}).get("backdoors", []) or []:
        btype = bd.get("type") if isinstance(bd, dict) else None
        if btype:
            add(btype)

    # credential types extracted
    for cred in (report.get("lateral_movement_results", {}) or {}).get("credentials", []) or []:
        ctype = cred.get("type") if isinstance(cred, dict) else None
        if ctype:
            key = _rule_for_cred_type(ctype)
            if key:
                add(key)

    # exfiltration methods
    for m in (report.get("exfiltration_results", {}) or {}).get("extraction_methods", []) or []:
        add(m)

    # cover tracks
    cover = report.get("cover_tracks_results", {}) or {}
    if (cover.get("logs_deleted") or 0) > 0:
        add("log_deletion")

    # recon findings
    recon = report.get("recon_results", {}) or {}
    endpoints = [str(e) for e in (recon.get("endpoints") or [])]
    hidden = [str(h) for h in (recon.get("hidden_routes") or [])]
    if hidden:
        add("hidden_routes")
    if any(any(hint in e for hint in EXPOSED_FILE_HINTS) for e in endpoints):
        add("file_extraction")
    if any(("debug" in h or "internal" in h or "admin" in h) for h in hidden + endpoints):
        add("debug_endpoints")

    out = list(seen.values())
    out.sort(key=lambda r: PRIORITY_ORDER.get(r["priority"], 9))

    # WAF challenge interception (real-engine runs): a positive finding —
    # the WAF blocked the scan, so the origin was never assessed.
    if report.get("waf"):
        out.append({
            "area": "WAF", "priority": "low",
            "title": "WAF challenge pages shielded the application from this scan",
            "fix": "Cloudflare served challenge/interstitial pages instead of the "
                   "application, so the origin could not be assessed from this "
                   "client — the WAF did its job. To assess the application behind "
                   "the WAF, run the scan from an allowlisted IP or temporarily "
                   "narrow the challenge rule, then re-test.",
        })

    if not out:
        # nothing succeeded — the defenses held
        out.append({
            "area": "Defense", "priority": "low",
            "title": "Defenses held — maintain the posture",
            "fix": "The attack chain was broken before any exploitation succeeded. Keep JWT signature verification strict, block dotfiles and config paths at the proxy, enforce rate limits and idempotency on state-changing endpoints, and re-test periodically with this tool.",
        })
    return out[:8]


def build_defense_posture(events: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Summarize defense engagements from request events (X-Defense header)."""
    counts: Dict[str, int] = {}
    total = 0
    for ev in events or []:
        if ev.get("kind") == "request" and ev.get("defense"):
            dtype = ev["defense"]
            counts[dtype] = counts.get(dtype, 0) + 1
            total += 1
    return {"total_blocks": total, "by_type": counts}


def enrich(report: Dict[str, Any], events: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Attach MITRE mapping, recommendations and defense posture to a report."""
    report = dict(report)
    report["mitre"] = MITRE
    report["recommendations"] = build_recommendations(report, events)
    report["defense"] = build_defense_posture(events)
    # WAF challenge interceptions deserve defense credit too. The engines
    # count them (report["waf"]) and the request tracer counts
    # cf-mitigated responses as events — take the max of the two so shared
    # sightings are not double-counted.
    waf = report.get("waf") or {}
    waf_blocks = int(waf.get("requests_intercepted") or 0)
    if waf_blocks:
        posture = report["defense"]
        by_type = dict(posture.get("by_type") or {})
        by_type["cloudflare_waf"] = max(int(by_type.get("cloudflare_waf", 0)), waf_blocks)
        report["defense"] = {"total_blocks": sum(by_type.values()), "by_type": by_type}
    # verdict line for quick scanning
    chain = report.get("attack_chain", {}) or {}
    exploited = bool(chain.get("phase_2_exploit"))
    exfiltrated = bool(chain.get("phase_5_exfiltration"))
    blocks = (report.get("defense", {}) or {}).get("total_blocks", 0)
    if exploited and exfiltrated:
        verdict = "FULL BREACH — the complete kill chain succeeded"
    elif exploited:
        verdict = "BREACH CONTAINED — foothold gained, exfiltration prevented"
    elif blocks:
        verdict = "ACCESS DENIED — target defenses repelled every attack"
    else:
        verdict = "ACCESS DENIED — no exploitation succeeded"
    report["verdict"] = verdict
    return report
