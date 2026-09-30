"""
WAF challenge-page detection (Cloudflare today, extensible tomorrow).

A challenge page is a DIFFERENT animal from a soft-404 catch-all:

  soft-404  : the ORIGIN answers unknown paths with the homepage (HTTP 200)
              — the app is reachable, just misleading.
  challenge : the WAF intercepts the request and serves an interstitial
              ("Just a moment...", "Checking your browser...", error 1020)
              — usually 403/503/429, occasionally 200 — and the application
              is NEVER reached at all.

Reports must label these distinctly: a 403 challenge page is NOT a
"protected endpoint", a 200 challenge page is NOT a "real response",
and the WAF deserves defense credit for blocking the run.
"""

from typing import Any, Dict, Mapping, Optional

# ---------------------------------------------------------------------------
# Markers
# ---------------------------------------------------------------------------

# Definitive body markers — Cloudflare-specific enough to trust on their own.
_DEFINITE = (
    # modern managed-challenge / Turnstile pages
    "cdn-cgi/challenge-platform",
    "_cf_chl_opt",
    "cf-chl-widget",
    "__cf_chl_",
    "cf-browser-verification",      # legacy "I'm Under Attack" interstitial
    "checking your browser before accessing",
    "checking if the site connection is secure",
    # WAF block / ban pages
    "attention required! | cloudflare",
    "error code: 1020",
    "error code: 1010",
    "error code: 1015",             # Cloudflare rate-limit block
)

# Soft markers — common on challenge pages but conceivable in ordinary copy;
# they only count when response headers prove the responder is Cloudflare.
_SOFT = (
    "just a moment",
    "verify you are human",
    "enable javascript and cookies to continue",
)

# Body scanning is skipped for these content types: challenge pages are HTML.
_NON_HTML_CT = ("json", "javascript", "css", "image", "audio", "video")

_MAX_BODY = 300_000   # challenge pages are small; don't scan huge payloads

_KIND_BY_MARKER = {
    "cdn-cgi/challenge-platform": "managed_challenge",
    "_cf_chl_opt": "managed_challenge",
    "cf-chl-widget": "managed_challenge",
    "__cf_chl_": "managed_challenge",
    "cf-browser-verification": "under_attack_mode",
    "checking your browser before accessing": "under_attack_mode",
    "checking if the site connection is secure": "managed_challenge",
    "attention required! | cloudflare": "waf_block",
    "error code: 1020": "waf_block",
    "error code: 1010": "waf_block",
    "error code: 1015": "rate_limit_block",
    "just a moment": "managed_challenge",
    "verify you are human": "managed_challenge",
    "enable javascript and cookies to continue": "managed_challenge",
}

_KIND_LABELS = {
    "managed_challenge": "managed challenge (\"Just a moment…\")",
    "under_attack_mode": "Under-Attack mode interstitial",
    "waf_block": "WAF block (error 1020)",
    "rate_limit_block": "WAF rate-limit block",
    "challenge": "challenge page",
}


def _hget(headers: Optional[Mapping], name: str) -> str:
    """Case-insensitive header lookup that tolerates plain dicts."""
    if not headers:
        return ""
    try:
        v = headers.get(name)
        if v is not None:
            return str(v)
    except Exception:
        pass
    lname = name.lower()
    for k, v in headers.items():
        if str(k).lower() == lname:
            return str(v)
    return ""


def challenge_label(ch: Optional[Dict[str, Any]]) -> str:
    """Human phrase for a detected challenge, e.g. 'managed challenge (...)'."""
    if not ch:
        return "challenge page"
    return _KIND_LABELS.get(ch.get("kind"), _KIND_LABELS["challenge"])


def detect_challenge(status: int, headers: Optional[Mapping],
                     body: Optional[str]) -> Optional[Dict[str, Any]]:
    """
    Identify a WAF challenge/interstitial response.

    Returns {"provider": "cloudflare", "kind": ..., "status": ...} when the
    response is a challenge page, else None. Deliberately conservative: a
    NORMAL page served through Cloudflare (Server: cloudflare, CF-Ray, no
    markers) is NOT a challenge.
    """
    # 1. Official signal: Cloudflare sets cf-mitigated: challenge on
    #    managed-challenge responses. Definitive regardless of body.
    mitigated = _hget(headers, "cf-mitigated").strip().lower()
    if mitigated == "challenge":
        return {"provider": "cloudflare", "kind": "managed_challenge",
                "status": status}

    if not body:
        return None

    ct = _hget(headers, "content-type").lower()
    if any(x in ct for x in _NON_HTML_CT):
        return None
    if len(body) > _MAX_BODY:
        return None

    low = body.lower()

    # 2. Definitive Cloudflare markers — trust on their own.
    for marker in _DEFINITE:
        if marker in low:
            return {"provider": "cloudflare",
                    "kind": _KIND_BY_MARKER[marker],
                    "status": status}

    # 3. Soft markers — only with corroborating Cloudflare header evidence.
    server = _hget(headers, "server").lower()
    is_cf = ("cloudflare" in server
             or _hget(headers, "cf-ray")
             or mitigated)
    if is_cf:
        for marker in _SOFT:
            if marker in low:
                return {"provider": "cloudflare",
                        "kind": _KIND_BY_MARKER[marker],
                        "status": status}

    return None


def note_challenge(engine: Any) -> None:
    """Record one WAF-intercepted request on the shared attack context.

    Engines store the run's AttackContext as ``self._ctx`` during execute();
    the counter feeds the report's ``waf`` section and defense posture.
    """
    ctx = getattr(engine, "_ctx", None)
    if ctx is not None:
        try:
            ctx.waf_interceptions += 1
        except Exception:
            pass
