"""
Soft-404 detection for real-world targets.

Many real sites (SPAs, static hosts, catch-all rewrite rules) answer EVERY
unknown path with the homepage and HTTP 200. Naive status-code checks then
report false positives: "endpoints discovered" that are just the homepage,
"exploits" that never happened.

Approach: probe a guaranteed-nonexistent path once per run. If it returns
200, its response becomes the baseline signature (content-type, length,
hash, <title>). Later 200 responses matching the signature are treated as
NOT FOUND.
"""

import hashlib
import re
import secrets
from typing import Any, Dict, Optional

import aiohttp

from .challenge import detect_challenge

_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.I | re.S)


async def probe_baseline(target: str) -> Dict[str, Optional[Any]]:
    """
    Fetch a path that cannot exist and classify the response:

      {"soft404":  sig,  "challenge": None}   catch-all: 200 homepage mirror
      {"soft404":  None, "challenge": ch}     WAF challenge/interstitial page
      {"soft404":  None, "challenge": None}   normal 404 behaviour — nothing to do
    """
    path = f"/no-such-path-{secrets.token_hex(8)}"
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(
                target + path,
                timeout=aiohttp.ClientTimeout(total=12),
                allow_redirects=True,
            ) as resp:
                body = await resp.text(errors="replace")
                # A WAF challenge page is NOT a catch-all: the app was never
                # reached. It wins — the run is being intercepted.
                ch = detect_challenge(resp.status, resp.headers, body)
                if ch:
                    return {"soft404": None, "challenge": ch}
                if resp.status != 200 or not body:
                    return {"soft404": None, "challenge": None}
                m = _TITLE_RE.search(body)
                return {
                    "soft404": {
                        "len": len(body),
                        "hash": hashlib.sha256(body.encode("utf-8", "replace")).hexdigest(),
                        "ct": (resp.headers.get("Content-Type") or "").split(";")[0].strip().lower(),
                        "title": (m.group(1).strip()[:120] if m else ""),
                    },
                    "challenge": None,
                }
    except Exception:
        return {"soft404": None, "challenge": None}


def is_soft404(status: int, body: str, content_type: str,
               sig: Optional[Dict[str, Any]]) -> bool:
    """True when this 200 response is just the catch-all page, not a real endpoint."""
    if not sig or status != 200 or body is None:
        return False
    ct = (content_type or "").split(";")[0].strip().lower()
    if ct != sig.get("ct"):
        # different content type than the catch-all page => a real endpoint
        return False
    blen = len(body or "")
    slen = int(sig.get("len") or 0)
    if blen == slen:
        return hashlib.sha256((body or "").encode("utf-8", "replace")).hexdigest() == sig.get("hash")
    # dynamic pages vary slightly: near-length + same <title> still counts
    title = sig.get("title") or ""
    if (title and title in (body or "")
            and abs(blen - slen) <= max(64, int(slen * 0.15))):
        return True
    return False
