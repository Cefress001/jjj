"""Cloudflare challenge-page detection: the detector behind honest labeling.

A challenge page is NOT a soft-404: the WAF intercepted the request and the
application was never reached. These tests pin the detector's behaviour,
especially the negative cases — a normal page served THROUGH Cloudflare
must not be flagged.
"""

import pytest

from attack_modules.challenge import detect_challenge, challenge_label


# --------------------------------------------------------------- fixtures

CF_CHALLENGE_BODY = (
    "<!DOCTYPE html><html><head><title>Just a moment...</title>"
    "<script src='/cdn-cgi/challenge-platform/h/b/orchestrate/chl_page/v1/abc.js'></script>"
    "</head><body><div class='main-wrapper'>Verify you are human by completing"
    " the challenge.</div></body></html>"
)

UNDER_ATTACK_BODY = (
    "<html><head><title>Attention Required! | Cloudflare</title></head>"
    "<body>Please wait... Checking your browser before accessing the site."
    " This process is automatic.</body></html>"
)

WAF_BLOCK_BODY = (
    "<html><head><title>Attention Required! | Cloudflare</title></head>"
    "<body>Error 1020 Ray ID: 8f3e2b1c4a9d1234 • Performance & security"
    " by Cloudflare</body></html>"
)

RATE_LIMIT_BODY = (
    "<html><head><title>Too Many Requests</title></head>"
    "<body>error code: 1015</body></html>"
)

NORMAL_CF_PAGE = (
    "<!DOCTYPE html><html><head><title>Concierge Caregiver Referral</title></head>"
    "<body><h1>Welcome to our site</h1><p>We help families in Orange County."
    " Just give us a moment and we will call you back.</p></body></html>"
)


# ------------------------------------------------------------- positives

def test_cf_mitigated_header_is_definitive():
    """Cloudflare's official cf-mitigated: challenge header wins instantly."""
    ch = detect_challenge(403, {"CF-Mitigated": "challenge"}, "<html></html>")
    assert ch and ch["provider"] == "cloudflare"
    assert ch["kind"] == "managed_challenge"


def test_managed_challenge_body_markers():
    ch = detect_challenge(403, {"Server": "cloudflare"}, CF_CHALLENGE_BODY)
    assert ch and ch["provider"] == "cloudflare"
    assert ch["kind"] == "managed_challenge"


def test_managed_challenge_without_server_header():
    """cdn-cgi/challenge-platform is definitive on its own (no CF headers)."""
    ch = detect_challenge(200, {}, CF_CHALLENGE_BODY)
    assert ch and ch["kind"] == "managed_challenge"


def test_under_attack_mode_page():
    ch = detect_challenge(503, {"Server": "cloudflare"}, UNDER_ATTACK_BODY)
    assert ch and ch["kind"] == "under_attack_mode"


def test_waf_block_page_1020():
    ch = detect_challenge(403, {"Server": "cloudflare"}, WAF_BLOCK_BODY)
    assert ch and ch["kind"] == "waf_block"


def test_rate_limit_block_page_1015():
    ch = detect_challenge(429, {"Server": "cloudflare"}, RATE_LIMIT_BODY)
    assert ch and ch["kind"] == "rate_limit_block"


def test_soft_marker_with_cf_evidence():
    """"Just a moment" counts when the responder is provably Cloudflare."""
    body = "<html><head><title>Just a moment...</title></head></html>"
    ch = detect_challenge(403, {"Server": "cloudflare", "CF-RAY": "abc123-LAX"}, body)
    assert ch and ch["kind"] == "managed_challenge"


def test_challenge_label_is_human_readable():
    ch = detect_challenge(403, {"CF-Mitigated": "challenge"}, "")
    label = challenge_label(ch)
    assert "managed challenge" in label


# ------------------------------------------------------------- negatives

def test_normal_cloudflare_proxied_page_is_not_a_challenge():
    """THE critical negative: CF-Ray + Server: cloudflare alone is normal."""
    ch = detect_challenge(200, {
        "Server": "cloudflare",
        "CF-RAY": "8f3e2b1c4a9d1234-LAX",
        "Content-Type": "text/html; charset=utf-8",
    }, NORMAL_CF_PAGE)
    assert ch is None


def test_soft_marker_without_cf_evidence_is_ignored():
    """"Just a moment" in ordinary copy, no Cloudflare headers → not a challenge."""
    body = "<html><body>Just a moment — your coffee is ready!</body></html>"
    assert detect_challenge(200, {"Server": "nginx"}, body) is None


def test_plain_403_json_api_is_not_a_challenge():
    ch = detect_challenge(403, {"Content-Type": "application/json"},
                          '{"error": "forbidden"}')
    assert ch is None


def test_json_content_type_skips_body_scan():
    """Marker text inside a JSON body must not trigger (challenges are HTML)."""
    ch = detect_challenge(200, {"Content-Type": "application/json",
                                "Server": "cloudflare"},
                          '{"note": "see cdn-cgi/challenge-platform docs"}')
    assert ch is None


def test_empty_body_is_not_a_challenge():
    assert detect_challenge(403, {"Server": "cloudflare"}, "") is None
    assert detect_challenge(403, {"Server": "cloudflare"}, None) is None


def test_huge_body_is_not_scanned():
    ch = detect_challenge(200, {"Server": "cloudflare"}, "x" * 400_000)
    assert ch is None


def test_case_insensitive_headers_and_markers():
    """Plain dicts with arbitrary header casing must behave like aiohttp's."""
    ch = detect_challenge(403, {"SeRvEr": "CloudFlare"},
                          "<html>JUST A MOMENT...</html>")
    assert ch and ch["kind"] == "managed_challenge"
