#!/usr/bin/env python3
"""Isolated Playwright worker for bounded, same-host browser discovery.

The parent process owns cancellation/timeouts. This worker writes exactly one
JSON object to stdout and diagnostics to stderr so a browser crash cannot take
down the application server.
"""

from __future__ import annotations

import json
import re
import sys
from collections import deque
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import parse_qsl, urljoin, urlsplit, urlunsplit

_DANGEROUS_TERMS = {
    "logout", "log-out", "signout", "sign-out", "delete", "remove", "destroy",
    "unsubscribe", "checkout", "purchase", "payment", "pay-now", "terminate",
    "deactivate", "close-account", "reset", "revoke", "cancel-subscription",
}


def canonical_browser_url(value: str) -> Optional[str]:
    try:
        parts = urlsplit(str(value or "").strip())
    except Exception:
        return None
    if parts.scheme.lower() not in ("http", "https") or not parts.hostname:
        return None
    host = parts.hostname.lower().rstrip(".")
    try:
        port = parts.port
    except ValueError:
        return None
    default = (parts.scheme.lower() == "http" and port == 80) or \
              (parts.scheme.lower() == "https" and port == 443)
    authority = host if port is None or default else f"{host}:{port}"
    return urlunsplit((parts.scheme.lower(), authority, parts.path or "/", parts.query, ""))


def same_hostname(url: str, hostname: str) -> bool:
    try:
        return (urlsplit(url).hostname or "").lower().rstrip(".") == hostname.lower().rstrip(".")
    except Exception:
        return False


def safe_navigation(url: str) -> bool:
    """Reject links likely to mutate state; forms are never submitted."""
    try:
        parts = urlsplit(url)
    except Exception:
        return False
    haystack = (parts.path + "?" + parts.query).lower()
    tokens = set(filter(None, re.split(r"[^a-z0-9]+", haystack)))
    if tokens & _DANGEROUS_TERMS:
        return False
    return not any(len(term) >= 6 and term in haystack for term in _DANGEROUS_TERMS)


def _limits(preset: str) -> Dict[str, int]:
    return {
        "stealth": {"pages": 5, "depth": 1, "requests": 250, "settle_ms": 300},
        "balanced": {"pages": 12, "depth": 2, "requests": 700, "settle_ms": 500},
        "aggressive": {"pages": 25, "depth": 2, "requests": 1400, "settle_ms": 650},
        "maximum": {"pages": 50, "depth": 3, "requests": 2500, "settle_ms": 800},
    }.get(preset, {"pages": 12, "depth": 2, "requests": 700, "settle_ms": 500})


def run(config: Dict[str, Any]) -> Dict[str, Any]:
    from playwright.sync_api import TimeoutError as PlaywrightTimeoutError
    from playwright.sync_api import sync_playwright

    target = canonical_browser_url(config.get("target", ""))
    if not target:
        raise ValueError("browser worker received an invalid target")
    scope_hostname = urlsplit(target).hostname or ""
    preset = str(config.get("preset") or "balanced")
    limits = _limits(preset)
    artifact_dir = Path(config.get("artifact_dir") or "") if config.get("artifact_dir") else None
    screenshots_enabled = bool(config.get("screenshots", True)) and artifact_dir is not None
    har_path = Path(config["har_path"]) if config.get("har_path") else None
    if artifact_dir is not None:
        artifact_dir.mkdir(parents=True, exist_ok=True)

    endpoints: Dict[str, Dict[str, Any]] = {}
    forms: List[Dict[str, Any]] = []
    websockets: List[str] = []
    pages: List[Dict[str, Any]] = []
    screenshots: List[str] = []
    errors: List[str] = []
    cross_origin_hosts = set()
    request_count = 0

    def note_endpoint(url: str, method: str = "GET", source: str = "browser-network",
                      resource_type: Optional[str] = None, status: Optional[int] = None,
                      content_type: Optional[str] = None,
                      body_fields: Optional[List[str]] = None) -> None:
        normalized = canonical_browser_url(url)
        if not normalized:
            return
        if not same_hostname(normalized, scope_hostname):
            host = urlsplit(normalized).hostname
            if host:
                cross_origin_hosts.add(host.lower())
            return
        key = normalized + "\n" + str(method or "GET").upper()
        record = endpoints.get(key)
        if record is None:
            if len(endpoints) >= 3000:
                return
            record = {
                "url": normalized,
                "method": str(method or "GET").upper(),
                "source": source,
                "resource_type": resource_type,
                "status": status,
                "content_type": content_type,
                "query_parameters": sorted({
                    name[:200] for name, _ in parse_qsl(
                        urlsplit(normalized).query, keep_blank_values=True)
                })[:100],
                "body_fields": sorted(set(body_fields or []))[:100],
            }
            endpoints[key] = record
        else:
            if status is not None:
                record["status"] = status
            if content_type:
                record["content_type"] = content_type
            if body_fields:
                record["body_fields"] = sorted(set(
                    list(record.get("body_fields") or []) + body_fields))[:100]
            if source not in str(record.get("source", "")):
                record["source"] = str(record.get("source") or "browser") + "," + source

    def request_body_fields(request) -> List[str]:
        """Return names only; never persist request body values or credentials."""
        try:
            body = request.post_data
            if not body or len(body) > 1024 * 1024:
                return []
            content_type = str(request.headers.get("content-type") or "").lower()
            if "json" in content_type:
                parsed = json.loads(body)
                return [str(key)[:200] for key in parsed.keys()] if isinstance(parsed, dict) else []
            if "x-www-form-urlencoded" in content_type:
                return [str(key)[:200] for key, _ in parse_qsl(body, keep_blank_values=True)]
        except Exception:
            pass
        return []

    def route_request(route) -> None:
        """Observe every request but block mutations, unsafe URLs, and budget overflow."""
        nonlocal request_count
        request = route.request
        request_count += 1
        fields = request_body_fields(request)
        note_endpoint(request.url, request.method, "browser-network", request.resource_type,
                      body_fields=fields)
        normalized = canonical_browser_url(request.url)
        cross_navigation = request.is_navigation_request() and (
            not normalized or not same_hostname(normalized, scope_hostname))
        blocked_method = request.method.upper() not in {"GET", "HEAD", "OPTIONS"}
        unsafe_url = bool(normalized and not safe_navigation(normalized))
        if request_count > limits["requests"] or cross_navigation or blocked_method or unsafe_url:
            route.abort("blockedbyclient")
        else:
            route.continue_()

    def on_response(response) -> None:
        try:
            request = response.request
            note_endpoint(response.url, request.method, "browser-response",
                          request.resource_type, response.status,
                          response.headers.get("content-type"))
        except Exception:
            pass

    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(
            headless=True,
            args=["--disable-dev-shm-usage", "--no-sandbox", "--disable-gpu"],
        )
        context_options = {
            "ignore_https_errors": False,
            "service_workers": "block",
            "viewport": {"width": 1365, "height": 768},
        }
        if har_path is not None:
            context_options.update({
                "record_har_path": str(har_path),
                "record_har_content": "omit",
                "record_har_mode": "minimal",
            })
        context = browser.new_context(**context_options)
        context.route("**/*", route_request)
        page = context.new_page()
        page.on("response", on_response)
        page.on("dialog", lambda dialog: dialog.dismiss())

        def on_websocket(ws) -> None:
            comparable = ws.url.replace("ws://", "http://", 1).replace(
                "wss://", "https://", 1)
            if same_hostname(comparable, scope_hostname):
                if ws.url not in websockets and len(websockets) < 200:
                    websockets.append(ws.url)
            else:
                host = urlsplit(comparable).hostname
                if host:
                    cross_origin_hosts.add(host.lower())

        page.on("websocket", on_websocket)

        queue = deque([(target, 0)])
        queued = {target}
        visited = set()
        while queue and len(visited) < limits["pages"] and request_count < limits["requests"]:
            url, depth = queue.popleft()
            if url in visited or not same_hostname(url, scope_hostname) or not safe_navigation(url):
                continue
            visited.add(url)
            page_info = {"url": url, "depth": depth, "status": None, "title": None}
            try:
                response = page.goto(url, wait_until="domcontentloaded", timeout=15000)
                page.wait_for_timeout(limits["settle_ms"])
                page_info["status"] = response.status if response else None
                page_info["url"] = canonical_browser_url(page.url) or url
                page_info["title"] = page.title()[:300]
                note_endpoint(page_info["url"], "GET", "browser-navigation", "document",
                              page_info["status"], None)

                dom = page.evaluate("""() => ({
                  links: Array.from(document.querySelectorAll('a[href]')).slice(0, 1000)
                    .map(e => e.href),
                  resources: Array.from(document.querySelectorAll('script[src],link[href]')).slice(0, 1000)
                    .map(e => e.src || e.href),
                  forms: Array.from(document.forms).slice(0, 100).map(f => ({
                    action: f.action || location.href,
                    method: (f.method || 'GET').toUpperCase(),
                    fields: Array.from(f.elements).slice(0, 100).map(e => ({
                      name: e.name || '', type: e.type || e.tagName.toLowerCase()
                    })).filter(e => e.name)
                  }))
                })""")
                for resource in dom.get("resources", []):
                    note_endpoint(resource, "GET", "browser-dom-resource")
                for form in dom.get("forms", []):
                    action = canonical_browser_url(form.get("action"))
                    if action and same_hostname(action, scope_hostname):
                        if len(forms) < 500:
                            forms.append({
                                "page": page_info["url"], "action": action,
                                "method": str(form.get("method") or "GET").upper(),
                                "fields": form.get("fields", [])[:100],
                            })
                        note_endpoint(action, form.get("method") or "GET", "browser-form")
                if depth < limits["depth"]:
                    for link in dom.get("links", []):
                        candidate = canonical_browser_url(urljoin(page.url, link))
                        if candidate and same_hostname(candidate, scope_hostname) and \
                                safe_navigation(candidate) and candidate not in queued:
                            queued.add(candidate)
                            queue.append((candidate, depth + 1))
                            if len(queued) >= limits["pages"] * 20:
                                break

                if screenshots_enabled and len(screenshots) < 5:
                    shot = artifact_dir / f"page-{len(screenshots) + 1:03d}.png"
                    page.screenshot(path=str(shot), full_page=False)
                    if shot.is_file() and shot.stat().st_size <= 5 * 1024 * 1024:
                        screenshots.append(str(shot))
                    elif shot.exists():
                        shot.unlink()
            except PlaywrightTimeoutError:
                errors.append(f"timeout: {url}")
            except Exception as exc:
                errors.append(f"{url}: {type(exc).__name__}: {str(exc)[:200]}")
            pages.append(page_info)

        context.close()
        browser.close()

    records = list(endpoints.values())
    api_calls = sum(1 for r in records if r.get("resource_type") in ("xhr", "fetch"))
    return {
        "endpoint_records": records,
        "endpoints": list(dict.fromkeys(r["url"] for r in records)),
        "forms": forms,
        "websockets": websockets,
        "pages": pages,
        "screenshots": screenshots,
        "cross_origin_hosts": sorted(cross_origin_hosts)[:200],
        "errors": errors[:200],
        "stats": {
            "pages_visited": len(pages),
            "requests_observed": request_count,
            "endpoints_discovered": len(records),
            "api_calls_observed": api_calls,
            "forms_discovered": len(forms),
            "websockets_discovered": len(websockets),
            "page_budget": limits["pages"],
            "request_budget": limits["requests"],
        },
    }


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: browser_worker.py CONFIG.json", file=sys.stderr)
        return 2
    config = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
    try:
        result = run(config)
    except Exception as exc:
        print(f"browser worker failed: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(result, separators=(",", ":"), default=str))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
