"""Run-scoped, in-scope endpoint inventory shared by scanner stages."""

from __future__ import annotations

import posixpath
from collections import Counter
from typing import Any, Dict, Iterable, List, Optional
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit


_STATIC_EXTENSIONS = {
    ".7z", ".avi", ".bmp", ".css", ".eot", ".flac", ".gif", ".gz",
    ".ico", ".jpeg", ".jpg", ".js", ".map", ".mov", ".mp3", ".mp4",
    ".mpeg", ".ogg", ".otf", ".pdf", ".png", ".svg", ".tar", ".tgz",
    ".ttf", ".wav", ".webm", ".webp", ".woff", ".woff2", ".zip",
}


def canonicalize_url(value: str) -> str:
    """Return a stable HTTP(S) URL or raise ValueError with a reason."""
    value = str(value or "").strip()
    if not value:
        raise ValueError("empty")
    try:
        parts = urlsplit(value)
    except Exception as exc:
        raise ValueError("invalid") from exc
    scheme = parts.scheme.lower()
    if scheme not in ("http", "https"):
        raise ValueError("unsupported_scheme")
    if parts.username is not None or parts.password is not None:
        raise ValueError("embedded_credentials")
    host = (parts.hostname or "").lower().rstrip(".")
    if not host:
        raise ValueError("missing_host")
    try:
        port = parts.port
    except ValueError as exc:
        raise ValueError("invalid_port") from exc
    default_port = (scheme == "http" and port == 80) or (scheme == "https" and port == 443)
    # Preserve IPv6 brackets in the reconstructed authority.
    authority_host = f"[{host}]" if ":" in host else host
    authority = authority_host if port is None or default_port else f"{authority_host}:{port}"
    path = parts.path or "/"
    # Normalize dot segments and repeated slashes without decoding escaped data.
    trailing = path.endswith("/")
    path = posixpath.normpath(path)
    while path.startswith("//"):
        path = path[1:]
    if not path.startswith("/"):
        path = "/" + path
    if trailing and path != "/":
        path += "/"
    query = urlencode(sorted(parse_qsl(parts.query, keep_blank_values=True)), doseq=True)
    return urlunsplit((scheme, authority, path, query, ""))


class EndpointCorpus:
    """Deduplicated endpoint set with provenance and strict hostname scope."""

    def __init__(self, target: str, maximum: int = 3000):
        seed = canonicalize_url(target)
        parsed = urlsplit(seed)
        self.scope_hostname = parsed.hostname or ""
        self.maximum = max(1, int(maximum))
        self._records: Dict[str, Dict[str, Any]] = {}
        self._rejected: Counter[str] = Counter()
        self._duplicates = 0
        self.primary_url = seed
        self.add(seed, "submitted", method="GET")

    def _in_scope(self, url: str) -> bool:
        return (urlsplit(url).hostname or "").lower() == self.scope_hostname.lower()

    @staticmethod
    def _is_static(url: str) -> bool:
        path = urlsplit(url).path.lower()
        return any(path.endswith(ext) for ext in _STATIC_EXTENSIONS)

    def add(self, url: str, source: str, method: str = "GET",
            status: Optional[int] = None, content_type: Optional[str] = None) -> bool:
        try:
            normalized = canonicalize_url(url)
        except ValueError as exc:
            self._rejected[str(exc)] += 1
            return False
        if not self._in_scope(normalized):
            self._rejected["out_of_scope"] += 1
            return False
        existing = self._records.get(normalized)
        if existing is not None:
            self._duplicates += 1
            if source and source not in existing["sources"]:
                existing["sources"].append(source)
            method = str(method or "GET").upper()
            if method not in existing["methods"]:
                existing["methods"].append(method)
            if status is not None:
                existing["status"] = int(status)
            if content_type:
                existing["content_type"] = str(content_type)
            return False
        if len(self._records) >= self.maximum:
            self._rejected["corpus_limit"] += 1
            return False
        parts = urlsplit(normalized)
        self._records[normalized] = {
            "url": normalized,
            "path": parts.path or "/",
            "query_parameters": sorted({key for key, _ in parse_qsl(parts.query, keep_blank_values=True)}),
            "methods": [str(method or "GET").upper()],
            "sources": [str(source or "unknown")],
            "status": int(status) if status is not None else None,
            "content_type": str(content_type) if content_type else None,
            "static": self._is_static(normalized),
            "order": len(self._records),
        }
        return True

    def add_many(self, urls: Iterable[str], source: str) -> int:
        return sum(1 for url in urls if self.add(url, source))

    def set_primary(self, url: str, source: str = "httpx") -> bool:
        try:
            normalized = canonicalize_url(url)
        except ValueError as exc:
            self._rejected[str(exc)] += 1
            return False
        if not self._in_scope(normalized):
            self._rejected["out_of_scope_primary"] += 1
            return False
        self.add(normalized, source)
        self.primary_url = normalized
        return True

    def records(self) -> List[Dict[str, Any]]:
        return [dict(record) for record in self._records.values()]

    def urls(self, include_static: bool = True, limit: Optional[int] = None) -> List[str]:
        records = self._records.values()
        values = [r["url"] for r in records if include_static or not r["static"]]
        return values if limit is None else values[:max(0, int(limit))]

    def select_for_scanning(self, limit: int) -> List[str]:
        """Choose dynamic endpoints first while retaining deterministic order."""
        dynamic = [r["url"] for r in self._records.values() if not r["static"]]
        return dynamic[:max(1, int(limit))]

    def summary(self) -> Dict[str, Any]:
        source_counts: Counter[str] = Counter()
        for record in self._records.values():
            source_counts.update(record["sources"])
        return {
            "status": "ready",
            "primary_url": self.primary_url,
            "scope_hostname": self.scope_hostname,
            "accepted": len(self._records),
            "dynamic": sum(1 for r in self._records.values() if not r["static"]),
            "static": sum(1 for r in self._records.values() if r["static"]),
            "duplicates": self._duplicates,
            "rejected": sum(self._rejected.values()),
            "rejected_by_reason": dict(self._rejected),
            "by_source": dict(source_counts),
            "records": self.records(),
        }
