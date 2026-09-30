"""Shared endpoint corpus normalization, scope and selection tests."""

import pytest


def test_canonicalization_collapses_equivalent_urls():
    from endpoint_corpus import canonicalize_url

    assert canonicalize_url("HTTPS://Example.COM:443/a//b/../c?z=2&a=1#frag") == \
        "https://example.com/a/c?a=1&z=2"
    assert canonicalize_url("http://example.com") == "http://example.com/"


@pytest.mark.parametrize("url,reason", [
    ("javascript:alert(1)", "unsupported_scheme"),
    ("ftp://example.com/file", "unsupported_scheme"),
    ("https://user:pass@example.com/", "embedded_credentials"),
    ("https:///missing", "missing_host"),
])
def test_canonicalization_rejects_unsafe_or_invalid_urls(url, reason):
    from endpoint_corpus import canonicalize_url

    with pytest.raises(ValueError, match=reason):
        canonicalize_url(url)


def test_corpus_enforces_scope_and_preserves_provenance():
    from endpoint_corpus import EndpointCorpus

    corpus = EndpointCorpus("https://Example.com/start")
    assert corpus.add("https://example.com/api/users?b=2&a=1#x", "katana", method="post")
    assert not corpus.add("https://EXAMPLE.com/api/users?a=1&b=2", "zap", method="GET")
    assert not corpus.add("https://cdn.example.net/app.js", "katana")
    record = [r for r in corpus.records() if r["path"] == "/api/users"][0]
    assert record["url"] == "https://example.com/api/users?a=1&b=2"
    assert record["sources"] == ["katana", "zap"]
    assert record["methods"] == ["POST", "GET"]
    summary = corpus.summary()
    assert summary["duplicates"] == 1
    assert summary["rejected_by_reason"]["out_of_scope"] == 1


def test_scanner_selection_excludes_static_assets_and_honors_budget():
    from endpoint_corpus import EndpointCorpus

    corpus = EndpointCorpus("https://example.com/")
    corpus.add("https://example.com/app.js", "katana")
    corpus.add("https://example.com/logo.png", "katana")
    corpus.add("https://example.com/api/users", "katana")
    corpus.add("https://example.com/account", "katana")
    selected = corpus.select_for_scanning(2)
    assert selected == ["https://example.com/", "https://example.com/api/users"]
    assert all(not value.endswith((".js", ".png")) for value in selected)
    assert corpus.summary()["static"] == 2


def test_corpus_limit_is_recorded():
    from endpoint_corpus import EndpointCorpus

    corpus = EndpointCorpus("https://example.com", maximum=2)
    assert corpus.add("https://example.com/one", "katana")
    assert not corpus.add("https://example.com/two", "katana")
    assert corpus.summary()["rejected_by_reason"]["corpus_limit"] == 1
