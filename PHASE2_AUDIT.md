# Phase 2 Browser Discovery — Implementation and Audit

**Date:** 2026-09-30

**Scope:** Playwright browser-native discovery and automatic pipeline integration

**Status:** Implementation and fixture tests complete; real Chromium/full-image smoke pending on a capable release runner

## Delivered flow

```text
submitted target
  → httpx canonical URL
  → Katana static crawl
  → isolated Playwright rendered/network discovery
  → shared endpoint corpus
  → browser HAR imported into ZAP passive analysis
  → profile-bounded corpus sent to Nuclei
  → existing combined report and archive
```

Playwright is an automatic internal stage. No scanner selector or parallel user
workflow was introduced: the product still accepts one target and one profile,
uses one progress/log stream, and emits one report.

## Safety and resource controls

- The browser runs in a child process group with parent-enforced cancellation and
  120–600 second profile timeouts.
- Profile limits bound pages, crawl depth, observed requests, and settle time.
- Only same-host HTTP(S) navigation is allowed. Cross-origin activity is
  observed by hostname but cross-origin navigations are aborted.
- Forms are inventoried but never submitted. Browser requests using methods
  other than GET, HEAD, or OPTIONS are recorded by name and then blocked.
- Logout, deletion, payment, account closure, subscription cancellation, and
  other destructive URL terms are rejected.
- Dialogs are dismissed and service workers are blocked to reduce uncontrolled
  behavior and persistence.
- Endpoint output, forms, WebSockets, errors, screenshots, worker stdout, and
  HAR files have explicit count or byte limits.
- Request-body values are never persisted. For JSON and URL-encoded requests,
  only bounded top-level field names are retained.
- Screenshot paths are converted to application-relative paths. Private HAR
  paths are removed from persisted scanner results.
- HAR files are deleted after ZAP handoff, including cancellation, error, and
  progress-callback failure paths. Adapter-level failures also delete partial
  HAR output.
- Worker crashes, malformed JSON, unavailability, and timeout become isolated
  scanner-stage failures and do not prevent ZAP/Nuclei or the overall run.

## Discovery coverage

The browser result records rendered links and forms, scripts and linked
resources, navigation, request/response traffic, fetch/XHR resource types,
methods, query/body field names, status codes, content types, source provenance,
WebSocket endpoints, and cross-origin host observations. Same-host discoveries
enter the existing `EndpointCorpus`; browser HAR is passed to ZAP with
`-importHar`; the updated corpus becomes Nuclei input.

## Packaging

The full Docker image pins `playwright==1.63.0` and installs its matching
Chromium revision at build time in `/ms-playwright`, readable by the unprivileged
`zap` runtime user. Direct/source installs only advertise the browser stage as
available when both the Python package and Chromium executable are present.
The lite image remains simulation-focused.

## Automated verification

The Phase 2 suite covers:

- URL canonicalization, strict hostname scope, and destructive-navigation rules;
- isolated worker JSON handling and report-path sanitization;
- malformed worker output and prompt process-tree cancellation;
- browser-to-corpus-to-Nuclei propagation;
- browser-HAR availability during ZAP and guaranteed deletion afterward;
- ZAP `-importHar` argument construction;
- browser crash isolation and downstream continuity; and
- a local JavaScript SPA fixture whose runtime API and rendered route do not
  appear in initial HTML.

The SPA acceptance test is conditional and executes automatically when a real
Playwright Chromium runtime is installed.

Latest local verification:

- `97 passed, 1 skipped in 58.86s` (the skip is the real-Chromium SPA test);
- Python compilation passed for application and test modules;
- JavaScript syntax, changed-file Ruff correctness checks, and whitespace checks passed;
- unified API smoke completed as run `a44763b6`, with all five stages present,
  browser honestly marked unavailable, and one accepted corpus endpoint.

## Validation boundary

This Arena workspace has no Docker/container builder. Installing the Playwright
Python package succeeded, but Chromium download from `cdn.playwright.dev` was
blocked by outbound TLS/network policy. Therefore fixture/unit validation is
reported separately from genuine Chromium validation; no claim is made that the
full image was built here.

Before release, a Docker-capable runner with image/CDN access must:

1. build the full image;
2. confirm all five stages appear in `/api/config`;
3. run the included SPA acceptance fixture with real Chromium;
4. verify the HAR imports into the bundled ZAP version;
5. cancel a live browser scan and confirm Chromium/ZAP children terminate;
6. verify screenshots are readable through the intended artifact/report path;
7. run a complete authorized local-target scan and archive/reload its report.
