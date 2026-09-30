# Offensive Emulator — Real-World Assessment Master Build Plan

**Status:** Active  
**Current milestone:** Phase 2 — Browser-native discovery (implemented; real-Chromium/full-container release smoke pending)

Detailed Phase 1 quality record: [`PHASE1_AUDIT.md`](PHASE1_AUDIT.md).

**Product constraint:** Preserve the existing one-target, one-profile, one-launch, one-report experience. New capabilities are internal pipeline stages, not competing user-facing modes.

## Product objective

Turn the application from a cinematic, app-specific attack demonstration into an evidence-driven web assessment platform that can assess authorized, real-world websites and APIs with useful coverage, reproducible evidence, bounded impact, and honest conclusions.

The finished pipeline will:

1. discover the real attack surface;
2. authenticate and maintain sessions;
3. execute browser and API workflows;
4. run passive and explicitly authorized active checks;
5. verify and deduplicate findings;
6. preserve evidence without leaking secrets;
7. enforce scope and resource policy;
8. prioritize findings with current vulnerability intelligence; and
9. compare results over time in the existing archive and report experience.

## Non-negotiable engineering principles

- **Evidence before claims:** an HTTP 200 response is never enough to claim exploitation.
- **One connected pipeline:** every stage consumes useful output from earlier stages.
- **Fail independently:** one scanner failure must not erase other results.
- **Scope first:** redirects, browser requests, APIs, and tools remain within the approved scope.
- **Bounded impact:** every run has request, rate, depth, time, response-size, and process limits.
- **Secrets are ephemeral:** credentials and tokens are encrypted at rest when persistence is required and redacted everywhere else.
- **Reproducibility:** record tool versions, template versions, policy, inputs, and timestamps.
- **Honest reporting:** distinguish observed, suspected, verified, and exploited states.
- **Backward compatibility:** existing API endpoints, archive records, and the one-button UI continue to work.
- **Testability:** every adapter has fixture tests; every phase has an end-to-end local target test.

---

# Delivery roadmap

## Phase 0 — Multi-tool foundation (completed baseline)

### Delivered

- Automatic adapters for httpx, Katana, OWASP ZAP baseline, and Nuclei.
- One combined report and archive.
- Process cancellation, timeouts, JSON/JSONL normalization, and isolated failures.
- Conservative rate controls and excluded Nuclei `dos`, `fuzz`, and `intrusive` tags.
- Full Docker packaging plus a lightweight image.

### Known limitation

The tools currently run mostly from the same seed URL. Their discoveries are merged after execution, but downstream tools do not consistently consume the discoveries of upstream tools.

---

## Phase 1 — Shared endpoint corpus and connected pipeline

**Goal:** Make the installed tools cooperate as one data pipeline.

### Architecture

Introduce a run-scoped `EndpointCorpus` as the source of truth for URLs:

```text
submitted target
    → canonical httpx result
    → Katana-discovered routes
    → ZAP-observed/affected URLs
    → bounded, in-scope endpoint set for Nuclei
    → one normalized corpus in the report
```

### Work packages

#### 1.1 URL canonicalization and scope

- Normalize scheme, host casing, default ports, fragments, paths, and query ordering.
- Reject unsupported schemes and credential-bearing URLs.
- Restrict additions to the submitted hostname by default.
- Track rejected URLs and rejection reasons.
- Preserve source provenance and observed HTTP methods.
- Deduplicate equivalent URLs without losing provenance.

#### 1.2 Endpoint inventory

Each endpoint record will contain:

- canonical URL;
- path and query-parameter names;
- observed methods;
- discovery sources;
- status code/content type when known;
- first-seen order;
- static/dynamic classification; and
- scan eligibility.

#### 1.3 Connected scanner execution

- httpx supplies the canonical reachable URL and technologies.
- Katana crawls the canonical URL, not the unverified raw input.
- Katana output enters the corpus immediately.
- ZAP runs against the canonical target and contributes affected URLs.
- Nuclei consumes a bounded corpus URL list rather than only the root target.
- Per-profile endpoint budgets prevent request explosions.

#### 1.4 Reporting and telemetry

- Persist corpus statistics and provenance in `scanner_results.endpoint_corpus`.
- Use the corpus to populate reconnaissance endpoints.
- Emit corpus update events and terminal summaries.
- Record how many URLs were accepted, rejected, deduplicated, and selected.

### Acceptance criteria

- Equivalent URLs collapse to one endpoint.
- Out-of-scope and non-HTTP URLs never reach downstream tools.
- Nuclei receives discovered dynamic endpoints through a temporary target list.
- Static assets are not sent to broad vulnerability templates by default.
- The existing HTTP API and UI workflow remain unchanged.
- Unit tests cover normalization, scope, provenance, budgets, and data flow.
- Existing backend tests remain green.

### Exit artifact

A deterministic endpoint corpus that all later phases—browser, authentication, API, verification, and active scanning—can reuse.

---

## Phase 2 — Browser-native discovery with Playwright

**Goal:** Accurately map JavaScript-heavy sites and client-side APIs.

### Work packages

- Bundle Playwright and pinned Chromium in the full image.
- Add an isolated browser worker with CPU, memory, page, and runtime limits.
- Navigate only corpus-approved origins.
- Capture navigation, fetch/XHR, GraphQL, form, script, and WebSocket URLs.
- Record HTTP methods, parameter names, content types, initiators, and response status.
- Discover routes from rendered DOM, source maps where permitted, and loaded scripts.
- Add safe click/navigation heuristics; exclude logout, delete, payment, and destructive controls.
- Capture screenshots and DOM snapshots only when policy permits.
- Feed browser traffic into the endpoint corpus and ZAP passive analysis.

### Acceptance criteria

- A local React/SPA fixture exposes routes invisible in initial HTML; the browser stage discovers them.
- Cross-origin browser requests are recorded but not followed unless explicitly in scope.
- Browser crashes and timeouts do not fail the overall run.
- Screenshots and artifacts obey size and redaction limits.

### Implementation status (2026-09-30)

- [x] Added a process-isolated Playwright worker with profile-specific page,
  depth, request, settle-time, and runtime budgets.
- [x] Added same-host navigation enforcement, mutation blocking, destructive URL
  filtering, dialog dismissal, and form discovery without submission.
- [x] Capture rendered links/resources/forms plus request/response, fetch/XHR,
  field names, content types, status, WebSocket, and cross-origin observations.
- [x] Added bounded screenshots, private bounded HAR retention, sanitized report
  paths, output limits, cancellation, and process-tree cleanup.
- [x] Feed browser records into the shared corpus and Nuclei; import browser HAR
  into ZAP and delete it in cancellation/error-safe cleanup.
- [x] Bundle pinned `playwright==1.63.0` and its matching Chromium in the full
  image; direct installs verify that both package and browser executable exist.
- [x] Added unit/fixture coverage for scope and safety helpers, worker isolation,
  cancellation, artifact sanitization, browser-to-ZAP/Nuclei propagation, HAR
  cleanup/import, and graceful unavailability.
- [ ] Execute the real-browser SPA acceptance test and full-image smoke on a
  Docker-capable runner. The test fixture is included and auto-runs when
  Chromium is available; this workspace could install the Python package but
  outbound policy blocked Chromium CDN access.

---

## Phase 3 — Authentication and session management

**Goal:** Assess meaningful authenticated application surfaces safely.

### Work packages

- Support ephemeral cookies, bearer tokens, API keys, and custom headers.
- Add login form configuration and Playwright login recording.
- Detect CSRF tokens and refresh them during workflows.
- Support OAuth/OIDC authorization-code flows and session renewal.
- Add multiple named test identities and role-aware scans.
- Detect logout/session-expiration and reauthenticate within limits.
- Encrypt persisted secrets with an operator-supplied key; default to memory-only.
- Redact secrets from logs, events, reports, screenshots, subprocess arguments, and archives.
- Pass scoped session material to browser, ZAP, Nuclei, and API stages without writing plaintext files where avoidable.

### Acceptance criteria

- A local authenticated fixture can be scanned beyond its login page.
- Expired sessions recover automatically.
- No known test secret appears in logs, JSON reports, HTML reports, or persisted runs.
- Role identities remain isolated.

---

## Phase 4 — API discovery and schema-driven assessment

**Goal:** Replace path guessing with contract-aware API testing.

### Work packages

- Detect OpenAPI/Swagger documents, Postman collections, GraphQL endpoints, and WSDL files.
- Parse and validate schemas in an isolated process.
- Expand schema operations into the endpoint corpus with method, content type, and parameter metadata.
- Run ZAP API scans for OpenAPI, GraphQL, and SOAP definitions.
- Integrate Schemathesis for bounded property-based OpenAPI testing.
- Generate safe example values and support operator-provided test data.
- Handle API authentication independently from browser authentication where required.
- Detect undocumented endpoints by comparing crawler traffic with schemas.

### Acceptance criteria

- OpenAPI fixture operations are discovered and tested using their declared methods.
- Invalid or hostile schemas cannot escape resource and scope limits.
- Reports distinguish schema-derived, observed, and guessed endpoints.

---

## Phase 5 — Evidence model and honest real-site reporting

**Goal:** Ensure every conclusion is traceable to reproducible evidence.

### Work packages

- Create a versioned finding schema with stable fingerprints.
- Store source tool, rule/template version, URL, method, parameter, confidence, and timestamps.
- Capture bounded/redacted request and response excerpts or hashes.
- Add finding states: `observed`, `suspected`, `verified`, `exploited`, `false_positive`, and `accepted_risk`.
- Separate scan coverage from vulnerability severity.
- Replace simulated breach language for real targets with assessment language.
- Preserve the current visual workflow while using real workflow labels and evidence internally.
- Add JSON, HTML, and SARIF exports from the normalized schema.

### Acceptance criteria

- Every high/critical finding has evidence or is explicitly marked unverified.
- Reports never equate status code alone with exploitation.
- Finding fingerprints remain stable across repeated scans.

---

## Phase 6 — Automated verification and false-positive control

**Goal:** Retest important findings independently and raise confidence.

### Work packages

- Add a verifier registry keyed by finding type/CWE/template.
- Compare baseline/control and payload responses.
- Confirm exposed files by signatures without storing secrets.
- Confirm version-based findings through multiple independent signals.
- Retest reflection, access control, headers, and cache findings with bounded checks.
- Add `confirmed`, `probable`, `unverified`, and `rejected` confidence outcomes.
- Preserve verification evidence and reason codes.
- Add operator false-positive decisions to future-run suppression rules.

### Acceptance criteria

- Verification cannot broaden scope or exceed the original scan policy.
- Fixture false positives are rejected while fixture true positives remain.
- Verification is idempotent and independently cancellable.

---

## Phase 7 — Policy engine, scope enforcement, and active assessment

**Goal:** Make deeper testing controlled, explicit, and auditable.

### Work packages

- Centralize target policy for every in-process and external tool.
- Add hostname/CIDR allowlists, redirect policy, DNS rebinding protection, and IP pinning.
- Block metadata, loopback, link-local, multicast, and private ranges unless local-lab policy allows them.
- Add path/method deny rules for logout, delete, billing, communications, and destructive operations.
- Enforce global request, byte, runtime, depth, concurrency, and per-host rate budgets.
- Translate existing profiles into concrete scanner policies.
- Add explicitly authorized active ZAP policies and carefully selected active Nuclei tags.
- Record authorization acknowledgement and complete audit trails.
- Add emergency process-tree termination and cleanup.

### Acceptance criteria

- Redirects and DNS changes cannot escape scope.
- Destructive fixture routes are never called under passive/balanced policy.
- Active checks cannot run without explicit policy authorization.
- Every external process receives enforceable limits.

---

## Phase 8 — Vulnerability intelligence and prioritization

**Goal:** Turn raw severity into actionable risk.

### Work packages

- Enrich CVEs with CVSS vectors, EPSS probability, CISA KEV status, vendor advisories, and patch data.
- Cache feeds with signatures, timestamps, and offline fallback.
- Combine exploitability, internet exposure, confidence, asset criticality, and authentication context.
- Avoid inflating severity when product/version evidence is weak.
- Show why a finding received its priority.

### Acceptance criteria

- Intelligence source and freshness are visible.
- Offline scans continue without stale data being represented as current.
- Priority calculations are deterministic and tested.

---

## Phase 9 — Differential scanning, scheduling, and CI/CD

**Goal:** Make the platform useful continuously, not only for one-off scans.

### Work packages

- Match findings across runs using stable fingerprints.
- Classify new, recurring, changed, resolved, and regressed findings.
- Compare endpoint, technology, TLS, certificate, and security-header changes.
- Add schedules with concurrency controls and retention policies.
- Add CI exit thresholds based on new verified findings.
- Export SARIF and machine-readable delta reports.
- Add webhook/GitHub integration without leaking evidence or secrets.

### Acceptance criteria

- Repeated identical scans produce no false “new” findings.
- Resolved fixture findings are recognized automatically.
- CI can fail only on policy-selected new findings.

---

## Phase 10 — Operator-defined business workflows

**Goal:** Test authorization and business logic that generic scanners cannot infer.

### Work packages

- Record Playwright journeys with named checkpoints and cleanup steps.
- Parameterize test data and identities.
- Run the same journey as multiple roles.
- Add assertions for ownership, authorization, state transitions, and invariant violations.
- Support create-test-cleanup transactions and recovery after partial failures.
- Version workflows and associate failures with exact steps and evidence.

### Acceptance criteria

- An IDOR fixture is detected by replaying an owner journey as a second user.
- Cleanup runs even after failure or cancellation.
- Workflows cannot navigate or transmit data outside approved scope.

---

# Cross-phase platform work

These tracks run alongside every phase:

## Reliability

- Persistent job queue, bounded worker pool, process supervision, and restart recovery.
- Per-tool health/version checks and deterministic startup diagnostics.
- Artifact retention quotas and cleanup.

## Supply-chain security

- Pin container images and scanner versions by digest.
- Record SBOMs and third-party licenses.
- Verify Nuclei template signatures and pin template snapshots per run.
- Automate dependency and image vulnerability checks.

## Performance

- Cache safe discovery results.
- Avoid scanning duplicate URL shapes and static assets.
- Stream large result sets instead of holding all raw tool output in memory.
- Add per-stage timing and coverage metrics.

## Testing

- Unit fixtures for every parser and normalizer.
- Local vulnerable applications for browser, auth, API, access-control, and false-positive scenarios.
- Golden report fixtures and schema compatibility tests.
- Container smoke tests with all bundled tools.
- Cancellation, timeout, crash, and malformed-output tests.

---

# Release gates

A phase is complete only when:

1. its acceptance criteria are automated;
2. existing tests remain green;
3. new fields are backward-compatible or schema-versioned;
4. cancellation and timeout behavior are verified;
5. secrets and scope behavior are tested;
6. documentation and operator warnings are current;
7. the full container passes a local smoke scan; and
8. reports accurately distinguish coverage, findings, and verified impact.

# Immediate execution checklist — Phase 1

- [x] Define endpoint corpus data model and normalization rules.
- [x] Implement run-scoped corpus.
- [x] Connect httpx canonical output to Katana.
- [x] Feed Katana and ZAP URLs into the corpus.
- [x] Feed a bounded dynamic endpoint list into Nuclei.
- [x] Add corpus telemetry and report fields.
- [x] Add unit and pipeline data-flow tests.
- [x] Run the complete regression suite and Phase 1 hardening audit (90 passing tests).
- [x] Document Phase 1 completion and remaining limitations.

## Phase 1 implementation record

Implemented in this milestone:

- deterministic HTTP(S) URL canonicalization;
- exact-host scope enforcement;
- rejection of unsupported schemes and credential-bearing URLs;
- provenance, method, status, content type, static/dynamic, duplicate, and rejection tracking;
- canonical httpx output passed to Katana;
- Katana and ZAP discoveries added immediately to the corpus;
- profile budgets of 25/75/150/300 dynamic endpoints for Nuclei;
- temporary Nuclei target lists instead of root-only scanning;
- corpus telemetry under `scanner_results.endpoint_corpus` and compact metadata under `endpoint_corpus`;
- backward-compatible report merging for runs created before the corpus; and
- fixture coverage for normalization, scope escape, provenance, static filtering, corpus limits, and scanner-to-scanner data flow.

Remaining limitations intentionally assigned to later phases:

- ZAP's packaged baseline command accepts a canonical root rather than an arbitrary URL corpus; browser/proxy traffic import will be added in Phase 2.
- Exact-host scope excludes subdomains until the Phase 7 policy engine supports explicit hostname allowlists.
- Authentication-aware endpoint identity and secret redaction arrive in Phases 3 and 5.
- The full scanner container still requires a smoke build in an environment with Docker and outbound image access.
