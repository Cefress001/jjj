# Phase 1 Quality Audit — Connected Scanner Pipeline

**Audit status:** Code-complete and regression-clean  
**Release status:** Conditional — full-image smoke build remains required on a Docker-capable runner  
**Scope:** Endpoint corpus, httpx → Katana → ZAP → Nuclei data flow, subprocess lifecycle, report merge, persistence compatibility, and bundled scanner image

## Executive conclusion

The Phase 1 code path has been reviewed and hardened beyond its initial implementation. The automated suite passes, malformed scanner data is isolated, endpoint input is bounded and scoped, scanner processes are cancelled as process trees, and downstream execution continues when an upstream tool fails.

No software can honestly be certified as having “no bugs.” Phase 1 is ready to serve as the code foundation for Phase 2 after one external release gate: build the full Docker image and perform a smoke scan with the real bundled versions of httpx, Katana, ZAP, Nuclei, and the baked Nuclei template snapshot. Docker is not available in the current Arena workspace, so that binary-level compatibility test cannot be completed here.

## Data-flow contract

```text
submitted URL
  └─ EndpointCorpus seed
      └─ httpx
          ├─ canonical in-scope URL → Katana
          └─ technology/status metadata → corpus/report
              └─ Katana
                  ├─ URL/method/status/content type → corpus
                  └─ out-of-scope URLs rejected
                      └─ ZAP baseline
                          ├─ canonical root → crawl/passive scan
                          └─ affected URLs → corpus
                              └─ Nuclei
                                  └─ bounded, deduplicated, dynamic corpus URLs
```

A tool failure produces `status: failed`; unavailable tools produce `status: unavailable`. Neither condition discards core results or prevents independent downstream tools from running with the best available corpus.

## Audit findings fixed

### Process lifecycle

- Scanner cancellation previously terminated only the direct process. Child processes, especially ZAP’s Java process, could survive.
- Added isolated process groups and terminate-then-kill process-tree cleanup.
- Processes are always reaped.
- Cancellation and timeout paths are tested.

### Output and memory safety

- JSONL collection was previously unbounded.
- Added per-tool record limits while continuing to drain output safely.
- ZAP terminal output is retained as a bounded tail.
- ZAP report files larger than 64 MB are rejected.
- ZAP alerts and per-alert instances are bounded.
- Invalid UTF-8 is replaced instead of killing reader threads.
- Reader sentinels are emitted in `finally`, preventing hangs after decoding or stream errors.

### Input integrity

- Nuclei target files now deduplicate targets, reject CR/LF injection, drop empty values, and enforce an independent maximum.
- Malformed command environment variables no longer break health/config endpoints.
- URL corpus entries reject control characters and oversized URLs.
- Internationalized hostnames are normalized with IDNA.
- Embedded URL credentials and unsupported schemes are rejected.

### Metadata robustness

- Invalid status values no longer raise exceptions.
- Method, source, and content-type metadata are length-bounded.
- ZAP’s malformed CWE/WASC values normalize to zero rather than failing a scan.
- Corpus records are returned as defensive deep copies.

### Secret exposure reduction

- Sensitive query values such as tokens, passwords, API keys, sessions, JWTs, and signatures remain available internally for scanner execution but are redacted in persisted corpus/report records.

### Pipeline continuity

- Katana falls back to its endpoint list if detailed endpoint records are unavailable.
- If httpx fails, Katana runs against the validated seed and can still feed Nuclei.
- Out-of-scope Katana/ZAP URLs never enter Nuclei’s target list.
- Legacy reports without corpus records retain the previous merge path.

### Container readiness

- Nuclei templates are downloaded during the full-image build into a known directory.
- The runtime image points Nuclei to the baked template snapshot, avoiding an unplanned first-scan template dependency.

## Automated verification

The suite currently covers:

- URL canonicalization and equivalent URL collapse;
- exact-host scope enforcement;
- unsupported schemes, embedded credentials, control characters, oversized URLs, IDNA, and invalid ports;
- provenance and method merging;
- corpus and Nuclei budgets;
- static asset exclusion;
- report redaction versus internal scanner input;
- defensive-copy behavior;
- malformed metadata;
- httpx canonical-target handoff to Katana;
- Katana-to-Nuclei endpoint propagation;
- out-of-scope rejection;
- upstream failure continuity;
- JSONL output caps and invalid UTF-8;
- Nuclei target-file injection resistance;
- ProjectDiscovery cancellation;
- ZAP cancellation and malformed metadata;
- ZAP findings integrated through the normal service lifecycle;
- zero-tool fallback;
- real-target soft-404, Cloudflare challenge, rate-limit, and unreachable-host behavior;
- API lifecycle, persistence, reports, and archive compatibility.

### Current results

- **90 tests passed**
- Python compilation passed.
- JavaScript syntax validation passed.
- Ruff undefined-name/import checks passed.
- A 20,000-input randomized malformed-URL exercise completed without a corpus exception.
- Dockerfile syntax was parsed successfully.

## Manual release checklist still required

Run these steps on a Docker-capable machine before labeling Phase 1 production-ready:

1. Build the full image without cache.
2. Confirm the four scanner binaries report versions.
3. Confirm the baked Nuclei template directory exists and is readable by user `zap`.
4. Start the built-in demo target.
5. Run one balanced scan and confirm all four tool statuses are `complete`.
6. Confirm Katana URLs appear in the corpus and Nuclei target count is greater than one.
7. Cancel a running scan and verify no Java, Chromium, or scanner process remains.
8. Run against local fixtures for redirects, soft-404, WAF challenge, malformed JSON, and large crawl output.
9. Restart the container and verify the run/report reloads.
10. Inspect JSON/HTML reports to confirm sensitive query values are redacted.

Suggested commands:

```bash
docker build --no-cache -t offensive-emulator:phase1 .
docker run --rm -p 8000:8000 --name oe-phase1 offensive-emulator:phase1

docker exec oe-phase1 httpx -version
docker exec oe-phase1 katana -version
docker exec oe-phase1 nuclei -version
docker exec oe-phase1 /zap/zap.sh -version
```

## Known limitations, not Phase 1 defects

- ZAP’s packaged baseline accepts a canonical root, not the complete arbitrary URL corpus. Browser/proxy traffic import belongs to Phase 2.
- Exact-host scope intentionally excludes subdomains until explicit allowlists are implemented in Phase 7.
- Cross-scanner semantic finding deduplication is scheduled for the Phase 5 finding model.
- Authenticated endpoint identity and comprehensive secret handling are Phase 3 and Phase 5 work.
- Template/image digest pinning and SBOM enforcement remain cross-phase supply-chain work.
- Arena’s current network policy may prevent public-target testing even when scanner binaries are present.

## Phase 1 exit decision

- **Code and tests:** PASS
- **Failure isolation:** PASS
- **Cancellation/process cleanup:** PASS in fixture tests
- **Scope/corpus handoff:** PASS
- **Backward compatibility:** PASS
- **Real bundled binary smoke scan:** BLOCKED BY ENVIRONMENT
- **Final production sign-off:** PENDING DOCKER SMOKE CHECK
