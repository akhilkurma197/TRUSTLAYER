# Phase One Security Validation

Date: 2026-10-30 (Asia/Calcutta)  
Branch: `docker-modec-work`

This report extends [Phase Zero](phase-zero-security-audit.md) without replacing its baseline. Existing working-tree edits and screenshot artifacts were preserved. The Docker and benchmark tests used local fixtures; this phase did not request RVCE again.

## RVCE 403 and prior implementation comparison

The Phase Zero evidence records the current Docker implementation's RVCE response as HTTP 403, while Google returned HTTP 200. The worktree and available Git history contain the Docker supervisor but not the prior working Chromium implementation or a reproducible capture of its browser/proxy/DNS/session configuration. A controlled side-by-side comparison of browser and Playwright versions, launch flags, egress routes, resolved addresses, TLS, request headers, cookies, and timing is therefore unavailable. No specific implementation regression has been demonstrated as the cause of the RVCE denial.

The current result remains **access denied/unresolved**, not a successful rendering of the RVCE homepage. A screenshot or response body from a 403 document is not evidence that the homepage rendered. This phase made no RVCE requests.

## Chromium and container verification

The opt-in `tests/docker_proxy_connectivity.test.js` passed against the rebuilt worker image. It confirmed the local worker's proxy-only network path, blocked loopback request, failed direct egress, read-only root filesystem, isolated network, resource settings, non-root identity, and PNG artifact. The actual Chromium sandbox probe reported:

- Chromium `156.0.8078.4`; worker package/Playwright release `1.64.1`.
- Worker and Chromium process UID/GID `1001/1001`.
- No `--no-sandbox` launch argument; launch requested `chromiumSandbox: true`.
- Container `NoNewPrivs=1`, `Seccomp=2`; effective/permitted capabilities were zero in the inspected processes, with `SYS_CHROOT` only in the container bounding set.
- Chromium created distinct user/PID namespaces for zygote/renderer processes in the inspected run. These observations establish process-level confinement signals, not a complete proof of each Chromium sandbox layer.
- `chrome://sandbox` produced no diagnostic text in the bundled headless build. The probe status is **UNAVAILABLE**. Consequently, Chromium's internal sandbox activation remains independently unverified. `--no-zygote-sandbox` was present on one zygote command line, which should be investigated against this pinned Playwright/headless build before claiming complete sandbox coverage.

Docker Desktop uses the shared WSL2 Linux engine described in Phase Zero. This is not a disposable VM or microVM per inspection.

## Resource limits and lifecycle changes

The worker launch remains non-root, read-only, capability-restricted, seccomp-filtered, no-new-privileges, and network-isolated behind its authenticated egress proxy. Existing Docker ceilings are 512 MiB memory, one CPU, 128 PIDs, 64 MiB `/tmp` and `/dev/shm`, with controller wall-time capped at 180 seconds and retained sessions at 150 seconds. The controller now enforces its concurrency limit from DNS preflight through worker/session cleanup (default 3; configurable maximum 16) and returns `BUSY` at capacity.

The egress proxy now bounds concurrent TCP connections (32), per-job requests (512), request bodies (16 KiB), individual HTTP response bodies (25 MiB), aggregate HTTPS tunnel bytes (100 MiB), upstream waits (10 seconds), tunnel idle time (30 seconds), and telemetry records (512). Hop-by-hop headers, including headers nominated by `Connection`, are removed. The worker caps extracted lists, removes the unused full-page HTML copy, bounds the response excerpt to a declared small identity-encoded body, and the supervisor retains only the last 64 KiB of process output.

The host bind-mounted job output directory still has no filesystem quota. Limits on response bytes and screenshot artifacts do not provide a hard host-side disk quota if Docker cleanup fails or a compromised process writes repeatedly within its mounted output directory. Add a quota or per-job size-limited volume in the next runtime phase. The worker now estimates `htmlBytes` using a bounded text traversal and DOM-node count; it no longer serializes a second full copy of the document.

## API boundary

The API now requires `TRUSTLAYER_API_TOKEN` with at least 32 bytes of secret material; startup refuses if it is absent or too short. Case creation/data, evidence screenshots, cancellation, and SSE routes are protected by bearer token or an 8-hour HttpOnly, SameSite=Strict session cookie. Cookie-backed mutations require a same-origin `Origin`; login attempts and sessions have bounded in-memory tables. The repository root is no longer served as static content; only explicit UI routes and `/vendor` are public.

This is a single-operator shared secret. It does not provide per-user case ownership, revocation, durable session storage, or identity audit records. Keep it behind a trusted deployment boundary and do not share it across mutually untrusted operators. The optional end-to-end API smoke test was not run because it creates a case for a public target; authentication behavior and protected route coverage were verified with local test fixtures instead.

## Status and evidence integrity

Worker classifications preserve distinctions between HTTP 401/403 (`BLOCKED`/`ACCESS_DENIED`), other HTTP errors (`HTTP_ERROR`), HTTP server errors (`HTTP_SERVER_ERROR` render metadata), navigation timeouts, proxy/DNS failures with no HTTP response, and rendered success/partial results. A 403 page remains observable evidence but is never promoted to a successfully rendered homepage or a phishing verdict solely because a response/screenshot exists.

## Local performance baseline

Measured results and raw samples are in [phase-one-benchmark-results.json](phase-one-benchmark-results.json). The benchmark ran 20 samples per case, with a fresh restricted Docker container and fresh Chromium process for each cold sample; the warm case reused one Chromium process for 20 page/context runs per case. It used `--network=none`, Playwright-fulfilled fixtures, a synthetic 403, a delayed page, a 1,500-node local DOM, and a 200 ms navigation timeout. It measures the worker/browser fixture path, not end-to-end proxy, DNS, target-site, OCR, or real investigation latency.

Timing units in the raw output are milliseconds; RSS is the worker Node process RSS, not total Chrome/container RSS. Cold container-to-worker startup median/p95 and per-case browser launch, navigation, screenshot, total, cleanup, timeout, screenshot failure, and memory distributions are recorded. There is no valid comparison against the previous Chromium implementation because its source/configuration and matching benchmark are unavailable. These values are a local reference, not a production SLO.

Selected median / p95 values from this run:

| Case | Cold browser launch | Cold navigation | Cold screenshot | Cold total | Warm total | Node RSS cold / warm median | Outcome |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | --- |
| Small HTML | 319 / 393 | 85 / 93 | 127 / 147 | 470 / 499 | 289 / 403 | 110 / 122 MiB | 200; 0 timeout, 0 screenshot failures |
| Inline assets | 286 / 304 | 76 / 81 | 109 / 126 | 371 / 448 | 305 / 390 | 111 / 122 MiB | 200; 0 timeout, 0 screenshot failures |
| Delayed content | 276 / 369 | 16 / 82 | 78 / 86 | 416 / 453 | 355 / 508 | 111 / 123 MiB | 200; 0 timeout, 0 screenshot failures |
| Synthetic access-denied page | 292 / 313 | 20 / 85 | 114 / 129 | 397 / 489 | 332 / 385 | 117 / 122 MiB | 403; 0 timeout, 0 screenshot failures |
| Moderate 1,500-node DOM | 280 / 311 | 21 / 83 | 129 / 194 | 419 / 499 | 383 / 434 | 119 / 122 MiB | 200; 0 timeout, 0 screenshot failures |
| Forced 200 ms timeout | 295 / 374 | 204 / 206 | 383 / 480 | 800 / 879 | 766 / 898 | 119 / 122 MiB | 20/20 timeouts, 0 screenshot failures |

Cold container-to-worker startup was 1,276 ms median / 1,411 ms p95 across 20 containers; the single warm container startup was 1,249 ms. Cold browser-close medians ranged from 125 to 180 ms across cases (p95 217 to 465 ms); warm browser close was 221 ms. Each per-case total includes context creation/close. The timeout scenario's screenshot is of the browser's timeout state, not successful target content. The benchmark records screenshot errors explicitly and had zero in this final run.

## Validation performed

- API authentication, status classification, SSRF/redirect revalidation, proxy adversarial limits, Mode C policy, and screenshot behavior: focused Node test runs passed.
- Docker proxy/connectivity and container/Chromium probe: 1 passed. Internal Chromium sandbox diagnostic: unavailable (recorded above).
- Repository-wide `node --test`: 123 tests, 121 passed, 0 failed, 2 skipped (opt-in Docker integration and public-target API smoke test); 163.7 seconds.
- Opt-in local Docker connectivity/container probe: 1 passed; it was run separately from repository-wide discovery.
- Final whitespace/diff checks are recorded in the completion report for this phase.

## Remaining security work

1. Obtain a trusted external auditor's sandbox verification for the pinned headless Chromium build; resolve the unavailable `chrome://sandbox` output and zygote behavior before treating internal sandbox layers as verified.
2. Replace Docker Desktop/shared WSL2 deployment with a disposable VM/microVM boundary for hostile-content inspection.
3. Add host-side job-output quotas and test Docker daemon loss, host process termination, container removal failure, browser crash, and proxy loss against the complete controller lifecycle.
4. Add multi-user authentication, case ownership, session revocation, and durable access audit if the service will serve multiple operators.
5. Re-run a matched, local benchmark on the old implementation only if its exact source and configuration can be recovered. Any future RVCE recheck should be bounded and authorized, with denial preserved as denial.
