# Phase Two: Per-Investigation Isolation and Resource Quotas

Audit date: 2026-10-31 (Asia/Calcutta)  
Branch: `docker-modec-work`

## Verdict

**Phase Two is incomplete.** The worktree remains on the requested branch and existing modifications/artifacts were preserved. Worker-side output limits and idempotent cleanup handling were improved and tested. However, each job's `/output` is still a host temporary-directory bind mount without a hard disk quota, and deterministic tests do not yet exercise all requested lifecycle outcomes against a live controller/worker. Do not treat this report as proof that all Phase Two completion criteria are met. Keep Mode C fail-closed on its existing Phase One runtime/sandbox checks; do not claim the missing Phase Two limits or external egress policy as verified.

No public target was visited. External direct egress was not tested. The local Docker integration navigated only to a loopback address and intentionally received an SSRF policy denial.

## Existing limits and enforcement boundaries

| Resource | Current bound | Enforcement boundary / gap |
|---|---:|---|
| Browser CPU | 1 CPU | Docker `--cpus=1.0` |
| Browser memory | 512 MiB | Docker `--memory=512m` |
| Browser processes | 128 PIDs | Docker `--pids-limit=128` |
| Proxy CPU / memory / PIDs | 0.25 CPU / 128 MiB / 32 PIDs | Docker runtime |
| Browser `/tmp`, `/dev/shm` | 64 MiB each | Docker tmpfs mounts; `noexec,nosuid` |
| Proxy `/tmp` | 32 MiB | Docker tmpfs mount; `noexec,nosuid` |
| Wall time | Requested timeout clamped to 1–180 s, plus 3 s supervisor watchdog; keepalive <=150 s | Controller timer and worker operation timeouts. Docker `--rm` plus explicit `docker rm -f` is intended cleanup; the timeout is supervisor-enforced, not a Docker runtime deadline. |
| Concurrent investigations | Default 3, configurable 1–16; no waiting queue | Controller admission set; excess returns `BUSY`. |
| Proxy requests / connections | 512 requests/job; 32 concurrent sockets | Proxy application limits |
| Proxy request / upstream data | 16 KiB request, 25 MiB upstream response, 100 MiB HTTPS tunnel/job; 10 s upstream timeout, 30 s idle timeout | Proxy application; tunnel cap is counted at the proxy socket boundary. |
| Proxy telemetry | 512 records per list | Proxy application ring buffer; worker network and blocked-event lists are now capped at 512 records each. |
| Target response excerpt | Declared body <= min(configured max, 512 KiB), excerpt 500 chars | Browser worker checks declared content length; this does not establish a hard cap on Chromium's internal response buffering. |
| Extracted DOM | Collection counts capped (headings 100, buttons 200, forms 100, form fields 100/form, scripts 200, links 500); text fields capped at 2048 chars | Browser worker extraction. Text-size estimate is bounded by configured `maxBytes` (16 KiB–5 MiB); it is not a cap on the live DOM retained by Chromium. |
| Result JSON | 2 MiB serialized cap | Worker rejects over-limit results before writing. `JSON.stringify` must allocate the serialization before this check; container memory remains the outer bound. |
| Screenshot | 1280x800 viewport, PNG >=1000 bytes and <=5 MiB | Worker captures to a buffer, validates PNG signature/dimensions/bytes, then writes exclusively. Supervisor independently validates signature/bytes. Browser capture's full-page mode is false. |
| Per-job output storage | **No hard quota** | Host temp directory is bind-mounted at `/output` into both job containers. Files are removed during cleanup but can consume host disk while the job runs. This is a Phase Two blocker. |

The worker image is pinned to Playwright image `v1.64.1-noble`, runs as `pwuser`, read-only root, dropped capabilities except `SYS_CHROOT`, no-new-privileges and seccomp. Browser and proxy use separate per-job containers and credentials. Browser is attached only to the internal Docker network; proxy is the only intended dual-homed service. The browser container does not mount the Docker socket.

## Changes in this phase

- `worker/resource_limits.js`: shared, deterministic helpers for bounded telemetry, PNG signature/dimension/byte validation, and serialized result byte ceilings.
- `worker/browser_worker.js`: caps network and blocked-request telemetry; validates screenshot dimensions and bytes before writing; caps extracted string fields; rejects oversized serialized output.
- `.dockerignore`: includes the new runtime module in the worker build context.
- `tests/resource_limits.test.js`: checks event count, screenshot boundaries and result output rejection.
- `core/investigators/live_job_controller.js`: cleanup is now coalesced/idempotent, retains the active handle until cleanup completes, and supports injected cleanup operations for deterministic verification.
- `tests/mode_c_security_gate.test.js`: verifies cleanup removes both container handles, signals the child once, removes per-job temporary files, and clears admission/active state.

## Lifecycle evidence and remaining gaps

New deterministic local cleanup test passed for two concurrent cleanup calls against a represented browser/proxy container pair, child handle and temporary output containing a stale result. This verifies controller cleanup bookkeeping and callbacks, not Docker daemon behavior.

The existing suite covers admission saturation, Docker startup refusal, cancellation path assertions and timeout/child-error cleanup source assertions. The local Docker integration exercises a real worker, screenshots, proxy refusal and Chromium sandbox, and its `finally` block attempts to stop/remove test containers and remove its temporary directory. It is not a fault-injection suite for worker startup failure, navigation timeout, worker crash, cancellation or output-limit violation. Repeated full investigations/failures are not yet exercised as cleanup regressions. Therefore cleanup for all requested terminal paths is not proven, and stale results were tested only as files removed from a test temporary directory, not across two live job executions.

The supervisor cleanup currently attempts Docker removals and local recursive deletion but catches errors. It does not surface a durable cleanup failure record. A failed daemon request or host file deletion can therefore leave resources behind without a positive cleanup verdict. This needs a follow-up hardening/test before claiming lifecycle completion.

## Network isolation audit

Evidence available in the checked-in implementation and local tests:

- `SSRFGuard` denies loopback, RFC1918, link-local/metadata, shared, multicast, reserved/documentation and non-global IPv6 ranges (including mapped IPv4); it rejects non-HTTP(S), embedded credentials and mixed public/prohibited DNS answers.
- Proxy permits ports 80/443 and GET/HEAD only, requires per-job proxy authentication in production, validates destinations before connecting and connects to the validated IP. Redirect requests return through the browser proxy and are revalidated at each destination.
- Browser container's Docker network is asserted internal in the local integration; loopback target through the proxy receives 403. The integration inspects that browser has only `trustlayer-isolated-net`, no Docker socket bind, and worker user/security/resource settings.
- Existing redirect and proxy adversarial tests use local fixtures to cover rebinding and prohibited redirect destinations.

Unverified:

- Arbitrary external direct-egress blocking from the Docker internal network was not probed. The previous public-IP test was intentionally removed; no public IP or website was contacted here.
- A loopback SSRF rejection does not prove that packets to all external destinations bypass no proxy. The local Docker network configuration is evidence of the intended topology, not an end-to-end external packet test.
- Host/Docker endpoint reachability from the worker was reviewed through network/socket mount configuration but not tested against a live host endpoint. No such access was attempted.
- Docker Desktop/WSL2 remains a shared host engine, not a per-job VM boundary.

## Commands and results

Pre-edit audit commands included `git status --short --branch`, `git branch --show-current`, `git diff --stat`, and reads of `docs/phase-zero-security-audit.md`, the controller, worker, proxy, SSRF guard, Dockerfile, and integration tests. Branch was `docker-modec-work`. Existing screenshot artifacts were not modified or removed.

Completed validation:

```text
node --check worker/browser_worker.js
node --check core/investigators/live_job_controller.js
node --test --test-name-pattern="isolates each browser job|performs idempotent cleanup" tests/mode_c_security_gate.test.js
# 2 passed, 0 failed, 0 skipped
node --test tests/resource_limits.test.js
# 3 passed, 0 failed, 0 skipped
$env:DOCKER_CONTEXT='desktop-linux'; docker --context desktop-linux version --format '{{.Server.Version}}'
# 28.5.1
$env:TRUSTLAYER_DOCKER_INTEGRATION='1'; node --test tests/docker_proxy_connectivity.test.js
# 1 passed, 0 failed, 0 skipped
node --test
# 129 passed, 0 failed, 2 skipped
npm.cmd test
# 7 passed, 0 failed, 0 skipped
```

The first non-elevated Docker test attempt failed because the process could not read Docker Desktop's user config/context metadata (`Access is denied`). The same local-only test completed successfully with authorized access to the existing `desktop-linux` context; the context was not changed. Live integration evidence recorded Chromium 156.0.8078.4 / Playwright 1.64.1, UID/GID 1001, renderer seccomp mode 2, `NoNewPrivs=1`, renderer filter count 3 vs container baseline 2, distinct browser/renderer user and PID namespaces, stable fresh process evidence, and verifier result `VERIFIED`. The target itself was `http://127.0.0.1/private/...`; it was denied and classified `ACCESS_DENIED`/`BLOCKED`. No actual public target was rendered.

The full Node run skipped the opt-in Docker test (run separately above) and Mode C API integration. These skips are not counted as passes. The Docker test does not test external egress.

`git diff --check` is still required after the final report edit and must be run before considering the worktree validated.

## Follow-up execution — 2026-10-31

This section supersedes the earlier “no hard quota” and “cleanup errors are suppressed” findings above. The historical sections are retained to show the audit progression.

### Storage boundary

The browser worker now mounts `/output` as a per-container Docker tmpfs capped at 24 MiB; its dedicated egress proxy has a separate 16 MiB `/output` tmpfs. Both are owned by UID/GID 1001 and mounted `noexec,nosuid` with mode 0700. They are independent per-job container namespaces; no host directory is mounted at `/output`. Supervisor delivery copies only allowlisted files through bounded Docker exec buffers, with caps of 2 MiB for each JSON result/ready file, 64 KiB for capture status, 5 MiB per screenshot, and 7 MiB for egress telemetry. Temporary transfer directories are unique `mkdtemp` paths and carry a random owner token checked before cleanup. The mount quotas cap total temporary and final file writes, including temporary files, rather than checking file size only after writes.

The local Docker integration separately filled a 1 MiB tmpfs as UID/GID 1001 using repeated 256 KiB writes; the filesystem returned `ENOSPC`, and the test confirmed the quota container was removed. The live worker's inspected `HostConfig` had no bind mounts and had the 24 MiB output tmpfs. Docker tmpfs is memory-backed: it consumes Docker engine memory and is not a persistent disk quota. Per-container limits are hard, but the engine-wide memory budget remains shared with Docker Desktop/WSL2. Host transfer storage is bounded by the explicit artifact allowlist and copy ceilings, rather than a host filesystem project quota.

### Cleanup and job separation

Cleanup runs each independent action even if another fails: clear watchers, publish any final initial screenshot, remove browser and proxy containers, terminate the Docker client child, and remove the owner-verified transfer directory. Diagnostics contain only safe operation names and error codes. Any error yields `FAILED`; the job stays reserved and active, and `retryCleanup(jobId)` can retry. Startup cleanup has the same fail-closed reservation behavior. Owner mismatch is reported and the unowned directory is left untouched.

Deterministic tests cover startup cleanup failure/retry, timeout, cancellation, worker crash, output-limit violation, repeated jobs, cleanup failure, and owner mismatch. The live local-only Docker test covers tmpfs quota exhaustion, a failed worker that writes a stale sentinel, a subsequent distinct job that does not observe that sentinel, and timeout/cancel dummy containers that are stopped and confirmed absent. The successful live browser job also used its own output tmpfs and passed the fresh Chromium verifier. The live integration does not inject all controller failure modes into a real Chromium investigation; startup/navigation/worker failure cleanup is covered through deterministic controller tests, not claimed as end-to-end Docker fault injection.

### Final validation

Commands and results for this follow-up:

```text
node --test tests/live_job_lifecycle.test.js tests/resource_limits.test.js tests/egress_proxy_adversarial.test.js
# 12 passed, 0 failed, 0 skipped
$env:DOCKER_CONTEXT='desktop-linux'; $env:TRUSTLAYER_DOCKER_INTEGRATION='1'; node --test tests/docker_proxy_connectivity.test.js
# 1 passed, 0 failed, 0 skipped; local-only; live fresh sandbox verifier VERIFIED
node --test
# 141 tests, 139 passed, 0 failed, 2 skipped
npm.cmd test
# 7 passed, 0 failed, 0 skipped
git diff --check
# passed (no whitespace errors)
```

The first full-suite run exposed obsolete static expectations in `tests/mode_c_security_gate.test.js` (cleanup callback injection, the screenshot watcher interval, and async cancellation). Those assertions were aligned to the current implementation, then the complete `node --test` run finished with 139 passes and no failures. The two skips were reported as skipped, not passes. `npm.cmd test` completed successfully. The local Docker integration contacted only local fixtures/containers; no public websites or public IPs were used. Its fresh live renderer verifier returned `VERIFIED` with Chromium 156.0.8078.4 / Playwright 1.64.1, UID/GID 1001, seccomp mode 2, `NoNewPrivs=1`, renderer filter count 3 versus worker baseline 2, and distinct browser/renderer user and PID namespaces.

### Network scope and verdict

External egress remains **unverified**. The internal network topology, proxy routing, SSRF/redirect checks, disallowed ports/methods and local adversarial fixtures provide local evidence, but no external IP or public website was probed. Do not describe arbitrary external egress blocking as verified.

**Phase Two resource-isolation requirements are implemented and validated for the tested Docker Desktop configuration; external egress verification remains outside the evidence collected and is not claimed.** The existing fresh sandbox `VERIFIED` gate is retained. The full Node suite includes two skipped tests; the opt-in Docker integration was run separately and passed.

## Required follow-up before Phase Two completion

The preceding follow-up closes the listed storage, cleanup observability, and job-isolation gaps for the current local Docker configuration. The final `git diff --check` passed after this report edit. External egress is intentionally unverified; any later external egress claim needs a separately authorized controlled test. No Phase Three work was started.
