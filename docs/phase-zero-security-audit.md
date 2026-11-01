# Phase Zero: Security Audit and Baseline

Audit date: 2026-10-30 (Asia/Calcutta)

## Scope and working-tree protection

- Active branch: `docker-modec-work`, at `10b1b1f` (`Save current Docker Mode C implementation`), tracking `origin/docker-modec-work`.
- `main` and `origin/main` point to `98d60cd`; the active branch is the existing Docker development branch requested by the implementation brief.
- The only pre-existing working-tree entries observed were 16 untracked screenshots under `data/screenshots/`. They were not opened, changed, or removed.
- No source files were changed while establishing this baseline.

## Runtime observed

- Host client: Windows; Docker Engine reports Linux containers through Docker Desktop, kernel `6.6.87.2-microsoft-standard-WSL2`, cgroup v2, overlayfs, seccomp and cgroup namespace support.
- Docker image `trustlayer-worker:latest` exists and declares `pwuser` as its configured user. No Trust Layer containers were running during the audit.
- `trustlayer-isolated-net` exists as an internal bridge; `trustlayer-egress-net` exists as an external bridge. Both reported IPv4 enabled and IPv6 disabled.
- The existing network integration test started a temporary authenticated proxy on the internal network, reached it from a separate test container, received a policy block for loopback, and observed a direct connection to `1.1.1.1:443` fail.
- This is Docker isolation under Docker Desktop's shared WSL2 engine. It is not a dedicated disposable VM or microVM per inspection. The runtime inspection did not establish a separate outer boundary for hostile Chromium compromise.

## Verified secure controls

| Control | Evidence | Verification |
| --- | --- | --- |
| Mode C refuses when Docker is unavailable and has no host-browser fallback | `mode_c_security_gate.test.js`; controller starts the worker only via Docker | Unit/security regression tests pass |
| Worker image selects non-root `pwuser` | Image metadata and `worker/Dockerfile` | Image metadata verified; live Chromium process identity not inspected |
| Chromium launch requests Playwright sandboxing and no `--no-sandbox` argument | `worker/browser_worker.js`; security gate tests | Source and regression tests pass; live Chromium sandbox state not inspected |
| Worker container requests read-only root, bounded `/tmp` and `/dev/shm`, dropped capabilities except `SYS_CHROOT`, no-new-privileges, seccomp, PID/memory/CPU limits | Docker arguments in `live_job_controller.js`; expanded `docker_proxy_connectivity.test.js` | Live Docker inspect confirms the configured limits, mounts, network, security options, and non-root user. `/proc` confirms UID 1001, `NoNewPrivs=1`, `Seccomp=2`, and no permitted/effective/ambient capabilities; only `SYS_CHROOT` is in the bounding set. |
| Browser worker and proxy use separate internal/outbound network topology | Controller network setup; `tests/docker_proxy_connectivity.test.js` | Local runtime test passes for proxy reachability and direct-egress denial |
| Proxy authenticates worker and validates destinations before connecting; HTTP forwarding pins a resolved address | `egress_proxy.js`, `ssrf_guard.js` | Unit tests and local Docker integration pass for covered cases |
| Known private, loopback, link-local, multicast, CGNAT, metadata, mapped-IPv6, documentation, and selected reserved address ranges are blocked | `ssrf_guard.js`, `live_inspector.test.js`, SSRF tests | Expanded local test vectors pass; no global guarantee for every special-purpose allocation |
| No persistent browser profile; a new context is created and closed per browser run | `browser_worker.js` | Source inspection; cross-run state isolation not verified in runtime |
| Cancellation/timeout paths remove named containers and temporary output | controller cleanup and Mode C security gate tests | Unit tests pass; Docker cleanup failure behavior not failure-injected |
| Screenshot delivery requires PNG signature/size checks and case-scoped storage | controller and screenshot tests | Covered tests pass |
| HTTP 403 is reported as access restriction rather than a successful inspection or phishing verdict | intelligence summary and end-to-end tests | Regression tests pass |

## Verified vulnerabilities or missing controls

| Finding | Evidence / impact |
| --- | --- |
| No dedicated per-job VM boundary | Docker Desktop shares a WSL2 Linux engine. A container escape would cross a container boundary into that shared engine environment; per-case VM reset is absent. |
| Browser confinement is asserted in worker output | `chromiumSandboxEnabled: true`, `networkIsolated`, and related report fields are set by application code. The supervisor partially verifies output, but this is not runtime evidence of Chromium sandbox activation or effective container settings. |
| Destination policy did not block every non-global/reserved range at the baseline | Baseline code omitted several IANA special-use blocks. Current code blocks selected non-global/reserved IPv4 ranges and restricts IPv6 to global-unicast space with selected special-purpose exclusions. This remains an explicit range list that requires maintenance. |
| Proxy and browser telemetry retained complete requested URLs at the baseline | Current HTTP/CONNECT proxy logs and browser network, blocked-request, redirect, and `Location` telemetry clear credentials, query, fragment, and non-root path data. Destination origin remains for investigation traceability; case target/final URL fields still preserve investigation inputs/results. |
| Proxy has no explicit upstream request/response byte, connection-count or per-request timeout limits | HTTP request bodies are streamed and response bodies are piped; CONNECT tunnels have no byte budget. The worker wall-clock deadline provides an outer bound but does not provide individual proxy resource budgets. |
| HTTP proxy response headers are forwarded without filtering | Hop-by-hop and oversized/unexpected response headers are not explicitly normalized. |
| Control/API routes have no authentication, authorization, or rate-limit middleware in the inspected server | The server enables broad CORS and exposes case creation, case data, screenshot, event-stream and cancellation routes. Safe deployment depends on an unstated network boundary. Interactive browser control is not implemented. |
| Worker output directory is a host bind mount | The controller mounts per-job temporary host storage into worker/proxy containers. It is scoped and removed in normal paths but is writable and not independently size-limited at the host filesystem layer. |
| Worker rebuild fingerprint omitted copied `core/` files at the baseline | Docker copies `core/` into the worker image, while the fingerprint originally covered only worker files. The controller now recursively includes every copied core file; the Mode C security gate has a regression check for this relationship. |
| `--keepAlive` retains a live browser session after results are published, but there is no investigator control interface | The worker can remain active for up to the configured 150 seconds; API cancellation terminates it, but secure interactive control and ownership checks are absent. |

## Unknowns requiring further verification

- Whether Chromium's own sandbox is independently active at the kernel level. The real worker launches Chromium with Playwright sandboxing enabled and renders a screenshot, but its `chromiumSandbox` report field is worker-generated.
- Actual browser packet behavior for WebSocket, WebRTC, DNS, IPv6, alternate protocols, redirects and proxy loss; the one integration test only covers proxy reachability, one loopback block, and one direct IPv4 connection failure.
- DNS rebinding behavior across repeated resolution, mixed public/private answers, HTTPS CONNECT, and redirects under a controlled adversarial resolver.
- Container cleanup when Docker is unavailable, the daemon hangs, the host process crashes, or Docker refuses removal.
- Temporary-directory ACLs, disk quotas, evidence retention, and screenshot/API authorization under the intended deployment model.
- Performance distributions and comparison against the prior non-Docker Chromium path. No controlled benchmark was run.
- A production VM/microVM runtime is not configured or tested here.

## Baseline tests

Commands and results before changes:

- `npm.cmd test` — 7 passed, 0 failed, about 108 seconds.
- `node --test tests/*.test.js` — 98 total, 96 passed, 0 failed, 2 skipped, about 165 seconds. Skips were the opt-in Docker connectivity test and opt-in Mode C API test.
- `$env:TRUSTLAYER_DOCKER_INTEGRATION='1'; node --test tests/docker_proxy_connectivity.test.js` — 1 passed, 0 failed, about 2 seconds.
- The opt-in Mode C API test was not run: its default target is a public website, and no specific real-world target was authorized for this baseline.

The first direct `npm test` invocation was blocked by the PowerShell execution policy for `npm.ps1`; the equivalent `npm.cmd test` ran successfully. Initial Docker pipe inspection also required elevated access; Docker Engine inspection then succeeded. No public website was opened as part of the Docker connectivity test.

## Implementation progress after the baseline

### Phase One: Docker intermediate runtime verification

The dedicated per-inspection VM/microVM target is not provisioned. The strongest supported state verified here remains the Docker worker under Docker Desktop's shared WSL2 engine. The opt-in Docker test now starts the actual `worker/browser_worker.js` with a loopback target that the proxy blocks locally. It inspects the live container, verifies the process UID and `/proc` security fields, confirms writes to the image root fail with `EROFS`, checks the only bind mount is per-test output storage, confirms Chromium runs without `--no-sandbox`, and validates the PNG artifact. The image fingerprint now includes all copied `core/` files so source changes trigger a rebuild. No public website is contacted.

This verifies the container policy on this Docker Desktop engine, but it does not prove a dedicated outer VM boundary or independently prove Chromium's internal sandbox namespace/seccomp behavior.

### Phase Two: destination and log hardening

- Added blocks for IPv4 current-network, IETF protocol assignment, documentation, benchmarking, and reserved ranges, plus IPv6 outside `2000::/3` and selected special-purpose ranges. The ranges were checked against the [IANA IPv4 special-purpose registry](https://www.iana.org/assignments/iana-ipv4-special-registry) and [IANA IPv6 special-purpose registry](https://www.iana.org/assignments/iana-ipv6-special-registry).
- Proxy logs now retain only target origin plus a redacted path; URL credentials, query values, and fragments are removed for HTTP and CONNECT records.
- A shared URL redactor is used by proxy and browser telemetry, including blocked requests, request/response observations, redirects, and response `Location` headers.
- CONNECT targets are parsed as URL authorities, rejecting malformed ports and path/query forms before opening a socket; bracketed IPv6 authorities are handled by URL parsing.
- Worker image freshness now hashes every file copied from `core/`, preventing the controller from reusing a stale bundled egress/SSRF implementation after a core edit.
- Regression tests cover the added address classes, log redaction, and malformed CONNECT authority handling.

Post-change verification:

- Focused SSRF, CONNECT, redaction, and fingerprint tests — 6 passed, 0 failed.
- `node --test tests/*.test.js` — 104 total, 102 passed, 0 failed, 2 opt-in tests skipped, about 157 seconds.
- `$env:TRUSTLAYER_DOCKER_INTEGRATION='1'; node --test tests/docker_proxy_connectivity.test.js` — 1 passed, 0 failed, including live runtime inspection, synthetic-secret telemetry redaction, and a local blocked-page screenshot.
- `npm.cmd test` — 7 passed, 0 failed, about 105 seconds.

