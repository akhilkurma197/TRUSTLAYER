# Phase One: Chromium Sandbox Verification

Date: 2026-10-31 (Asia/Calcutta)  
Branch: `docker-modec-work`

## Current verified status — 2026-10-31

The final local-only Docker integration run completed successfully against the rebuilt `desktop-linux` worker image. The live verifier returned `VERIFIED` for the renderer process and its evidence was fresh and stable across a second `/proc` read. The earlier “unverified” sections below record the state before Docker access was restored and are superseded by this result.

For the tested image/configuration, the Phase 1 Chromium renderer verification criteria are met. The `chrome://sandbox` page remains unavailable; the verdict comes from the independent live `/proc` process checks described below. External direct-egress reachability was intentionally not tested in the local-only integration run.

## Initial finding before Docker access was restored

The live Chromium sandbox state is **unverified in this run**. The Docker Desktop Linux engine is unavailable (`docker info` cannot connect to `//./pipe/dockerDesktopLinuxEngine`), so the worker image could not be launched and its Chromium process tree could not be inspected. Do not allow live Mode C inspection under this unverified configuration. The supervisor now rejects any worker result without explicit `VERIFIED` renderer evidence; Mode A URL-only analysis remains independent.

This does not establish that Chromium's sandbox is disabled. It means the available runtime evidence is insufficient to establish that its renderer protections are active.

## Evidence and layer boundaries

- The pinned worker image is `mcr.microsoft.com/playwright:v1.64.1-noble`; the worker package uses Playwright `1.64.1`. The worker runs as `pwuser` and requests `chromiumSandbox: true`, with no `--no-sandbox` or `--disable-setuid-sandbox` argument.
- Historical Phase Zero evidence observed UID/GID 1001, container `NoNewPrivs=1` and `Seccomp=2`, and distinct renderer user/PID namespaces. That earlier probe did not record `Seccomp_filters` deltas or renderer parentage, so it cannot prove Chromium added a renderer seccomp filter or determine whether the renderer's parent zygote carried `--no-zygote-sandbox`.
- `--no-zygote-sandbox` alone does not identify which child processes are sandboxed. Chromium documents a utility-process zygote arrangement where the zygote starts without the namespace sandbox and the utility child applies its specialized sandbox later. The previous process capture lacks enough parent/child evidence to associate that behavior with this renderer tree. [Chromium sandboxing documentation](https://chromium.googlesource.com/chromium/src/%2B/refs/heads/main/sandbox/linux/README.md)
- An empty `chrome://sandbox` page is inconclusive. The new verifier instead creates a local page and checks every observed renderer for user/PID namespace separation from the browser, `NoNewPrivs=1`, seccomp filter mode, an additional seccomp filter beyond the Node/container baseline, and a renderer parent zygote without `--no-zygote-sandbox`. It reports `VERIFIED`, `UNVERIFIED`, or `UNAVAILABLE`; anything except `VERIFIED` prevents target navigation.
- Playwright's `chromiumSandbox` launch option is requested, but a launch option is not runtime proof. [Playwright `BrowserType.launch`](https://playwright.dev/docs/api/class-browsertype)
- Container protections (non-root user, read-only root, dropped capabilities, no-new-privileges, seccomp, resource caps, internal browser network and authenticated egress proxy) are a separate layer. Docker Desktop's shared WSL2 engine is also not a disposable per-job VM boundary. This phase does not claim a VM/hypervisor boundary.

The seccomp filter-count comparison is a Linux `/proc` observation. `Seccomp=2` means filter mode; a renderer filter count greater than the worker baseline gives evidence of an additional process filter, while still not proving every Chromium sandbox property. [Linux `proc_pid_status(5)` documentation](https://www.kernel.org/doc/man-pages/6.17/html/proc_pid_status.html)

## Changes

- Added `worker/chromium_sandbox_verifier.js`, which gathers local process evidence after loading an in-memory fixture and rejects missing renderer, zygote, namespace, or seccomp evidence.
- Updated `worker/browser_worker.js` to request Chromium sandboxing, verify the renderer before any target navigation, and report the measured result instead of hardcoding sandbox-enabled state.
- Added `core/investigators/chromium_sandbox_status.js`; the supervisor accepts a live result only when the report and verifier both say `VERIFIED`, otherwise the job is failed and its sandbox flag is false.
- Added deterministic security-gate coverage for verified/unverified evidence, renderer crash/missing process, pre-navigation gating, launch failure reporting, and timeout/cancellation/child cleanup paths. Mode A's URL-only regression test remains in the suite.
- Updated the opt-in Docker integration assertions to require a `VERIFIED` live worker result. The integration probe was not executable because Docker was unavailable.

## Validation

- `node --check` passed for the verifier, worker, probe, status helper, and supervisor.
- Targeted deterministic tests passed: **4 passed, 0 failed** for verifier acceptance/rejection, diagnostic failure, pre-navigation gate, and bounded DOM extraction. (The added cleanup-source assertion is to be rerun with the final targeted command.)
- `git diff --check` passed before the final test addition; rerun after this report.
- Docker integration / live Chromium verification: **not run**, Docker Desktop engine pipe unavailable.
- No public websites were visited.

## Follow-up attempt: 2026-10-31

Commands run from the repository root:

```text
git status --short --branch
git diff --check
git diff --stat
git branch --show-current
docker info
```

The branch remained `docker-modec-work`. The status/diff showed the pre-existing modified and untracked work, including screenshot artifacts; none were altered by this follow-up. `git diff --check` completed without reporting whitespace errors.

Docker was unavailable. `docker info` selected context `default`, printed a warning that `C:\Users\akhil\.docker\config.json` was inaccessible, then failed to connect to `//./docker_engine` because the named pipe does not exist. Since no Linux engine is reachable, work stopped here as requested. The opt-in integration command was **not run**; no image build, worker launch, `/proc` inspection, full Node suite, or public-site request was attempted.

**Phase 1 remains blocked; Mode C must remain disabled.** The live verifier has not been shown to reject stale or malformed process snapshots in a running worker, and no fresh live evidence exists for the browser/renderer security properties. The immediate blocker is an available Docker Desktop Linux engine (and access to its configured Docker client context). After that is restored, rerun the documented opt-in integration test; only proceed to the full test suite if live sandbox verification succeeds.

## Follow-up attempt: 2026-10-31 (integration review)

Read this report, `tests/docker_proxy_connectivity.test.js`, `worker/chromium_sandbox_verifier.js`, and `worker/chromium_sandbox_probe.js` before execution. The integration test's browser navigation target is loopback (`127.0.0.1`) and its sandbox probe only loads a local fixture / `chrome://sandbox`. However, its egress-control check also attempts a direct TCP connection to public IP `1.1.1.1:443` to assert that direct egress is blocked. Under the stated stop condition, the integration test was not run pending user direction on that public-IP probe. No public website was visited.

Commands run:

```text
docker context show
docker version
docker context ls
docker --context desktop-linux info
```

This shell reported active context `default`, not `desktop-linux`. Docker CLI access to the default daemon failed on `//./pipe/docker_engine` (`Access is denied`). The explicitly selected `desktop-linux` query also failed before contacting an engine because the CLI could not read `C:\Users\akhil\.docker\contexts\meta\...\meta.json` (`Access is denied`); `docker context ls` could not read the same Docker config/context metadata. No context was changed. The user's stated successful Docker server state could not be independently observed from this process.

The opt-in command remains **not run**. Consequently there is no current live worker or renderer evidence, and no full Node suite was run. The earlier targeted test result remains historical only. Mode C stays disabled and Phase 1 is incomplete. To proceed, the Docker context must be accessible in this environment and the public-IP egress probe must be authorized or replaced by an approved local-only check; neither issue was bypassed here.

## Next step from initial audit (superseded)

Start Docker Desktop's Linux engine, rebuild the worker image from this checkout, and run the opt-in local integration test: `TRUSTLAYER_DOCKER_INTEGRATION=1 node --test tests/docker_proxy_connectivity.test.js`. Permit Mode C only if the integration output reports `VERIFIED`; otherwise keep it refused and use the recorded failure codes to identify the missing runtime prerequisite. No Phase Two work is included here.

## Final execution record — 2026-10-31

### Preservation and preflight

- Confirmed branch `docker-modec-work`; inspected `git status`, existing diff summary, this report, the integration test, worker verifier, and probe before test execution. Existing modified files, untracked artifacts, and screenshots were preserved.
- The initial shell invocation could not read Docker's user context metadata. After explicit approval to access Docker, commands selected `desktop-linux` through the process-local `DOCKER_CONTEXT` environment variable; the global Docker context was not changed.
- Docker server: Engine `28.5.1`, Docker Desktop on WSL2 kernel `6.6.87.2-microsoft-standard-WSL2`.
- Confirmed `trustlayer-isolated-net` is `bridge true` (internal) and `trustlayer-egress-net` is `bridge false` (external).
- Source review found `.dockerignore` excluded new runtime imports (`chromium_sandbox_verifier.js`, `chromium_sandbox_probe.js`, `url_redaction.js`, and `worker_result_status.js`). Added only these required build-context allowlist entries and a regression assertion. A rebuilt image was checked to contain the verifier and imports.

### Local-only integration and live evidence

The integration test previously attempted a public `1.1.1.1:443` TCP connection. That probe was removed. The test now explicitly asserts the browser network is Docker-internal and tests the proxy only against a loopback URL rejected by SSRF policy. Its title and assertions state that external direct egress is not tested. No public website or public IP was contacted by this integration test.

Commands completed:

```text
$env:DOCKER_CONTEXT='desktop-linux'; docker build -t trustlayer-worker:latest -f worker/Dockerfile .
$env:DOCKER_CONTEXT='desktop-linux'; $env:TRUSTLAYER_DOCKER_INTEGRATION='1'; node --test tests/docker_proxy_connectivity.test.js
```

The offline build attempt (`docker build --network=none ...`) failed at `npm ci` with `EAI_AGAIN` for `registry.npmjs.org`. The successful standard build reused the cached pinned dependency-install layer and copied the current source. This was package build activity only; no investigation target was loaded.

The final opt-in integration run passed: **1 passed, 0 failed, 0 skipped**. It checked Docker container user `pwuser` (UID/GID `1001/1001`), non-privileged/read-only container, dropped capabilities except `SYS_CHROOT`, no-new-privileges, seccomp, resource limits, internal-only browser network, loopback SSRF denial, result redaction, and screenshot artifact. The actual worker navigated only to `http://127.0.0.1/...`; the proxy denied that loopback request and the worker reported `BLOCKED`/`ACCESS_DENIED` as expected.

Live Chromium evidence from the separate local probe (Chromium `156.0.8078.4`, Playwright `1.64.1`):

- Worker UID/GID: `1001/1001`; Chromium launch requested `chromiumSandbox: true` and showed no `--no-sandbox` flag.
- Browser user/PID namespaces: `user:[4026531837]`, `pid:[4026532643]`.
- Renderer PID `87`, parent zygote PID `25`; renderer namespaces `user:[4026532789]`, `pid:[4026532716]`, distinct from the browser.
- Worker baseline seccomp filter count `2`; renderer count `3`; renderer `Seccomp=2`, `NoNewPrivs=1`.
- Renderer parent zygote was verified and did not carry `--no-zygote-sandbox`. Another zygote (PID `22`) did carry that flag, but it was not the renderer's parent.
- Each required renderer record passed freshness checks and was reread from `/proc`; `processEvidenceFresh=true`, `processEvidenceStable=true`, `filtersAddedBeyondContainer=true`, `namespacesIsolated=true`, and `parentHasZygoteSandbox=true`.
- `chrome://sandbox` returned no diagnostic text (`UNAVAILABLE`); it did not contribute affirmative evidence.

The verifier now rejects stale observations (over 10 seconds), malformed filter counts/namespaces, missing baseline/process/renderer/zygote evidence, duplicate or invalid PIDs, missing security fields, changed process evidence between reads, and any renderer failing a required check. The deterministic test suite covers verified, stale, malformed, incomplete, crash/unavailable and zygote-failure cases.

### Regression tests and completion

Commands completed:

```text
node --test
npm.cmd test
node --test --test-name-pattern="accepts only a renderer|fails sandbox verification|requires the live worker|fails closed on browser launch" tests/mode_c_security_gate.test.js
node --test --test-name-pattern="includes every file copied" tests/mode_c_security_gate.test.js
git diff --check
```

`node --test`: **125 passed, 0 failed, 2 skipped** (the opt-in Docker integration and Mode C API integration are skipped by default; the Docker integration was run separately and passed). `npm.cmd test`: **7 passed, 0 failed**. The PowerShell `npm test` shim was blocked by execution policy, so the equivalent `npm.cmd test` command was used. Targeted verifier/lifecycle checks: **4 passed**; build-context regression: **1 passed**. `git diff --check` passed after the final edits.

The Mode A core tests perform URL/DNS analysis, but Mode A did not issue HTTP requests to the named public domains. No public website was visited during this phase. The RVCE target was not contacted. Mode C is eligible to run with this pinned worker/security configuration only through the normal supervisor path, which requires a fresh `VERIFIED` result on every worker run; any missing or inconclusive check remains fail-closed. The shared Docker Desktop/WSL2 engine is not a per-job VM boundary, and this local-only run does not independently prove external egress denial. No Phase Two work was started.
