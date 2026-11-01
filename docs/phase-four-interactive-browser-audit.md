# Phase 4 - Interactive Sandbox Browser Audit

Audit date: 2026-10-31 (Asia/Calcutta)
Branch: `docker-modec-work`

## Verdict

The backend and worker protocol for bounded interactive sessions is implemented. Interactive investigations use the existing Mode C supervisor, Docker worker, authenticated egress proxy, SSRF validation, and fresh Chromium sandbox verification gate. The API refuses an interaction when no matching live worker is available. Mode A remains unchanged.

The worker side of this feature was **not live-verified** because Docker access failed in this shell. The new local API/action tests pass, but they do not prove that Docker stdin framing, Chromium actions, browser observations, or interactive screenshot transfer work end-to-end. Phase 4 should therefore be reviewed as an implementation with an outstanding Docker integration requirement, not as a fully verified live browser capability.

No public website or public target IP was contacted. The pre-existing full test suites include Mode A investigations named for public domains. Inspection of `InvestigationEngine.createCase` and its Mode A branch confirms these cases use URL analysis and hostname enrichment without issuing target HTTP requests; host DNS resolution can still occur through the configured resolver. The explicit Mode A no-network test passed.

## Architecture and API

- `POST /api/cases` accepts `interactive: true` only with `inspectionMode: ISOLATED_LIVE` and explicit consent. It starts the normal Mode C pipeline and marks the case with a bounded interactive-session state.
- `GET /api/cases/:id` returns the session state, current redacted URL, collection status, action count, limitations, and bounded event history.
- `POST /api/cases/:id/interactions` accepts one strict action at a time. The existing authenticated `POST /api/cases/:id/cancel-live` and `/cancel` endpoints stop the case/session.
- `GET /api/cases/:id/events` carries the existing SSE stream and snapshot. Interactive observations use Phase 3's version 1 `validateEvidenceEvent` contract and are stored per case in memory.
- `GET /api/cases/:id/interactive-artifacts/:artifactId` serves a validated screenshot only when the artifact ID exists in that case's in-memory ownership map. Path resolution is confined to `data/screenshots`.
- Case, action, state, SSE, and artifact routes remain behind the existing API authentication middleware. Request bodies remain under the existing 64 KiB cap.

The browser command channel is a line-delimited, supervisor-to-worker JSON protocol over the Docker CLI stdin pipe (`docker run -i`). The worker uses the existing browser and browser context; no host browser, profile, credentials, cookies, filesystem, or JavaScript execution endpoint is exposed. A response frame is correlated by a random request ID. The supervisor validates every action and validates navigation again with `SSRFGuard`; the existing egress proxy independently enforces destination and redirect policy for browser traffic.

## Supported actions and limits

Actions are `navigate`, `back`, `forward`, `reload`, `scroll`, `click`, `type`, and `screenshot`.

- At most 20 actions per session, 5 screenshots, 5 seconds per action, and 120 seconds of session lifetime.
- Scroll is limited to 1-800 pixels. Selectors must match the narrow single-selector grammar in `core/interactive_action.js`. Typed text is limited to 200 printable characters.
- Clicks are limited to visible, non-form buttons with explicit `type="button"` or role buttons. Links, form controls, submit-like controls, download/permission controls, and controls with sensitive/action terms are rejected. Downloads remain disabled in the browser context and permissions are not granted.
- Typing is limited to visible standalone text/search/textarea fields outside forms. Fields whose name, ID, autocomplete, or label suggests credentials, identity, payment, OTP, or phone data are rejected. Typed content is not included in events, logs, results, or API responses.
- Each interactive screenshot is a viewport PNG bounded by the worker to 1280x800 and 5 MiB. At most five are stored per session.
- If an action times out, the supervisor stops the worker session rather than permitting a timed-out action to continue in the background.

## Events and observations

Events are validated and sequenced per investigation using the Phase 3 event schema. The bounded stream can contain investigator action accepted/rejected/started/completed/failed records, main-frame navigation commits, redirects, request starts/failures, response status and resource type, popup closure, page-state snapshots, session termination status, and screenshot evidence references.

URL paths, queries, fragments, and credentials are redacted before interactive events and action responses are stored or returned. Page-state snapshots record only title/text lengths, form count, and bounded input-type metadata. The system does not collect page text or typed values through the interactive event path. Event history is capped at 512 entries per case.

These events do not establish comprehensive network interception. Worker request/response observations are browser events for the existing page; enforcement continues to rely on the shared proxy for browser traffic and redirect revalidation. No claim is made that every browser-internal or future page's activity appears in the event timeline. Popup pages are immediately closed.

## Files changed

- `.dockerignore`: include the shared action validator in the worker build context.
- `core/interactive_action.js`: strict action schema and action/session/screenshot ceilings.
- `core/investigators/live_job_controller.js`: interactive-only stdin pipe, bounded frame parser, case-bound action dispatch, per-action timeout, and session end reporting after cleanup.
- `worker/browser_worker.js`: action loop inside the existing sandboxed browser, safe browser event capture, non-sensitive page-state metadata, download/permission safeguards, and bounded screenshot transfer.
- `core/investigation_engine.js`: route interactive cases through the isolated worker even for built-in demo hostnames; propagate worker events and lifecycle.
- `backend/server.js`: interactive case state, authenticated action/artifact APIs, validated SSE evidence events, and per-case artifact ownership.
- `tests/interactive_action.test.js`, `tests/interactive_api.test.js`: bounded action, case binding, authentication, unavailable-worker, and artifact boundary tests.

No UI, Phase 5 feature, public endpoint, or database migration was added.

## Validation

Completed:

```text
node --check backend/server.js
node --check core/investigators/live_job_controller.js
node --check core/investigation_engine.js
node --check worker/browser_worker.js
# passed

node --test tests/interactive_action.test.js tests/interactive_api.test.js tests/evidence_event.test.js tests/api_auth.test.js
# 10 passed, 0 failed, 0 skipped

node --test tests/interactive_action.test.js tests/interactive_api.test.js tests/live_job_lifecycle.test.js tests/mode_c_security_gate.test.js
# 34 passed, 0 failed, 0 skipped (final targeted regression run)

node --test
# 151 tests, 149 passed, 0 failed, 2 skipped
# skipped: opt-in local Docker integration and opt-in Mode C API smoke test

npm.cmd test
# 7 passed, 0 failed, 0 skipped

$env:TRUSTLAYER_DOCKER_INTEGRATION='1'; node --test tests/docker_proxy_connectivity.test.js
# 1 failed before test setup: Docker could not inspect trustlayer-isolated-net
# Docker config C:\Users\akhil\.docker\config.json and default Windows pipe access were denied.

docker --context desktop-linux version --format '{{.Server.Version}}'
# failed: Access is denied reading the Docker config and desktop-linux context metadata.
```

The opt-in Docker test was inspected before invocation. Its explicit targets are the internal proxy and loopback; it contains no public URL/IP target. It failed on its first `docker network inspect`, so no worker or Chromium process was started. Live integration, action execution, fresh sandbox evidence for the modified worker image, and live screenshot transfer are unverified. No context was changed and no Docker bypass was attempted.

`git diff --check` and a trailing-whitespace scan of added files are recorded after this report is written.

## Live verification recovery attempt - 2026-10-31

### Docker diagnosis

- Docker Desktop and `com.docker.backend` processes were present, but the engine was not accessible from this shell; process presence does not establish engine readiness.
- `docker context show` returned `default`. No `DOCKER_*` environment overrides were present.
- The Docker CLI warned that it could not read `C:\Users\akhil\.docker\config.json` (`Access is denied`). `docker context ls` and `docker context inspect desktop-linux` could not read context metadata under `C:\Users\akhil\.docker\contexts\meta` (`Access is denied`).
- `docker --context desktop-linux version --format '{{.Server.Version}}'` failed while reading the `desktop-linux` context metadata.
- `docker version --format '{{.Server.Version}}'` attempted the default Windows endpoint `//./pipe/docker_engine` and failed with `Access is denied`. `Test-Path \\.\pipe\docker_engine` also returned an access-denied error.
- The integration test calls `docker` without `--context`, so it uses the shell's `default` context. It does not select `desktop-linux` itself.

Safe recovery: run verification in the existing PowerShell environment and Windows user session that already has authorized Docker Desktop access. Confirm `docker --context desktop-linux version` succeeds there. Since the integration test uses bare `docker` commands, set the process-scoped `$env:DOCKER_CONTEXT='desktop-linux'` in that PowerShell before invoking the test. This does not change the stored Docker context. Do not change ACLs, elevate, or bypass the pipe restriction.

### Test suitability and execution

`tests/docker_proxy_connectivity.test.js` was inspected. It targets the internal Docker proxy and literal `127.0.0.1`; there are no public hostnames, public IPs, or public DNS lookups in that test. The loopback target is expected to be denied by SSRF policy. It is not a purpose-built successful local page fixture and it does not exercise the interactive API/action protocol. Its assertions cover worker sandbox/proxy behavior and a rendered denial result, not the requested ten-step interactive workflow. No safe end-to-end interactive Docker test currently exists. The opt-in API smoke test defaults to `https://www.google.com` and must not be enabled for this verification.

Docker was unavailable, so the opt-in integration was not run in this recovery attempt. No browser or proxy containers started. The earlier recorded integration attempt failed at `docker network inspect trustlayer-isolated-net` with the same config/engine access denial.

Safe local tests run in this recovery attempt:

```text
node --test tests/interactive_action.test.js tests/interactive_api.test.js tests/evidence_event.test.js tests/api_auth.test.js tests/live_job_lifecycle.test.js
# 19 passed, 0 failed, 0 skipped

git diff --check
# passed
```

`node --test` and `npm.cmd test` were not rerun in this recovery attempt. Their existing core investigation tests use public hostnames and invoke `dns.lookup`; rerunning them here would make public DNS requests, which this verification explicitly forbids. The previous Phase 4 run recorded 151 tests (149 passed, 0 failed, 2 skipped) and `npm.cmd test` (7 passed, 0 failed, 0 skipped); those prior counts are not results of this recovery attempt.

No real worker/Chromium run, interaction, page-state change, live event delivery, screenshot transfer, cross-investigation artifact/event isolation, cancellation cleanup, or repeated-job isolation was verified in this attempt. Those remain unverified pending an authorized shell with working Docker access and a new local-fixture interactive integration test.

## Limitations and follow-up

1. Worker command framing, actual Playwright interactions, response correlation under Docker, and repeated interactive screenshot transfer need opt-in local Docker integration against a purpose-built local fixture before Phase 4 can be considered live-verified.
2. Existing Mode C cleanup diagnostics remain authoritative. The interactive session state reports cleanup failure when the supervisor reports one, but this turn did not execute live Docker cleanup paths.
3. Case state, event timelines, sessions, and interactive artifact ownership are process-local. After server restart the event history and interactive screenshot ownership map are unavailable; artifacts may remain as confined orphan files. No durable event store or startup orphan cleanup is implemented.
4. Single-operator authentication remains the Phase 3 model; it does not provide separate user/tenant ownership.
5. The existing external direct-egress limitation remains unverified. This phase makes no claim that arbitrary external egress is blocked beyond the configured proxy/network boundary.

Phase 4 stops here. No UI, campaign analysis, evidence graph, or deployment work was started.

## Case-authorization regression audit - 2026-10-31

### Review findings and change

The review confirmed case credentials are generated with `crypto.randomBytes(32)`, returned only on authenticated case creation, and retained as a SHA-256 verifier. Verification validates the 43-character base64url format, hashes the presented credential, and compares equal-length digest buffers with `timingSafeEqual`. Missing, malformed, incorrect, and cross-case credentials fail closed with the same unavailable/not-found response. The token is not stored in case schema/logs/events, not included in worker arguments, and is not sent to the inspected browser through the worker protocol. The UI uses same-origin API URLs; its `fetch`, `EventSource`, and screenshot loads use the HttpOnly case cookie. Direct API clients use `X-TrustLayer-Case-Access`.

The audit found that the cookie advertised an eight-hour lifetime but server-side case authorization did not expire a copied header credential. This is fixed: cases now hold an expiration timestamp alongside the verifier, and `hasCaseAccess` rejects missing, malformed, or expired timestamps before checking the credential. The lifetime matches the existing eight-hour session/cookie lifetime. Deterministic tests cover expiry, unknown/post-restart IDs, case-list filtering, and Case A's credential against Case B's live-inspection route.

All case-specific routes were reviewed: case listing is operator-authenticated and filters each summary by its case credential; case detail, SSE, live inspection, interactions, both cancellation routes, standard screenshots, and interactive artifacts require the matching credential. Unknown in-memory cases, including IDs after process restart, return unavailable/not-found and cannot use orphaned screenshot files as authorization. Existing in-memory objects lacking the verifier or expiry fail closed. No privileged case-data listing bypass was found.

Cookie and header authentication are consistently combined with operator authentication. Cookie-authenticated state-changing requests require an exact same-origin `Origin`; the cookie is `HttpOnly`, `SameSite=Strict`, scoped to `/api`, and expires after eight hours. Explicit bearer-authenticated requests are not ambient browser credentials and do not use the cookie CSRF path. No CORS middleware is configured. The frontend uses same-origin routes. SSE checks authorization at connection establishment, has a bounded lifetime, and removes per-case and global listeners on disconnect. Existing direct API clients must retain the one-time creation token and send the case header; losing it requires creating another case. Logout expires presented case cookies.

Mode A remains on the existing investigation pipeline and is covered by a local literal-loopback fixture test with no target HTTP request or public DNS lookup. The fresh Mode C `VERIFIED` requirement remains enforced before navigation; selected verifier/refusal tests passed. The final Mode A public-hostname test in `tests/mode_c_security_gate.test.js` was deliberately excluded. The earlier interrupted full-file run and its potential DNS/DoH activity are recorded above; this audit did not repeat it.

### Deterministic regression validation

Commands run:

```powershell
node --test tests/case_access.test.js tests/api_auth.test.js tests/interactive_api.test.js tests/evidence_event.test.js tests/interactive_action.test.js
# 13 passed, 0 failed, 0 skipped

node --test --test-name-pattern='strictly refuses live inspection when container runtime is unavailable|requires the live worker to verify sandbox state before target navigation|accepts only a renderer with namespace isolation and an additional Chromium seccomp filter' tests/mode_c_security_gate.test.js
# 3 passed, 0 failed, 0 skipped; public-hostname Mode A test excluded

node --check backend/server.js
node --check core/case_access.js
node --check tests/case_access.test.js
node --check tests/api_auth.test.js
node --check tests/interactive_api.test.js
# all syntax checks passed

git diff --check
# passed
```

The authorization tests use only loopback HTTP servers and literal loopback targets. They assert missing operator authentication, missing/incorrect/correct credentials, cross-case access denial (including live inspection), list filtering, expired and unknown case refusal, cookie authentication, CSRF Origin rejection, SSE authorization/disconnect cleanup, interaction/screenshot/artifact/cancellation authorization, credential redaction, verifier-only storage, and no credential in pipeline arguments. No public target, public DNS lookup, Docker test, or Google-targeted smoke test was run for this audit. Full `node --test`, `npm.cmd test`, and the complete Mode C security-gate file remain unrun here because their existing tests can issue public DNS/network requests.

### Residual limitations

Case records, expiry metadata, event history, sessions, and interactive artifact ownership remain process-local; after restart cases are unavailable and any leftover artifact is not retrievable through the API. This is safe failure but not durable recovery. The installation still has one shared operator identity. The tests establish code-level non-forwarding and local API authorization; they do not perform live browser/Docker verification. Phase 4 interactive Docker workflow and external egress remain unverified.

## Local-fixture interactive integration implementation - 2026-10-31

### Fixture arrangement and security boundary

Added an opt-in test-only fixture policy. The integration test creates a deterministic HTTP fixture container attached only to `trustlayer-isolated-net`, with a generated `trustlayer-fixture-<nonce>.test` alias and one inspected RFC1918 address on port 8080. It builds a derivative worker image from the already-present `trustlayer-worker:latest` image using `docker build --network=none`; it does not pull a base image or install packages. The existing production image tag is not changed.

The supervisor's explicit `configureLocalFixtureForTests` hook refuses configuration unless `NODE_ENV=test`. It pins the exact generated hostname/address/port and, while configured, rejects every other destination before DNS. The fixture runs only on a generated internal Docker network separate from the worker network. The proxy joins both internal networks; the browser joins only `trustlayer-isolated-net`, so it cannot connect directly to the fixture. In this mode the controller does not connect the proxy to the production outbound `trustlayer-egress-net`. The test proxy receives the tuple only through supervisor-generated container arguments, requires `NODE_ENV=test`, and becomes allowlist-only: it accepts only the exact HTTP origin and rejects CONNECT, wrong ports, direct IPs, and every other host before DNS. The worker page cannot configure or widen the policy. Existing production calls use the unchanged SSRF/DNS validation path when no test policy is configured. Redirects are separate proxy requests; a local deterministic proxy test follows a fixture 302 to loopback and verifies that the redirect destination is denied.

The Mode C engine starts DNS enrichment asynchronously. The opt-in test substitutes deterministic DNS enrichment only for its generated fixture hostname; other names retain the normal resolver. Its fixture page has no external resources or links. The worker and proxy receive no operator or case credentials. The test image preserves the existing non-root worker, seccomp profile, Chromium sandbox, resource limits, tmpfs output quota, and authenticated proxy path.

### Implemented versus verified

- **Implemented:** `tests/docker_interactive_fixture.test.js` exercises real API case creation and credentials, the global supervisor, authenticated proxy container, isolated browser worker, and Chromium. It asserts fresh `VERIFIED` renderer evidence, local navigation, text entry, click-driven page-state metadata change, validated event delivery over authenticated SSE, screenshot capture and case-scoped API retrieval, cross-case denials for SSE/interactions/artifacts, unsafe loopback rejection, cancellation, container/temp-directory/job-reservation cleanup, and a second case with distinct events and screenshot bytes. Test cleanup attempts all tracked container, event-stream, artifact, and job cleanup operations even after assertions fail.
- **Locally tested:** the fixture policy and proxy behavior were run only against loopback using a local HTTP fixture; ordinary SSRFGuard loopback rejection remains intact. No Docker or public network was used.
- **Docker-tested:** no new end-to-end Docker assertions have yet run. The Codex shell does not have Docker access; this turn did not invoke Docker.
- **Still unverified:** real Chromium startup, fresh live sandbox evidence in the derived test image, browser actions, API SSE/artifact delivery, Docker cleanup and repeated-job isolation. External egress is not tested or claimed blocked.

### Safe local validation run

```powershell
node --test tests/local_fixture_policy.test.js tests/evidence_event.test.js tests/interactive_action.test.js
# 9 passed, 0 failed, 0 skipped

node --check core/investigators/test_local_fixture.js
node --check core/investigators/live_job_controller.js
node --check core/investigators/live_inspector.js
node --check core/investigators/egress_proxy.js
node --check worker/egress_proxy_worker.js
node --check tests/local_fixture_policy.test.js
node --check tests/docker_interactive_fixture.test.js
# all syntax checks passed

git diff --check
# passed
```

### Commands for the authorized Docker PowerShell session

Run these from the repository root in the PowerShell session where Docker Desktop's Linux engine is already accessible. They use only local Docker networking and fixtures; the first test builds its test image with build networking disabled.

```powershell
$env:DOCKER_CONTEXT = 'desktop-linux'
$env:NODE_ENV = 'test'
$env:TRUSTLAYER_DOCKER_INTERACTIVE_FIXTURE = '1'
node --test tests/docker_interactive_fixture.test.js

$env:TRUSTLAYER_DOCKER_INTEGRATION = '1'
node --test tests/docker_proxy_connectivity.test.js
```

The interactive test requires the existing `trustlayer-worker:latest` image and the documented `trustlayer-isolated-net` network. It asserts those local prerequisites before launching the fixture. `docker_proxy_connectivity.test.js` remains the separate baseline. The Google-default API smoke test and all public-hostname/DNS suites remain excluded. Record actual Docker context, test counts, whether Chromium started, and cleanup outcomes after these commands complete; until then, Phase 4 remains incomplete.

## End-to-end integration completion attempt - 2026-10-31

### Docker access check

Commands run in this PowerShell process:

```powershell
docker version --format 'client={{.Client.Version}} server={{.Server.Version}}'
docker context show
docker --context desktop-linux version --format 'client={{.Client.Version}} server={{.Server.Version}}'
```

The shell could not read `C:\Users\akhil\.docker\config.json` or `desktop-linux` context metadata (Access is denied). `docker context show` reported `default`; the `desktop-linux` version command failed before connecting to the engine. The earlier safe endpoint probe also returned Access Denied for `\\.\pipe\docker_engine`. Docker Desktop/backend processes being present is not evidence that this shell can use the engine. No configuration, permissions, context, or security settings were changed.

### Integration test and network review

Inspected `docs/phase-four-interactive-browser-audit.md`, `tests/docker_proxy_connectivity.test.js`, `tests/mode_c_api_smoke.test.js`, and `core/investigators/ssrf_guard.js`.

`tests/docker_proxy_connectivity.test.js` uses the internal proxy and literal loopback target `http://127.0.0.1/...`; it checks that SSRF policy blocks the target and does not provide a successful local fixture workflow. It therefore does not assert authenticated fixture investigation creation, permitted navigation/action, observable page mutation, event delivery, authorized screenshot API retrieval, cross-investigation denial, or repeated-job isolation. A successful fixture route cannot be added safely by merely allowing loopback in production SSRF rules. No integration-test code was changed in this attempt.

`tests/mode_c_api_smoke.test.js` defaults to Google and was not enabled. The core/golden investigation tests include public hostnames whose enrichment path invokes `dns.lookup`; neither public DNS nor public HTTP was used in this attempt.

The opt-in Docker test was not run because Docker is inaccessible from this process. Consequently, no test worker, proxy container, or Chromium process was started and no live workflow step was verified. Safe recovery is to run from the already-authorized PowerShell user session where `docker --context desktop-linux version` succeeds, then set process-local `$env:DOCKER_CONTEXT='desktop-linux'` for tests that invoke bare `docker`. This recommendation does not alter persistent Docker configuration.

### Tests actually run

```powershell
node --test tests/interactive_action.test.js tests/interactive_api.test.js tests/evidence_event.test.js tests/api_auth.test.js tests/live_job_lifecycle.test.js
# 19 passed, 0 failed, 0 skipped

git diff --check
# passed
```

Not run: opt-in Docker integration (Docker endpoint/config access denied); `node --test` and `npm.cmd test` (their core/golden tests perform public DNS lookups, disallowed for this task). These are not counted as passes. The full-suite counts recorded in earlier audit entries are historical and do not represent this attempt.

### Verdict

Phase 4 end-to-end live verification remains incomplete. No authenticated local-fixture browser session, fresh live sandbox gate, Chromium startup, navigation/action/page mutation, browser event stream, API screenshot retrieval, cross-investigation denial, prohibited-navigation live rejection, container/artifact cleanup, or second-job stale-state check was evidenced in this attempt. The targeted deterministic local tests passed, but they do not substitute for the requested Docker workflow. No claim is made that the actual interactive workflow succeeded.

## Case-scoped authorization update - 2026-10-31

### Authorization model

Operator authentication remains the existing API bearer token or authenticated same-site session cookie. Case permission is now a separate 256-bit random credential issued only after operator-authenticated `POST /api/cases` succeeds. The response returns `caseAccessToken` once and sets a browser cookie with `HttpOnly`, `SameSite=Strict`, `Path=/api`, and the existing eight-hour session lifetime. Direct API clients send the value in `X-TrustLayer-Case-Access`; browser fetch, EventSource, and screenshot requests carry the cookie automatically. The credential is never accepted in the URL, query, or request body.

The case object retains only a SHA-256 verifier. Verification checks token shape and compares fixed-size digest buffers with `timingSafeEqual`. Invalid, absent, or mismatched case credentials produce the same not-found response after operator authentication. A case credential for one ID cannot authorize another ID. `GET /api/cases` returns only case summaries for which the request has a matching credential; case-specific read, event, screenshot, interaction, live-inspection, artifact, and cancellation routes all check the matching case credential. Logout expires the known case cookies.

The credential is not inserted into the case schema, target URL, event data, logs, worker options, Docker arguments, or browser requests. The supervisor continues to use internal case IDs and receives no credential. Mode C's fresh sandbox verification remains unchanged and required.

### Compatibility and recovery behavior

- Browser clients created by this server retain the credential in an HttpOnly API cookie; no UI URL or EventSource change is required.
- Direct API clients must save the one-time creation response token and supply `X-TrustLayer-Case-Access` on later case requests. Losing that token requires creating a new case; there is no token-retrieval endpoint.
- Existing in-memory case objects without `_caseAccessVerifier` fail closed. The current case store is process-local, so a server restart drops the cases and their credentials; old screenshots may remain as orphaned files but cannot be served through an unknown case route.
- `/api/cases` is not an unscoped administrative data bypass. It filters summaries by presented case credentials.

### Deterministic tests run

```powershell
node --test tests/case_access.test.js tests/api_auth.test.js tests/interactive_api.test.js tests/evidence_event.test.js tests/interactive_action.test.js
# 13 passed, 0 failed, 0 skipped

node --test --test-name-pattern='requires the live worker to verify sandbox state before target navigation|accepts only a renderer with namespace isolation and an additional Chromium seccomp filter' tests/mode_c_security_gate.test.js
# 2 passed, 0 failed, 0 skipped

git diff --check
# result recorded after this audit update
```

The new API tests use only `127.0.0.1` for their HTTP test server and target, and run the actual Mode A analysis path for that literal IP (which takes the direct-IP DNS fast path and makes no target HTTP request). They assert missing/wrong/correct credentials, Case A credential against Case B, SSE disconnect cleanup, interaction/screenshot/artifact/cancellation authorization, redaction, verifier-only storage, and that the pipeline receives no raw credential. The selected Mode C tests assert fresh VERIFIED renderer evidence is still required before navigation. Docker integration was not run in this authorization task.

One broader command was started and interrupted:

```powershell
node --test tests/mode_c_security_gate.test.js
# all tests through the screenshot-path check printed as passing; process remained active in the final Mode A test and was interrupted.
```

That file's final Mode A test uses `http://hdfc-netbanking-verify.xyz/`. The run was stopped after recognizing this public hostname. The test can issue system DNS queries and Cloudflare DNS-over-HTTPS fallback requests; whether any resolver or DoH traffic escaped before interruption is unknown. This incomplete run is not counted as a pass, and no claim is made that this attempt avoided all public DNS or network activity. The filtered Mode C command above avoids executing that Mode A test. No public website HTTP request or Docker integration was intentionally run.

### Remaining Phase 4 verification blockers

Live local-fixture interactive workflow verification remains outstanding. This task did not add a test-only SSRF exception and did not contact Docker. External egress remains unverified. The operator credential is still shared across the single-operator installation; the new random case credential narrows access to each investigation but does not add multi-user identities or durable case recovery.

## Local-fixture Docker readiness failure - 2026-10-31

### Reported live result

The Docker-enabled PowerShell run of `node --test tests/docker_interactive_fixture.test.js` failed with `fixture server readiness timed out` after approximately 15.6 seconds. Afterward, `docker --context desktop-linux ps -a` showed no containers, and `docker network ls` showed the two persistent Trust Layer networks but no generated fixture network. No container ID was supplied to `docker logs`; the literal PowerShell input `docker logs <CONTAINER_ID>` produced a parser error. No fixture logs or live container state were obtained from that attempt.

The post-run absence of the fixture container and generated network does not establish whether startup failed: the test's `finally` block always attempts to remove both and then checks that they are gone. The live cause remains undetermined.

### Code trace and diagnostic change

Before the timeout, the test builds `trustlayer-worker:phase4-fixture-test` from the existing local worker image with `docker build --network=none`, creates a generated `bridge --internal` fixture network, then starts a non-root fixture container (`pwuser`) on only that network. It launches the inherited worker image's Node runtime with an inline HTTP fixture listening on port 8080, with a read-only root filesystem, bounded `/tmp`, dropped capabilities, no-new-privileges, a PID limit, a 32 MiB memory limit, and a 0.25 CPU limit. Readiness is checked by running a Node HTTP request to `127.0.0.1:8080` inside the fixture container. Each failed `docker exec` probe is currently caught and retried until the 10-second readiness deadline; the outer `finally` then removes the fixture resources.

On readiness failure the test now emits a bounded diagnostic before entering cleanup: the returned container ID, selected container state including exit code and OOM status, network names/IPs/aliases, the exact in-container readiness target, and at most the last 4,000 characters of the fixture's last 60 log lines. The fixture receives no operator, case, or proxy credentials and does not log requests. Diagnostic strings redact common credential-shaped fields; no full container configuration or environment is dumped. Diagnostics are best-effort and do not replace or skip cleanup.

The code confirms that readiness probe errors were suppressed and that cleanup removes the evidence. It does not prove a specific startup cause. For example, a resource-limit termination, invalid runtime invocation, or other container startup error cannot be distinguished without the requested state/log evidence.

### Validation and status

No Docker command was run from the Codex shell. The reported live test is a failure, not a pass; Chromium startup and all workflow assertions after fixture readiness remain unverified. The user's post-run container/network listing is consistent with the unconditional `finally` cleanup and is not evidence that a fixture container was never created. No public network access was added and production SSRF/proxy rules were not changed for this diagnostic improvement.

Safe checks run in this shell:

```powershell
node --check tests/docker_interactive_fixture.test.js
# passed
node --test tests/local_fixture_policy.test.js
# 2 passed, 0 failed, 0 skipped
git diff --check
# passed
```

The Docker integration and public-network-dependent suites were not run here. Phase 4 remains incomplete.

## Fixture readiness follow-up - 2026-10-31

### Reported second live failure

The Docker-enabled run again timed out at fixture readiness after approximately 15 seconds. The reported diagnostic showed the fixture container running at `172.20.0.2`, an intended readiness target of `http://127.0.0.1:8080/` from inside that container, and empty container logs. No live Docker commands were run from the Codex shell.

### Entrypoint, bind, probe, and address agreement

`worker/Dockerfile.local-fixture-test` inherits `trustlayer-worker:latest` and does not declare a new entrypoint. The base `worker/Dockerfile` declares `ENTRYPOINT ["node", "worker/browser_worker.js"]`, but the fixture test's `docker run` explicitly overrides it with `--entrypoint node` and supplies `-e <fixtureScript()>`. Therefore, the actual fixture process is `node -e <inline HTTP server script>`, running as `pwuser`; it does not start `browser_worker.js`. The script binds `0.0.0.0:8080`.

The old readiness probe ran `docker exec <fixture> node -e <HTTP request>`: it ran inside the fixture container, not on the host. Thus a second Node process was started under the fixture container's 32 MiB memory limit. Given the reported still-running server process and empty logs, pressure from this additional Node process is a plausible cause of the probe failing, but no reported OOM state or probe stderr proves it. The server previously wrote nothing to stdout/stderr; `-d` does not suppress container logs, but an intentionally silent server naturally produced empty logs.

The generated `fixtureHost` is used as the Docker `--network-alias`, the URL hostname, and the exact test fixture policy hostname. `fixturePort` is 8080 in the server, URL, supervisor policy, and proxy CLI policy. The supervisor pins the fixture address/port, and the proxy is attached to the generated fixture network in addition to `trustlayer-isolated-net`; proxy validation still permits only the exact pinned hostname and port. The network alias is now asserted from container network metadata.

### Fix and verification status

The readiness probe no longer starts a second Node process. The fixture server now writes `TRUSTLAYER_FIXTURE_READY` only after Node reports the `0.0.0.0:8080` listen succeeded; readiness polls only that fixture log marker. This avoids competing with the server for the 32 MiB limit. It does not change the resource limit or destination policy. The authenticated API workflow still supplies the end-to-end HTTP response check after startup. Diagnostics continue to print before cleanup on marker timeout.

No live run has verified this fix. Root cause remains a supported hypothesis rather than a confirmed finding. The Docker integration and browser workflow remain failed/unverified; Phase 4 is incomplete.

## Interactive worker readiness failure follow-up - 2026-10-31

### Reported live result and diagnosis

The latest Docker-enabled run reported `investigation TL-2026-1031-1704-09F5FB37C02D worker readiness timed out (interactive worker failed before readiness)` after approximately 98 seconds. This message alone does not establish whether a worker container was created, its exit/OOM state, or whether failure occurred during proxy startup/authentication, Chromium launch/sandbox verification, or fixture navigation. No corresponding live container logs or exit status were supplied, and Docker was not invoked from the Codex shell.

A code-confirmed delay bug explains the approximately 98-second wait: `waitReady()` detected FAILED and threw, but the shared `waitFor()` catches predicate errors and retries them until its default 90-second deadline. It then reported its own timeout with the saved failure in parentheses. `waitReady()` now returns a terminal failure outcome from the predicate and throws immediately outside `waitFor()`. This corrects the reporting delay; it does not infer or fix the underlying worker failure.

### Diagnostics added before teardown

In the explicit test-only fixture configuration, the controller now invokes a bounded diagnostics callback before cleanup for failed/timed-out browser jobs and startup failures. The integration test reports each worker, proxy, and fixture container's inspectable ID, status, running state, exit code, OOM flag, bounded network names/IPs/aliases, and bounded log excerpt. Worker logs are filtered to the worker failure marker so browser event payloads/page observations are not dumped; proxy logs are filtered to startup/error markers. Common credentials, bearer values, URL credentials, and secret-like query parameters are redacted. The callback is best-effort and cleanup still runs if diagnostics fail.

When available before cleanup, the report also includes a bounded proxy-observation summary with destination host, pinned target IP, response status, and blocked reason/type. It omits request URLs and headers. This will show whether the proxy recorded a fixture request to the pinned fixture IP; absence of an allowed-request record does not by itself prove a DNS failure.

The source confirms the supervisor config pins the exact fixture hostname/address/port and the proxy uses that pinned address for the outbound socket, rather than resolving an arbitrary fixture target. `DNSReconInvestigator.resolve` is deterministically mapped to the fixture address in the test. This establishes the intended policy path, not that the failed live run reached it. The test still uses a dedicated internal fixture network and the proxy's exact-origin allowlist.

The pre-cleanup snapshot also includes a compact worker result status/error, HTTP status, sandbox verification verdict/failure codes, and bounded network-failure summaries with URLs omitted. This should distinguish an explicit sandbox-verification failure or a recorded navigation/proxy network error where the worker result contains that evidence. Proxy authentication rejection is not currently recorded as a proxy observation, so it may remain unresolved if no corresponding worker failure detail or request record exists.

### Validation and remaining status

No Docker command was run here. The latest live run remains failed, and whether its worker was created or whether sandbox verification, proxy authentication, or navigation failed remains unverified pending the new diagnostics. Phase 4 is incomplete.

## Egress proxy startup failure investigation - 2026-10-31

### Reported live evidence

The latest local-only Docker attempt reported the proxy container exited with code 2, `oomKilled=false`, and empty logs. It was attached to `trustlayer-isolated-net` and the generated internal fixture network. The fixture was running with its generated hostname alias at `172.20.0.2`. No worker container was observed and Chromium readiness was not reached.

### Confirmed configuration mismatch

The controller starts the proxy with `--entrypoint node trustlayer-worker:phase4-fixture-test worker/egress_proxy_worker.js ...`, credentials, output path, `NODE_ENV=test`, and test fixture hostname/address/port. The proxy is then attached to the generated fixture network. The baseline connectivity test uses the same Node entrypoint and proxy worker script against `trustlayer-worker:latest`, but without the test-only fixture policy arguments/environment; it starts a production-policy proxy and then probes it from a worker on `trustlayer-isolated-net`.

The test proxy's `normalizeTestLocalFixturePolicy()` requires `networkName` as well as hostname, private address, and port. The controller previously passed the first three fixture values but omitted the network name. The proxy worker then passed an object without `networkName` to that normalizer, which deterministically throws; the worker's invalid-fixture-configuration branch exits with code 2. This matches the reported exit status. The fixture host/IP/port themselves match the policy formats; the omitted required network field is the confirmed defect.

The proxy worker wrote a generic rejection message to stderr and immediately called `process.exit(2)`. Immediate exit can truncate buffered stderr, explaining the empty Docker log despite that code path attempting to report an error. Startup rejection now writes the generic message and waits for the stderr write callback before exiting. No credentials are included in these messages.

### Fix and regression test

The controller now passes `--test-fixture-network=<generated internal network>` with the existing fixture tuple. The proxy worker requires all four fixture arguments and validates the complete tuple before constructing the proxy. This preserves the exact-origin test allowlist and the separate internal networks. The test-only failure diagnostics also retain generic proxy configuration rejection messages.

Added `tests/egress_proxy_startup.test.js`, a local subprocess regression that omits the required network field, asserts exit code 2 and the flushed generic diagnostic, and verifies username/password values do not appear. It makes no network connection. The normalizer's existing local tests cover valid fixture-policy tuples.

### Validation and remaining status

No Docker command was run in the Codex shell. The reported proxy failure is explained by the missing network argument, and the source-level fix is in place; the live end-to-end workflow has not yet been rerun. Chromium was not reached in the reported run. Phase 4 remains incomplete.

## Phase 4 final local Docker integration audit - 2026-10-31

### Reported Docker results

The operator reported these completed runs from the Docker-enabled PowerShell session; they were not rerun from the Codex shell:

| Command | Reported result | Scope |
| --- | --- | --- |
| `node --test tests/docker_interactive_fixture.test.js` | 1 passed, 0 failed, 0 skipped; approximately 222.7 seconds | Full local-fixture interactive API/supervisor/proxy/worker workflow |
| `node --test tests/docker_proxy_connectivity.test.js` | 1 passed, 0 failed, 0 skipped; approximately 22.1 seconds | Local-only proxy, browser sandbox, bounded output, cleanup and repeat-worker checks |

The operator reported the live verifier as `VERIFIED`, with fresh/stable renderer evidence, Seccomp mode 2, NoNewPrivs=1, an additional renderer seccomp filter, and isolated browser/renderer namespaces. The separate `chromeSandboxDiagnostic` field remained `UNAVAILABLE`; the test's project verifier passed, but the independent Chrome diagnostic is not claimed as successful. Both tests explicitly avoid using these results to claim external egress blocking.

### Assertion-to-behavior review

`tests/docker_interactive_fixture.test.js` asserts:

- Authenticated case creation returns 201 and a case credential of the expected shape.
- The actual live inspection returns `VERIFIED`, HTTP 200, the fixture's final URL, and an active interactive runtime. It asserts the worker and proxy containers are running and that only the proxy joins both the fixture and isolated worker networks.
- Typing succeeds; clicking the fixture button succeeds; subsequent DOM telemetry has a greater visible-text length. The test validates event schema and receives an authenticated SSE `evidence_event` scoped to the case. The state-change check is an observed length increase rather than an assertion over the exact rendered label text.
- A worker screenshot action returns an artifact ID; the authorized API returns bounded PNG bytes with the PNG signature.
- Case A's credential is denied for Case B's events, artifact, and interaction routes (404).
- A loopback target is classified BLOCKED and the investigation remains incomplete.
- Both interactive jobs are cancelled; job reservations are released; browser/proxy containers and supervisor temp directories are absent. The finalizer checks fixture container/network removal and removes only artifacts created by this test.
- A second investigation has a distinct job, no prior event IDs or changed-state telemetry, a different screenshot artifact ID/hash, and its own successful API artifact retrieval.

`tests/docker_proxy_connectivity.test.js` asserts:

- The authenticated proxy is reachable from the isolated worker network and returns 403 for a prohibited loopback target.
- The actual browser worker runs non-root with read-only root filesystem, the configured seccomp profile, no-new-privileges, dropped capabilities, process/memory/CPU bounds, quota-limited tmpfs output, no host bind mounts, and only the internal worker network.
- Live Chromium is present without `--no-sandbox`. The live sandbox verifier and separate probe require fresh, stable renderer evidence, additional seccomp filtering, isolated user/PID namespaces, and Seccomp=2/NoNewPrivs=1.
- Screenshot bytes are valid PNG, sensitive telemetry is redacted, quota exhaustion returns ENOSPC, and failed/terminated/repeated worker containers do not reuse stale result data.

The successful fixture navigation through a browser attached only to `trustlayer-isolated-net`, while the fixture is reachable only on its separate internal network and the authenticated proxy is the only container attached to both, demonstrates the intended local proxy path. The fixture test does not separately assert a proxy observation row matching the fixture IP; its direct assertions are the successful response, the exact-origin configuration, and the inspected network attachments.

Assertion boundaries: the page-change check compares successive `visibleTextLength` observations and does not assert the literal post-click label. The test opens the authenticated SSE stream, validates a received event against the evidence schema, then closes the reader; it does not separately inspect the server's SSE-client set after disconnect. The route's close/abort handler clears the heartbeat and removes the response from both subscriber sets, while the live test's cleanup assertions directly cover the investigation job reservation, worker/proxy containers, temporary directory, and fixture resources. The cancellation assertions establish cleanup after cancellation; they do not exercise normal completion as a separate terminal path.

### Final status and limitations

`git diff --check` passed in this review. No Docker, public-target, or public-DNS tests were run from the Codex shell. The repository remains on `docker-modec-work`; all existing modifications, untracked files, and screenshots remain present.

Based on the operator-reported completed runs and the assertions reviewed above, Phase 4 meets its local interactive workflow acceptance criteria: real fixture navigation and interaction, sandbox-gated Chromium, authenticated event/artifact APIs, cross-case denial, unsafe-target blocking, cancellation cleanup, and repeated-job isolation all have explicit end-to-end assertions. The noted assertion boundaries do not invalidate those scoped criteria, but are useful refinements if stronger evidence is needed. External direct-egress reachability/blocking remains unverified and must not be claimed. The independent Chrome sandbox diagnostic remains unavailable even though Trust Layer's live renderer verifier reported VERIFIED. If a stronger traffic-path assertion is desired, the smallest follow-up is to assert a sanitized proxy observation for the exact fixture hostname and pinned IP in the interactive test; this does not block the current result because the successful navigation and inspected two-network topology already exercise the authenticated proxy path.
