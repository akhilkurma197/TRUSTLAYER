# Phase 3 — API Security and Investigation Data Model

Audit date: 2026-10-31 (Asia/Calcutta)
Branch: `docker-modec-work`

## Verdict

API security and the minimum investigation/evidence contract have been hardened and validated with local tests. Every `/api` route is behind the operator authentication middleware except the explicitly public `POST /api/auth/session` login route. Private case data, SSE and screenshots require the single operator credential or its scoped session cookie. The frontend shell and explicitly mounted vendor assets remain public. No health/readiness API exists. No public network requests were made.

This preserves a **single trusted operator** model. The bearer secret grants access to all cases; the application does not provide independent users, tenants, or per-case owner ACLs. A caller holding the operator secret can substitute another valid case ID and access that case because they are the same operator. Unknown and malformed IDs return the same generic 404. This is not multi-user IDOR protection; add per-case ownership only with a deliberate multi-user identity model.

The local Docker integration was not run in this turn. The exact check `docker --context desktop-linux version --format '{{.Server.Version}}'` failed because this shell could not read `C:\Users\akhil\.docker\config.json` and the `desktop-linux` context `meta.json` (`Access is denied`). No context was changed and no Docker workaround was attempted. The Node tests still exercise Mode C fail-closed behavior and fresh-verifier requirements; this turn does not claim fresh live container verification.

## Endpoint inventory

| Endpoint | Access | Purpose / notes |
|---|---|---|
| `GET /`, `/investigate`, `/console`, `/investigation`, `/investigation.html` | Public | Frontend shell; sensitive data fetched through authenticated API calls. |
| `GET /vendor/*` | Public allowlisted static files | Vendor assets only, dotfiles denied, no directory index. No repository-root static mount. |
| `POST /api/auth/session` | Public login, rate limited | Accepts the operator token in a bounded JSON body; issues an HttpOnly, SameSite=Strict, `/api`-scoped session cookie. Secure flag is set in production. Origin is checked when supplied. |
| `POST /api/auth/logout` | Auth required | Invalidates session cookie. Cookie-authenticated mutations require matching Origin. |
| `POST /api/cases` | Auth required | Create a case and start analysis; target/type/mode/context validated and bounded. |
| `GET /api/cases` | Auth required | Lists cases for the single operator. |
| `GET /api/cases/:id` | Auth required | Returns the case schema; malformed and absent IDs share the same 404 response. |
| `GET /api/cases/:id/events` | Auth required | Case-scoped SSE snapshot/events; bounded per-case and global connections, 20-second heartbeat, 30-minute maximum lifetime, disconnect cleanup. |
| `GET /api/cases/:id/screenshot[?type=initial]` | Auth required | Streams only a known case's PNG under the screenshot root; type allowlisted, symlink-resolved path checked, regular file and 5 MiB cap checked. Other query types and stale/orphan case IDs are unavailable. |
| `POST /api/cases/:id/live-inspect` | Auth required | Explicit consent required; bounded rate, duplicate running inspection rejected; Mode C still depends on controller's fresh `VERIFIED` sandbox gate. |
| `POST /api/cases/:id/cancel-live`, `/cancel` | Auth required | Cancels case/runtime and records lifecycle state. |
| Other `/api/*` paths/methods | Auth required, then generic 404 | No health/readiness or worker administration route is exposed. |

There is no route that serves `data/screenshots`, docs, source files, or the repository root. Screenshot API access is case-gated; the single operator credential is the global authority, not an individual case owner token.

## Authentication, authorization, and secret handling

- Startup fails closed unless `TRUSTLAYER_API_TOKEN` contains 32–1024 bytes. Bearer secrets are compared with `timingSafeEqual` for equal-length values; malformed and different-length values are rejected. The error response never echoes the submitted token.
- Password/token material is accepted only by the public session endpoint or Authorization header; it is not placed in a URL. Session IDs are random, held in process memory, expire after eight hours, and are not returned in JSON.
- Login is limited to five failures per source IP per minute. The API requires authentication before body parsing and route work.
- Case identifiers accept legacy three-character suffixes and new 12-hex-character random suffixes. New IDs use cryptographic randomness and process-lifetime collision checks. Invalid/missing IDs produce generic 404s.
- Cookie-authenticated mutations require same-origin validation. Bearer-token clients remain compatible with the existing single-operator workflow.
- Operational messages pass through redaction for URL paths/query/fragments, URL credentials, bearer values, and common secret assignments. URL parsing and top-level processing failures use generic safe errors. Synthetic-secret tests cover these paths.
- Session state, login limits, case storage, active-case limits and SSE connection accounting are process-local. Restart invalidates sessions and resets in-memory rate limits. Deploying multiple server processes requires shared session/rate state or sticky routing and a trusted reverse-proxy policy; `req.socket.remoteAddress` intentionally does not trust forwarded headers.
- Token rotation is an operator-managed environment change followed by process restart. There is no overlapping-key rotation protocol.

## Request and service limits

| Boundary | Enforced bound | Scope / caveat |
|---|---:|---|
| Main server request headers | 16 KiB | Configured on Node HTTP server. Embedded consumers should preserve this limit. |
| Header wait / request timeout | 15 s / 30 s | Main HTTP server; SSE heartbeat prevents idle socket timeout. |
| Login JSON | 2 KiB | Applied before credential validation. |
| Authenticated API JSON | 64 KiB | Body parser rejects larger/chunked bodies with a safe 413 response. |
| Target / expected context | 4 KiB / 1000 chars | UTF-8 target bytes; type, mode and capture delay are allowlisted. |
| Case creation | 20 per source IP per minute | In-memory fixed window, before route validation/work; all creation modes count. |
| Live inspection trigger | 10 per source IP per minute | In-memory fixed window; existing running case cannot be concurrently retriggered. |
| Login | 5 failed attempts per source IP per minute | In-memory; successful login clears the source bucket. |
| Case store / active cases | 1000 total / 16 active | In-memory process-local capacity. There is no waiting queue; excess work receives 429/503. |
| Case list response | 100 most recent | Bounds the list endpoint; full case retrieval remains case-scoped. |
| SSE | 8 per case / 128 total; 20 s heartbeat; 30 min lifetime | Per process; disconnect removes response from both sets. |
| Screenshot response | 5 MiB; PNG signature | Bounds artifact read/stream; worker also enforces dimensions and bytes. |
| Evidence event | 16 KiB, 64 references, 20 limitations, 2048-char finding/observation | Enforced by versioned validator; evidence references must belong to supplied investigation set. |

JSON parse failures, oversized bodies and unexpected API routes return bounded generic JSON errors without stack traces, secret values or filesystem paths. The API does not currently expose an expensive-analysis endpoint separate from case creation. Analysis execution remains background work after a bounded create request.

## Investigation and evidence contract

- Case IDs remain the existing `TL-YYYY-MMDD-HHmm-...` family; new IDs use 12 cryptographically random hexadecimal characters. Existing three-character IDs remain accepted for compatibility.
- Existing detailed `schema.status` stage/terminal conventions remain intact. `schema.lifecycleState` adds a compact lifecycle: `created`, `queued`, `running`, `completed`, `failed`, `cancelled`, or `timed_out`. This architecture has no queue, so ordinary cases transition directly from created to running. Mode C render timeout maps to `timed_out`; cancellation is retained across aborted pipeline completion.
- `core/evidence_event.js` defines version 1 event validation: investigation ID, event ID, timestamp, expected next sequence, event type, source, URL/origin context, evidence references, observation/finding, observed versus inferred kind, confidence/severity, collection status, freshness (`live`, `replayed`, `stored`) and explicit limitations for partial/failed collection. Validation requires the current investigation's known evidence IDs and prior event IDs; duplicate IDs and cross-investigation references are rejected. URL credentials, query and fragment data are rejected; sensitive field names and overlong payloads are rejected.
- No database migration, event persistence layer or event-ingestion endpoint was added. Existing `schema.evidence` remains the persisted evidence convention. The new event contract is a validated extension point for later producers; it must be called by any future ingestion boundary before accepting/storing an event.
- The worker continues to collect bounded DOM data and does not intentionally extract form field values. Evidence references are not independently owned across operators because the application remains single-operator.

## Threats addressed and files changed in this phase

- `backend/server.js`: consistent `/api` auth, case-ID validation, same-origin session mutations, bounded input/rate/capacity checks, SSE lifecycle, artifact confinement, and safe error responses.
- `core/investigation_engine.js`: cryptographically random collision-checked IDs, lifecycle updates, and safe logging/error text.
- `core/case_schema.js`: explicit lifecycle field.
- `core/log_redaction.js`: URL and secret-value redaction for operational messages.
- `core/evidence_event.js`: versioned event and lifecycle validators.
- `tests/api_auth.test.js`: auth/session coverage, enumeration response parity, size/rate checks, SSE disconnect, screenshot authorization/path confinement, and synthetic secret non-echo.
- `tests/evidence_event.test.js`: lifecycle/event contract, cross-case reference rejection, URL/query and sensitive-field rejection, and synthetic-secret log redaction.
- `core/investigation_engine.test.js`: generated ID format/uniqueness and lifecycle initialization/terminal-block assertions.
- `docs/phase-three-api-security-audit.md`: this inventory, guarantees, limits, validation and caveats.

Earlier Phase 1/2 files and user changes were preserved. No screenshots were modified or removed, and no UI/browser-control feature was added.

## Validation

Completed in this turn:

```text
node --check backend/server.js
node --check core/investigation_engine.js
node --check core/evidence_event.js
node --check core/log_redaction.js
# passed

node --test tests/api_auth.test.js tests/evidence_event.test.js
# 7 passed, 0 failed, 0 skipped

node --test tests/api_auth.test.js tests/evidence_event.test.js tests/mode_c_security_gate.test.js tests/mode_c_api_smoke.test.js
# 28 passed, 0 failed, 1 skipped (opt-in Docker API integration)

node --test
# 147 tests, 145 passed, 0 failed, 2 skipped

npm.cmd test
# 7 passed, 0 failed, 0 skipped

docker --context desktop-linux version --format '{{.Server.Version}}'
# failed: Docker client could not read existing user config/context metadata (Access is denied)

git diff --check
# passed; a separate trailing-whitespace scan also passed for new files
```

The opt-in Docker API smoke test and local Docker integration were not run because Docker Desktop context metadata was inaccessible in this shell. Their opt-in skips are not counted as passes. Node's normal suite also includes the Mode C runtime-unavailable refusal test. No public websites or public IP addresses were contacted.

## Remaining limitations and risks

1. Single-operator bearer authority has no per-case tenant ownership. Anyone with the operator secret can access every case.
2. Rate limits, sessions, cases, active-work accounting and SSE caps are in-memory and per process; they do not protect a horizontally scaled deployment without shared coordination.
3. Docker live Mode C API/integration was not re-exercised in this turn; current fresh sandbox evidence is not re-claimed from this validation run. The fresh `VERIFIED` requirement remains enforced.
4. External direct egress remains unverified, as previously documented.
5. The evidence event validator is not yet wired to persistence or an ingestion route. Future producers must use it at their trust boundary and supply that investigation's known evidence IDs.
6. The server binds to `0.0.0.0`; deployment should use a trusted TLS-terminating front end, explicit `TRUSTLAYER_PUBLIC_ORIGIN`, and firewall policy. Forwarded IP headers are not trusted for rate-limit identity.

Phase 3 work stops here. Phase 4 and interactive browser UI work were not started.
