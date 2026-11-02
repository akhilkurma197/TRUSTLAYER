# Trust Layer

Trust Layer investigates URLs and QR payloads using URL analysis, redirect tracing and isolated Chromium inspection. Mode C runs a disposable browser worker and a separate authenticated egress proxy; screenshots and findings are attached to the investigation case.

## Start the application

For local development, run this from the repository root:

```powershell
node backend/server.js
```

On first non-production startup, Trust Layer creates a cryptographically random `TRUSTLAYER_API_TOKEN` in the gitignored root `.env` file. Later starts reuse it. Keep `.env` private and do not commit or copy its contents into source files or logs. The local server binds to `127.0.0.1`; open `http://localhost:3000`. The dashboard and Investigation Console automatically establish an eight-hour, HttpOnly, SameSite=Strict `/api` session after a same-origin loopback request. You do not need to copy or enter the token. Reloads continue through the cookie, and after a backend restart the browser silently establishes a fresh local session. The API token is never sent to frontend code or browser storage.

The dashboard and Investigation Console headers provide **Replace API token** and **Clear API session** controls. In local development, Replace establishes a new loopback session; in production it requests the configured API token. Clearing signs out the current browser until an explicit replacement or page reload. Local automatic authentication is enabled only by the non-production server entrypoint, requires a loopback TCP peer and exact same-origin `Origin`, and is disabled in production. Do not expose or reverse-proxy the local development listener. For production TLS-terminating reverse proxies set `TRUSTLAYER_PUBLIC_ORIGIN` to the exact public origin (for example `https://trustlayer.example`). Production startup does not load `.env` or generate a token; it requires `TRUSTLAYER_API_TOKEN` from the process environment.

The token can also be supplied through the process environment, which takes precedence over `.env`; startup reports only the configuration source, never its value. The local `.env` loader uses Node built-ins and adds no runtime dependency. `NODE_ENV=test` follows the non-production loopback-only startup behavior; it does not disable API authentication.

This is a single-operator boundary: every holder of the configured API token shares access to all in-memory cases and their screenshots. It is not a multi-user ownership system. Do not share the token among mutually untrusted users or expose the service to the public internet without a separate identity and authorization layer.

## Enable Mode C

Mode C requires Docker Desktop using Linux containers and a running Docker daemon. The account running the Trust Layer backend must be allowed to access the Docker daemon. On Windows this normally means membership in `docker-users` and a sign-out/sign-in after the membership change. Do not run the application as an elevated administrator merely to work around a missing Docker permission.

Run the setup check from the repository root:

```powershell
.
scripts\setup_mode_c.ps1
```

The backend also verifies and builds the pinned worker image before each live run. It refuses inspection if Docker or the required network configuration is unavailable; it never falls back to a host browser or an HTTP-only result represented as a rendered inspection.

The worker runs as `pwuser`, with a read-only root filesystem, bounded memory/CPU/PIDs, ephemeral writable mounts, no `SYS_ADMIN`, and only the `SYS_CHROOT` capability Chromium needs. `worker/chromium-seccomp.json` is based on the [Moby default seccomp profile](https://github.com/moby/profiles/blob/main/seccomp/default.json) and permits Chromium's user-namespace syscalls. The worker sits on an internal Docker bridge with no direct internet route. A per-run authenticated proxy is the only outbound path and performs destination validation and DNS-pinned connections.

Mode C visits untrusted websites. Docker isolation reduces risk but does not make hostile content harmless. Each run is time-limited and its worker/proxy containers are removed when it ends. A valid PNG is required before the run can be reported as a completed rendered inspection; blocked targets and failed renders remain explicitly incomplete.

## Tests

Run unit and fixture tests with `npm test`. Docker integration checks are opt-in and require working Docker daemon access:

```powershell
$env:TRUSTLAYER_DOCKER_INTEGRATION = '1'
node --test tests/docker_proxy_connectivity.test.js
$env:TRUSTLAYER_DOCKER_API_INTEGRATION = '1'
node --test tests/mode_c_api_smoke.test.js
```
