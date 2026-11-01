# Trust Layer

Trust Layer investigates URLs and QR payloads using URL analysis, redirect tracing and isolated Chromium inspection. Mode C runs a disposable browser worker and a separate authenticated egress proxy; screenshots and findings are attached to the investigation case.

## Start the application

The control API requires a single-operator secret of at least 32 random bytes. Do not commit it, paste it into source files, or include it in logs. In PowerShell, generate an ephemeral secret and start the server in the same shell:

```powershell
npm install
$apiSecretBytes = [byte[]]::new(32)
[System.Security.Cryptography.RandomNumberGenerator]::Fill($apiSecretBytes)
$env:TRUSTLAYER_API_TOKEN = [Convert]::ToBase64String($apiSecretBytes)
npm start
```

The browser UI prompts for this token on its first API request. It exchanges the token for an eight-hour, HttpOnly, SameSite=Strict session cookie; the token itself is not stored in browser storage or placed in URLs. Direct API clients can send `Authorization: Bearer <token>`. For TLS-terminating reverse proxies set `NODE_ENV=production` and `TRUSTLAYER_PUBLIC_ORIGIN` to the exact public origin (for example `https://trustlayer.example`). Protect the environment variable using the host's secret-management facilities.

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
