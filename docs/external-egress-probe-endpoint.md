# Controlled endpoint for the external-egress probe

`tests/fixtures/egress_probe_endpoint.js` is a small endpoint for a server and DNS name you control. It implements the exact contract used by `tests/helpers/external_egress_probe.js`:

- The probe sends `GET /probe` with `X-TrustLayer-Egress-Probe: tl-egress-{direct|proxy}-{http|https}-{uuid}`.
- The endpoint returns HTTP 200 and `X-TrustLayer-Probe-Ack` with the exact same marker. The body is a fixed, short text response. It never redirects.
- For a valid request, one JSON log line contains only the marker, the HTTP scheme, and `request.socket.remoteAddress`. Invalid requests receive 400 and their supplied header values are not logged.
- The marker itself identifies whether the request was the direct or proxy attempt. Compare marker IDs printed by the Docker test with endpoint logs; the peer address is the remote address observed at the endpoint. If a TCP forwarder or NAT is in front, confirm what peer address the endpoint sees from that network setup.
- HTTPS uses Node's normal TLS server with TLS 1.2 minimum. Supply a certificate valid for the endpoint hostname and a matching private key. The test client keeps certificate verification enabled; self-signed or mismatched certificates do not count as successful proxy controls.

## Safe deployment

Use a temporary VM or other host and DNS name under your control. Do not use Google or another third-party website as a substitute. Install this repository's endpoint script on that host (or copy only the script; it uses Node built-ins). Keep the TLS private key outside the repository and readable only by the endpoint service account.

The listener defaults to loopback and unprivileged ports. On the controlled host, configure:

```sh
TRUSTLAYER_EGRESS_BIND_HOST=CONTROLLED_HOST_INTERFACE_IP \
TRUSTLAYER_EGRESS_HTTP_PORT=8080 \
TRUSTLAYER_EGRESS_HTTPS_PORT=8443 \
TRUSTLAYER_EGRESS_TLS_KEY=/secure/path/egress.key \
TRUSTLAYER_EGRESS_TLS_CERT=/secure/path/egress-fullchain.pem \
node tests/fixtures/egress_probe_endpoint.js
```

Set the bind host to the controlled server's interface address reachable from the forwarding rule (not `0.0.0.0` unless that is necessary and firewall restricted). Forward TCP port 80 to the endpoint's HTTP listener and TCP port 443 to its HTTPS listener at the host/network edge. Use TCP forwarding so TLS reaches Node unchanged and its HTTPS log records `scheme: "https"`. Apply inbound firewall rules on the controlled host/network to permit only the known outbound address(es) of the Docker test environment, and only TCP 80/443. Do not expose the endpoint to the entire Internet when a narrower source allowlist is available. Keep service and firewall logs enabled for the test window. Remove the temporary forwarding/firewall rules and stop the endpoint after testing.

If the allowed source addresses are not known, first determine them from your own network administration or endpoint logs and arrange a narrowly scoped test window. Do not broaden Trust Layer's worker networking to make the endpoint reachable. If a load balancer or TLS-terminating reverse proxy is necessary, ensure it preserves the marker header and use its access log to correlate the actual client peer address; the Node endpoint will then report the proxy's socket address rather than the original client.

Before running the Docker probe, verify from an authorized external client that both `http://YOUR_HOSTNAME/probe` and `https://YOUR_HOSTNAME/probe` return 400 when no marker is provided (the endpoint intentionally requires the probe header), and verify HTTPS certificate validity with the system trust store. Do not test with a browser or any unbounded scanner. During the Docker test, correlate each emitted marker ID against the endpoint's logs. A marker seen by the endpoint proves that specific attempt reached it; absence of a marker alone does not prove egress blocking.

## Configure the opt-in test

Run from the Docker-enabled PowerShell session after the endpoint is reachable and its logs are accessible:

```powershell
$env:DOCKER_CONTEXT = 'desktop-linux'
$env:TRUSTLAYER_DOCKER_EXTERNAL_EGRESS = '1'
$env:TRUSTLAYER_EGRESS_HTTP_URL = 'http://YOUR_HOSTNAME/probe'
$env:TRUSTLAYER_EGRESS_HTTPS_URL = 'https://YOUR_HOSTNAME/probe'
node --test tests/docker_external_egress.test.js
```

Use the exact hostname on the HTTPS certificate. The current harness permits only HTTP port 80 and HTTPS port 443, does not follow redirects, rejects URLs with embedded credentials/fragments, and probes only the two supplied URLs. It generates a distinct marker for each direct/proxy and HTTP/HTTPS attempt. Do not set these environment variables to third-party or unauthorized destinations. The Docker test output plus matching endpoint logs are required to assess the result; preparing or locally testing the endpoint does not verify external egress policy.
