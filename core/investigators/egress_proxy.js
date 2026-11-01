/**
 * Trust Layer — Controlled Egress Proxy v1.0
 * Enforces strict network boundaries on worker outbound traffic:
 * 1. Blocks all non-public, loopback, private, link-local, and metadata destinations.
 * 2. Pinning: Connects directly to pre-validated IP addresses to prevent DNS rebinding.
 * 3. Default-deny ports: Permits only approved web destination ports (80, 443).
 * 4. Method restriction: Intercepts and blocks state-mutating requests (POST, PUT, DELETE, PATCH).
 * 5. Transparent HTTPS CONNECT tunneling with destination address validation.
 */

import http from 'node:http';
import net from 'node:net';
import { randomUUID, timingSafeEqual } from 'node:crypto';
import { URL } from 'node:url';
import { SSRFGuard } from './ssrf_guard.js';
import { redactSensitiveUrl } from './url_redaction.js';
import { normalizeTestLocalFixturePolicy, validateTestLocalFixtureUrl } from './test_local_fixture.js';

function stripHopByHopHeaders(headers) {
  const forwarded = { ...headers };
  const hopByHop = new Set(['connection', 'keep-alive', 'proxy-authenticate', 'proxy-authorization',
    'proxy-connection', 'transfer-encoding', 'upgrade', 'te', 'trailer']);
  for (const name of String(headers.connection || '').split(',')) {
    if (name.trim()) hopByHop.add(name.trim().toLowerCase());
  }
  for (const name of hopByHop) delete forwarded[name];
  return forwarded;
}

export class ControlledEgressProxy {
  constructor(options = {}) {
    this.allowedPorts = new Set(options.allowedPorts || [80, 443]);
    this._testBypassSsrf = options._testBypassSsrf || false;
    if (options.testLocalFixturePolicy && process.env.NODE_ENV !== 'test') {
      throw new Error('Test fixture proxy policy is available only in NODE_ENV=test.');
    }
    this.testLocalFixturePolicy = options.testLocalFixturePolicy
      ? normalizeTestLocalFixturePolicy(options.testLocalFixturePolicy) : null;
    this._policyToken = randomUUID();
    this.requireAuth = options.requireAuth === true;
    this.username = this.requireAuth ? (options.username || randomUUID()) : null;
    this.password = this.requireAuth ? (options.password || randomUUID()) : null;
    this._authorization = this.requireAuth
      ? `Basic ${Buffer.from(`${this.username}:${this.password}`).toString('base64')}`
      : null;
    this.blockedRequests = [];
    this.allowedRequests = [];
    this.maxConcurrentConnections = options.maxConcurrentConnections || 32;
    this.maxRequestsPerJob = options.maxRequestsPerJob || 512;
    this.maxRequestBytes = options.maxRequestBytes || 16 * 1024;
    this.maxResponseBytes = options.maxResponseBytes || 25 * 1024 * 1024;
    this.maxTunnelBytes = options.maxTunnelBytes || 100 * 1024 * 1024;
    this.upstreamTimeoutMs = options.upstreamTimeoutMs || 10_000;
    this.tunnelIdleTimeoutMs = options.tunnelIdleTimeoutMs || 30_000;
    this.maxTelemetryRecords = options.maxTelemetryRecords || 512;
    this.requestCount = 0;
    this.server = null;
    this.port = Number.isInteger(options.port) ? options.port : null;
    this.host = options.host || '127.0.0.1';
  }

  /**
   * Start the proxy server on an ephemeral loopback port.
   * @returns {Promise<{ host: string, port: number, proxyUrl: string }>}
   */
  async start() {
    return new Promise((resolve, reject) => {
      this.server = http.createServer({
        maxHeaderSize: 16 * 1024,
        requestTimeout: 10_000,
        headersTimeout: 10_000,
        keepAliveTimeout: 1_000,
        maxRequestsPerSocket: this.maxRequestsPerJob
      }, (req, res) => this._handleHttpRequest(req, res));
      this.server.maxConnections = this.maxConcurrentConnections;
      this.server.maxRequestsPerSocket = this.maxRequestsPerJob;
      this.server.on('connect', (req, clientSocket, head) => this._handleHttpsConnect(req, clientSocket, head));

      this.server.on('error', (err) => {
        reject(err);
      });

      this.server.listen(this.port || 0, this.host, () => {
        const addr = this.server.address();
        this.port = addr.port;
        resolve({
          host: this.host,
          port: this.port,
          proxyUrl: `http://${this.host}:${this.port}`,
          username: this.username,
          password: this.password
        });
      });
    });
  }

  _record(collection, record) {
    if (collection.length >= this.maxTelemetryRecords) collection.shift();
    collection.push(record);
  }

  _consumeRequest(res, socket = null) {
    if (this.requestCount < this.maxRequestsPerJob) {
      this.requestCount++;
      return true;
    }
    if (res) {
      res.writeHead(429, { 'Content-Type': 'application/json', 'X-TrustLayer-Egress-Policy': `${this._policyToken}:REQUEST_LIMIT` });
      res.end(JSON.stringify({ error: 'Per-job proxy request limit reached.' }));
    } else if (socket) {
      socket.write('HTTP/1.1 429 Too Many Requests\r\nConnection: close\r\n\r\n');
      socket.destroy();
    }
    return false;
  }

  /**
   * Handle cleartext HTTP proxy requests
   */
  async _handleHttpRequest(req, res) {
    const startTime = Date.now();

    if (!this._isAuthorized(req.headers['proxy-authorization'])) {
      res.writeHead(407, { 'Proxy-Authenticate': 'Basic realm="TrustLayer Egress"' });
      res.end('Proxy authentication required');
      return;
    }
    if (!this._consumeRequest(res)) return;

    // 1. Method restriction (Observation Mode Only — no state-changing operations)
    if (req.method !== 'GET' && req.method !== 'HEAD') {
      const blockedItem = {
        time: new Date().toISOString(),
        method: req.method,
        url: redactSensitiveUrl(req.url),
        reason: `Disallowed HTTP method ${req.method} — Inspection is read-only (GET/HEAD permitted).`,
        type: 'MUTATING_REQUEST_BLOCKED'
      };
      this._record(this.blockedRequests, blockedItem);
      res.writeHead(405, { 'Content-Type': 'application/json', 'X-TrustLayer-Egress-Policy': `${this._policyToken}:METHOD_BLOCKED` });
      res.end(JSON.stringify({ error: blockedItem.reason }));
      return;
    }

    let targetUrl;
    try {
      targetUrl = new URL(req.url);
    } catch {
      res.writeHead(400, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Malformed proxy request URL' }));
      return;
    }

    // 2. Port check
    const port = targetUrl.port ? parseInt(targetUrl.port, 10) : (targetUrl.protocol === 'https:' ? 443 : 80);
    const fixtureValidation = validateTestLocalFixtureUrl(targetUrl.href, this.testLocalFixturePolicy);
    if (this.testLocalFixturePolicy && !fixtureValidation) {
      this._record(this.blockedRequests, { time: new Date().toISOString(), method: req.method,
        url: redactSensitiveUrl(req.url), reason: 'Test proxy permits only its pinned local fixture origin.', type: 'TEST_FIXTURE_ORIGIN_BLOCKED' });
      res.writeHead(403, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Destination is outside the local test fixture allowlist.' }));
      return;
    }
    if (!this.allowedPorts.has(port) && !fixtureValidation) {
      const blockedItem = {
        time: new Date().toISOString(),
        method: req.method,
        url: redactSensitiveUrl(req.url),
        reason: `Port ${port} blocked by egress policy (allowed: ${Array.from(this.allowedPorts).join(', ')})`,
        type: 'PORT_DISALLOWED'
      };
      this._record(this.blockedRequests, blockedItem);
      res.writeHead(403, { 'Content-Type': 'application/json', 'X-TrustLayer-Egress-Policy': `${this._policyToken}:PORT_BLOCKED` });
      res.end(JSON.stringify({ error: blockedItem.reason }));
      return;
    }

    // 3. Pre-connection destination validation with SSRFGuard
    const validation = fixtureValidation || await SSRFGuard.validateAndResolve(targetUrl.href, { _testBypassSsrf: this._testBypassSsrf });
    if (!validation.allowed) {
      const blockedItem = {
        time: new Date().toISOString(),
        method: req.method,
        url: redactSensitiveUrl(req.url),
        reason: validation.blockedReason,
        type: 'SSRF_BLOCKED'
      };
      this._record(this.blockedRequests, blockedItem);
      res.writeHead(403, { 'Content-Type': 'application/json', 'X-TrustLayer-Egress-Policy': `${this._policyToken}:DESTINATION_BLOCKED` });
      res.end(JSON.stringify({ error: `Egress Proxy Blocked: ${validation.blockedReason}` }));
      return;
    }

    const targetIp = validation.connectAddress || validation.resolvedIps[0] || targetUrl.hostname;

    const declaredRequestBytes = Number(req.headers['content-length'] || 0);
    if (declaredRequestBytes > this.maxRequestBytes) {
      res.writeHead(413, { 'Content-Type': 'application/json', 'X-TrustLayer-Egress-Policy': `${this._policyToken}:REQUEST_TOO_LARGE` });
      res.end(JSON.stringify({ error: 'Proxy request body exceeds the configured limit.' }));
      return;
    }

    // 4. Forward request to pinned IP
    const forwardedHeaders = stripHopByHopHeaders(req.headers);
    const forwardOptions = {
      host: targetIp,
      port,
      path: targetUrl.pathname + targetUrl.search,
      method: req.method,
      headers: {
        ...forwardedHeaders,
        host: targetUrl.host
      }
    };

    const upstreamReq = http.request(forwardOptions, (upstreamRes) => {
      let responseBytes = 0;
      const responseHeaders = stripHopByHopHeaders(upstreamRes.headers);
      res.writeHead(upstreamRes.statusCode, responseHeaders);
      upstreamRes.on('data', chunk => {
        responseBytes += chunk.length;
        if (responseBytes > this.maxResponseBytes) {
          this._record(this.blockedRequests, {
            time: new Date().toISOString(), method: req.method, url: redactSensitiveUrl(targetUrl.href),
            reason: 'Upstream response exceeded the configured per-resource byte limit.', type: 'RESPONSE_TOO_LARGE'
          });
          upstreamRes.destroy();
          if (!res.destroyed) res.destroy();
        }
      });
      upstreamRes.pipe(res);
      this._record(this.allowedRequests, {
        time: new Date().toISOString(),
        method: req.method,
        url: redactSensitiveUrl(targetUrl.href),
        status: upstreamRes.statusCode,
        targetIp,
        resolvedIps: validation.resolvedIps,
        destinationHost: targetUrl.hostname,
        durationMs: Date.now() - startTime
      });
    });

    upstreamReq.on('error', (err) => {
      if (!res.headersSent) {
        res.writeHead(502, { 'Content-Type': 'application/json', 'X-TrustLayer-Egress-Policy': `${this._policyToken}:UPSTREAM_FAILED` });
        res.end(JSON.stringify({ error: `Upstream connection failed: ${err.message}` }));
      }
    });

    upstreamReq.setTimeout(this.upstreamTimeoutMs, () => upstreamReq.destroy(new Error('Upstream request timed out.')));
    req.on('aborted', () => upstreamReq.destroy());
    res.on('close', () => { if (!res.writableEnded) upstreamReq.destroy(); });
    let requestBytes = 0;
    req.on('data', chunk => {
      requestBytes += chunk.length;
      if (requestBytes > this.maxRequestBytes) {
        upstreamReq.destroy(new Error('Proxy request body exceeded the configured limit.'));
        if (!res.headersSent) {
          res.writeHead(413, { 'Content-Type': 'application/json', 'X-TrustLayer-Egress-Policy': `${this._policyToken}:REQUEST_TOO_LARGE` });
          res.end(JSON.stringify({ error: 'Proxy request body exceeds the configured limit.' }));
        } else if (!res.destroyed) res.destroy();
      }
    });

    req.pipe(upstreamReq);
  }

  /**
   * Handle HTTPS CONNECT tunneling
   */
  async _handleHttpsConnect(req, clientSocket, head) {
    const startTime = Date.now();
    if (!this._isAuthorized(req.headers['proxy-authorization'])) {
      clientSocket.write('HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm="TrustLayer Egress"\r\n\r\n');
      clientSocket.destroy();
      return;
    }
    if (!this._consumeRequest(null, clientSocket)) return;
    let connectTarget;
    try {
      if (typeof req.url !== 'string' ||
          !/^(?:\[[0-9a-fA-F:.]+\]|[a-zA-Z0-9.-]+):\d{1,5}$/.test(req.url)) {
        throw new Error('invalid CONNECT authority');
      }
      connectTarget = new URL(`https://${req.url}`);
      if (connectTarget.username || connectTarget.password || connectTarget.pathname !== '/' ||
          connectTarget.search || connectTarget.hash) throw new Error('invalid CONNECT authority');
    } catch {
      this._record(this.blockedRequests, {
        time: new Date().toISOString(), method: 'CONNECT', url: redactSensitiveUrl(`https://${req.url}`),
        reason: 'Malformed CONNECT authority', type: 'MALFORMED_CONNECT_TARGET'
      });
      clientSocket.write('HTTP/1.1 400 Bad Request\r\n\r\n');
      clientSocket.destroy();
      return;
    }
    const rawHost = connectTarget.hostname.replace(/^\[|\]$/g, '');
    const port = connectTarget.port ? Number(connectTarget.port) : 443;

    if (this.testLocalFixturePolicy) {
      this._record(this.blockedRequests, { time: new Date().toISOString(), method: 'CONNECT',
        url: redactSensitiveUrl(`https://${req.url}`), reason: 'Test proxy permits only its pinned HTTP fixture origin.', type: 'TEST_FIXTURE_ORIGIN_BLOCKED' });
      clientSocket.write('HTTP/1.1 403 Forbidden\r\n\r\n');
      clientSocket.destroy();
      return;
    }

    // 1. Destination port check
    if (!this.allowedPorts.has(port)) {
      this._record(this.blockedRequests, {
        time: new Date().toISOString(),
        method: 'CONNECT',
        url: redactSensitiveUrl(`https://${req.url}`),
        reason: `Port ${port} blocked by egress policy`,
        type: 'PORT_DISALLOWED'
      });
      clientSocket.write('HTTP/1.1 403 Forbidden (Non-Approved Egress Port)\r\n\r\n');
      clientSocket.destroy();
      return;
    }

    // 2. Pre-connection IP validation via SSRFGuard
    const validation = await SSRFGuard.validateAndResolve(`https://${rawHost}:${port}/`, { _testBypassSsrf: this._testBypassSsrf });
    if (!validation.allowed) {
      this._record(this.blockedRequests, {
        time: new Date().toISOString(),
        method: 'CONNECT',
        url: redactSensitiveUrl(`https://${req.url}`),
        reason: validation.blockedReason,
        type: 'SSRF_BLOCKED'
      });
      clientSocket.write(`HTTP/1.1 403 Forbidden (SSRF Blocked: ${validation.blockedReason})\r\n\r\n`);
      clientSocket.destroy();
      return;
    }

    // 3. Connect to validated IP to enforce connection-time DNS pinning
    const targetIp = validation.connectAddress || validation.resolvedIps[0] || rawHost;
    const upstreamSocket = net.connect(port, targetIp, () => {
      upstreamSocket.setTimeout(this.tunnelIdleTimeoutMs, () => {
        clientSocket.destroy();
        upstreamSocket.destroy();
      });
      clientSocket.setTimeout(this.tunnelIdleTimeoutMs, () => {
        clientSocket.destroy();
        upstreamSocket.destroy();
      });
      clientSocket.write('HTTP/1.1 200 Connection Established\r\n\r\n');
      if (head && head.length > 0) {
        upstreamSocket.write(head);
      }
      upstreamSocket.pipe(clientSocket);
      clientSocket.pipe(upstreamSocket);

      let tunnelBytes = head?.length || 0;
      const enforceTunnelBudget = chunk => {
        tunnelBytes += chunk.length;
        if (tunnelBytes > this.maxTunnelBytes) {
          this._record(this.blockedRequests, {
            time: new Date().toISOString(), method: 'CONNECT', url: redactSensitiveUrl(`https://${req.url}`),
            reason: 'HTTPS tunnel exceeded the configured byte limit.', type: 'TUNNEL_TOO_LARGE'
          });
          clientSocket.destroy();
          upstreamSocket.destroy();
        }
      };
      upstreamSocket.on('data', enforceTunnelBudget);
      clientSocket.on('data', enforceTunnelBudget);

      this._record(this.allowedRequests, {
        time: new Date().toISOString(),
        method: 'CONNECT',
        url: redactSensitiveUrl(`https://${req.url}`),
        targetIp,
        destinationHost: rawHost,
        resolvedIps: validation.resolvedIps,
        durationMs: Date.now() - startTime,
        status: 200
      });
    });

    upstreamSocket.setTimeout(this.upstreamTimeoutMs, () => {
      if (!clientSocket.destroyed) clientSocket.write('HTTP/1.1 504 Gateway Timeout\r\nConnection: close\r\n\r\n');
      clientSocket.destroy();
      upstreamSocket.destroy();
    });
    upstreamSocket.on('error', () => {
      clientSocket.destroy();
    });

    clientSocket.on('error', () => {
      upstreamSocket.destroy();
    });
  }

  _isAuthorized(value) {
    if (!this.requireAuth) return true;
    if (typeof value !== 'string' || !this._authorization || value.length !== this._authorization.length) return false;
    return timingSafeEqual(Buffer.from(value), Buffer.from(this._authorization));
  }

  /**
   * Stop the proxy server.
   */
  async stop() {
    return new Promise((resolve) => {
      if (this.server) {
        this.server.close(() => {
          this.server = null;
          resolve();
        });
      } else {
        resolve();
      }
    });
  }
}
