import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import dns from 'node:dns/promises';
import { SSRFGuard } from '../core/investigators/ssrf_guard.js';
import { RedirectTracer } from '../core/investigators/redirect_tracer.js';

describe('Mode B redirect trace', () => {
  it('reports real HTTP redirect and final response observations from a controlled fixture server', async () => {
    const server = http.createServer((req, res) => {
      if (req.url === '/begin') {
        res.writeHead(302, { Location: '/landing', 'X-Redirect-Source': 'controlled-fixture' });
        res.end();
        return;
      }
      res.writeHead(200, {
        'Content-Type': 'text/html; charset=utf-8',
        'X-Frame-Options': 'DENY',
        Server: 'trust-layer-controlled-fixture'
      });
      res.end('<!doctype html><title>Observed Landing</title><h1>Fixture destination</h1>');
    });
    await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
    const address = server.address();
    try {
      const initialUrl = `http://127.0.0.1:${address.port}/begin`;
      const result = await RedirectTracer.trace(initialUrl, {
        _testBypassSsrf: true,
        timeoutMs: 1500,
        maxTotalMs: 5000,
        maxHops: 4,
        allowedPorts: [address.port]
      });
      if (process.env.TRUSTLAYER_PRINT_MODE_B_RESULT === '1') {
        console.log(JSON.stringify({
          status: result.status,
          initialUrl: result.initialUrl,
          finalUrl: result.finalUrl,
          hops: result.redirectChain.map(hop => ({
            hop: hop.hop,
            status: hop.status,
            location: hop.location,
            connectedIp: hop.connectedIp || null,
            destinationResolvedIps: hop.destinationResolvedIps || [],
            latencyMs: hop.latencyMs,
            headers: hop.headers,
            outcome: hop.isFinal ? 'FINAL_RESPONSE' : (hop.blocked ? 'BLOCKED' : 'REDIRECT_FOLLOWED')
          })),
          responseHeaders: result.headers,
          limitations: result.limitations
        }, null, 2));
      }

      assert.equal(result.status, 'SUCCESS');
      assert.equal(result.initialUrl, initialUrl);
      assert.equal(result.finalUrl, `http://127.0.0.1:${address.port}/landing`);
      assert.equal(result.hopsCount, 1);
      assert.equal(result.redirectChain.length, 2);
      assert.equal(result.redirectChain[0].status, 302);
      assert.equal(result.redirectChain[0].location, '/landing');
      assert.equal(result.redirectChain[0].toUrl, result.finalUrl);
      assert.equal(result.redirectChain[1].status, 200);
      assert.equal(result.redirectChain[1].isFinal, true);
      assert.equal(result.headers['x-frame-options'], 'DENY');
      assert.ok(result.latencyMs >= 0);
      assert.match(result.limitations.join(' '), /full rendered webpage was not inspected/i);
    } finally {
      await new Promise(resolve => server.close(resolve));
    }
  });

  it('does not classify policy blocks as phishing or as a clean result', async () => {
    const result = await RedirectTracer.trace('http://127.0.0.1/private');
    assert.equal(result.status, 'BLOCKED');
    assert.equal(result.riskLevel, 'UNKNOWN');
    assert.equal(result.riskScore, 0);
    assert.match(result.error, /loopback|blocked/i);
  });

  it('revalidates DNS at the proxy connection boundary when answers rebind', async () => {
    const originalResolve4 = dns.resolve4;
    const originalResolve6 = dns.resolve6;
    let lookups = 0;
    dns.resolve4 = async () => (++lookups === 1 ? ['93.184.216.34'] : ['127.0.0.1']);
    dns.resolve6 = async () => { throw Object.assign(new Error('no AAAA'), { code: 'ENODATA' }); };
    try {
      const result = await RedirectTracer.trace('http://rebind.fixture/', { timeoutMs: 1000, maxTotalMs: 3000, maxHops: 3 });
      assert.equal(result.status, 'BLOCKED');
      assert.ok(lookups >= 2, 'the controlled proxy must perform its own fresh DNS validation');
      assert.match(result.error, /blocked|private|loopback/i);
    } finally {
      dns.resolve4 = originalResolve4;
      dns.resolve6 = originalResolve6;
    }
  });

  it('blocks a later redirect hop to a prohibited destination without contacting it', async () => {
    const requests = [];
    const server = http.createServer((req, res) => {
      requests.push(req.url);
      if (req.url === '/begin') {
        res.writeHead(302, { Location: '/next' });
        res.end();
      } else if (req.url === '/next') {
        res.writeHead(302, { Location: `http://127.0.0.1:${server.address().port}/private` });
        res.end();
      } else {
        res.writeHead(200);
        res.end('unexpected fixture path');
      }
    });
    await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
    const originalValidate = SSRFGuard.validateAndResolve;
    SSRFGuard.validateAndResolve = async url => {
      const parsed = new URL(url);
      if (parsed.hostname === 'redirect.fixture') {
        return { allowed: true, blockedReason: null, resolvedIps: ['93.184.216.34'], connectAddress: '127.0.0.1', canonicalUrl: parsed.href };
      }
      return { allowed: false, blockedReason: 'Loopback destination blocked by fixture policy', resolvedIps: ['127.0.0.1'], canonicalUrl: parsed.href };
    };
    try {
      const url = `http://redirect.fixture:${server.address().port}/begin`;
      const result = await RedirectTracer.trace(url, { timeoutMs: 1000, maxTotalMs: 4000, maxHops: 5, allowedPorts: [server.address().port] });
      assert.equal(result.status, 'BLOCKED');
      assert.equal(requests.length, 2);
      assert.deepEqual(requests, ['/begin', '/next']);
      assert.equal(result.redirectChain.at(-1).blocked, true);
    } finally {
      SSRFGuard.validateAndResolve = originalValidate;
      await new Promise(resolve => server.close(resolve));
    }
  });

  it('rejects malformed redirect destinations without following them', async () => {
    const server = http.createServer((_req, res) => {
      res.writeHead(302, { Location: 'http://[::1' });
      res.end();
    });
    await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
    try {
      const result = await RedirectTracer.trace(`http://127.0.0.1:${server.address().port}/begin`, {
        _testBypassSsrf: true, timeoutMs: 1000, maxTotalMs: 3000, maxHops: 3, allowedPorts: [server.address().port]
      });
      assert.equal(result.status, 'BLOCKED');
      assert.match(result.error, /invalid redirect/i);
    } finally {
      await new Promise(resolve => server.close(resolve));
    }
  });
});
