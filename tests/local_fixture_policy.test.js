import assert from 'node:assert/strict';
import http from 'node:http';
import { randomUUID } from 'node:crypto';
import { test } from 'node:test';
import { ControlledEgressProxy } from '../core/investigators/egress_proxy.js';
import { SSRFGuard } from '../core/investigators/ssrf_guard.js';
import { normalizeTestLocalFixturePolicy, validateTestLocalFixtureUrl } from '../core/investigators/test_local_fixture.js';

function viaProxy(proxy, url) {
  return new Promise((resolve, reject) => {
    const request = http.get({ host: '127.0.0.1', port: proxy.port, path: url }, response => {
      let body = '';
      response.setEncoding('utf8');
      response.on('data', chunk => { body += chunk; });
      response.on('end', () => resolve({ status: response.statusCode, body, headers: response.headers }));
    });
    request.setTimeout(2500, () => request.destroy(new Error('local proxy request timed out')));
    request.on('error', reject);
  });
}

test('test fixture policy pins one local origin and leaves ordinary SSRF blocks intact', async () => {
  const priorNodeEnv = process.env.NODE_ENV;
  process.env.NODE_ENV = 'test';
  let port;
  const fixture = http.createServer((req, res) => {
    if (req.url === '/redirect') {
      res.writeHead(302, { Location: `http://127.0.0.1:${port}/private` });
      return res.end();
    }
    res.writeHead(200, { 'Content-Type': 'text/plain' });
    res.end('local-fixture');
  });
  await new Promise(resolve => fixture.listen(0, '127.0.0.1', resolve));
  port = fixture.address().port;
  const hostname = `trustlayer-fixture-${randomUUID().slice(0, 12)}.test`;
  const policy = normalizeTestLocalFixturePolicy({ hostname, address: '127.0.0.1', port,
    networkName: 'trustlayer-fixture-net-12345678' });
  const proxy = new ControlledEgressProxy({ port: 0, requireAuth: false, testLocalFixturePolicy: policy,
    maxResponseBytes: 1024, upstreamTimeoutMs: 1500 });
  try {
    await proxy.start();
    const exact = validateTestLocalFixtureUrl(`http://${hostname}:${port}/`, policy);
    assert.equal(exact.allowed, true);
    assert.equal(exact.connectAddress, '127.0.0.1');
    assert.equal(validateTestLocalFixtureUrl(`http://${hostname}:${port + 1}/`, policy), null);
    assert.equal(validateTestLocalFixtureUrl(`http://127.0.0.1:${port}/`, policy), null);
    assert.throws(() => normalizeTestLocalFixturePolicy({ hostname, address: '8.8.8.8', port }), /Invalid test-only/);
    assert.equal((await SSRFGuard.validateAndResolve(`http://127.0.0.1:${port}/`)).allowed, false,
      'the ordinary SSRF guard must continue rejecting direct loopback URLs');

    const allowed = await viaProxy(proxy, `http://${hostname}:${port}/`);
    assert.equal(allowed.status, 200);
    assert.equal(allowed.body, 'local-fixture');

    const wrongPort = await viaProxy(proxy, `http://${hostname}:${port + 1}/`);
    assert.equal(wrongPort.status, 403, 'fixture hostname on any other port must be denied before DNS');
    const directLoopback = await viaProxy(proxy, `http://127.0.0.1:${port}/`);
    assert.equal(directLoopback.status, 403, 'fixture policy must not allow arbitrary loopback origins');
    const unlistedHost = await viaProxy(proxy, `http://trustlayer-fixture-unlisted.test:${port}/`);
    assert.equal(unlistedHost.status, 403, 'fixture proxy must deny unlisted hosts before DNS');
    const redirect = await viaProxy(proxy, `http://${hostname}:${port}/redirect`);
    assert.equal(redirect.status, 302);
    assert.equal((await viaProxy(proxy, redirect.headers.location)).status, 403,
      'a redirect to an unsafe local destination must be independently revalidated and blocked');
    assert.equal(proxy.allowedRequests.length, 2);
    assert.ok(proxy.allowedRequests.every(item => item.targetIp === '127.0.0.1'));
    assert.equal(proxy.blockedRequests.length, 4);
  } finally {
    await proxy.stop();
    fixture.closeAllConnections();
    await new Promise(resolve => fixture.close(resolve));
    if (priorNodeEnv === undefined) delete process.env.NODE_ENV;
    else process.env.NODE_ENV = priorNodeEnv;
  }
});

test('fixture proxy policy cannot be configured outside the explicit test runtime', () => {
  const priorNodeEnv = process.env.NODE_ENV;
  try {
    delete process.env.NODE_ENV;
    assert.throws(() => new ControlledEgressProxy({ testLocalFixturePolicy: {
      hostname: 'trustlayer-fixture-production.test', address: '10.0.0.5', port: 8080,
      networkName: 'trustlayer-fixture-net-12345678'
    } }), /only in NODE_ENV=test/);
  } finally {
    if (priorNodeEnv !== undefined) process.env.NODE_ENV = priorNodeEnv;
  }
});
