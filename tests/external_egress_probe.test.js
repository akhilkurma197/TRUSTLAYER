import assert from 'node:assert/strict';
import http from 'node:http';
import dns from 'node:dns/promises';
import { once } from 'node:events';
import { test } from 'node:test';
import { classifyProbe, parseAuthorizedProbeUrls, probeDirect, probeThroughProxy } from './helpers/external_egress_probe.js';
import { cleanupDockerContainers, readOnlyFileBindMount } from './helpers/docker_external_egress_resources.js';
import { SSRFGuard } from '../core/investigators/ssrf_guard.js';

async function listen(server) {
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  return server.address().port;
}

test('external probe URL input is explicit, protocol-bound, and rejects embedded credentials', () => {
  assert.throws(() => parseAuthorizedProbeUrls(undefined, 'https://authorized.invalid/'), /HTTP probe URL is required/);
  assert.throws(() => parseAuthorizedProbeUrls('https://authorized.invalid/', 'https://authorized.invalid/'), /explicit http:/);
  assert.throws(() => parseAuthorizedProbeUrls('http://user:pass@authorized.invalid/', 'https://authorized.invalid/'), /without credentials/);
  assert.throws(() => parseAuthorizedProbeUrls('http://authorized.invalid:8080/', 'https://authorized.invalid/'), /port is outside/);
  assert.deepEqual(parseAuthorizedProbeUrls('http://authorized.invalid/check', 'https://authorized.invalid/check'), {
    httpUrl: 'http://authorized.invalid/check', httpsUrl: 'https://authorized.invalid/check'
  });
});

test('probe helper uses a read-only file bind and cleanup attempts every owned container', () => {
  const mount = readOnlyFileBindMount('C:\\workspace\\trustlayer\\tests\\helpers\\probe.js',
    '/home/pwuser/app/worker/external_egress_probe.mjs');
  assert.equal(mount, 'type=bind,source=C:\\workspace\\trustlayer\\tests\\helpers\\probe.js,target=/home/pwuser/app/worker/external_egress_probe.mjs,readonly');
  assert.throws(() => readOnlyFileBindMount('relative/probe.js', '/probe.mjs'), /absolute path/);
  assert.throws(() => readOnlyFileBindMount('C:\\probe,unsafe.js', '/probe.mjs'), /without mount separators/);

  const attempted = [];
  const failed = cleanupDockerContainers(['probe-container', 'proxy-container'], name => {
    attempted.push(name);
    if (name === 'probe-container') throw new Error('fixture remove failure');
  });
  assert.deepEqual(attempted, ['probe-container', 'proxy-container']);
  assert.deepEqual(failed, ['probe-container']);
});

test('local controlled HTTP fixture distinguishes direct and authenticated-proxy markers', async t => {
  const received = [];
  const endpoint = http.createServer((request, response) => {
    const marker = request.headers['x-trustlayer-egress-probe'];
    received.push({ marker, path: request.url, proxyAuthorizationForwarded: Boolean(request.headers['proxy-authorization']) });
    response.setHeader('x-trustlayer-probe-ack', marker || '');
    response.writeHead(200, { 'content-type': 'text/plain' });
    response.end('local fixture');
  });
  const endpointPort = await listen(endpoint);
  const proxy = http.createServer((request, response) => {
    const expectedAuth = `Basic ${Buffer.from('test-user:test-password').toString('base64')}`;
    if (request.headers['proxy-authorization'] !== expectedAuth) {
      response.writeHead(407); response.end(); return;
    }
    const target = new URL(request.url);
    const marker = request.headers['x-trustlayer-egress-probe'];
    const upstream = http.request({ hostname: target.hostname, port: target.port, path: `${target.pathname}${target.search}`,
      headers: { 'x-trustlayer-egress-probe': marker } }, incoming => {
      response.writeHead(incoming.statusCode, incoming.headers);
      incoming.pipe(response);
    });
    upstream.once('error', () => { response.writeHead(502); response.end(); });
    upstream.end();
  });
  const proxyPort = await listen(proxy);
  t.after(async () => {
    endpoint.closeAllConnections(); proxy.closeAllConnections();
    await Promise.all([new Promise(resolve => endpoint.close(resolve)), new Promise(resolve => proxy.close(resolve))]);
  });

  const url = `http://127.0.0.1:${endpointPort}/controlled`; // Local-only fixture URL.
  const direct = await probeDirect(url, { timeoutMs: 1000 });
  const viaProxy = await probeThroughProxy(url, { host: '127.0.0.1', port: proxyPort, username: 'test-user', password: 'test-password' }, { timeoutMs: 1000 });
  assert.equal(direct.status, 200);
  assert.equal(direct.markerAcknowledged, true);
  assert.equal(viaProxy.status, 200);
  assert.equal(viaProxy.markerAcknowledged, true);
  assert.equal(classifyProbe(direct), 'FAIL', 'a successful direct connection is a proxy-bypass failure');
  assert.equal(classifyProbe(viaProxy, { expectedProxySuccess: true }), 'PASS');
  assert.equal(received.length, 2);
  assert.equal(new Set(received.map(item => item.marker)).size, 2);
  assert.ok(received.every(item => item.path === '/controlled'));
  assert.ok(received.every(item => !item.proxyAuthorizationForwarded), 'proxy authentication must not reach the target fixture');
});

test('direct probe preserves its pinned address with Node all-address lookup callbacks', async t => {
  const originalLookup = dns.lookup;
  const endpoint = http.createServer((request, response) => {
    response.setHeader('x-trustlayer-probe-ack', request.headers['x-trustlayer-egress-probe'] || '');
    response.writeHead(200, { 'content-type': 'text/plain' });
    response.end('pinned local fixture');
  });
  const port = await listen(endpoint);
  t.after(async () => {
    dns.lookup = originalLookup;
    endpoint.closeAllConnections();
    await new Promise(resolve => endpoint.close(resolve));
  });

  // Keep name resolution deterministic and local while exercising the custom
  // lookup callback that Node's HTTP client invokes with `all: true`.
  dns.lookup = async () => [{ address: '127.0.0.1', family: 4 }];
  const result = await probeDirect(`http://fixture.invalid:${port}/probe`, { timeoutMs: 1000 });
  assert.equal(result.status, 200);
  assert.equal(result.markerAcknowledged, true);
  assert.equal(result.dnsStatus, 'RESOLVED');
});

test('ambiguous timeout and DNS failures are not treated as proof of blocked direct egress', () => {
  assert.equal(classifyProbe({ transport: 'direct', dnsStatus: 'RESOLVED', errorCode: 'ETIMEDOUT' }), 'NOT VERIFIED');
  assert.equal(classifyProbe({ transport: 'direct', dnsStatus: 'FAILED', errorCode: 'ENETUNREACH' }), 'NOT VERIFIED');
  assert.equal(classifyProbe({ transport: 'direct', dnsStatus: 'RESOLVED', errorCode: 'ENETUNREACH' }), 'PASS');
  assert.equal(classifyProbe({ transport: 'direct', status: 200, transportProtocol: 'https' }), 'FAIL');
  assert.equal(classifyProbe({ transport: 'authenticated-proxy', transportProtocol: 'https', status: 200,
    markerAcknowledged: true, tlsVerified: false }, { expectedProxySuccess: true }), 'NOT VERIFIED');
  assert.equal(classifyProbe({ transport: 'authenticated-proxy', transportProtocol: 'https', status: 200,
    markerAcknowledged: true, tlsVerified: true }, { expectedProxySuccess: true }), 'PASS');
});

test('probe proxy policy fails closed without contacting Cloudflare DoH after local DNS failure', async () => {
  const original = { resolve4: dns.resolve4, resolve6: dns.resolve6, lookup: dns.lookup, fetch: globalThis.fetch,
    disable: process.env.TRUSTLAYER_DISABLE_DOH_FALLBACK };
  let fetchCalls = 0;
  try {
    dns.resolve4 = async () => { throw new Error('fixture DNS failure'); };
    dns.resolve6 = async () => { throw new Error('fixture DNS failure'); };
    dns.lookup = async () => { throw new Error('fixture DNS failure'); };
    globalThis.fetch = async () => { fetchCalls++; throw new Error('unexpected external DoH'); };
    process.env.TRUSTLAYER_DISABLE_DOH_FALLBACK = '1';
    const result = await SSRFGuard.validateAndResolve('https://authorized-endpoint.invalid/');
    assert.equal(result.allowed, false);
    assert.match(result.blockedReason, /fallback is disabled/);
    assert.equal(fetchCalls, 0);
  } finally {
    dns.resolve4 = original.resolve4;
    dns.resolve6 = original.resolve6;
    dns.lookup = original.lookup;
    globalThis.fetch = original.fetch;
    if (original.disable === undefined) delete process.env.TRUSTLAYER_DISABLE_DOH_FALLBACK;
    else process.env.TRUSTLAYER_DISABLE_DOH_FALLBACK = original.disable;
  }
});
