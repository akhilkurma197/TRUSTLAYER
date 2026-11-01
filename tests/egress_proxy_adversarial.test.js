import assert from 'node:assert/strict';
import http from 'node:http';
import net from 'node:net';
import { test } from 'node:test';
import { ControlledEgressProxy } from '../core/investigators/egress_proxy.js';

function listen(server) {
  return new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
}

function close(server) {
  return new Promise(resolve => server.close(resolve));
}

function proxyRequest(proxyInfo, url, { headers = {}, method = 'GET', body = '' } = {}) {
  return new Promise(resolve => {
    const req = http.request({
      hostname: proxyInfo.host, port: proxyInfo.port, method, path: url,
      headers: { ...headers, 'proxy-authorization': `Basic ${Buffer.from(`${proxyInfo.username}:${proxyInfo.password}`).toString('base64')}` }
    }, res => {
      const chunks = [];
      res.on('data', chunk => chunks.push(chunk));
      res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body: Buffer.concat(chunks).toString() }));
      res.on('aborted', () => resolve({ status: res.statusCode, headers: res.headers, aborted: true }));
    });
    req.setTimeout(1500, () => { req.destroy(); resolve({ timeout: true }); });
    req.on('error', () => resolve({ disconnected: true }));
    if (body) req.write(body);
    req.end();
  });
}

test('proxy bounds requests, responses, upstream waits, concurrency, and telemetry while stripping proxy credentials', async () => {
  let receivedHeaders = null;
  let receivedCount = 0;
  const target = http.createServer((req, res) => {
    receivedCount++;
    receivedHeaders = req.headers;
    if (req.url === '/slow') {
      setTimeout(() => { if (!res.destroyed) res.end('late'); }, 150);
      return;
    }
    if (req.url === '/large') {
      res.writeHead(200, { 'Content-Type': 'text/plain', 'Connection': 'keep-alive, X-Hop', 'X-Hop': 'hop-secret', 'X-Fixture': 'large' });
      res.end('x'.repeat(4096));
      return;
    }
    res.writeHead(200, { 'Content-Type': 'text/plain', 'Connection': 'keep-alive, X-Hop', 'X-Hop': 'hop-secret', 'X-Fixture': 'ok' });
    res.end('ok');
  });
  await listen(target);
  const port = target.address().port;
  const proxy = new ControlledEgressProxy({
    requireAuth: true, username: 'proxy-user', password: 'synthetic-proxy-secret',
    allowedPorts: [port], _testBypassSsrf: true, maxRequestBytes: 8,
    maxResponseBytes: 128, upstreamTimeoutMs: 30, maxTelemetryRecords: 2,
    maxConcurrentConnections: 4, maxRequestsPerJob: 16
  });
  const info = await proxy.start();
  const targetUrl = `http://127.0.0.1:${port}`;
  try {
    const oversizedHeaderResponse = await new Promise(resolve => {
      const socket = net.connect(info.port, info.host);
      let response = '';
      socket.setTimeout(1000, () => { socket.destroy(); resolve(response); });
      socket.on('data', chunk => { response += chunk.toString(); });
      socket.on('close', () => resolve(response));
      socket.on('error', () => resolve(response));
      socket.on('connect', () => socket.write(
        `GET ${targetUrl}/ok HTTP/1.1\r\nHost: 127.0.0.1\r\nProxy-Authorization: Basic ${Buffer.from(`${info.username}:${info.password}`).toString('base64')}\r\nX-Oversized: ${'x'.repeat(20 * 1024)}\r\n\r\n`
      ));
    });
    assert.doesNotMatch(oversizedHeaderResponse, /200 OK/, 'oversized headers must not reach upstream');
    assert.equal(receivedCount, 0);

    const ok = await proxyRequest(info, `${targetUrl}/ok`, { headers: { 'X-Request-Test': 'present' } });
    assert.equal(ok.status, 200);
    assert.equal(ok.body, 'ok');
    assert.equal(ok.headers['x-hop'], undefined, 'connection-nominated hop-by-hop headers must be removed');
    assert.equal(receivedHeaders['proxy-authorization'], undefined, 'proxy credentials must never reach the destination');
    assert.equal(receivedHeaders['proxy-connection'], undefined);

    const oversizedRequest = await proxyRequest(info, `${targetUrl}/ok`, {
      method: 'GET', headers: { 'content-length': '12' }, body: 'x'.repeat(12)
    });
    assert.equal(oversizedRequest.status, 413);
    assert.equal(receivedCount, 1, 'oversized requests must be rejected before upstream forwarding');

    const oversizedResponse = await proxyRequest(info, `${targetUrl}/large`);
    assert.ok(oversizedResponse.disconnected || oversizedResponse.aborted || oversizedResponse.status === 200);
    assert.ok(proxy.blockedRequests.some(item => item.type === 'RESPONSE_TOO_LARGE'));

    const slow = await proxyRequest(info, `${targetUrl}/slow`);
    assert.equal(slow.status, 502, 'upstream timeout should return a bounded failure instead of hanging');
    assert.ok(proxy.requestCount <= 16);
    assert.ok(proxy.server.maxConnections <= 4);
    assert.equal(proxy.server.maxRequestsPerSocket, 16);
    assert.equal(proxy.requestCount <= proxy.maxRequestsPerJob, true);
    assert.ok(proxy.allowedRequests.length <= 2, 'telemetry retention must remain bounded');
    assert.ok(proxy.blockedRequests.length <= 2, 'blocked telemetry retention must remain bounded');
  } finally {
    await proxy.stop();
    await close(target);
  }
});
