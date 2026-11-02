import assert from 'node:assert/strict';
import http from 'node:http';
import { once } from 'node:events';
import { test } from 'node:test';
import { createEgressProbeHandler, createEgressProbeServers } from './fixtures/egress_probe_endpoint.js';

async function listen(server) {
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  return server.address().port;
}

test('controlled endpoint acknowledges only bounded scheme-matched probe markers and logs peer metadata', async t => {
  const logs = [];
  const server = http.createServer(createEgressProbeHandler({ scheme: 'http', logger: line => logs.push(JSON.parse(line)) }));
  const port = await listen(server);
  t.after(async () => {
    server.closeAllConnections();
    await new Promise(resolve => server.close(resolve));
  });

  const request = headers => new Promise((resolve, reject) => {
    const req = http.get({ hostname: '127.0.0.1', port, path: '/probe', headers }, response => {
      const chunks = [];
      response.on('data', chunk => chunks.push(chunk));
      response.on('end', () => resolve({ status: response.statusCode, headers: response.headers,
        body: Buffer.concat(chunks).toString('utf8') }));
    });
    req.once('error', reject);
  });

  const marker = 'tl-egress-direct-http-123e4567-e89b-12d3-a456-426614174000';
  const ok = await request({ 'x-trustlayer-egress-probe': marker });
  assert.equal(ok.status, 200);
  assert.equal(ok.headers['x-trustlayer-probe-ack'], marker);
  assert.equal(ok.headers.location, undefined, 'probe endpoint must not redirect');
  assert.ok(Buffer.byteLength(ok.body) < 256);
  assert.deepEqual(logs, [{ event: 'trustlayer-egress-probe', scheme: 'http', marker, peerIp: '127.0.0.1' }]);

  const invalid = await request({ 'x-trustlayer-egress-probe': 'not-a-marker' });
  assert.equal(invalid.status, 400);
  assert.equal(invalid.headers['x-trustlayer-probe-ack'], undefined);
  assert.equal(logs.length, 1, 'untrusted marker data must not be written to logs');
});

test('HTTPS endpoint configuration requires valid, explicit TLS material before creating listeners', () => {
  assert.throws(() => createEgressProbeServers({}), /explicit TLS key and certificate/);
  assert.throws(() => createEgressProbeServers({ tlsKey: 'not a private key', tlsCert: 'not a certificate' }),
    /PEM|key|certificate|options/i);
});
