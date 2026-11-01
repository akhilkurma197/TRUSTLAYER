import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { randomBytes } from 'node:crypto';
import { test } from 'node:test';
import { createApp } from '../backend/server.js';
import { createCaseAccessCredential } from '../core/case_access.js';

test('API authentication protects case, SSE, and screenshot routes and issues scoped browser sessions', async () => {
  const apiToken = randomBytes(32).toString('base64url');
  const caseId = 'TL-2026-1031-1200-ABC';
  const caseAccess = createCaseAccessCredential();
  const cases = new Map([[caseId, {
    id: caseId, target: 'https://example.invalid/', status: 'COMPLETED', currentStage: 'DONE',
    assessment: {}, evidence: [], schema: { id: caseId, target: 'https://example.invalid/', status: 'COMPLETED' },
    _caseAccessVerifier: caseAccess.verifier, _caseAccessExpiresAt: Date.now() + 60 * 60 * 1000
  }]]);
  const app = createApp({ apiToken, cases });
  const server = app.listen(0, '127.0.0.1');
  await new Promise(resolve => server.once('listening', resolve));
  const base = `http://127.0.0.1:${server.address().port}`;
  const bearer = { Authorization: `Bearer ${apiToken}` };
  const fetchAt = (path, options = {}) => fetch(`${base}${path}`, options);

  try {
    assert.throws(() => createApp({ apiToken: 'short' }), /32 to 1024 bytes/);
    assert.throws(() => createApp({ apiToken: 'x'.repeat(1025) }), /32 to 1024 bytes/);
    for (const path of ['/api/cases', `/api/cases/${caseId}`, `/api/cases/${caseId}/evidence-report`, `/api/cases/${caseId}/events`, `/api/cases/${caseId}/screenshot`]) {
      assert.equal((await fetchAt(path)).status, 401, `${path} must reject anonymous access`);
    }
    const unauthenticatedCreate = await fetchAt('/api/cases', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ target: 'https://example.invalid/' })
    });
    assert.equal(unauthenticatedCreate.status, 401, 'costly case creation must authenticate before request handling');
    assert.equal(cases.size, 1);

    assert.equal((await fetchAt('/api/cases', { headers: { Authorization: 'Bearer incorrect-token' } })).status, 401);
    const caseHeaders = { ...bearer, 'X-TrustLayer-Case-Access': caseAccess.token };
    assert.equal((await fetchAt(`/api/cases/${caseId}`, { headers: bearer })).status, 404);
    assert.equal((await fetchAt(`/api/cases/${caseId}`, { headers: caseHeaders })).status, 200);
    assert.equal((await fetchAt(`/api/cases/${caseId}/evidence-report`, { headers: bearer })).status, 404,
      'operator authentication without the case credential must not expose the evidence report');
    const reportResponse = await fetchAt(`/api/cases/${caseId}/evidence-report`, { headers: caseHeaders });
    assert.equal(reportResponse.status, 200);
    assert.equal((await reportResponse.json()).verdict.scope, 'URL_ONLY');
    const unknown = await fetchAt('/api/cases/TL-2026-1031-1200-XYZ', { headers: bearer });
    const malformed = await fetchAt('/api/cases/not-a-case-id', { headers: bearer });
    assert.equal(unknown.status, 404);
    assert.equal(malformed.status, 404);
    assert.equal((await unknown.text()), await malformed.text(), 'unknown and malformed IDs must not reveal case existence');
    assert.equal((await fetchAt('/data/screenshots/TL-2026-1031-1200-ABC.png')).status, 404, 'repository static serving must not expose evidence files');
    assert.equal((await fetchAt('/docs/phase-zero-security-audit.md')).status, 404, 'repository static serving must not expose audit files');
    assert.equal((await fetchAt('/vendor/jsQR.js')).status, 200, 'the explicitly mounted frontend vendor asset remains available');

    const loginSecretCanary = 'SYNTHETIC-OPERATOR-SECRET-CANARY';
    const badLogin = await fetchAt('/api/auth/session', {
      method: 'POST', headers: { 'Content-Type': 'application/json', Origin: base },
      body: JSON.stringify({ token: loginSecretCanary })
    });
    assert.equal(badLogin.status, 401);
    assert.equal((await badLogin.text()).includes(loginSecretCanary), false, 'authentication errors must not echo synthetic secret values');
    const login = await fetchAt('/api/auth/session', {
      method: 'POST', headers: { 'Content-Type': 'application/json', Origin: base },
      body: JSON.stringify({ token: apiToken })
    });
    assert.equal(login.status, 204);
    const cookie = login.headers.get('set-cookie');
    assert.match(cookie || '', /HttpOnly/);
    assert.match(cookie || '', /SameSite=Strict/);
    assert.match(cookie || '', /Path=\/api/);
    const sessionId = /trustlayer_session=([^;]+)/.exec(cookie || '')?.[1];
    assert.ok(sessionId);
    assert.equal((await fetchAt(`/api/cases/${caseId}`, { headers: { Cookie: `trustlayer_session=${sessionId}; trustlayer_case_${caseId}=${caseAccess.token}` } })).status, 200);

    const csrfDenied = await fetchAt('/api/cases', {
      method: 'POST', headers: { Cookie: `trustlayer_session=${sessionId}`, Origin: 'https://attacker.invalid', 'Content-Type': 'application/json' },
      body: JSON.stringify({ target: 'https://example.invalid/' })
    });
    assert.equal(csrfDenied.status, 403);
    const logout = await fetchAt('/api/auth/logout', {
      method: 'POST', headers: { Cookie: `trustlayer_session=${sessionId}; trustlayer_case_${caseId}=${caseAccess.token}`, Origin: base }
    });
    assert.equal(logout.status, 204);
    assert.match(logout.headers.get('set-cookie') || '', new RegExp(`trustlayer_case_${caseId}=; Path=/api; HttpOnly; SameSite=Strict; Max-Age=0`));
    assert.equal((await fetchAt('/api/cases', { headers: { Cookie: `trustlayer_session=${sessionId}` } })).status, 401);
  } finally {
    server.closeAllConnections();
    await new Promise(resolve => server.close(resolve));
  }
});

test('API bounds malformed and oversized JSON, rate limits creation, and closes SSE clients', async () => {
  const apiToken = randomBytes(32).toString('base64url');
  const caseId = 'TL-2026-1031-1201-DEF';
  const caseAccess = createCaseAccessCredential();
  const owned = { id: caseId, target: '', schema: { id: caseId }, _caseAccessVerifier: caseAccess.verifier,
    _caseAccessExpiresAt: Date.now() + 60 * 60 * 1000, _sseClients: new Set(), on() {} };
  const app = createApp({ apiToken, cases: new Map([[caseId, owned]]), rateLimits: { createPerMinute: 1 } });
  const server = app.listen(0, '127.0.0.1');
  await new Promise(resolve => server.once('listening', resolve));
  const base = `http://127.0.0.1:${server.address().port}`;
  const headers = { Authorization: `Bearer ${apiToken}`, 'Content-Type': 'application/json' };
  try {
    const malformed = await fetch(`${base}/api/cases`, { method: 'POST', headers, body: '{' });
    assert.equal(malformed.status, 400);
    assert.deepEqual(await malformed.json(), { error: 'Malformed JSON request body.' });
    const oversized = await fetch(`${base}/api/cases`, { method: 'POST', headers, body: JSON.stringify({ target: 'x'.repeat(65 * 1024) }) });
    assert.equal(oversized.status, 413);
    assert.match((await oversized.text()), /64 KiB limit/);
    const invalid = await fetch(`${base}/api/cases`, { method: 'POST', headers, body: JSON.stringify({ target: '' }) });
    assert.equal(invalid.status, 400);
    const limited = await fetch(`${base}/api/cases`, { method: 'POST', headers, body: JSON.stringify({ target: '' }) });
    assert.equal(limited.status, 429);
    assert.equal((await fetch(`${base}/api/cases/${caseId}/events`)).status, 401);

    const abort = new AbortController();
    const response = await fetch(`${base}/api/cases/${caseId}/events`, { headers: { Authorization: `Bearer ${apiToken}`, 'X-TrustLayer-Case-Access': caseAccess.token }, signal: abort.signal });
    assert.equal(response.status, 200);
    const reader = response.body.getReader();
    const first = await reader.read();
    assert.match(new TextDecoder().decode(first.value), /snapshot/);
    assert.equal(owned._sseClients.size, 1, 'completed request body must not be mistaken for a closed SSE response');
    abort.abort();
    await reader.cancel().catch(() => {});
    for (let i = 0; i < 20 && owned._sseClients.size; i++) await new Promise(resolve => setTimeout(resolve, 10));
    assert.equal(owned._sseClients.size, 0, 'disconnected SSE response must be removed from its case');
  } finally {
    server.closeAllConnections();
    await new Promise(resolve => server.close(resolve));
  }
});

test('screenshot delivery requires a known case and confines artifacts to its screenshot directory', async () => {
  const apiToken = randomBytes(32).toString('base64url');
  const caseId = `TL-2026-1031-1203-${randomBytes(6).toString('hex').toUpperCase()}`;
  const caseAccess = createCaseAccessCredential();
  const cases = new Map([[caseId, { id: caseId, schema: { id: caseId }, _caseAccessVerifier: caseAccess.verifier,
    _caseAccessExpiresAt: Date.now() + 60 * 60 * 1000 }]]);
  const screenshotPath = path.resolve('data', 'screenshots', `${caseId}.png`);
  const app = createApp({ apiToken, cases });
  const server = app.listen(0, '127.0.0.1');
  await new Promise(resolve => server.once('listening', resolve));
  const base = `http://127.0.0.1:${server.address().port}`;
  const caseHeaders = { Authorization: `Bearer ${apiToken}`, 'X-TrustLayer-Case-Access': caseAccess.token };
  try {
    const traversal = await fetch(`${base}/api/cases/${caseId}/screenshot?type=..%2F..%2F..%2Fbackend%2Fserver.js`, {
      headers: caseHeaders
    });
    assert.equal(traversal.status, 404);
    assert.equal(fs.existsSync(screenshotPath), false);
    fs.writeFileSync(screenshotPath, Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]), { flag: 'wx' });
    const response = await fetch(`${base}/api/cases/${caseId}/screenshot`, { headers: caseHeaders });
    assert.equal(response.status, 200);
    assert.equal(response.headers.get('content-type'), 'image/png');
    assert.equal((await response.arrayBuffer()).byteLength, 8);
    const orphan = await fetch(`${base}/api/cases/TL-2026-1031-1203-000000000000/screenshot`, { headers: { Authorization: `Bearer ${apiToken}` } });
    assert.equal(orphan.status, 404);
  } finally {
    server.closeAllConnections();
    await new Promise(resolve => server.close(resolve));
    fs.rmSync(screenshotPath, { force: true });
  }
});
