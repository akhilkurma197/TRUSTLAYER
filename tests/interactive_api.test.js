import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { test } from 'node:test';
import { createApp } from '../backend/server.js';
import { createCaseAccessCredential } from '../core/case_access.js';

test('interactive endpoints require authentication and enforce case/action boundaries', async () => {
  const token = randomBytes(32).toString('base64url');
  const id = 'TL-2026-1031-1200-ABC';
  const otherId = 'TL-2026-1031-1200-DEF';
  const credentials = new Map();
  const makeCase = caseId => {
    const access = createCaseAccessCredential();
    credentials.set(caseId, access);
    return { id: caseId, _caseAccessVerifier: access.verifier, _caseAccessExpiresAt: Date.now() + 60 * 60 * 1000,
      schema: { id: caseId, evidence: [], liveInspection: { runtimeSessionActive: true },
        interactiveSession: { enabled: true, status: 'RUNNING', events: [], actionCount: 0 } },
      addEvidence() { throw new Error('No artifact should be accepted in this test.'); } };
  };
  const cases = new Map([[id, makeCase(id)], [otherId, makeCase(otherId)]]);
  const server = createApp({ apiToken: token, cases }).listen(0, '127.0.0.1');
  await new Promise(resolve => server.once('listening', resolve));
  const base = `http://127.0.0.1:${server.address().port}`;
  const headers = { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' };
  const caseHeaders = caseId => ({ ...headers, 'X-TrustLayer-Case-Access': credentials.get(caseId).token });
  try {
    assert.equal((await fetch(`${base}/api/cases/${id}/interactions`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}' })).status, 401);
    assert.equal((await fetch(`${base}/api/cases/${id}/interactions`, { method: 'POST', headers, body: JSON.stringify({ action: { type: 'evaluate', expression: '1' } }) })).status, 404, 'operator authentication alone must not grant case access');
    assert.equal((await fetch(`${base}/api/cases/${id}/interactions`, { method: 'POST', headers: caseHeaders(otherId), body: JSON.stringify({ action: { type: 'back' } }) })).status, 404, 'another case credential must not authorize this case');
    assert.equal((await fetch(`${base}/api/cases/${id}/interactions`, { method: 'POST', headers: caseHeaders(id), body: JSON.stringify({ action: { type: 'evaluate', expression: '1' } }) })).status, 400);
    assert.equal((await fetch(`${base}/api/cases/${id}/interactions`, { method: 'POST', headers: caseHeaders(id), body: JSON.stringify({ action: { type: 'back' } }) })).status, 409, 'authorized case without worker must fail closed');
    const viewportAction = await fetch(`${base}/api/cases/${id}/interactions`, { method: 'POST', headers: caseHeaders(id),
      body: JSON.stringify({ action: { type: 'pointer_click', x: 5000, y: 5000 } }) });
    assert.equal(viewportAction.status, 409,
      'a valid coordinate action passes schema validation and then fails closed because this test has no worker');
    assert.equal((await viewportAction.json()).error, 'Interactive browser session is unavailable.');
    assert.equal((await fetch(`${base}/api/cases/${id}/interactive-artifacts/${'a'.repeat(32)}`, { headers: caseHeaders(id) })).status, 404);
    assert.equal((await fetch(`${base}/api/cases/${id}/interactive-artifacts/${'a'.repeat(32)}`)).status, 401);
    assert.equal((await fetch(`${base}/api/cases/${id}/interactive-viewport`, { headers })).status, 404,
      'operator authentication alone must not authorize viewport frames');
    assert.equal((await fetch(`${base}/api/cases/${id}/interactive-viewport`, { headers: caseHeaders(otherId) })).status, 404,
      'cross-case credentials must not authorize viewport frames');
    assert.equal((await fetch(`${base}/api/cases/${id}/interactive-viewport`, { headers: caseHeaders(id) })).status, 409,
      'viewport capture must fail closed when no active isolated worker is present');
    assert.equal(cases.get(id).schema.interactiveSession.actionCount, 0);
  } finally {
    server.closeAllConnections();
    await new Promise(resolve => server.close(resolve));
  }
});
