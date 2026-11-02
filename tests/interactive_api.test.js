import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { test } from 'node:test';
import { createApp } from '../backend/server.js';
import { createCaseAccessCredential } from '../core/case_access.js';
import { globalJobController } from '../core/investigators/live_job_controller.js';

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

test('pointer traffic has an independent budget; discrete actions stay available and repeated action IDs execute once', async () => {
  const token = randomBytes(32).toString('base64url');
  const id = 'TL-2026-1101-1540-ACT';
  const access = createCaseAccessCredential();
  const icase = { id, _caseAccessVerifier: access.verifier, _caseAccessExpiresAt: Date.now() + 60_000,
    schema: { id, evidence: [], liveInspection: { runtimeSessionActive: true },
      interactiveSession: { enabled: true, status: 'RUNNING', events: [], actionCount: 0, screenshotCount: 0 } } };
  const calls = [];
  const previousInteract = globalJobController.interact;
  globalJobController.interact = async (caseId, action) => {
    calls.push({ caseId, type: action.type });
    return { ok: true, action: action.type, url: 'http://fixture.invalid/' };
  };
  const server = createApp({ apiToken: token, cases: new Map([[id, icase]]) }).listen(0, '127.0.0.1');
  await new Promise(resolve => server.once('listening', resolve));
  const base = `http://127.0.0.1:${server.address().port}`;
  const headers = { Authorization: `Bearer ${token}`, 'X-TrustLayer-Case-Access': access.token, 'Content-Type': 'application/json' };
  const submit = (action, actionId = randomBytes(16).toString('hex')) => fetch(`${base}/api/cases/${id}/interactions`, {
    method: 'POST', headers, body: JSON.stringify({ actionId, action })
  });
  try {
    for (let index = 0; index < 40; index++) {
      const response = await submit({ type: 'pointer_move', x: index * 100, y: 5000 });
      assert.equal(response.status, 200, `pointer movement ${index + 1} should use only the pointer budget`);
    }
    for (const action of [
      { type: 'click', selector: '#safe-button' },
      { type: 'type', selector: '#note', text: 'harmless text' },
      { type: 'pointer_scroll', x: 5000, y: 5000, direction: 'down', pixels: 100 }
    ]) assert.equal((await submit(action)).status, 200, `${action.type} remains available after pointer movement`);
    assert.equal(calls.filter(call => call.type === 'pointer_move').length, 40);

    const repeatedId = randomBytes(16).toString('hex');
    const clickAction = { type: 'click', selector: '#safe-button' };
    const beforeDuplicate = calls.filter(call => call.type === 'click').length;
    const [first, concurrentDuplicate] = await Promise.all([submit(clickAction, repeatedId), submit(clickAction, repeatedId)]);
    assert.equal(first.status, 200);
    assert.equal(concurrentDuplicate.status, 200);
    assert.equal((await submit(clickAction, repeatedId)).status, 200, 'a completed retry returns its cached result');
    assert.equal(calls.filter(call => call.type === 'click').length, beforeDuplicate + 1,
      'the worker receives an action ID only once, including concurrent retries');
    assert.equal((await submit({ type: 'scroll', direction: 'down', pixels: 50 }, repeatedId)).status, 409,
      'an action ID cannot be reused for a different action');

    for (let index = 0; index < 26; index++) {
      assert.equal((await submit({ type: 'back' })).status, 200);
    }
    assert.equal((await submit({ type: 'back' })).status, 429,
      'the independent discrete-action limit still rejects excessive requests');
  } finally {
    globalJobController.interact = previousInteract;
    server.closeAllConnections();
    await new Promise(resolve => server.close(resolve));
  }
});

test('cancellation is idempotent and an in-flight viewport capture settles without publishing a stale frame', async () => {
  const token = randomBytes(32).toString('base64url');
  const id = 'TL-2026-1101-1540-CAN';
  const access = createCaseAccessCredential();
  let completeEvents = 0;
  let releaseCapture;
  let captureStarted;
  const started = new Promise(resolve => { captureStarted = resolve; });
  const icase = { id, _caseAccessVerifier: access.verifier, _caseAccessExpiresAt: Date.now() + 60_000,
    _abortController: new AbortController(),
    schema: { id, status: 'COMPLETED', evidence: [], liveInspection: { runtimeSessionActive: true },
      interactiveSession: { enabled: true, status: 'RUNNING', events: [], actionCount: 0, screenshotCount: 0 } },
    log() {}, emit(event) { if (event === 'complete') completeEvents++; } };
  const previousCapture = globalJobController.captureViewport;
  globalJobController.captureViewport = async () => {
    captureStarted();
    return new Promise(resolve => { releaseCapture = resolve; });
  };
  const server = createApp({ apiToken: token, cases: new Map([[id, icase]]) }).listen(0, '127.0.0.1');
  await new Promise(resolve => server.once('listening', resolve));
  const base = `http://127.0.0.1:${server.address().port}`;
  const headers = { Authorization: `Bearer ${token}`, 'X-TrustLayer-Case-Access': access.token };
  try {
    const frameRequest = fetch(`${base}/api/cases/${id}/interactive-viewport`, { headers });
    await started;
    const cancelUrl = `${base}/api/cases/${id}/cancel-live`;
    const firstCancel = await fetch(cancelUrl, { method: 'POST', headers });
    assert.equal(firstCancel.status, 200);
    assert.equal(icase.schema.interactiveSession.status, 'CANCELLED');
    const repeatedCancel = await fetch(cancelUrl, { method: 'POST', headers });
    assert.equal(repeatedCancel.status, 200);
    assert.equal((await repeatedCancel.json()).alreadyStopped, true);
    assert.equal(completeEvents, 1, 'repeated cancellation must not emit duplicate terminal events');

    releaseCapture({ ok: true, viewportBase64: Buffer.from('stale frame').toString('base64') });
    const lateFrame = await frameRequest;
    assert.equal(lateFrame.status, 204, 'late capture settles as no-content once the authorized case is terminal');
    assert.equal(await lateFrame.text(), '');

    const stoppedFrame = await fetch(`${base}/api/cases/${id}/interactive-viewport`, { headers });
    assert.equal(stoppedFrame.status, 204, 'new polls after cancellation also settle without a misleading worker error');
  } finally {
    globalJobController.captureViewport = previousCapture;
    server.closeAllConnections();
    await new Promise(resolve => server.close(resolve));
  }
});
