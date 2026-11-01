import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { randomBytes } from 'node:crypto';
import { test } from 'node:test';
import { createApp } from '../backend/server.js';
import { createCaseAccessCredential, verifyCaseAccessCredential } from '../core/case_access.js';
import { InvestigationEngine } from '../core/investigation_engine.js';

const operatorToken = randomBytes(32).toString('base64url');
const caseAId = `TL-2026-1031-1301-${randomBytes(6).toString('hex').toUpperCase()}`;
const caseBId = `TL-2026-1031-1302-${randomBytes(6).toString('hex').toUpperCase()}`;

function testCase(id, credential) {
  return {
    id,
    target: 'http://127.0.0.1/',
    status: 'RUNNING',
    currentStage: 'ISOLATED_LIVE',
    evidence: [],
    schema: { id, target: 'http://127.0.0.1/', status: 'RUNNING', lifecycleState: 'running', evidence: [],
      interactiveSession: { enabled: true, status: 'RUNNING', events: [], actionCount: 0, screenshotCount: 0 } },
    _caseAccessVerifier: credential.verifier,
    _caseAccessExpiresAt: Date.now() + 60 * 60 * 1000,
    _sseClients: new Set(),
    addEvidence() { return { id: `ev-${randomBytes(4).toString('hex')}` }; },
    log(message) { this.logs = [...(this.logs || []), message]; },
    emit() {}
  };
}

test('case credentials scope case data, SSE, interactions, screenshots, artifacts, and cancellation', async () => {
  const credentialA = createCaseAccessCredential();
  const credentialB = createCaseAccessCredential();
  const caseA = testCase(caseAId, credentialA);
  const caseB = testCase(caseBId, credentialB);
  let abortsA = 0;
  let abortsB = 0;
  caseA._abortController = { abort() { abortsA++; } };
  caseB._abortController = { abort() { abortsB++; } };

  const screenshotRoot = path.resolve('data', 'screenshots');
  fs.mkdirSync(screenshotRoot, { recursive: true });
  const screenshotA = path.join(screenshotRoot, `${caseAId}.png`);
  const screenshotB = path.join(screenshotRoot, `${caseBId}.png`);
  const artifactA = path.join(screenshotRoot, `${caseAId}-interactive-test.png`);
  const artifactId = randomBytes(16).toString('hex');
  const png = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);
  fs.writeFileSync(screenshotA, png, { flag: 'wx' });
  fs.writeFileSync(screenshotB, png, { flag: 'wx' });
  fs.writeFileSync(artifactA, png, { flag: 'wx' });
  caseA._interactiveArtifacts = new Map([[artifactId, artifactA]]);

  const cases = new Map([[caseAId, caseA], [caseBId, caseB]]);
  const server = createApp({ apiToken: operatorToken, cases }).listen(0, '127.0.0.1');
  await new Promise(resolve => server.once('listening', resolve));
  const base = `http://127.0.0.1:${server.address().port}`;
  const operator = { Authorization: `Bearer ${operatorToken}` };
  const authorized = credential => ({ ...operator, 'X-TrustLayer-Case-Access': credential.token });
  const at = (route, options = {}) => fetch(`${base}${route}`, options);
  const jsonPost = (headers, body = {}) => ({ method: 'POST', headers: { ...headers, 'Content-Type': 'application/json' }, body: JSON.stringify(body) });

  try {
    // Operator authentication and case permission are independent gates.
    assert.equal((await at(`/api/cases/${caseAId}`, { headers: { 'X-TrustLayer-Case-Access': credentialA.token } })).status, 401);
    assert.equal((await at(`/api/cases/${caseAId}`, { headers: operator })).status, 404);
    assert.equal((await at(`/api/cases/${caseAId}`, { headers: authorized({ token: randomBytes(32).toString('base64url') }) })).status, 404);
    assert.equal((await at(`/api/cases/${caseAId}`, { headers: authorized(credentialA) })).status, 200);
    assert.equal((await at(`/api/cases/${caseBId}`, { headers: authorized(credentialA) })).status, 404, 'case A credential must not authorize case B');
    assert.equal((await at(`/api/cases/${caseBId}/live-inspect`, jsonPost(authorized(credentialA), { consentConfirmed: true }))).status, 404,
      'case A credential must not authorize live inspection of case B');
    const listedWithA = await (await at('/api/cases', { headers: authorized(credentialA) })).json();
    assert.deepEqual(listedWithA.cases.map(item => item.id), [caseAId], 'case summaries must be filtered by each case credential');
    assert.equal((await (await at('/api/cases', { headers: operator })).json()).cases.length, 0);

    // Correct case permission reaches the interaction handler; no live worker
    // is attached in this deterministic API test, so it must still fail closed.
    assert.equal((await at(`/api/cases/${caseAId}/interactions`, jsonPost(operator, { action: { type: 'back' } }))).status, 404);
    assert.equal((await at(`/api/cases/${caseAId}/interactions`, jsonPost(authorized(credentialB), { action: { type: 'back' } }))).status, 404);
    assert.equal((await at(`/api/cases/${caseAId}/interactions`, jsonPost(authorized(credentialA), { action: { type: 'back' } }))).status, 409);
    assert.equal(caseA.schema.interactiveSession.actionCount, 0);

    // Screenshot and interactive artifact delivery is case-scoped.
    assert.equal((await at(`/api/cases/${caseAId}/screenshot`, { headers: operator })).status, 404);
    const screenshotResponse = await at(`/api/cases/${caseAId}/screenshot`, { headers: authorized(credentialA) });
    assert.equal(screenshotResponse.status, 200);
    assert.equal((await screenshotResponse.arrayBuffer()).byteLength, png.length);
    assert.equal((await at(`/api/cases/${caseBId}/screenshot`, { headers: authorized(credentialA) })).status, 404);
    const artifactRoute = `/api/cases/${caseAId}/interactive-artifacts/${artifactId}`;
    assert.equal((await at(artifactRoute, { headers: operator })).status, 404);
    const artifactResponse = await at(artifactRoute, { headers: authorized(credentialA) });
    assert.equal(artifactResponse.status, 200);
    assert.equal((await artifactResponse.arrayBuffer()).byteLength, png.length);
    assert.equal((await at(`/api/cases/${caseBId}/interactive-artifacts/${artifactId}`, { headers: authorized(credentialA) })).status, 404);

    // Unauthorized cancellation must not mutate or abort either case.
    assert.equal((await at(`/api/cases/${caseAId}/cancel-live`, jsonPost(operator))).status, 404);
    assert.equal((await at(`/api/cases/${caseAId}/cancel`, jsonPost(authorized(credentialB)))).status, 404);
    assert.equal(abortsA, 0);
    assert.equal(abortsB, 0);
    assert.equal((await at(`/api/cases/${caseAId}/cancel-live`, jsonPost(authorized(credentialA)))).status, 200);
    assert.equal(abortsA, 1);
    assert.equal(abortsB, 0);
    assert.equal((await at(`/api/cases/${caseBId}/cancel`, jsonPost(authorized(credentialB)))).status, 200);
    assert.equal(abortsB, 1, 'correct case B credential must authorize cancellation of case B');

    // SSE requires both credentials and removes its listener after disconnect.
    assert.equal((await at(`/api/cases/${caseAId}/events`, { headers: operator })).status, 404);
    assert.equal((await at(`/api/cases/${caseAId}/events`, { headers: authorized(credentialB) })).status, 404);
    const abort = new AbortController();
    const eventResponse = await at(`/api/cases/${caseAId}/events`, { headers: authorized(credentialA), signal: abort.signal });
    assert.equal(eventResponse.status, 200);
    const reader = eventResponse.body.getReader();
    assert.match(new TextDecoder().decode((await reader.read()).value), /snapshot/);
    assert.equal(caseA._sseClients.size, 1);
    abort.abort();
    await reader.cancel().catch(() => {});
    for (let i = 0; i < 30 && caseA._sseClients.size; i++) await new Promise(resolve => setTimeout(resolve, 10));
    assert.equal(caseA._sseClients.size, 0);

    // Credentials never enter schemas, logs, API errors, or target URLs.
    const wrong = randomBytes(32).toString('base64url');
    const denied = await at(`/api/cases/${caseAId}`, { headers: authorized({ token: wrong }) });
    assert.equal((await denied.text()).includes(wrong), false);
    assert.equal(JSON.stringify(caseA.schema).includes(credentialA.token), false);
    assert.equal(JSON.stringify(caseA.logs || []).includes(credentialA.token), false);
    assert.equal(caseA.target, 'http://127.0.0.1/');
    assert.equal(Object.hasOwn(caseA, '_caseAccessToken'), false);
    assert.equal(verifyCaseAccessCredential(credentialA.token, caseA._caseAccessVerifier), true);

    // Unknown, post-restart, and expired case access all fail closed.
    assert.equal((await at('/api/cases/TL-2026-1031-1303-UNKNOWN', { headers: authorized(credentialA) })).status, 404);
    const validExpiry = caseA._caseAccessExpiresAt;
    caseA._caseAccessExpiresAt = Date.now() - 1;
    assert.equal((await at(`/api/cases/${caseAId}`, { headers: authorized(credentialA) })).status, 404, 'expired case credentials must fail closed');
    caseA._caseAccessExpiresAt = validExpiry;
  } finally {
    server.closeAllConnections();
    await new Promise(resolve => server.close(resolve));
    fs.rmSync(screenshotA, { force: true });
    fs.rmSync(screenshotB, { force: true });
    fs.rmSync(artifactA, { force: true });
  }
});

test('case creation issues a one-time verifier-backed credential for local Mode A cases', async () => {
  const cases = new Map();
  const launchedCases = [];
  const server = createApp({ apiToken: operatorToken, cases, investigateCase: (...args) => {
    launchedCases.push(args);
    return InvestigationEngine.investigate(args[0]);
  } }).listen(0, '127.0.0.1');
  await new Promise(resolve => server.once('listening', resolve));
  const base = `http://127.0.0.1:${server.address().port}`;
  try {
    const response = await fetch(`${base}/api/cases`, {
      method: 'POST',
      headers: { Authorization: `Bearer ${operatorToken}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({ target: 'http://127.0.0.1/', targetType: 'URL', inspectionMode: 'URL_ONLY' })
    });
    assert.equal(response.status, 201);
    const created = await response.json();
    assert.equal(typeof created.caseAccessToken, 'string');
    assert.equal(created.caseAccessToken.length, 43);
    const setCookie = response.headers.get('set-cookie') || '';
    assert.match(setCookie, /HttpOnly/);
    assert.match(setCookie, /SameSite=Strict/);
    assert.match(setCookie, /Path=\/api/);
    assert.equal(new RegExp(`trustlayer_case_${created.caseId}=([^;]+)`).exec(setCookie)?.[1], created.caseAccessToken);
    const icase = cases.get(created.caseId);
    assert.ok(icase);
    assert.equal(icase.schema.inspectionMode, 'URL_ONLY');
    assert.equal(icase.target, 'http://127.0.0.1/');
    await new Promise(resolve => setImmediate(resolve));
    assert.equal(launchedCases.length, 1, 'Mode A case creation must still start its investigation pipeline');
    assert.equal(launchedCases[0].length, 1, 'the raw case credential must not be forwarded to the investigation pipeline');
    assert.equal(launchedCases[0][0], icase);
    for (let attempt = 0; attempt < 200 && !icase.schema.completedAt; attempt++) await new Promise(resolve => setTimeout(resolve, 10));
    assert.ok(icase.schema.completedAt, 'local-IP Mode A analysis should complete without target HTTP or public DNS');
    assert.equal(icase.schema.inspectionMode, 'URL_ONLY');
    assert.equal(Object.values(icase).includes(created.caseAccessToken), false);
    assert.equal(verifyCaseAccessCredential(created.caseAccessToken, icase._caseAccessVerifier), true);
    assert.equal(JSON.stringify(icase.schema).includes(created.caseAccessToken), false);
    const cookieRead = await fetch(`${base}/api/cases/${created.caseId}`, {
      headers: { Authorization: `Bearer ${operatorToken}`, Cookie: setCookie.split(';')[0] }
    });
    assert.equal(cookieRead.status, 200, 'browser case cookie must authorize matching case routes');
    assert.equal(JSON.stringify(launchedCases).includes(created.caseAccessToken), false, 'credential must not reach worker or target-facing pipeline arguments');
    assert.equal(JSON.stringify(icase.logs || []).includes(created.caseAccessToken), false, 'credential must not enter case logs');
    assert.equal((await (await fetch(`${base}/api/cases/${created.caseId}`, { headers: { Authorization: `Bearer ${operatorToken}` } })).text()).includes(created.caseAccessToken), false);
    const listed = await fetch(`${base}/api/cases`, {
      headers: { Authorization: `Bearer ${operatorToken}`, 'X-TrustLayer-Case-Access': created.caseAccessToken }
    });
    assert.deepEqual((await listed.json()).cases.map(item => item.id), [created.caseId]);
  } finally {
    server.closeAllConnections();
    await new Promise(resolve => server.close(resolve));
  }
});
