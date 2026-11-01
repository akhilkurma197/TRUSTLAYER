import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { test } from 'node:test';
import { createApp } from '../backend/server.js';

async function withTestServer(run) {
  const apiToken = randomBytes(32).toString('base64url');
  const cases = new Map();
  const app = createApp({ apiToken, cases, investigateCase: async () => {} });
  const server = app.listen(0, '127.0.0.1');
  await new Promise(resolve => server.once('listening', resolve));
  const base = `http://127.0.0.1:${server.address().port}`;
  try {
    await run({ apiToken, cases, base });
  } finally {
    server.closeAllConnections();
    await new Promise(resolve => server.close(resolve));
  }
}

test('case creation persists and returns the explicitly selected interactive-controls flag', async () => {
  await withTestServer(async ({ apiToken, cases, base }) => {
    const create = (payload, headers = {}) => fetch(`${base}/api/cases`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', ...headers },
      body: JSON.stringify(payload)
    });
    const modeCBase = { target: 'https://fixture.invalid/', inspectionMode: 'ISOLATED_LIVE', consentConfirmed: true };

    assert.equal((await create({ ...modeCBase, interactive: true })).status, 401,
      'operator authentication is still required before an interactive case can be created');
    assert.equal(cases.size, 0);
    assert.equal((await create({ target: 'https://fixture.invalid/', interactive: true }, {
      Authorization: `Bearer ${apiToken}`
    })).status, 400, 'interactive controls remain restricted to Mode C');
    assert.equal(cases.size, 0);

    const enabledResponse = await create({ ...modeCBase, interactive: true }, {
      Authorization: `Bearer ${apiToken}`
    });
    assert.equal(enabledResponse.status, 201);
    const enabled = await enabledResponse.json();
    assert.equal(enabled.interactiveEnabled, true);
    assert.equal(enabled.inspectionMode, 'ISOLATED_LIVE');
    assert.equal(cases.get(enabled.caseId).schema.interactiveSession.enabled, true,
      'the selected value is persisted before the investigation pipeline starts');

    const disabledResponse = await create({ ...modeCBase, target: 'https://another.invalid/', interactive: false }, {
      Authorization: `Bearer ${apiToken}`
    });
    assert.equal(disabledResponse.status, 201);
    const disabled = await disabledResponse.json();
    assert.equal(disabled.interactiveEnabled, false);
    assert.equal(Object.hasOwn(cases.get(disabled.caseId).schema, 'interactiveSession'), false,
      'a case created without opt-in remains non-interactive');

    const unauthorizedUpgrade = await fetch(`${base}/api/cases/${disabled.caseId}/live-inspect`, {
      method: 'POST', headers: { Authorization: `Bearer ${apiToken}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({ consentConfirmed: true, interactive: true })
    });
    assert.equal(unauthorizedUpgrade.status, 404,
      'operator authentication alone does not authorize access to an existing case');
    const accessToken = disabled.caseAccessToken;
    const authorizedUpgrade = await fetch(`${base}/api/cases/${disabled.caseId}/live-inspect`, {
      method: 'POST', headers: {
        Authorization: `Bearer ${apiToken}`, 'X-TrustLayer-Case-Access': accessToken,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({ consentConfirmed: true, interactive: true })
    });
    assert.equal(authorizedUpgrade.status, 200);
    assert.equal(Object.hasOwn(cases.get(disabled.caseId).schema, 'interactiveSession'), false,
      'authorizing Mode C on an existing case does not convert it to interactive');
  });
});
