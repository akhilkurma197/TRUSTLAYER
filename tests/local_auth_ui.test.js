import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { test } from 'node:test';
import { chromium } from 'playwright';
import { createApp } from '../backend/server.js';

test('frontend keeps only an HttpOnly API session across reloads and exposes clear/replace controls', async () => {
  const apiToken = randomBytes(32).toString('base64url');
  const server = createApp({ apiToken, cases: new Map(), investigateCase: async () => {} }).listen(0, '127.0.0.1');
  await new Promise(resolve => server.once('listening', resolve));
  const base = `http://127.0.0.1:${server.address().port}`;
  let browser;
  try {
    browser = await chromium.launch({ headless: true });
    const context = await browser.newContext();
    const page = await context.newPage();
    let promptCount = 0;
    const promptTokens = [apiToken, 'invalid-local-token-canary', apiToken];
    page.on('dialog', async dialog => {
      if (dialog.type() === 'prompt') { promptCount++; await dialog.accept(promptTokens.shift() || ''); }
      else await dialog.accept();
    });
    await page.goto(`${base}/investigation.html`, { waitUntil: 'domcontentloaded' });
    const firstRequestStatus = await page.evaluate(async () => (await window.trustLayerApiFetch('/api/cases')).status);
    assert.equal(firstRequestStatus, 200);
    assert.equal(promptCount, 1, 'concurrent unauthenticated UI requests share one token prompt');

    const sessionCookie = async () => (await context.cookies(`${base}/api/`)).find(cookie => cookie.name === 'trustlayer_session');
    const firstCookie = await sessionCookie();
    assert.ok(firstCookie);
    assert.equal(firstCookie.httpOnly, true);
    assert.equal(firstCookie.sameSite, 'Strict');
    assert.equal(firstCookie.path, '/api');
    assert.equal(await page.evaluate(token => Object.values(localStorage).some(value => value.includes(token)), apiToken), false,
      'raw API token must not be stored in browser localStorage');
    assert.equal((await page.locator('body').innerText()).includes(apiToken), false, 'raw API token must not appear in page content');

    await page.reload({ waitUntil: 'domcontentloaded' });
    assert.equal(await page.evaluate(async () => (await window.trustLayerApiFetch('/api/cases')).status), 200);
    assert.equal(promptCount, 1, 'HttpOnly session cookie authenticates after a page reload without another token prompt');

    const clearButton = page.getByRole('button', { name: 'Clear API session' });
    await clearButton.click();
    assert.equal(await sessionCookie(), undefined, 'clear control expires the HttpOnly API session');
    assert.equal(await page.evaluate(async () => (await window.trustLayerApiFetch('/api/cases')).status), 401,
      'cleared session remains unauthenticated until an explicit sign-in');
    assert.equal(promptCount, 1, 'clearing does not trigger repeated background prompts');

    const rejectedReplacement = page.waitForResponse(response =>
      new URL(response.url()).pathname === '/api/auth/session' && response.status() === 401, { timeout: 5_000 });
    await page.getByRole('button', { name: 'Replace API token' }).click();
    await rejectedReplacement;
    assert.equal(await sessionCookie(), undefined, 'an invalid replacement must leave the browser signed out');
    assert.equal(promptCount, 2);
    assert.equal(await page.evaluate(async () => (await window.trustLayerApiFetch('/api/cases')).status), 401);

    const acceptedReplacement = page.waitForResponse(response =>
      new URL(response.url()).pathname === '/api/auth/session' && response.status() === 204, { timeout: 5_000 });
    await page.getByRole('button', { name: 'Replace API token' }).click();
    await acceptedReplacement;
    const replacementCookie = await sessionCookie();
    assert.ok(replacementCookie);
    assert.equal(replacementCookie.httpOnly, true);
    assert.equal(promptCount, 3, 'replace control requests the configured token explicitly');
    assert.equal(await page.evaluate(async () => (await window.trustLayerApiFetch('/api/cases')).status), 200);
    assert.equal(promptCount, 3);
    await context.close();
  } finally {
    if (browser) await browser.close();
    server.closeAllConnections();
    await new Promise(resolve => server.close(resolve));
  }
});

test('loopback dashboard and Investigation Console authenticate without prompts across reload and backend restart', async () => {
  const apiToken = randomBytes(32).toString('base64url');
  const listen = port => {
    const server = createApp({ apiToken, localDevelopmentAuth: true, cases: new Map(), investigateCase: async () => {} })
      .listen(port, '127.0.0.1');
    return new Promise((resolve, reject) => {
      server.once('listening', () => resolve(server));
      server.once('error', reject);
    });
  };
  let server = await listen(0);
  const port = server.address().port;
  const base = `http://localhost:${port}`;
  let browser;
  let promptCount = 0;
  try {
    browser = await chromium.launch({ headless: true });
    const context = await browser.newContext();
    const page = await context.newPage();
    page.on('dialog', async dialog => {
      if (dialog.type() === 'prompt') promptCount++;
      await dialog.dismiss();
    });

    for (const route of ['/', '/investigation.html']) {
      await page.goto(`${base}${route}`, { waitUntil: 'domcontentloaded' });
      assert.equal(await page.evaluate(async () => (await window.trustLayerApiFetch('/api/cases')).status), 200,
        `${route} uses the shared local browser authentication flow`);
    }
    const cookie = async () => (await context.cookies(`${base}/api/`)).find(item => item.name === 'trustlayer_session');
    const firstCookie = await cookie();
    assert.ok(firstCookie);
    assert.equal(firstCookie.httpOnly, true);
    assert.equal(firstCookie.sameSite, 'Strict');
    assert.equal(firstCookie.path, '/api');
    assert.equal(promptCount, 0);

    await page.reload({ waitUntil: 'domcontentloaded' });
    assert.equal(await page.evaluate(async () => (await window.trustLayerApiFetch('/api/cases')).status), 200);
    assert.equal(promptCount, 0, 'reload reuses the HttpOnly session');

    server.closeAllConnections();
    await new Promise(resolve => server.close(resolve));
    server = await listen(port);
    await page.reload({ waitUntil: 'domcontentloaded' });
    assert.equal(await page.evaluate(async () => (await window.trustLayerApiFetch('/api/cases')).status), 200,
      'stale session after backend restart is replaced through local same-origin authentication');
    assert.equal(promptCount, 0, 'backend restart requires no copied token');
    assert.equal((await cookie())?.httpOnly, true);
    assert.equal(await page.evaluate(() => Object.keys(localStorage).some(key => /token/i.test(key))), false,
      'the browser does not persist an API token');
    await context.close();
  } finally {
    if (browser) await browser.close();
    server.closeAllConnections();
    await new Promise(resolve => server.close(resolve));
  }
});
