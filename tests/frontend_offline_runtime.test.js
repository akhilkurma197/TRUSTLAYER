import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import test from 'node:test';
import { chromium } from 'playwright';
import { createApp } from '../backend/server.js';

test('dashboard and Investigation Console load without external requests or browser console errors', async t => {
  const server = createApp({
    apiToken: randomBytes(32).toString('base64url'),
    localDevelopmentAuth: true,
    cases: new Map(),
    investigateCase: async () => {}
  }).listen(0, '127.0.0.1');
  await new Promise(resolve => server.once('listening', resolve));
  const base = `http://127.0.0.1:${server.address().port}`;
  let browser;
  try {
    try { browser = await chromium.launch({ headless: true }); }
    catch (error) { t.skip(`local Playwright browser unavailable: ${error.message}`); return; }

    const page = await browser.newPage();
    const externalRequests = [];
    const consoleErrors = [];
    page.on('request', request => {
      const url = new URL(request.url());
      if (url.origin !== base) externalRequests.push({ origin: url.origin, resourceType: request.resourceType() });
    });
    page.on('console', message => {
      if (message.type() === 'error') consoleErrors.push(message.text().slice(0, 240));
    });
    page.on('pageerror', error => consoleErrors.push(error.name));

    for (const route of ['/', '/investigation.html']) {
      const response = await page.goto(`${base}${route}`, { waitUntil: 'networkidle', timeout: 10_000 });
      assert.equal(response.status(), 200, `${route} should be served successfully`);
      assert.ok(await page.title());
    }

    assert.deepEqual(externalRequests, [], 'frontend assets must not require third-party network access');
    assert.deepEqual(consoleErrors, [], 'both real frontend routes should load without console or page errors');
  } finally {
    if (browser) await browser.close();
    server.closeAllConnections();
    await new Promise(resolve => server.close(resolve));
  }
});
