import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { test } from 'node:test';
import { chromium } from 'playwright';
import { createApp } from '../backend/server.js';

test('Investigation Console offers interactive opt-in before case creation and an explicit new-case path for existing cases', async t => {
  const apiToken = randomBytes(32).toString('base64url');
  const cases = new Map();
  const app = createApp({ apiToken, cases, investigateCase: async () => {} });
  const server = app.listen(0, '127.0.0.1');
  await new Promise(resolve => server.once('listening', resolve));
  const base = `http://127.0.0.1:${server.address().port}`;
  let browser;

  try {
    browser = await chromium.launch({ headless: true });
    const context = await browser.newContext();
    const page = await context.newPage();
    page.on('dialog', async dialog => {
      if (dialog.type() === 'prompt') await dialog.accept(apiToken);
      else await dialog.dismiss();
    });
    await page.goto(`${base}/investigation.html`, { waitUntil: 'domcontentloaded' });

    await page.locator('#btn-new-case').click();
    const optIn = page.locator('#intake-mode-c-interactive-optin');
    assert.equal(await optIn.isChecked(), false, 'new case starts with interactive controls opt-in unchecked');
    assert.equal(await optIn.isDisabled(), true, 'interactive controls are only selectable for Mode C');
    await page.locator('#intake-input').fill('https://existing-case.invalid/');
    const ordinaryCreatePromise = page.waitForResponse(response => {
      const request = response.request();
      return new URL(response.url()).pathname === '/api/cases' && request.method() === 'POST' && response.status() === 201;
    }, { timeout: 5_000 });
    await page.locator('#intake-submit-btn').click();
    const ordinaryCreate = await ordinaryCreatePromise;
    const ordinaryCase = await ordinaryCreate.json();
    assert.equal(ordinaryCreate.request().postDataJSON().inspectionMode, 'URL_ONLY');
    assert.equal(ordinaryCreate.request().postDataJSON().interactive, undefined,
      'the unchecked/default case creation omits interactive opt-in');
    assert.equal(ordinaryCase.interactiveEnabled, false);
    assert.equal(Object.hasOwn(cases.get(ordinaryCase.caseId).schema, 'interactiveSession'), false);
    await page.locator('.nav-item[data-view="website"]').click();
    assert.equal(await page.locator('#view-website #ov-interactive-browser-card').isVisible(), false,
      'screenshot view does not show controls for a case that was not opted in');

    // Reproduce the exact user path: an existing non-interactive case opens
    // the warning, whose button must launch the actual new-case intake form.
    await page.locator('#btn-hdr-mode-c').click();
    assert.equal(await page.locator('#mode-c-interactive-upgrade-note').isVisible(), true,
      'existing-case authorization explains that interactive mode cannot be added');
    await page.locator('#mode-c-new-interactive-case').click();
    assert.equal(await page.locator('#mode-c-consent-modal').isVisible(), false);
    assert.equal(await page.locator('#intake-modal').isVisible(), true);
    assert.equal(await page.locator('#intake-input').inputValue(), 'https://existing-case.invalid/');
    assert.equal(await page.locator('input[name="inspection-mode"][value="ISOLATED_LIVE"]').isChecked(), true);
    assert.equal(await optIn.isChecked(), false, 'the replacement case starts with a fresh opt-in');
    assert.equal(await optIn.isEnabled(), true);

    const optionLabel = page.locator('label[for="intake-mode-c-interactive-optin"]');
    await optionLabel.click();
    assert.equal(await optIn.isChecked(), true, 'a normal label click checks the checkbox');
    await optionLabel.click();
    assert.equal(await optIn.isChecked(), false, 'a second normal label click unchecks the checkbox');
    await optIn.click();
    assert.equal(await optIn.isChecked(), true, 'a normal checkbox click checks the input');

    await page.locator('#intake-submit-btn').click();
    assert.equal(await page.locator('#mode-c-interactive-consent-summary').isVisible(), true,
      'the authorization step summarizes the pre-creation choice');
    assert.equal(await page.locator('#mode-c-consent-modal #intake-mode-c-interactive-optin').count(), 0,
      'the authorization modal cannot change an existing case into an interactive case');

    const createResponsePromise = page.waitForResponse(response => {
      const request = response.request();
      return new URL(response.url()).pathname === '/api/cases' && request.method() === 'POST' && response.status() === 201;
    }, { timeout: 5_000 });
    await page.locator('#modal-confirm-btn').click();
    const createResponse = await createResponsePromise;
    const requestBody = createResponse.request().postDataJSON();
    const created = await createResponse.json();
    assert.equal(requestBody.interactive, true, 'initial case creation carries the checked value');
    assert.equal(requestBody.inspectionMode, 'ISOLATED_LIVE');
    assert.equal(created.interactiveEnabled, true, 'the API confirms the persisted value');
    assert.equal(cases.get(created.caseId).schema.interactiveSession.enabled, true);

    await page.locator('.nav-item[data-view="website"]').click();
    const browserControls = page.locator('#view-website #ov-interactive-browser-card');
    assert.equal(await browserControls.isVisible(), true,
      'the controls must be visible in the same Website view as the inspected screenshot');
    assert.equal(await page.locator('#interactive-status').innerText(), 'STARTING');
    assert.match(await page.locator('#interactive-status-detail').innerText(), /Controls unlock only after sandbox verification/);
    assert.equal(await page.locator('#interactive-type').isDisabled(), true,
      'actions remain disabled until the actual worker start acknowledgement');
    assert.equal(await page.locator('#interactive-scroll').isDisabled(), true);

    const fallbackControls = page.locator('#ov-interactive-browser-card details');
    assert.equal(await fallbackControls.evaluate(details => details.open), false,
      'button-based controls are intentionally collapsed by default');
    await fallbackControls.locator('summary').click();
    assert.equal(await fallbackControls.evaluate(details => details.open), true,
      'the fallback section opens through its visible summary');
    const selectorInput = page.locator('#interactive-type-selector');
    const textInput = page.locator('#interactive-type-text');
    assert.equal(await selectorInput.isVisible(), true);
    assert.equal(await textInput.isVisible(), true);
    await selectorInput.fill('#note');
    await textInput.fill('local-only-note');
    assert.equal(await selectorInput.inputValue(), '#note');
    assert.equal(await textInput.inputValue(), 'local-only-note');

    await context.close();
  } finally {
    if (browser) await browser.close();
    server.closeAllConnections();
    await new Promise(resolve => server.close(resolve));
  }
});
