import assert from 'node:assert/strict';
import http from 'node:http';
import test from 'node:test';
import { chromium } from 'playwright';
import { isSafePointerTarget } from '../core/interactive_action.js';
import { clickPointerInteractiveTarget, inspectFocusedInteractiveTarget, inspectPointerInteractiveTarget, pressFocusedInteractiveKey,
  typeFocusedInteractiveText, InteractiveActionPolicyError } from '../core/interactive_browser_actions.js';

test('local browser policy operates ordinary links, native/custom controls and keyboard without permitting unsafe actions', async t => {
  const root = `<!doctype html><title>Fixture home</title><style>body{min-height:1800px}label,button,input,select,summary,[role=tab],[role=checkbox]{display:block;margin:12px}</style>
    <a id="same-page" href="#same-page-target">Same-page link</a><div id="same-page-target">Same-page destination</div>
    <a id="article" href="/article">Read article</a>
    <a id="unsafe" href="javascript:document.title='unsafe'">Unsafe scheme</a>
    <button id="harmless" type="button" onclick="document.querySelector('#state').textContent='Button changed state'">Harmless action</button>
    <p id="state">Ready</p>
    <label id="checkbox-label" for="updates"><input id="updates" type="checkbox" name="updates"> Receive local updates</label>
    <label for="region-north"><input id="region-north" type="radio" name="region" value="north"> North region</label>
    <label for="region-south"><input id="region-south" type="radio" name="region" value="south"> South region</label>
    <div id="custom-toggle" role="checkbox" tabindex="0" aria-checked="false" onclick="this.setAttribute('aria-checked',this.getAttribute('aria-checked')==='true'?'false':'true')" onkeydown="if(event.key===' '){event.preventDefault();this.click()}">Custom local toggle</div>
    <label for="choice">Local choice</label><select id="choice" name="choice" aria-label="Local choice" onchange="document.querySelector('#state').textContent='Choice: '+this.value"><option value="one">One</option><option value="two">Two</option></select>
    <details id="details"><summary>Show more details</summary><p id="detail-text">Expanded detail</p></details>
    <div role="tablist" aria-label="Local tabs"><button id="tab-first" type="button" role="tab" aria-selected="true" tabindex="0" onclick="document.querySelector('#tab-state').textContent='First tab active'" onkeydown="if(event.key==='ArrowRight'){document.querySelector('#tab-state').textContent='Second tab active';document.querySelector('#tab-second').focus()}">First tab</button><button id="tab-second" type="button" role="tab" aria-selected="false" tabindex="-1" onclick="document.querySelector('#tab-state').textContent='Second tab active'" onkeydown="if(event.key==='ArrowLeft'){document.querySelector('#tab-state').textContent='First tab active';document.querySelector('#tab-first').focus()}">Second tab</button></div><p id="tab-state">First tab active</p>
    <form method="get" action="/search"><label for="query">Search query</label><input id="query" name="q" type="search" autocomplete="off"><button type="submit">Search</button></form>
    <label for="note">Ordinary note</label><textarea id="note" autocomplete="off"></textarea>`;
  const article = `<!doctype html><title>Fixture article</title><a id="next" href="/next">Next article</a><p>Article page</p>`;
  const next = '<!doctype html><title>Fixture next</title><p id="next-state">Second local fixture page</p>';
  const search = '<!doctype html><title>Fixture search</title><p id="search-state">Local search result</p>';
  const server = http.createServer((request, response) => {
    const body = request.url.startsWith('/search?') ? search : request.url === '/article' ? article : request.url === '/next' ? next : root;
    response.writeHead(200, { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store' });
    response.end(body);
  }).listen(0, '127.0.0.1');
  await new Promise(resolve => server.once('listening', resolve));

  let browser;
  try {
    try { browser = await chromium.launch({ headless: true }); }
    catch (error) { t.skip(`local Playwright browser unavailable: ${error.message}`); return; }
    const page = await browser.newPage({ viewport: { width: 1280, height: 800 } });
    await page.goto(`http://127.0.0.1:${server.address().port}/`);

    const clickAt = async selector => {
      const box = await page.locator(selector).boundingBox();
      assert.ok(box, `${selector} must have a visible viewport box`);
      return clickPointerInteractiveTarget(page, Math.round(box.x + box.width / 2), Math.round(box.y + box.height / 2));
    };
    const unsafeTarget = await inspectPointerInteractiveTarget(page,
      (await page.locator('#unsafe').boundingBox()).x + 10, (await page.locator('#unsafe').boundingBox()).y + 5);
    assert.equal(isSafePointerTarget(unsafeTarget), false, 'script URLs remain prohibited');
    await assert.rejects(clickAt('#unsafe'), error => error instanceof InteractiveActionPolicyError && error.code === 'TARGET_NOT_PERMITTED');

    const samePageClick = await clickAt('#same-page');
    assert.equal(samePageClick.navigationChanged, true, 'the isolated worker can report a real same-page URL change without returning its fragment');
    await page.waitForFunction(() => location.hash === '#same-page-target');
    assert.equal(new URL(page.url()).hash, '#same-page-target', 'same-page links use real Chromium navigation');
    const articleClick = await clickAt('#article');
    assert.equal(articleClick.navigationChanged, true, 'ordinary same-tab navigation is observed after Chromium commits it');
    await page.waitForURL(url => url.pathname === '/article');
    assert.equal(await page.title(), 'Fixture article');
    await page.goBack();
    assert.equal(new URL(page.url()).pathname, '/');
    await page.goForward();
    assert.equal(new URL(page.url()).pathname, '/article');
    const nextClick = await clickAt('#next');
    assert.equal(nextClick.navigationChanged, true, 'subsequent same-tab navigation is observed independently');
    await page.waitForURL(url => url.pathname === '/next');
    assert.equal(await page.locator('#next-state').innerText(), 'Second local fixture page');
    await page.goBack();
    await page.goBack();

    await clickAt('#harmless');
    assert.equal(await page.locator('#state').innerText(), 'Button changed state', 'the page click handler ran');
    await clickAt('#checkbox-label');
    assert.equal(await page.locator('#updates').isChecked(), true, 'a label click toggles the real checkbox');
    const checkboxBox = await page.locator('#updates').boundingBox();
    assert.equal((await inspectPointerInteractiveTarget(page, checkboxBox.x + checkboxBox.width / 2,
      checkboxBox.y + checkboxBox.height / 2))?.type, 'checkbox');
    await pressFocusedInteractiveKey(page, 'Space');
    assert.equal(await page.locator('#updates').isChecked(), false, 'Space dispatches a real checkbox key action');
    assert.equal((await inspectFocusedInteractiveTarget(page)).id, 'updates');
    assert.equal((await pressFocusedInteractiveKey(page, 'Tab')).targetKind, 'radio', 'Tab advances focus using Chromium');
    await clickAt('#region-south');
    assert.equal(await page.locator('#region-south').isChecked(), true, 'radio selection changes through Chromium input');
    await clickAt('#custom-toggle');
    assert.equal(await page.locator('#custom-toggle').getAttribute('aria-checked'), 'true', 'custom checkbox click handler changes its observed state');
    await pressFocusedInteractiveKey(page, 'Space');
    assert.equal(await page.locator('#custom-toggle').getAttribute('aria-checked'), 'false', 'Space activates a custom ARIA checkbox');

    await clickAt('#choice');
    await pressFocusedInteractiveKey(page, 'ArrowDown');
    const committedSelect = await pressFocusedInteractiveKey(page, 'Enter');
    assert.equal(committedSelect.targetKind, 'select', 'Enter reports the prevalidated standalone native select without inspecting a replaced document');
    assert.equal(await page.locator('#choice').inputValue(), 'two', 'keyboard selection updates the native select');
    assert.equal(await page.locator('#state').innerText(), 'Choice: two', 'the select change handler observed the selection');
    await pressFocusedInteractiveKey(page, 'Escape');

    await clickAt('#details summary');
    assert.equal(await page.locator('#details').evaluate(element => element.open), true, 'summary click expands details');
    await pressFocusedInteractiveKey(page, 'Space');
    assert.equal(await page.locator('#details').evaluate(element => element.open), false, 'Space collapses a focused disclosure');
    await clickAt('#details summary');
    await clickAt('#tab-first');
    await pressFocusedInteractiveKey(page, 'ArrowRight');
    assert.equal(await page.locator('#tab-state').innerText(), 'Second tab active', 'a real arrow key reaches the focused tab');
    await pressFocusedInteractiveKey(page, 'Enter');
    assert.equal(await page.locator('#tab-state').innerText(), 'Second tab active', 'Enter activation dispatches to the focused tab');

    await clickAt('#query');
    await typeFocusedInteractiveText(page, 'local query');
    await pressFocusedInteractiveKey(page, 'Enter');
    await page.waitForURL(url => url.pathname === '/search' && url.searchParams.get('q') === 'local query');
    assert.equal(await page.locator('#search-state').innerText(), 'Local search result', 'GET search navigation occurs in Chromium');
    await page.goBack();
    await clickAt('#note');
    await typeFocusedInteractiveText(page, 'ordinary local text');
    assert.equal(await page.locator('#note').inputValue(), 'ordinary local text');
    await pressFocusedInteractiveKey(page, 'Backspace');
    assert.equal(await page.locator('#note').inputValue(), 'ordinary local tex');
    await assert.rejects(typeFocusedInteractiveText(page, 'person@example.test'), error => error.code === 'TARGET_NOT_PERMITTED');

    await page.mouse.move(1100, 700);
    await page.mouse.wheel(0, 600);
    await page.waitForFunction(() => window.scrollY > 0, null, { timeout: 1_000 });
    assert.ok(await page.evaluate(() => window.scrollY > 0), 'ordinary scrolling remains functional');
    assert.equal(isSafePointerTarget({ tagName: 'SELECT', name: 'choice', withinForm: true, formMethod: 'post' }), false,
      'controls in a state-changing POST form remain blocked');
    assert.equal(isSafePointerTarget({ tagName: 'INPUT', type: 'checkbox', name: 'consent' }), false,
      'consent checkboxes remain blocked by policy');
  } finally {
    if (browser) await browser.close();
    server.closeAllConnections();
    await new Promise(resolve => server.close(resolve));
  }
});
