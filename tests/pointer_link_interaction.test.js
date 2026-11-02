import assert from 'node:assert/strict';
import http from 'node:http';
import test from 'node:test';
import { chromium } from 'playwright';
import { isSafePointerTarget } from '../core/interactive_action.js';

test('local browser policy permits an ordinary same-origin article link and harmless button while rejecting unsafe links', async t => {
  const root = `<!doctype html><title>Fixture home</title><style>body{min-height:1800px}a,button{display:block;margin:24px}</style>
    <a id="article" href="/article">Read article</a>
    <a id="unsafe" href="javascript:document.title='unsafe'">Unsafe scheme</a>
    <button id="harmless" type="button" onclick="document.querySelector('#state').textContent='Button changed state'">Harmless action</button>
    <p id="state">Ready</p>`;
  const article = `<!doctype html><title>Fixture article</title><a id="next" href="/next">Next article</a><p>Article page</p>`;
  const next = '<!doctype html><title>Fixture next</title><p id="next-state">Second local fixture page</p>';
  const server = http.createServer((request, response) => {
    const body = request.url === '/article' ? article : request.url === '/next' ? next : root;
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

    const clickPermittedTarget = async selector => {
      const hit = await page.locator(selector).evaluate(element => {
        const rect = element.getBoundingClientRect();
        const x = rect.left + rect.width / 2;
        const y = rect.top + rect.height / 2;
        const hitElement = document.elementFromPoint(x, y);
        const target = hitElement?.closest('a[href],button,[role="button"],input[type="search"],input[type="text"],textarea') || hitElement;
        return {
          point: { x, y },
          target: { tagName: target?.tagName, type: target?.getAttribute('type') || '',
            name: target?.getAttribute('name') || '', id: target?.id || '', label: target?.innerText || '',
            role: target?.getAttribute('role') || '', withinForm: Boolean(target?.closest('form')),
            download: Boolean(target?.hasAttribute('download')), contentEditable: target?.getAttribute('contenteditable') === 'true',
            href: target?.href || '', target: target?.getAttribute('target') || '' }
        };
      });
      assert.equal(isSafePointerTarget(hit.target), true, `local viewport target ${selector} should be permitted`);
      await page.mouse.click(hit.point.x, hit.point.y);
    };

    const unsafeTarget = await page.locator('#unsafe').evaluate(element => ({ tagName: element.tagName,
      href: element.href, label: element.innerText, target: element.getAttribute('target') || '' }));
    assert.equal(isSafePointerTarget(unsafeTarget), false, 'script URLs remain prohibited');

    await clickPermittedTarget('#article');
    await page.waitForURL(url => url.pathname === '/article');
    assert.equal(await page.title(), 'Fixture article', 'native same-origin hyperlink navigation must occur');
    await page.goBack();
    assert.equal(new URL(page.url()).pathname, '/');
    await page.goForward();
    assert.equal(new URL(page.url()).pathname, '/article');

    await clickPermittedTarget('#next');
    await page.waitForURL(url => url.pathname === '/next');
    assert.equal(await page.locator('#next-state').innerText(), 'Second local fixture page');

    await page.goBack();
    await page.goBack();
    await clickPermittedTarget('#harmless');
    assert.equal(await page.locator('#state').innerText(), 'Button changed state');
    await page.mouse.move(1100, 700);
    await page.mouse.wheel(0, 600);
    await page.waitForFunction(() => window.scrollY > 0, null, { timeout: 1_000 });
    assert.ok(await page.evaluate(() => window.scrollY > 0), 'ordinary scrolling remains functional');
  } finally {
    if (browser) await browser.close();
    server.closeAllConnections();
    await new Promise(resolve => server.close(resolve));
  }
});
