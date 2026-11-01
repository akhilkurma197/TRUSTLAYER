import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import http from 'node:http';
import { test } from 'node:test';
import { chromium } from 'playwright';
import { readDisplayedViewportFrame } from './helpers/displayed_viewport_frame.js';

test('viewport frame measurement reads non-empty displayed bytes after page fetch consumes the response', async t => {
  const bytes = Buffer.alloc(300, 0x5a);
  bytes.set([0xff, 0xd8, 0xff], 0);
  const server = http.createServer((request, response) => {
    if (request.url === '/') {
      response.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
      return response.end('<img id="viewport">');
    }
    response.writeHead(200, { 'content-type': 'image/jpeg', 'content-length': String(bytes.length), 'cache-control': 'no-store' });
    response.end(bytes);
  }).listen(0, '127.0.0.1');
  await new Promise(resolve => server.once('listening', resolve));
  let browser;
  try {
    browser = await chromium.launch({ headless: true });
  } catch (error) {
    t.skip(`local Playwright browser unavailable: ${error.message}`);
    server.closeAllConnections();
    await new Promise(resolve => server.close(resolve));
    return;
  }
  try {
    const page = await browser.newPage();
    const frameResponsePromise = page.waitForResponse(response => new URL(response.url()).pathname === '/frame');
    await page.goto(`http://127.0.0.1:${server.address().port}/`);
    const browserFrameSize = await page.evaluate(async () => {
      const response = await fetch('/frame');
      const blob = await response.blob();
      document.getElementById('viewport').src = URL.createObjectURL(blob);
      return blob.size;
    });
    const frameResponse = await frameResponsePromise;
    const responseBodyReportedByPlaywright = (await frameResponse.body()).length;
    assert.equal(browserFrameSize, bytes.length, 'the page fetch must receive the full response before rendering its blob');
    assert.equal(frameResponse.headers()['content-length'], String(bytes.length));

    const displayedFrame = await readDisplayedViewportFrame(page.locator('#viewport'));
    assert.equal(displayedFrame.type, 'image/jpeg');
    assert.equal(displayedFrame.bytes, bytes.length);
    assert.equal(displayedFrame.sha256, createHash('sha256').update(bytes).digest('hex'));
    assert.equal(responseBodyReportedByPlaywright, 0,
      'in this Playwright path, body() after the page consumed the fetch returns empty even though Content-Length and displayed Blob prove frame delivery');
  } finally {
    await browser.close();
    server.closeAllConnections();
    await new Promise(resolve => server.close(resolve));
  }
});
