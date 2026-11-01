import assert from 'node:assert/strict';
import test from 'node:test';
import { chromium } from 'playwright';
import { installInteractiveCardObserver } from './helpers/interactive_card_observer.js';

test('interactive card observer reports initial state and later view/card visibility transitions', async () => {
  const browser = await chromium.launch({ headless: true });
  try {
    const page = await browser.newPage();
    const observations = [];
    page.on('console', message => {
      if (message.type() !== 'info' || !message.text().startsWith('[trustlayer-ui-card-state]')) return;
      observations.push(JSON.parse(message.text().slice('[trustlayer-ui-card-state]'.length)));
    });
    await page.addInitScript(installInteractiveCardObserver);
    await page.goto('data:text/html,%3Csection%20id%3D%22view-overview%22%20class%3D%22view-pane%20active%22%3E%3Cdiv%20id%3D%22ov-interactive-browser-card%22%20style%3D%22display%3Anone%22%3E%3Cspan%20id%3D%22interactive-status%22%3ESTARTING%3C%2Fspan%3E%3C%2Fdiv%3E%3C%2Fsection%3E');
    await page.waitForFunction(() => document.getElementById('interactive-status')?.textContent === 'STARTING', null, { timeout: 1_000 });
    assert.equal(observations[0]?.reason, 'initial');
    assert.equal(observations[0]?.overviewActive, true);
    assert.equal(observations[0]?.cardExists, true);
    assert.equal(observations[0]?.cardDisplay, 'none');

    await page.evaluate(() => {
      document.getElementById('ov-interactive-browser-card').style.display = 'block';
      document.getElementById('view-overview').classList.remove('active');
    });
    await page.waitForFunction(() => document.querySelectorAll('#ov-interactive-browser-card').length === 1);
    await new Promise((resolve, reject) => {
      const deadline = setTimeout(() => reject(new Error('card transition observation timed out')), 1_000);
      const check = () => {
        if (observations.some(item => item.reason === 'attribute-change' && item.cardDisplay === 'block' && item.overviewActive === false)) {
          clearTimeout(deadline);
          resolve();
        } else setTimeout(check, 5);
      };
      check();
    });
    assert.equal(observations.at(-1).cardParentId, 'view-overview');
    assert.ok(observations.every(item => !('token' in item) && !('caseId' in item)));
  } finally {
    await browser.close();
  }
});
