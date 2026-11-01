import { chromium } from 'playwright';
import { verifyChromiumSandbox } from './chromium_sandbox_verifier.js';

let browser;
try {
  browser = await chromium.launch({
    headless: true,
    chromiumSandbox: true,
    args: [
      '--disable-gpu', '--disable-dev-shm-usage', '--disable-background-networking',
      '--disable-sync', '--disable-default-apps', '--disable-extensions', '--mute-audio', '--no-first-run'
    ]
  });
  const page = await browser.newPage();
  const sandboxVerification = await verifyChromiumSandbox(browser, page);
  let chromeSandboxDiagnostic = 'UNAVAILABLE';
  let chromeSandboxText = '';
  try {
    await page.goto('chrome://sandbox', { waitUntil: 'domcontentloaded', timeout: 3000 });
    chromeSandboxText = (await page.locator('body').innerText({ timeout: 1500 })).replace(/\s+/g, ' ').trim().slice(0, 1000);
    if (chromeSandboxText) chromeSandboxDiagnostic = 'AVAILABLE';
  } catch {}
  const result = {
    diagnosticStatus: sandboxVerification.status,
    sandboxVerification,
    chromeSandboxDiagnostic,
    chromeSandboxText,
    uid: process.getuid?.(),
    gid: process.getgid?.(),
    browserVersion: browser.version(),
    launchOptions: {
      chromiumSandbox: true,
      args: ['--disable-gpu', '--disable-dev-shm-usage', '--disable-background-networking',
        '--disable-sync', '--disable-default-apps', '--disable-extensions', '--mute-audio', '--no-first-run']
    }
  };
  console.log(JSON.stringify(result));
  if (sandboxVerification.status !== 'VERIFIED') process.exitCode = 2;
} catch (error) {
  console.log(JSON.stringify({ diagnosticStatus: 'UNAVAILABLE', reason: String(error.message).slice(0, 240) }));
  process.exitCode = 2;
} finally {
  if (browser) await browser.close().catch(() => {});
}
