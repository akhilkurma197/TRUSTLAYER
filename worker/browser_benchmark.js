import { chromium } from 'playwright';
import fs from 'node:fs';

const args = Object.fromEntries(process.argv.slice(2).map(arg => {
  const [key, value] = arg.replace(/^--/, '').split('=');
  return [key, value];
}));
const scenarios = ['small', 'assets', 'delayed', 'forbidden', 'moderate', 'timeout'];
const rounds = Math.min(50, Math.max(1, Number.parseInt(args.rounds || '20', 10)));
const mode = args.mode === 'cold' ? 'cold' : 'warm';
const containerToScriptMs = Math.max(0, Date.now() - Number(args.containerStartedAt || Date.now()));

function fixture(name) {
  if (name === 'forbidden') return { status: 403, body: '<!doctype html><title>Access denied</title><h1>403</h1><p>fixture response</p>' };
  if (name === 'moderate') return { status: 200, body: `<title>Moderate</title><main>${'<article><h2>Local deterministic content</h2><p>fixture</p></article>'.repeat(500)}</main>` };
  if (name === 'assets') return { status: 200, body: '<title>Assets</title><style>body{color:#234} .ready{display:block}</style><img src="data:image/gif;base64,R0lGODlhAQABAAD/ACwAAAAAAQABAAACADs="><div class="ready">loaded</div><script>document.body.dataset.script="done"</script>' };
  if (name === 'delayed') return { status: 200, body: '<title>Delayed</title><main>initial</main><script>setTimeout(()=>{document.body.dataset.ready="yes";document.body.insertAdjacentHTML("beforeend","<p>hydrated</p>")},75)</script>' };
  return { status: 200, body: '<title>Small</title><h1>Local benchmark fixture</h1><p>deterministic content</p>' };
}

function memoryMb() {
  try {
    const status = fs.readFileSync('/proc/self/status', 'utf8');
    return Number(status.match(/^VmRSS:\s+(\d+)/m)?.[1] || 0) / 1024;
  } catch { return null; }
}

async function runScenario(browser, name) {
  const started = performance.now();
  const context = await browser.newContext({ viewport: { width: 1280, height: 800 } });
  const page = await context.newPage();
  await page.route('https://*.trustlayer-benchmark.invalid/**', async route => {
    if (name === 'timeout') { await new Promise(resolve => setTimeout(resolve, 500)); return route.fulfill({ status: 200, body: '<title>late</title>' }).catch(() => {}); }
    const data = fixture(name);
    await route.fulfill({ status: data.status, contentType: 'text/html', body: data.body });
  });
  let navigationMs = null, status = null, timedOut = false, screenshotMs = null, screenshotBytes = 0, screenshotError = null;
  try {
    const navStart = performance.now();
    try {
      const response = await page.goto(`https://${name}.trustlayer-benchmark.invalid/`, { waitUntil: 'commit', timeout: name === 'timeout' ? 200 : 5000 });
      navigationMs = performance.now() - navStart;
      status = response?.status() ?? null;
      await page.waitForLoadState('load', { timeout: 1000 }).catch(() => {});
    } catch (error) {
      navigationMs = performance.now() - navStart;
      timedOut = /timeout/i.test(error.message);
    }
    if (name === 'delayed') await page.waitForFunction(() => document.body.dataset.ready === 'yes', null, { timeout: 1000 });
    const shotStart = performance.now();
    try {
      const png = await page.screenshot({ type: 'png', timeout: 3000 });
      screenshotMs = performance.now() - shotStart;
      screenshotBytes = png.byteLength;
    } catch (error) { screenshotError = error.message.slice(0, 240); }
  } finally {
    await context.close();
  }
  return { mode, scenario: name, totalMs: performance.now() - started, navigationMs,
    screenshotMs, screenshotBytes, screenshotError, status, timedOut, rssMb: memoryMb() };
}

const output = [];
let browserVersion = null;
if (mode === 'cold') {
  for (let round = 0; round < rounds; round++) {
    for (const name of scenarios) {
      const launchStart = performance.now();
      const browser = await chromium.launch({ headless: true, chromiumSandbox: true,
        args: ['--disable-gpu', '--disable-dev-shm-usage', '--no-first-run'] });
      browserVersion = browser.version();
      const browserLaunchMs = performance.now() - launchStart;
      const sample = await runScenario(browser, name);
      const cleanupStart = performance.now();
      await browser.close();
      output.push({ ...sample, browserLaunchMs, cleanupMs: performance.now() - cleanupStart });
    }
  }
} else {
  const launchStart = performance.now();
  const browser = await chromium.launch({ headless: true, chromiumSandbox: true,
    args: ['--disable-gpu', '--disable-dev-shm-usage', '--no-first-run'] });
  browserVersion = browser.version();
  const browserLaunchMs = performance.now() - launchStart;
  try {
    for (let round = 0; round < rounds; round++) {
      for (const name of scenarios) output.push(await runScenario(browser, name));
    }
  } finally {
    const closeStart = performance.now();
    await browser.close();
    var cleanupMs = performance.now() - closeStart;
  }
  output.forEach(sample => { sample.browserLaunchMs = browserLaunchMs; sample.cleanupMs = cleanupMs; });
}
console.log(JSON.stringify({ mode, rounds, containerToScriptMs,
  browserVersion, samples: output }));
