/**
 * Trust Layer — Isolated Browser Worker v2.0
 * Executed only by the disposable Docker worker runtime supervised by LiveJobController.
 * Uses real Playwright Chromium rendering with network interception & screenshot capture.
 * Zero database access, zero application secrets, zero user browser profiles.
 * All outbound network traffic routed through Controlled Egress Proxy.
 */

import fs from 'node:fs';
import path from 'node:path';
import readline from 'node:readline';
import { URL } from 'node:url';
import { redactSensitiveUrl } from '../core/investigators/url_redaction.js';
import { classifyWorkerResultStatus } from '../core/investigators/worker_result_status.js';
import { verifyChromiumSandbox } from './chromium_sandbox_verifier.js';
import { appendBounded, isBoundedPng, serializeBoundedJson, MAX_RESULT_BYTES, MAX_TEXT_FIELD_CHARS } from './resource_limits.js';
import { validateInteractiveAction, hasSensitiveText, isSafePointerTarget, isSafeTextTarget,
  MAX_INTERACTIVE_ACTIONS, MAX_INTERACTIVE_POINTER_MOVES, MAX_INTERACTIVE_SCREENSHOTS, MAX_INTERACTIVE_VIEWPORT_FRAME_BYTES,
  INTERACTION_TIMEOUT_MS, MAX_SESSION_MS } from '../core/interactive_action.js';

// Parse command-line flags
function parseArgs() {
  const args = {};
  for (const arg of process.argv.slice(2)) {
    if (arg.startsWith('--')) {
      const eqIdx = arg.indexOf('=');
      if (eqIdx !== -1) {
        const key = arg.slice(2, eqIdx);
        const val = arg.slice(eqIdx + 1);
        args[key] = val;
      }
    }
  }
  return args;
}

const args = parseArgs();
const targetUrl = args.url;
const jobId = args.jobId || 'job-' + Date.now();
const proxyUrl = args.proxy;
const proxyUsername = args.proxyUsername;
const proxyPassword = args.proxyPassword;
const outputPath = args.output;
const screenshotPath = args.screenshot;
const initialScreenshotPath = args.initialScreenshot;
const timeoutMs = parseInt(args.timeout || '25000', 10);
const keepAliveMs = Math.min(150000, Math.max(0, parseInt(args.keepAlive || '120000', 10)));
const interactive = args.interactive === '1';
const handoffGraceMs = Math.min(5000, Math.max(0, parseInt(args.handoffGrace || '0', 10)));
const requestedCaptureDelayMs = Number.parseInt(args.captureDelayMs || '10000', 10);
const captureDelayMs = [0, 5000, 10000].includes(requestedCaptureDelayMs) ? requestedCaptureDelayMs : 10000;
const captureStatusPath = args.captureStatus || (outputPath ? `${outputPath}.capture-status.json` : null);
const maxHops = parseInt(args.maxRedirects || '5', 10);
const maxBytes = Math.min(5 * 1024 * 1024, Math.max(16 * 1024, Number.parseInt(args.maxBytes || '1000000', 10) || 1000000));
// Output bounds are worker policy, with container memory/tmpfs and supervisor
// time limits providing the outer resource boundary.

if (!targetUrl || !outputPath) {
  console.error('Usage: node worker/browser_worker.js --url=<url> --output=<path> [--screenshot=<path>] [--proxy=<proxyUrl>] [--timeout=<ms>]');
  process.exit(1);
}

const startTime = Date.now();
const stageTimings = { browser_launch_ms: 0, navigation_ms: 0, render_readiness_ms: 0, user_countdown_ms: 0, screenshot_capture_ms: 0 };
const networkEvents = [];
const pendingRenderRequests = new Map();
let lastRenderNetworkActivityAt = Date.now();
const blockedRequests = [];
const redirectChain = [];
const warnings = [];
const errors = [];
const limitations = [];
let sandboxVerification = null;

function writeBoundedJson(filePath, value) {
  fs.writeFileSync(filePath, serializeBoundedJson(value, MAX_RESULT_BYTES), { flag: 'wx' });
}

// Try to load Playwright
let playwright = null;
try {
  playwright = await import('playwright');
} catch (e) {
  errors.push(`Playwright is unavailable; refusing Mode C without rendered browser inspection: ${e.message}`);
}

/**
 * Execute real Playwright browser inspection and screenshot capture
 */
async function runPlaywrightInspection() {
  const chromium = playwright.chromium;
  const launchOptions = {
    headless: true,
    chromiumSandbox: true,
    args: [
      '--disable-gpu',
      '--disable-dev-shm-usage',
      '--disable-background-networking',
      '--disable-sync',
      '--disable-default-apps',
      '--disable-extensions',
      '--mute-audio',
      '--no-first-run'
    ]
  };

  if (proxyUrl) {
    launchOptions.proxy = {
      server: proxyUrl,
      ...(proxyUsername && proxyPassword ? { username: proxyUsername, password: proxyPassword } : {})
    };
  }

  const launchStartedAt = Date.now();
  let browser = await chromium.launch(launchOptions);
  stageTimings.browser_launch_ms = Date.now() - launchStartedAt;
  let context = null;
  let page = null;
  let screenshotCaptured = false;
  let screenshotBytes = 0;
  let finalScreenshotCapturedAt = null;
  let initialScreenshotCaptured = false;

function safeResponseHeaders(headers = {}, responseUrl = undefined) {
  const safeNames = ['content-type', 'content-length', 'server', 'via', 'location', 'date',
    'x-cache', 'x-request-id', 'cf-ray', 'x-trustlayer-egress-policy'];
  return Object.fromEntries(safeNames.filter(name => headers[name] !== undefined)
    .map(name => [name, name === 'location'
      ? redactSensitiveUrl(String(headers[name]), responseUrl)
      : String(headers[name]).slice(0, 512)]));
}

function safeRequestHeaders(headers = {}) {
  const safeNames = ['user-agent', 'accept', 'accept-language', 'sec-fetch-site',
    'sec-fetch-mode', 'sec-fetch-dest', 'upgrade-insecure-requests'];
  return Object.fromEntries(safeNames.filter(name => headers[name] !== undefined)
    .map(name => [name, String(headers[name]).slice(0, 512)]));
}

async function extractRedirectChain(finalResponse) {
  if (!finalResponse) return [];
  const reversed = [];
  let request = finalResponse.request();
  while (request && reversed.length < 10) {
    const response = await request.response().catch(() => null);
    const observed = response && networkEvents.findLast(event =>
      event.url === redactSensitiveUrl(request.url()) && event.status === response.status());
    reversed.push({
      url: redactSensitiveUrl(request.url()),
      status: response?.status() ?? null,
      location: response?.headers()?.location
        ? redactSensitiveUrl(response.headers().location, request.url()) : null,
      timingMs: observed?.timingMs ?? null,
      correlationId: jobId,
      final: request === finalResponse.request()
    });
    request = request.redirectedFrom();
  }
  return reversed.reverse();
}

async function safeResponseExcerpt(response) {
  if (!response) return '';
  const headers = response.headers();
  const type = String(headers['content-type'] || '').toLowerCase();
  const length = Number(headers['content-length']);
  // Do not drain an unknown-length or compressed body from the page response.
  // The proxy bounds transport bytes; this excerpt additionally requires a
  // small, declared, identity-encoded body before reading it.
  if (!(type.includes('text/') || type.includes('html') || type.includes('json')) ||
      !Number.isFinite(length) || length < 0 || length > Math.min(maxBytes, 512 * 1024) ||
      (headers['content-encoding'] && headers['content-encoding'] !== 'identity')) return '';
  const body = await Promise.race([
    response.text().catch(() => ''),
    new Promise(resolve => setTimeout(() => resolve(''), 600))
  ]);
  return String(body).replace(/<script\b[^>]*>[\s\S]*?<\/script>/gi, ' ')
    .replace(/<style\b[^>]*>[\s\S]*?<\/style>/gi, ' ')
    .replace(/<[^>]+>/g, ' ').replace(/&nbsp;|&#160;/gi, ' ')
    .replace(/&amp;/gi, '&').replace(/&lt;/gi, '<').replace(/&gt;/gi, '>')
    .replace(/\s+/g, ' ').trim().slice(0, 500);
}

  try {
    context = await browser.newContext({
      viewport: { width: 1280, height: 800 },
      userAgent: 'TrustLayer-Isolated-Browser/2.5 (Security Investigation Bot; Restricted Sandbox; ReadOnly)',
      ignoreHTTPSErrors: false,
      permissions: [], acceptDownloads: false, serviceWorkers: 'block'
    });

    page = await context.newPage();

    // Observe meaningful page mutations from document start. InnerHTML snapshots
    // are expensive and miss quiet periods between hydration bursts.
    await page.addInitScript(() => {
      window.__trustLayerRenderSignals = { lastMutationAt: Date.now(), mutations: 0 };
      const observe = () => {
        if (!document.documentElement || window.__trustLayerRenderSignals.observer) return;
        const observer = new MutationObserver((records) => {
          if (records.some(record => record.type === 'childList' || record.type === 'characterData' ||
              (record.type === 'attributes' && ['src', 'srcset', 'href', 'class', 'style'].includes(record.attributeName)))) {
            window.__trustLayerRenderSignals.lastMutationAt = Date.now();
            window.__trustLayerRenderSignals.mutations += records.length;
          }
        });
        observer.observe(document.documentElement, { subtree: true, childList: true, characterData: true,
          attributes: true, attributeFilter: ['src', 'srcset', 'href', 'class', 'style'] });
        window.__trustLayerRenderSignals.observer = observer;
      };
      observe();
      document.addEventListener('DOMContentLoaded', observe, { once: true });
    });

    // ── Network Request Interception (Observation Mode: Block non-GET/HEAD mutations) ──
    await page.route('**/*', async (route) => {
      const req = route.request();
      const method = req.method();
      const reqUrl = req.url();
      const resourceType = req.resourceType();

      // Block state-changing mutation requests
      if (method !== 'GET' && method !== 'HEAD') {
        const blockedItem = {
          time: new Date().toISOString(),
          method,
          url: redactSensitiveUrl(reqUrl),
          resourceType,
          reason: `Disallowed HTTP method ${method} — Observation mode prohibits data transmission / state mutation.`
        };
        appendBounded(blockedRequests, blockedItem);
        await route.abort('blockedbyclient');
        return;
      }

      route.continue();
    });

    // Record response events
    const renderResourceTypes = new Set(['document', 'stylesheet', 'script', 'image', 'font']);
    page.on('request', (req) => {
      if (!renderResourceTypes.has(req.resourceType())) return;
      pendingRenderRequests.set(req, { type: req.resourceType(), url: req.url(), startedAt: Date.now() });
      lastRenderNetworkActivityAt = Date.now();
    });
    const finishRenderRequest = (req) => {
      if (pendingRenderRequests.delete(req)) lastRenderNetworkActivityAt = Date.now();
    };
    page.on('requestfinished', finishRenderRequest);
    page.on('requestfailed', finishRenderRequest);

    page.on('response', (res) => {
      try {
        const req = res.request();
        appendBounded(networkEvents, {
          time: new Date().toISOString(),
          method: req.method(),
          url: redactSensitiveUrl(req.url()),
          status: res.status(),
          type: req.resourceType() || res.headers()['content-type'] || 'resource',
          size: res.headers()['content-length'] ? `${res.headers()['content-length']} B` : 'Unknown',
          timingMs: Date.now() - startTime
        });
      } catch {}
    });

    // Record request failures (including proxy blocks)
    page.on('requestfailed', (req) => {
      const failure = req.failure();
      appendBounded(networkEvents, {
        time: new Date().toISOString(),
        method: req.method(),
        url: redactSensitiveUrl(req.url()),
        status: 'FAILED',
        type: req.resourceType(),
        error: failure?.errorText || 'Request failed'
      });
    });

    // ── Navigate to Target ──
    // Verify Chromium's renderer sandbox against live /proc state on a local
    // fixture before the submitted target URL is ever navigated.
    sandboxVerification = await verifyChromiumSandbox(browser, page);
    if (sandboxVerification.status !== 'VERIFIED') {
      throw new Error(`Required Chromium renderer sandbox verification failed: ${sandboxVerification.failures?.join(', ') || sandboxVerification.status}`);
    }

    let response = null;
    let observedMainDocumentResponse = null;
    page.on('response', (candidate) => {
      try {
        if (candidate.request().isNavigationRequest() && candidate.request().frame() === page.mainFrame()) {
          observedMainDocumentResponse = candidate;
        }
      } catch {}
    });
    const navigationStartedAt = Date.now();
    let navigationError = null;
    try {
      response = await page.goto(targetUrl, {
        // Reserve time for readiness checks and screenshot capture instead of
        // letting slow document navigation consume the full job budget.
        // Capture a useful initial viewport early; later readiness checks can
        // continue while that first screenshot is already being published.
        timeout: Math.min(7000, Math.max(5000, Math.floor(timeoutMs * 0.28))),
        // Commit is sufficient for the first (explicitly partial) viewport.
        // DOMContentLoaded is handled by the separate bounded readiness phase
        // so a slow document does not delay the first screenshot.
        waitUntil: 'commit'
      });
    } catch (navErr) {
      navigationError = navErr;
      errors.push(`Browser navigation error: ${navErr.message}`);
    }
    stageTimings.navigation_ms = Date.now() - navigationStartedAt;
    if (!response && observedMainDocumentResponse) response = observedMainDocumentResponse;

    // Publish an explicitly partial first viewport as soon as navigation
    // settles. Waiting for image/font/DOM stability before this point can push
    // otherwise useful evidence past the UI's ten-second first-image target.
    if (initialScreenshotPath) {
      try {
        if (response || observedMainDocumentResponse) await page.waitForTimeout(300);
        fs.mkdirSync(path.dirname(initialScreenshotPath), { recursive: true });
        const initialPng = await page.screenshot({ type: 'png', fullPage: false });
        if (!isBoundedPng(initialPng)) throw new Error('Initial screenshot exceeded PNG dimension or byte limits.');
        fs.writeFileSync(initialScreenshotPath, initialPng, { flag: 'wx' });
        initialScreenshotCaptured = true;
        if (!initialScreenshotCaptured) warnings.push('Initial viewport screenshot was outside the accepted artifact size bounds.');
      } catch (initialShotError) {
        warnings.push(`Initial viewport screenshot failed: ${initialShotError.message}`);
      }
    }

    // Bounded render readiness. Background polling/websockets never hold the
    // capture open; the wait is driven by document lifecycle, visible resources,
    // meaningful content, and a short mutation quiet window.
    let renderStatus = 'RENDER_PARTIAL';
    let readinessDiagnostics = {};
    const renderStartedAt = Date.now();
    try {
      const readinessDeadline = Date.now() + Math.min(7000, Math.max(2500, Math.floor(timeoutMs * 0.35)));
      const remaining = () => Math.max(1, readinessDeadline - Date.now());
      const domContentLoaded = await page.waitForFunction(
        () => document.readyState === 'interactive' || document.readyState === 'complete', null,
        { timeout: Math.min(2500, remaining()) }
      ).then(() => true).catch(() => false);
      let state = null;
      let stableAt = 0;
      while (Date.now() < readinessDeadline) {
        state = await page.evaluate(() => {
          const visible = (el) => {
            const rect = el.getBoundingClientRect();
            const style = getComputedStyle(el);
            return rect.width > 0 && rect.height > 0 && style.visibility !== 'hidden' && style.display !== 'none';
          };
          const images = [...(document.images || [])].filter(img => {
            const r = img.getBoundingClientRect();
            return r.bottom > 0 && r.top < innerHeight && r.right > 0 && r.left < innerWidth;
          });
          const pendingImages = images.filter(img => !img.complete || (img.currentSrc && img.naturalWidth === 0)).length;
          const visibleText = (document.body?.innerText || '').replace(/\\s+/g, ' ').trim().slice(0, 120);
          const hasRenderedContent = Boolean(visibleText || [...document.querySelectorAll('img,svg,canvas,video')].some(visible));
          const pendingStylesheets = [...document.querySelectorAll('link[rel="stylesheet"]')]
            .filter(link => !link.sheet).length;
          const signals = window.__trustLayerRenderSignals || {};
          return { readyState: document.readyState, hasRenderedContent, visibleTextLength: visibleText.length,
            visibleImageCount: images.length, pendingImages, pendingStylesheets,
            lastMutationAt: signals.lastMutationAt || Date.now(), mutationCount: signals.mutations || 0,
            fontStatus: document.fonts?.status || 'unsupported' };
        }).catch(() => null);
        if (!state) break;
        const pendingCriticalRequests = pendingRenderRequests.size;
        const networkQuiet = Date.now() - lastRenderNetworkActivityAt >= 350;
        const resourcesReady = state.pendingImages === 0 && state.pendingStylesheets === 0 &&
          pendingCriticalRequests === 0 && networkQuiet;
        const mutationQuiet = Date.now() - state.lastMutationAt >= 700;
        if (state.hasRenderedContent && resourcesReady && mutationQuiet) { stableAt = Date.now(); break; }
        await page.waitForTimeout(Math.min(200, remaining())).catch(() => {});
      }
      // Decode viewport images after their network loads; decode is separately
      // bounded and never allows a broken image to hold the worker open.
      const imageDecodesReady = await page.evaluate(async () => {
        const images = [...(document.images || [])].filter(img => {
          const r = img.getBoundingClientRect();
          return r.bottom > 0 && r.top < innerHeight && r.right > 0 && r.left < innerWidth &&
            img.complete && img.naturalWidth > 0 && typeof img.decode === 'function';
        });
        return Promise.race([
          Promise.allSettled(images.map(img => img.decode())).then(results => results.every(result => result.status === 'fulfilled')),
          new Promise(resolve => setTimeout(() => resolve(false), 700))
        ]);
      }).catch(() => false);
      // Font loading is useful but non-critical: bound it separately so late
      // third-party fonts cannot starve the screenshot.
      const fontsReady = await page.evaluate(() => !document.fonts?.ready ? true :
        Promise.race([document.fonts.ready.then(() => true), new Promise(resolve => setTimeout(() => resolve(false), 500))])
      ).catch(() => false);
      readinessDiagnostics = { domContentLoaded, readyState: state?.readyState || 'unavailable',
        hasRenderedContent: state?.hasRenderedContent || false, visibleTextLength: state?.visibleTextLength || 0,
        visibleImageCount: state?.visibleImageCount || 0, pendingImages: state?.pendingImages ?? null,
        pendingStylesheets: state?.pendingStylesheets ?? null,
        pendingCriticalRequests: pendingRenderRequests.size,
        networkQuietMs: Date.now() - lastRenderNetworkActivityAt,
        imageDecodesReady, mutationCount: state?.mutationCount || 0,
        stableAt: stableAt || null, fontsReady, waitMs: Date.now() - renderStartedAt,
        timedOut: Date.now() >= readinessDeadline && !stableAt };
      const isAccessDenied = response && [401, 403].includes(response.status());
      renderStatus = isAccessDenied ? 'ACCESS_DENIED'
        : (response?.status() >= 500 ? 'HTTP_SERVER_ERROR'
          : (response?.status() >= 400 ? 'HTTP_ERROR'
            : (domContentLoaded && stableAt && imageDecodesReady ? 'RENDER_COMPLETE'
              : (readinessDiagnostics.timedOut ? 'RENDER_TIMEOUT' : 'RENDER_PARTIAL'))));
    } catch {
      renderStatus = 'RENDER_PARTIAL';
    }
    stageTimings.render_readiness_ms = Date.now() - renderStartedAt;

    // Countdown begins only after the bounded DOM/readiness milestone. A
    // status file is the backend-authoritative clock consumed by the UI.
    const countdownStartedAt = Date.now();
    const countdownEndsAt = countdownStartedAt + captureDelayMs;
    const writeCaptureStatus = (status, extra = {}) => {
      if (!captureStatusPath) return;
      try {
        fs.writeFileSync(captureStatusPath, JSON.stringify({ status, captureDelayMs,
          countdownStartedAt, countdownEndsAt, updatedAt: Date.now(), renderStatus, ...extra }));
      } catch {}
    };
    writeCaptureStatus(captureDelayMs ? 'COUNTDOWN' : 'CAPTURING', { readinessDiagnostics });
    if (captureDelayMs > 0) {
      while (Date.now() < countdownEndsAt) {
        await page.waitForTimeout(Math.min(250, countdownEndsAt - Date.now())).catch(() => {});
        writeCaptureStatus(Date.now() >= countdownEndsAt ? 'CAPTURING' : 'COUNTDOWN', { readinessDiagnostics });
      }
    }
    stageTimings.user_countdown_ms = Date.now() - countdownStartedAt;

    // The user-configured deadline is the screenshot capture point. Capture
    // before DOM extraction, OCR preparation, or any post-render analysis.
    if (screenshotPath) {
      try {
        fs.mkdirSync(path.dirname(screenshotPath), { recursive: true });
        const screenshotStartedAt = Date.now();
        const screenshotBuffer = await page.screenshot({ type: 'png', fullPage: false });
        if (!isBoundedPng(screenshotBuffer)) throw new Error('Screenshot exceeded PNG dimension or byte limits.');
        fs.writeFileSync(screenshotPath, screenshotBuffer, { flag: 'wx' });
        screenshotBytes = screenshotBuffer.length;
        screenshotCaptured = true;
        finalScreenshotCapturedAt = Date.now();
        stageTimings.screenshot_capture_ms = Date.now() - screenshotStartedAt;
        writeCaptureStatus(screenshotCaptured ? 'READY' : 'FAILED', { capturedAt: finalScreenshotCapturedAt, screenshotBytes, readinessDiagnostics });
      } catch (shotErr) {
        warnings.push(`Screenshot capture failed: ${shotErr.message}`);
        writeCaptureStatus('FAILED', { error: shotErr.message });
      }
    }

    if (observedMainDocumentResponse) response = observedMainDocumentResponse;
    const finalUrl = page.url();
    const httpStatus = response ? response.status() : null;
    const contentType = response?.headers()['content-type'] || 'text/html';
    const responseHeaders = safeResponseHeaders(response?.headers() || {}, response?.url());
    const responseBodyExcerpt = await safeResponseExcerpt(response);
    const tlsDetails = response ? await response.securityDetails().catch(() => null) : null;
    const browserPeerAddress = response ? await response.serverAddr().catch(() => null) : null;
    redirectChain.push(...await extractRedirectChain(response));

    // ── Extract Live Rendered DOM ──
    const renderedData = await page.evaluate(({ maxHtmlBytes, maxTextFieldChars }) => {
      const bounded = value => String(value || '').slice(0, maxTextFieldChars);
      const title = bounded(document.title) || null;
      const metaDesc = bounded(document.querySelector('meta[name="description"]')?.getAttribute('content')) || null;

      // Headings
      const headings = [];
      document.querySelectorAll('h1, h2, h3').forEach((h) => {
        if (headings.length >= 100) return;
        const t = (h.textContent || '').trim();
        if (t && t.length > 1 && !headings.includes(t)) headings.push(bounded(t));
      });

      // Buttons / CTAs
      const buttons = [];
      document.querySelectorAll('button, input[type="submit"], input[type="button"], a.btn, a.button').forEach((b) => {
        if (buttons.length >= 200) return;
        const val = b.value || b.textContent || '';
        const t = val.trim();
        if (t && !buttons.includes(t)) buttons.push(bounded(t));
      });

      // Forms
      const forms = [];
      document.querySelectorAll('form').forEach((f) => {
        if (forms.length >= 100) return;
          const action = bounded(f.getAttribute('action'));
        const method = (f.getAttribute('method') || 'GET').toUpperCase();
        const inputs = [];
        let hasPassword = false;
        let hasSensitive = false;

        f.querySelectorAll('input, select, textarea').forEach((inp) => {
          if (inputs.length >= 100) return;
          const type = (inp.getAttribute('type') || 'text').toLowerCase();
          const name = bounded(inp.getAttribute('name') || inp.getAttribute('id'));
          const placeholder = bounded(inp.getAttribute('placeholder'));
          const isHidden = type === 'hidden' || inp.style?.display === 'none';
          const isPassword = type === 'password';
          const isSensitive = isPassword || /otp|cvv|card|ssn|pin|token|secret/i.test(name);
          if (isPassword) hasPassword = true;
          if (isSensitive) hasSensitive = true;

          inputs.push({
            name,
            type,
            placeholder,
            isPassword,
            isSensitive,
            isHidden,
            isUserEditable: !isHidden
          });
        });

        const isExternal = action.startsWith('http') && !action.includes(window.location.hostname);
        forms.push({
          action,
          method,
          destinationHost: action.startsWith('http') ? (new URL(action, window.location.href)).hostname : window.location.hostname,
          fields: inputs.map(i => i.name).filter(Boolean),
          inputs,
          hasPassword,
          hasSensitive,
          isExternal
        });
      });

      // Scripts
      const scripts = [];
      document.querySelectorAll('script').forEach((s) => {
        if (scripts.length >= 200) return;
        const src = s.getAttribute('src');
        if (src) {
          try {
            const parsed = new URL(src, window.location.href);
            scripts.push({
              src: bounded(src),
              domain: parsed.hostname,
              isExternal: parsed.hostname !== window.location.hostname,
              isInline: false
            });
          } catch {
            scripts.push({ src, domain: null, isExternal: false, isInline: false });
          }
        } else {
          scripts.push({ src: null, domain: null, isExternal: false, isInline: true });
        }
      });

      // Links
      const links = [];
      document.querySelectorAll('a[href]').forEach((a) => {
        if (links.length >= 500) return;
        const href = a.getAttribute('href');
        if (href && !href.startsWith('#') && !href.startsWith('javascript:')) {
          try {
            const parsed = new URL(href, window.location.href);
            links.push({
              href: bounded(href),
              isExternal: parsed.hostname !== window.location.hostname
            });
          } catch {}
        }
      });

      const externalDomains = [...new Set(scripts.filter(s => s.domain).map(s => s.domain))];
      const domNodes = document.querySelectorAll('*').length;
      // Estimate size without serializing the entire untrusted DOM into a new
      // large string. Stop text counting at the configured inspection budget.
      const textWalker = document.createTreeWalker(document.documentElement, NodeFilter.SHOW_TEXT);
      let textLength = 0;
      while (textLength < maxHtmlBytes && textWalker.nextNode()) {
        textLength += Math.min(maxHtmlBytes - textLength, textWalker.currentNode.nodeValue?.length || 0);
      }
      const htmlBytes = Math.min(maxHtmlBytes, domNodes * 16 + textLength * 2);

      return {
        title,
        metaDescription: metaDesc,
        headings,
        buttons,
        forms,
        scripts,
        links,
        externalDomains,
        domNodes,
        htmlBytes,
        htmlBytesIsEstimate: true,
      };
    }, { maxHtmlBytes: maxBytes, maxTextFieldChars: MAX_TEXT_FIELD_CHARS });
    if (!renderedData.domNodes) {
      renderStatus = navigationError && /timeout/i.test(navigationError.message) ? 'RENDER_TIMEOUT' : 'RENDER_FAILED';
    } else if (response && [401, 403].includes(response.status())) {
      renderStatus = 'ACCESS_DENIED';
    } else if (navigationError && renderStatus !== 'RENDER_COMPLETE') {
      renderStatus = /timeout/i.test(navigationError.message) ? 'RENDER_TIMEOUT' : 'RENDER_PARTIAL';
    }

    const pageExtraction = {
      status: 'COMPLETED',
      title: renderedData.title,
      headings: renderedData.headings,
      metaDescription: renderedData.metaDescription,
      buttons: renderedData.buttons,
      domNodes: renderedData.domNodes,
      htmlBytes: renderedData.htmlBytes,
      htmlBytesIsEstimate: renderedData.htmlBytesIsEstimate,
      forms: renderedData.forms,
      scripts: renderedData.scripts,
      iframes: [],
      links: renderedData.links,
      externalDomains: renderedData.externalDomains,
      domFingerprint: `DOM-${renderedData.domNodes}N-${renderedData.forms.length}F-${renderedData.scripts.length}S`,
      screenshotAvailable: screenshotCaptured,
      screenshotBytes,
      initialScreenshotAvailable: initialScreenshotCaptured,
      renderStatus,
      screenshotMetadata: screenshotCaptured ? { checkpoint: 'FINAL', capturedAt: finalScreenshotCapturedAt, finalUrl,
        renderStatus, readinessDiagnostics } : null
    };

    const inspectionResult = {
      jobId,
      targetUrl,
      browserDiagnostics: {
        browser: 'Chromium',
        browserVersion: browser.version(),
        playwrightVersion: '1.64.1',
        headless: launchOptions.headless,
        chromiumSandbox: launchOptions.chromiumSandbox,
        chromiumSandboxVerification: sandboxVerification,
        launchArguments: launchOptions.args,
        userAgent: 'TrustLayer-Isolated-Browser/2.5 (Security Investigation Bot; Restricted Sandbox; ReadOnly)',
        proxyConfigured: Boolean(proxyUrl),
        navigationWaitUntil: 'commit',
        navigationTimeoutMs: Math.min(7000, Math.max(5000, Math.floor(timeoutMs * 0.28)))
      },
      durationMs: Date.now() - startTime,
      warnings,
      errors,
      limitations,
      status: classifyWorkerResultStatus(httpStatus, renderedData.domNodes),
      finalUrl,
      httpStatus,
      responseHeaders,
      responseDiagnostics: {
        statusCode: httpStatus,
        statusText: response?.statusText() || null,
        finalResponseUrl: response?.url() || finalUrl,
        origin: responseHeaders['x-trustlayer-egress-policy'] ? 'EGRESS_PROXY_POLICY' : (response ? 'TARGET_TLS_TUNNEL' : 'NO_HTTP_RESPONSE'),
        tls: tlsDetails,
        browserPeerAddress,
        browserPeerRole: proxyUrl ? 'CONFIGURED_EGRESS_PROXY_SOCKET' : 'DIRECT_SOCKET_NOT_PERMITTED_BY_MODE_C_POLICY'
      },
      requestHeaders: safeRequestHeaders(response?.request().headers() || {}),
      responseBodyExcerpt,
      correlationId: jobId,
      contentType,
      redirectChain,
      pageExtraction,
      networkEvents,
      blockedRequests,
      screenshotCaptured,
      screenshotBytes,
      modeCTimings: { ...stageTimings },
      renderStatus,
      readinessDiagnostics,
      screenshotCapture: { status: screenshotCaptured ? 'READY' : 'FAILED', captureDelayMs,
        countdownStartedAt, countdownEndsAt, capturedAt: finalScreenshotCapturedAt, screenshotBytes },
      isolationReport: {
        sandboxType: 'PLAYWRIGHT_WORKER_IN_CONTAINER',
        playwrightAvailable: true,
        chromiumSandboxEnabled: sandboxVerification?.status === 'VERIFIED',
        chromiumSandboxVerification: sandboxVerification,
        credentialsIsolated: true,
        cookiesIsolated: true,
        downloadsBlocked: true,
        storageEphemeral: true,
        proxyEnforced: !!proxyUrl,
        networkIsolated: null,
        runtimeMode: 'WORKER_RUNTIME_PENDING_SUPERVISOR_VALIDATION',
        workerPid: process.pid,
        screenshotCaptured
      }
    };

    // Publish real page data as soon as capture and extraction finish. The
    // supervisor can complete the case while this isolated browser remains
    // available for the requested short live session.
    fs.mkdirSync(path.dirname(outputPath), { recursive: true });
    writeBoundedJson(`${outputPath}.ready`, inspectionResult);
    if (interactive && keepAliveMs > 0) await runInteractiveSession(page, context, Math.min(keepAliveMs, MAX_SESSION_MS));
    else if (keepAliveMs > 0) await page.waitForTimeout(keepAliveMs).catch(() => {});
    if (context) { await context.close().catch(() => {}); context = null; }
    if (browser) { await browser.close().catch(() => {}); browser = null; }
    return inspectionResult;

  } finally {
    if (context) await context.close().catch(() => {});
    if (browser) await browser.close().catch(() => {});
  }
}

async function runInteractiveSession(page, context, durationMs) {
  let endsAt = null;
  let started = false;
  let sessionTimer = null;
  page.setDefaultTimeout(INTERACTION_TIMEOUT_MS);
  page.setDefaultNavigationTimeout(INTERACTION_TIMEOUT_MS);
  let count = 0;
  let pointerMoveCount = 0;
  let screenshotCount = 0;
  let sequence = 0;
  const emit = (type, observation, url = page.url(), details = {}) => {
    if (sequence >= 512) return;
    const safeUrl = (() => { const redacted = redactSensitiveUrl(url); return redacted.startsWith('http') ? redacted.slice(0, 2048) : undefined; })();
    const reason = ['SESSION_LIMIT_REACHED', 'INPUT_CLOSED'].includes(details.reason) ? details.reason : undefined;
    process.stdout.write(`TL_EVENT:${JSON.stringify({ type, observation: String(observation).slice(0, 512), url: safeUrl,
      ...(reason ? { reason } : {}), sequence: ++sequence, timestamp: Date.now() })}\n`);
  };
  const commands = readline.createInterface({ input: process.stdin, crlfDelay: Infinity });
  let resolveStarted;
  let resolveClosed;
  const startedPromise = new Promise(resolve => { resolveStarted = resolve; });
  const closedPromise = new Promise(resolve => { resolveClosed = resolve; });
  let endReason = 'INPUT_CLOSED';
  commands.once('close', () => {
    clearTimeout(sessionTimer);
    resolveStarted(false);
    resolveClosed();
  });
  page.on('framenavigated', frame => { if (frame === page.mainFrame()) emit('navigation_committed', 'Main frame navigation committed.'); });
  emit('navigation_completed', 'Initial browser page is ready for interaction.');
  page.on('request', request => emit('request_started', `${request.method()} ${request.resourceType()}`, request.url()));
  page.on('requestfailed', request => emit('request_failed', request.failure()?.errorText || 'Request failed.', request.url()));
  page.on('response', response => {
    if (response.request().redirectedFrom()) emit('redirect', `HTTP ${response.status()} redirect observed.`, response.url());
    emit('response_received', `HTTP ${response.status()} ${response.request().resourceType()}`, response.url());
  });
  page.on('popup', popup => { emit('popup_blocked', 'A new page was closed by session policy.', popup.url()); popup.close().catch(() => {}); });
  const onLine = async line => {
    let message;
    try { message = JSON.parse(line); } catch { return; }
    if (message?.command === 'START_INTERACTIVE') {
      if (!started) {
        started = true;
        endsAt = Date.now() + durationMs;
        sessionTimer = setTimeout(() => {
          endReason = 'SESSION_LIMIT_REACHED';
          commands.close();
        }, durationMs);
        emit('interactive_session_started', 'Supervisor opened the bounded interaction window.');
        resolveStarted(true);
      }
      return;
    }
    const { requestId, action } = message || {};
    if (typeof requestId !== 'string' || requestId.length > 80) return;
    const viewportCapture = message?.command === 'CAPTURE_VIEWPORT';
    if (viewportCapture) {
      if (!started || Date.now() >= endsAt) {
        process.stdout.write(`TL_RESPONSE:${JSON.stringify({ requestId, ok: false, error: 'Interactive browser session is unavailable.' })}\n`);
        return;
      }
      try {
        const bytes = await page.screenshot({ type: 'jpeg', quality: 45, fullPage: false, timeout: INTERACTION_TIMEOUT_MS });
        if (!Buffer.isBuffer(bytes) || bytes.length < 256 || bytes.length > MAX_INTERACTIVE_VIEWPORT_FRAME_BYTES) throw new Error('viewport frame exceeded limit');
        process.stdout.write(`TL_RESPONSE:${JSON.stringify({ requestId, ok: true, viewportBase64: bytes.toString('base64') })}\n`);
      } catch {
        process.stdout.write(`TL_RESPONSE:${JSON.stringify({ requestId, ok: false, error: 'Viewport frame unavailable.' })}\n`);
      }
      return;
    }
    if (!started) {
      process.stdout.write(`TL_RESPONSE:${JSON.stringify({ requestId, ok: false, error: 'Interactive session has not started.' })}\n`);
      return;
    }
    const validation = validateInteractiveAction(action);
    const pointerMove = action?.type === 'pointer_move';
    if (!validation.valid || (!pointerMove && count >= MAX_INTERACTIVE_ACTIONS) ||
        (pointerMove && pointerMoveCount >= MAX_INTERACTIVE_POINTER_MOVES) || (action?.type === 'screenshot' && screenshotCount >= MAX_INTERACTIVE_SCREENSHOTS) || Date.now() >= endsAt) {
      process.stdout.write(`TL_RESPONSE:${JSON.stringify({ requestId, ok: false, error: 'Action rejected by session policy.' })}\n`); return;
    }
    if (pointerMove) pointerMoveCount++;
    else count++;
    if (!pointerMove) emit('action_started', `Investigator requested ${action.type}.`);
    let response = { requestId, ok: true, action: action.type, url: redactSensitiveUrl(page.url()) };
    try {
      const timeout = { timeout: INTERACTION_TIMEOUT_MS };
      if (action.type === 'navigate') await page.goto(action.url, { ...timeout, waitUntil: 'domcontentloaded' });
      else if (action.type === 'back') await page.goBack({ ...timeout, waitUntil: 'domcontentloaded' });
      else if (action.type === 'forward') await page.goForward({ ...timeout, waitUntil: 'domcontentloaded' });
      else if (action.type === 'reload') await page.reload({ ...timeout, waitUntil: 'domcontentloaded' });
      else if (action.type === 'scroll') await page.evaluate(({ direction, pixels }) => window.scrollBy(0, (direction === 'up' ? -1 : 1) * pixels), action);
      else if (['pointer_move', 'pointer_click', 'pointer_scroll'].includes(action.type)) {
        const viewport = page.viewportSize();
        const x = Math.min(viewport.width - 1, Math.round(action.x * (viewport.width - 1) / 10000));
        const y = Math.min(viewport.height - 1, Math.round(action.y * (viewport.height - 1) / 10000));
        if (action.type === 'pointer_move') await page.mouse.move(x, y);
        else if (action.type === 'pointer_scroll') {
          await page.mouse.move(x, y);
          await page.mouse.wheel(0, (action.direction === 'up' ? -1 : 1) * action.pixels);
        } else {
          const target = await page.evaluate(({ x, y }) => {
            const hit = document.elementFromPoint(x, y);
            const el = hit?.closest('button,[role="button"],input[type="search"],input[type="text"],textarea') || hit;
            if (!el || !el.isConnected || !el.getClientRects().length) return null;
            return { tagName: el.tagName, type: el.getAttribute('type') || '', name: el.getAttribute('name') || '',
              id: el.id || '', autocomplete: el.getAttribute('autocomplete') || '', ariaLabel: el.getAttribute('aria-label') || '',
              label: el.innerText || '', role: el.getAttribute('role') || '', withinForm: Boolean(el.closest('form')),
              formMethod: el.closest('form')?.method || '',
              disabled: Boolean(el.disabled), readOnly: Boolean(el.readOnly), download: el.hasAttribute('download'),
              contentEditable: el.getAttribute('contenteditable') === 'true' };
          }, { x, y });
          const safe = isSafePointerTarget(target);
          if (!safe) throw new Error('The selected viewport target is not permitted.');
          await page.mouse.click(x, y);
        }
      }
      else if (action.type === 'type_focused') {
        const target = await page.evaluate(() => {
          const el = document.activeElement;
          if (!el || !el.isConnected || !el.getClientRects().length) return null;
          return { tagName: el.tagName, type: el.getAttribute('type') || '', name: el.getAttribute('name') || '', id: el.id || '',
            autocomplete: el.getAttribute('autocomplete') || '', ariaLabel: el.getAttribute('aria-label') || '',
            withinForm: Boolean(el.closest('form')), formMethod: el.closest('form')?.method || '',
            disabled: Boolean(el.disabled), readOnly: Boolean(el.readOnly) };
        });
        if (!isSafeTextTarget(target) || hasSensitiveText(action.text)) throw new Error('Text entry is not allowed for the focused field or content.');
        await page.keyboard.press('Control+A');
        await page.keyboard.type(action.text);
        response.typed = true;
      }
      else if (action.type === 'key') {
        const target = await page.evaluate(() => {
          const el = document.activeElement;
          if (!el || !el.isConnected || !el.getClientRects().length) return null;
          return { tagName: el.tagName, type: el.getAttribute('type') || '', name: el.getAttribute('name') || '', id: el.id || '',
            autocomplete: el.getAttribute('autocomplete') || '', ariaLabel: el.getAttribute('aria-label') || '',
            withinForm: Boolean(el.closest('form')), formMethod: el.closest('form')?.method || '',
            disabled: Boolean(el.disabled), readOnly: Boolean(el.readOnly) };
        });
        if (!isSafeTextTarget(target)) throw new Error('Keyboard input is not allowed for the focused field.');
        await page.keyboard.press(action.key);
      }
      else if (action.type === 'click') {
        const locator = page.locator(action.selector).first();
        const safe = await locator.evaluate(el => el.isConnected && el.getClientRects().length > 0 && !el.closest('form') &&
          !el.matches('a, input, select, textarea, [download], [contenteditable="true"]') &&
          (el.tagName === 'BUTTON' ? (el.getAttribute('type') || 'submit') === 'button' : el.getAttribute('role') === 'button') &&
          !/pay|payment|submit|download|permission|install|delete|remove|authorize|grant|login|log\s*in|sign\s*in|authenticate|verify|checkout|purchase|transfer|consent/i.test(`${el.innerText || ''} ${el.getAttribute('aria-label') || ''}`));
        if (!safe) throw new Error('The selected element is not an allowed non-submitting control.');
        await locator.click(timeout);
      } else if (action.type === 'type') {
        const locator = page.locator(action.selector).first();
        const target = await locator.evaluate(el => ({ visible: el.isConnected && el.getClientRects().length > 0,
          tagName: el.tagName, type: el.getAttribute('type') || '', name: el.getAttribute('name') || '', id: el.id || '',
          autocomplete: el.getAttribute('autocomplete') || '', ariaLabel: el.getAttribute('aria-label') || '',
          withinForm: Boolean(el.closest('form')), formMethod: el.closest('form')?.method || '',
          disabled: Boolean(el.disabled), readOnly: Boolean(el.readOnly) }));
        if (!target.visible || !isSafeTextTarget(target) || hasSensitiveText(action.text)) throw new Error('The selected element or text is not allowed.');
        await locator.fill(action.text, timeout);
        response.typed = true;
      } else if (action.type === 'screenshot') {
        const shot = await page.screenshot({ type: 'png', fullPage: false, timeout: INTERACTION_TIMEOUT_MS });
        if (!isBoundedPng(shot)) throw new Error('Screenshot exceeded artifact limits.');
        response.screenshotBase64 = shot.toString('base64');
        screenshotCount++;
      }
      response.url = redactSensitiveUrl(page.url());
      if (pointerMove) {
        if (pointerMoveCount % 20 === 0) emit('pointer_position_sampled', 'Coalesced pointer position updated.');
      } else {
        const pageState = await page.evaluate(() => ({ titleLength: document.title.length,
          visibleTextLength: document.body?.innerText?.length || 0, formCount: document.forms.length,
          inputTypes: [...document.querySelectorAll('input')].slice(0, 32).map(input => input.type || 'text') }));
        emit('dom_change', `Page state metadata: ${JSON.stringify(pageState).slice(0, 400)}.`);
        emit('action_completed', `Investigator ${action.type} action completed.`);
      }
    } catch (error) {
      response = { requestId, ok: false, error: 'Action could not be completed under browser policy.' };
      if (!pointerMove) emit('action_failed', `Investigator ${action.type} action failed.`);
    }
    process.stdout.write(`TL_RESPONSE:${JSON.stringify(response)}\n`);
  };
  let commandChain = Promise.resolve();
  commands.on('line', line => { commandChain = commandChain.then(() => onLine(line)).catch(() => {}); });
  const startAcknowledged = await startedPromise;
  if (startAcknowledged) await closedPromise;
  emit('interactive_session_ended', 'Interactive worker session ended.', page.url(), { reason: endReason });
}

// ── Main Entrypoint ──
(async () => {
  try {
    if (!playwright) throw new Error('Playwright is required for Mode C; HTTP-only fallback is disabled.');
    const result = await runPlaywrightInspection();

    result.jobId = jobId;
    result.targetUrl = targetUrl;
    result.durationMs = Date.now() - startTime;
    result.warnings = warnings;
    result.errors = errors;
    result.limitations = limitations;

    fs.mkdirSync(path.dirname(outputPath), { recursive: true });
    writeBoundedJson(outputPath, result);
    if (handoffGraceMs > 0) await new Promise(resolve => setTimeout(resolve, handoffGraceMs));
    process.exit(0);
  } catch (fatal) {
    const safeFailureType = /^[A-Za-z][A-Za-z0-9]*$/.test(String(fatal?.name || '')) ? fatal.name : 'Error';
    const safeFailureCode = /^[A-Z0-9_]+$/.test(String(fatal?.code || '')) ? `:${fatal.code}` : '';
    const safeFailureDetail = String(fatal?.message || '').split('\n')[0]
      .replaceAll(targetUrl, '[TARGET]')
      .replace(/https?:\/\/[^\s"'<>]+/ig, '[URL]')
      .replace(/(token|secret|password|cookie|authorization)\s*[=:]\s*[^\s&]+/ig, '$1=[REDACTED]')
      .replace(/[A-Za-z0-9_-]{32,}/g, '[REDACTED]').slice(0, 180);
    console.error(`TRUSTLAYER_WORKER_FAILURE=${safeFailureType}${safeFailureCode}:${safeFailureDetail}`);
    const errorResult = {
      jobId,
      targetUrl,
      status: 'FAILED',
      error: fatal.message,
      durationMs: Date.now() - startTime,
      isolationReport: {
        sandboxType: 'WORKER_RUNTIME_UNVERIFIED',
        workerPid: process.pid,
        chromiumSandboxEnabled: false,
        chromiumSandboxVerification: sandboxVerification || {
          status: 'UNAVAILABLE', browserSandboxEnabled: false,
          failures: ['BROWSER_LAUNCH_OR_SANDBOX_DIAGNOSTIC_NOT_COMPLETED']
        },
        error: fatal.message
      }
    };
    try {
      fs.mkdirSync(path.dirname(outputPath), { recursive: true });
      writeBoundedJson(outputPath, errorResult);
    } catch {}
    process.exit(1);
  }
})();
