import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import http from 'node:http';
import path from 'node:path';
import { createHash, randomBytes, randomUUID } from 'node:crypto';
import { test } from 'node:test';
import { chromium } from 'playwright';
import { createApp } from '../backend/server.js';
import { validateEvidenceEvent } from '../core/evidence_event.js';
import { globalJobController, interactiveLifecycleEvidence } from '../core/investigators/live_job_controller.js';
import { classifyInteractiveUiReadiness, isInteractiveUiReady } from './helpers/interactive_startup_diagnostics.js';
import { closeBrowserBounded } from './helpers/bounded_browser_shutdown.js';
import { buildTypingControlFailureDiagnostic, logDiagnosticSafely, safeUiPath,
  withPlaywrightStepDeadline } from './helpers/typing_control_failure_diagnostic.js';
import { installInteractiveCardObserver } from './helpers/interactive_card_observer.js';
import { summarizeInteractionFailure } from './helpers/interactive_failure_summary.js';
import { prepareTypingActionInputs } from './helpers/typing_action_inputs.js';
import { fixtureCredentialMarker, summarizeFixtureCredentialObservations } from './helpers/fixture_credential_marker.js';
import { isExpectedCancelledEventStreamAbort } from './helpers/expected_sse_abort.js';
import { classifyConsoleError, isExpectedCaseCreationAuthChallenge } from './helpers/console_error_classification.js';
import { DNSReconInvestigator } from '../core/investigators/dns_recon.js';

const enabled = process.env.TRUSTLAYER_DOCKER_INTERACTIVE_FIXTURE === '1';
const testTimeoutMs = 360_000;
const fixturePort = 8080;
const screenshotRoot = path.resolve('data', 'screenshots');

function docker(args, timeout = 30_000) {
  return execFileSync('docker', args, { encoding: 'utf8', timeout, maxBuffer: 4 * 1024 * 1024,
    windowsHide: true, stdio: ['ignore', 'pipe', 'pipe'] }).trim();
}

function redactFixtureLog(value) {
  return String(value)
    .replace(/((?:password|token|secret|authorization|cookie)["'\s:=]+)[^\s,}"']+/gi, '$1[REDACTED]')
    .replace(/\bBearer\s+\S+/gi, 'Bearer [REDACTED]')
    .replace(/(https?:\/\/)[^/@\s:]+:[^/@\s]+@/gi, '$1[REDACTED]@')
    .replace(/([?&](?:token|secret|key|password)=)[^&\s]+/gi, '$1[REDACTED]')
    .slice(-4_000);
}

function redactDiagnosticField(value) {
  return redactFixtureLog(value).slice(0, 500);
}

function printFixtureReadinessDiagnostics({ fixtureName, fixtureContainerId, fixtureNetworkName, readinessTarget }) {
  const diagnostics = { type: 'fixture-readiness-failure', containerName: fixtureName,
    containerId: fixtureContainerId || null, expectedNetwork: fixtureNetworkName, readinessTarget };
  try {
    const state = JSON.parse(docker(['inspect', fixtureName, '--format={{json .State}}'], 5000));
    diagnostics.state = { status: state.Status, running: state.Running, exitCode: state.ExitCode,
      oomKilled: state.OOMKilled, error: redactFixtureLog(state.Error || '') };
  } catch {
    diagnostics.state = 'container inspect unavailable';
  }
  try {
    const networks = JSON.parse(docker(['inspect', fixtureName, '--format={{json .NetworkSettings.Networks}}'], 5000));
    diagnostics.networkAttachments = Object.entries(networks || {}).map(([name, item]) => ({
      name, ipAddress: item.IPAddress || '', aliases: (item.Aliases || []).slice(0, 8)
    }));
  } catch {
    diagnostics.networkAttachments = 'container network inspect unavailable';
  }
  try {
    // This purpose-built fixture receives no credentials and does not log requests.
    diagnostics.logs = redactFixtureLog(docker(['logs', '--tail', '60', fixtureName], 5000));
  } catch {
    diagnostics.logs = 'fixture logs unavailable';
  }
  console.error(`[trustlayer-fixture-diagnostic] ${JSON.stringify(diagnostics)}`);
}

function inspectContainerForFailure(role, name) {
  const item = { role, name };
  try {
    const state = JSON.parse(docker(['inspect', name, '--format={{json .State}}'], 4000));
    item.containerId = docker(['inspect', name, '--format={{.Id}}'], 4000);
    item.state = { status: state.Status, running: state.Running, exitCode: state.ExitCode,
      oomKilled: state.OOMKilled, error: redactFixtureLog(state.Error || '') };
  } catch {
    item.state = 'container inspect unavailable';
  }
  try {
    const networks = JSON.parse(docker(['inspect', name, '--format={{json .NetworkSettings.Networks}}'], 4000));
    item.networkAttachments = Object.entries(networks || {}).map(([network, value]) => ({
      name: network, ipAddress: value.IPAddress || '', aliases: (value.Aliases || []).slice(0, 8)
    }));
  } catch {
    item.networkAttachments = 'container network inspect unavailable';
  }
  try {
    const lines = docker(['logs', '--tail', '80', name], 4000).split(/\r?\n/);
    const safeLines = role === 'worker'
      ? lines.filter(line => /^(?:TRUSTLAYER_WORKER_FAILURE=|Usage: node worker\/browser_worker\.js)/.test(line))
      : (role === 'proxy'
        ? lines.filter(line => /^(?:TRUST_LAYER_EGRESS_READY|Egress proxy (?:requires|rejected|failed to start):|Failed to persist egress observations:)/.test(line))
        : lines);
    item.logs = redactFixtureLog(safeLines.join('\n'));
  }
  catch { item.logs = 'container logs unavailable'; }
  return item;
}

function readSafeProxySummary(tempDir) {
  if (!tempDir) return 'proxy output directory unavailable';
  try {
    const outputPath = path.join(tempDir, 'egress.json');
    if (!fs.existsSync(outputPath) || fs.statSync(outputPath).size > 7 * 1024 * 1024) return 'proxy observations unavailable';
    const observations = JSON.parse(fs.readFileSync(outputPath, 'utf8'));
    const requests = (items, allowed) => (Array.isArray(items) ? items : []).slice(-20).map(item => allowed
      ? { method: item.method, status: item.status, destinationHost: item.destinationHost,
        targetIp: item.targetIp, resolvedIps: (item.resolvedIps || []).slice(0, 8) }
      : { method: item.method, type: item.type, reason: redactDiagnosticField(item.reason || '') });
    return { allowedRequests: requests(observations.allowedRequests, true).slice(-10),
      blockedRequests: requests(observations.blockedRequests, false).slice(-10) };
  } catch {
    return 'proxy observations unavailable or malformed';
  }
}

function printRuntimeFailureDiagnostics({ caseId, status, error, browserContainerName, egressContainerName,
  workerError, workerStatus, workerHttpStatus, sandboxVerification, networkFailures, tempDir,
  fixtureName, fixtureNetworkName, fixtureHost, fixturePort }) {
  const diagnostics = {
    type: 'interactive-worker-readiness-failure', caseId, status,
    error: redactFixtureLog(error || ''), workerStatus: redactFixtureLog(workerStatus || ''),
    workerError: redactFixtureLog(workerError || ''), workerHttpStatus,
    sandboxVerification, networkFailures: (networkFailures || []).slice(-8).map(item => ({
      method: item.method, type: item.type, status: item.status, error: redactDiagnosticField(item.error || '')
    })),
    readinessTarget: `http://${fixtureHost}:${fixturePort}/ through the job's authenticated egress proxy`,
    containers: [
      inspectContainerForFailure('worker', browserContainerName),
      inspectContainerForFailure('proxy', egressContainerName),
      inspectContainerForFailure('fixture', fixtureName)
    ],
    expectedFixtureNetwork: fixtureNetworkName,
    proxyObservations: readSafeProxySummary(tempDir)
  };
  console.error(`[trustlayer-runtime-diagnostic] ${JSON.stringify(diagnostics)}`);
}

function fixtureScript() {
  const html = `<!doctype html><html><head><meta charset="utf-8"><title>Trust Layer Local Fixture</title></head>
<body><h1>Local interactive fixture</h1><p id="state">State: ready</p>
<button id="change" type="button" onclick="document.getElementById('state').textContent='State: changed for local test';">Change state</button>
<label for="note">Local note</label><input id="note" type="text" autocomplete="off"></body></html>`;
  return `const http=require('node:http');const html=${JSON.stringify(html)};const credentialMarker=${fixtureCredentialMarker.toString()};http.createServer((req,res)=>{console.log(credentialMarker(req.headers));if(req.method!=='GET'){res.writeHead(405);return res.end()}res.writeHead(200,{'content-type':'text/html; charset=utf-8','content-length':Buffer.byteLength(html),'cache-control':'no-store'});res.end(html)}).listen(${fixturePort},'0.0.0.0',()=>console.log('TRUSTLAYER_FIXTURE_READY'))`;
}

async function waitFor(predicate, label, timeoutMs = 90_000) {
  const deadline = Date.now() + timeoutMs;
  let lastError;
  while (Date.now() < deadline) {
    try {
      const result = await predicate();
      if (result) return result;
    } catch (error) { lastError = error; }
    await new Promise(resolve => setTimeout(resolve, 100));
  }
  throw new Error(`${label} timed out${lastError ? ` (${lastError.message})` : ''}`);
}

async function settleTasksWithin(tasks, timeoutMs) {
  let timer;
  try {
    return await Promise.race([
      Promise.allSettled(tasks).then(() => true),
      new Promise(resolve => { timer = setTimeout(() => resolve(false), timeoutMs); })
    ]);
  } finally { clearTimeout(timer); }
}

async function clickForApiResponse({ page, button, base, pathname, appRequests, appResponses,
  failedAppRequests, label, caseId, handleRef, timeline = [], recordTimeline = () => {}, timeoutMs = 15_000 }) {
  const expectedUrl = new URL(pathname, base);
  const responsePromise = page.waitForResponse(response => {
    const url = new URL(response.url());
    return url.origin === expectedUrl.origin && url.pathname === expectedUrl.pathname &&
      response.request().method() === 'POST';
  }, { timeout: timeoutMs });
  try {
    // Promise.all attaches rejection handlers to both operations immediately.
    // This prevents a fast response timeout from becoming an unhandled
    // rejection while Playwright is still waiting for the button click.
    if (label === 'typing interaction') recordTimeline('first-typing-click-started');
    const [response] = await Promise.all([responsePromise, button.click({ timeout: 5_000 })]);
    return response;
  } catch (error) {
    const pathOf = value => {
      try { return new URL(value).pathname; } catch { return '[invalid-url]'; }
    };
    const activeHandle = caseId ? [...globalJobController.activeJobs.values()].find(item => item.job?.caseId === caseId) : null;
    // `activeJobs` is intentionally cleared at cleanup. Use the retained handle
    // reference for historical readiness/exit evidence; absence from the live
    // map must never be reported as proof that readiness was not received.
    const handle = handleRef || activeHandle;
    const lifecycle = handle ? interactiveLifecycleEvidence(handle) : null;
    logDiagnosticSafely('trustlayer-ui-action-diagnostic', () => ({
      type: 'ui-api-action-failure', label, operation: 'click-and-api-response',
      errorName: /^[A-Za-z][A-Za-z0-9]*$/.test(error?.name || '') ? error.name : 'Error',
      expectedPath: expectedUrl.pathname, currentUrl: safeUiPath(page.url()), pageClosed: page.isClosed(),
      matchingRequests: appRequests.filter(item => pathOf(item.url) === expectedUrl.pathname)
        .slice(-4).map(item => ({ method: item.method, path: pathOf(item.url) })),
      matchingResponses: appResponses.filter(item => pathOf(item.url) === expectedUrl.pathname)
        .slice(-4).map(item => ({ method: item.method, path: pathOf(item.url), status: item.status })),
      matchingRequestFailures: failedAppRequests.filter(item => item.path === expectedUrl.pathname)
        .slice(-4).map(({ path, errorCode, method, resourceType }) => ({ path, errorCode, method, resourceType })),
      workerReadiness: {
        active: Boolean(activeHandle),
        historicalEvidenceAvailable: Boolean(lifecycle),
        ...(lifecycle || { readyEventReceived: null, endReason: null, workerExitCode: null, workerSignalCode: null })
      },
      timeline: timeline.slice(-12)
    }));
    throw error;
  }
}

async function openEvents(base, caseId, operatorToken, caseToken) {
  const abort = new AbortController();
  const response = await fetch(`${base}/api/cases/${caseId}/events`, {
    headers: { Authorization: `Bearer ${operatorToken}`, 'X-TrustLayer-Case-Access': caseToken }, signal: abort.signal
  });
  assert.equal(response.status, 200, 'authorized SSE connection must open');
  const messages = [];
  const reader = response.body.getReader();
  const pump = (async () => {
    let buffer = '';
    try {
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        buffer += new TextDecoder().decode(value, { stream: true });
        let boundary;
        while ((boundary = buffer.indexOf('\n\n')) >= 0) {
          const frame = buffer.slice(0, boundary);
          buffer = buffer.slice(boundary + 2);
          const data = frame.split('\n').filter(line => line.startsWith('data:')).map(line => line.slice(5).trim()).join('\n');
          if (data) { try { messages.push(JSON.parse(data)); } catch {} }
        }
      }
    } catch {}
  })();
  return {
    messages,
    async waitFor(predicate, label, timeoutMs = 12_000) {
      return waitFor(() => messages.find(predicate), label, timeoutMs);
    },
    async close() {
      abort.abort();
      await reader.cancel().catch(() => {});
      await Promise.race([pump, new Promise(resolve => setTimeout(resolve, 1000))]);
    }
  };
}

async function createInvestigation(base, operatorToken, target) {
  const response = await fetch(`${base}/api/cases`, {
    method: 'POST', headers: { Authorization: `Bearer ${operatorToken}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({ target, targetType: 'URL', inspectionMode: 'ISOLATED_LIVE', consentConfirmed: true,
      captureDelayMs: 0, interactive: true })
  });
  assert.equal(response.status, 201);
  const created = await response.json();
  assert.equal(typeof created.caseAccessToken, 'string');
  assert.equal(created.caseAccessToken.length, 43);
  assert.equal(JSON.stringify(created).includes(operatorToken), false);
  return created;
}

async function getCase(base, operatorToken, created) {
  const response = await fetch(`${base}/api/cases/${created.caseId}`, {
    headers: { Authorization: `Bearer ${operatorToken}`, 'X-TrustLayer-Case-Access': created.caseAccessToken }
  });
  assert.equal(response.status, 200);
  return response.json();
}

async function readCaseForFailureDiagnostic(base, operatorToken, created, timeoutMs = 1500) {
  const controller = new AbortController();
  const startedAt = performance.now();
  let stage = 'REQUEST_HEADERS';
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const response = await fetch(`${base}/api/cases/${created.caseId}`, {
      headers: { Authorization: `Bearer ${operatorToken}`, 'X-TrustLayer-Case-Access': created.caseAccessToken },
      signal: controller.signal
    });
    if (!response.ok) return { readStatus: 'HTTP_ERROR', httpStatus: response.status, schema: null };
    stage = 'RESPONSE_BODY';
    try {
      const schema = await response.json();
      if (!schema || schema.id !== created.caseId || typeof schema.interactiveSession !== 'object') {
        return { readStatus: 'INVALID_SCHEMA', httpStatus: response.status, schema: null };
      }
      return { readStatus: 'OK', httpStatus: response.status, schema };
    } catch {
      return { readStatus: 'INVALID_JSON', httpStatus: response.status, schema: null };
    }
  } catch (error) {
    return { readStatus: controller.signal.aborted ? 'TIMEOUT' : 'NETWORK_ERROR',
      errorName: ['AbortError', 'TimeoutError', 'TypeError'].includes(error?.name) ? error.name : 'Error',
      stage, elapsedMs: Math.max(0, Math.round(performance.now() - startedAt)), schema: null };
  } finally {
    clearTimeout(timer);
  }
}

async function readInteractiveUiSnapshot(page) {
  return page.evaluate(() => {
    const statuses = document.querySelectorAll('#interactive-status');
    const cards = document.querySelectorAll('#ov-interactive-browser-card');
    const controls = document.querySelectorAll('#interactive-type');
    const status = statuses.length === 1 ? statuses[0] : null;
    const card = cards.length === 1 ? cards[0] : null;
    const control = controls.length === 1 ? controls[0] : null;
    const isVisible = element => {
      if (!element) return false;
      const style = getComputedStyle(element);
      const rect = element.getBoundingClientRect();
      return style.display !== 'none' && style.visibility !== 'hidden' && rect.width > 0 && rect.height > 0;
    };
    const schema = window.activeCase?.schema || null;
    const sse = (window.__trustLayerSseMessages || []).slice(-24).flatMap(entry => {
      try {
        const message = JSON.parse(entry.data);
        return [{
          receivedAt: Number.isFinite(entry.receivedAt) ? entry.receivedAt : null,
          event: ['snapshot', 'stage', 'complete', 'evidence_event'].includes(message.event) ? message.event : 'other',
          stage: typeof message.data?.stage === 'string' && /^[A-Z0-9_]{1,64}$/.test(message.data.stage) ? message.data.stage : null,
          caseStatus: typeof message.schema?.status === 'string' ? message.schema.status : null,
          interactiveStatus: typeof message.schema?.interactiveSession?.status === 'string' ? message.schema.interactiveSession.status : null,
          runtimeSessionActive: typeof message.schema?.liveInspection?.runtimeSessionActive === 'boolean'
            ? message.schema.liveInspection.runtimeSessionActive : null,
          evidenceEventType: typeof message.data?.type === 'string' && /^[a-z_]{1,40}$/.test(message.data.type) ? message.data.type : null
        }];
      } catch { return []; }
    });
    return {
      documentReadyState: document.readyState,
      caseStatus: typeof schema?.status === 'string' ? schema.status : null,
      interactiveStatus: typeof schema?.interactiveSession?.status === 'string' ? schema.interactiveSession.status : null,
      runtimeSessionActive: typeof schema?.liveInspection?.runtimeSessionActive === 'boolean' ? schema.liveInspection.runtimeSessionActive : null,
      displayedStatus: status?.innerText || null,
      statusCount: statuses.length,
      cardCount: cards.length,
      cardVisible: isVisible(card),
      controlCount: controls.length,
      controlVisible: isVisible(control),
      controlEnabled: control ? control.matches(':enabled') : false,
      activeViewId: document.querySelector('.view-pane.active')?.id || null,
      sse
    };
  });
}

async function readInteractiveUiSnapshotBounded(page, timeoutMs = 750) {
  if (page.isClosed()) return { readStatus: 'PAGE_CLOSED' };
  let timer;
  try {
    const snapshot = await Promise.race([
      readInteractiveUiSnapshot(page).then(value => ({ readStatus: 'OK', value }), error => ({
        readStatus: 'EVALUATION_ERROR',
        errorName: /^[A-Za-z][A-Za-z0-9]*$/.test(error?.name || '') ? error.name : 'Error'
      })),
      new Promise(resolve => { timer = setTimeout(() => resolve({ readStatus: 'TIMEOUT' }), timeoutMs); })
    ]);
    return snapshot;
  } finally {
    clearTimeout(timer);
  }
}

async function prepareTypingControlForClick(page, onOperation = () => {}) {
  const view = page.locator('#view-overview');
  const card = view.locator('#ov-interactive-browser-card');
  const button = card.locator('#interactive-type');
  const step = async (name, run) => {
    onOperation(name);
    return withPlaywrightStepDeadline(name, run, 1_000);
  };
  await step('wait-for-card', () => card.waitFor({ state: 'visible', timeout: 1_000 }));
  const count = await step('count-button', () => button.count());
  if (count !== 1) throw new Error(`typing control count was ${count}`);
  await step('wait-for-button', () => button.waitFor({ state: 'visible', timeout: 1_000 }));
  await step('scroll-button', () => button.scrollIntoViewIfNeeded({ timeout: 1_000 }));
  const enabled = await step('check-button-enabled', () => button.isEnabled());
  if (!enabled) throw new Error('typing control was disabled after UI readiness');
  onOperation('read-control-state');
  return {
    button,
    state: {
      interactiveStatus: await step('read-interactive-status', () => page.locator('#interactive-status').innerText({ timeout: 1_000 })),
      enabled
    }
  };
}

function validateCaseEvents(schema) {
  const items = schema.interactiveSession.events;
  const knownEvidenceIds = new Set((schema.evidence || []).map(item => item.id));
  const knownEventIds = new Set();
  for (let i = 0; i < items.length; i++) {
    const result = validateEvidenceEvent(items[i], { investigationId: schema.id, knownEvidenceIds,
      expectedSequence: i + 1, knownEventIds });
    assert.equal(result.valid, true, `event ${i + 1} must satisfy the event schema: ${result.errors.join(', ')}`);
    knownEventIds.add(items[i].eventId);
  }
  return items;
}

async function waitReady(base, operatorToken, created) {
  const outcome = await waitFor(async () => {
    const schema = await getCase(base, operatorToken, created);
    if (schema.interactiveSession?.status === 'FAILED' || schema.liveInspection?.status === 'FAILED') {
      return { failed: schema };
    }
    if (schema.interactiveSession?.status === 'RUNNING' && schema.liveInspection?.runtimeSessionActive === true) {
      return { ready: schema };
    }
    return null;
  }, `investigation ${created.caseId} worker readiness`);
  if (outcome.failed) {
    throw new Error(`interactive worker failed before readiness (session=${outcome.failed.interactiveSession?.status || 'unknown'}, inspection=${outcome.failed.liveInspection?.status || 'unknown'})`);
  }
  return outcome.ready;
}

async function postAction(base, operatorToken, created, action) {
  const response = await fetch(`${base}/api/cases/${created.caseId}/interactions`, {
    method: 'POST', headers: { Authorization: `Bearer ${operatorToken}`, 'X-TrustLayer-Case-Access': created.caseAccessToken,
      'Content-Type': 'application/json' }, body: JSON.stringify({ action })
  });
  const body = await response.json();
  assert.equal(response.status, 200, `action ${action.type} must succeed: ${JSON.stringify(body)}`);
  return body;
}

async function assertJobReleased(caseId, jobId) {
  await waitFor(() => ![...globalJobController.activeJobs.values()].some(handle => handle.job?.caseId === caseId),
    `controller reservation cleanup for ${caseId}`, 15_000);
  assert.equal(globalJobController.admittedJobs.has(jobId), false);
}

test('opt-in Playwright UI workflow through the local Mode C fixture, supervisor, proxy and Chromium', {
  skip: !enabled, timeout: testTimeoutMs
}, async () => {
  assert.equal(process.env.NODE_ENV, 'test', 'fixture integration must run with NODE_ENV=test');
  assert.equal(process.env.DOCKER_CONTEXT, 'desktop-linux', 'use the authorized desktop-linux Docker context');

  const nonce = randomUUID().replaceAll('-', '').slice(0, 16).toLowerCase();
  const testStartedAt = performance.now();
  const timeline = [];
  const testStartedWallAt = Date.now();
  const recordTimeline = (step, details = {}) => timeline.push({ step,
    elapsedMs: Math.max(0, Math.round(performance.now() - testStartedAt)),
    wallElapsedMs: Math.max(0, Date.now() - testStartedWallAt), ...details });
  const fixtureName = `trustlayer-local-fixture-${process.pid}-${nonce}`;
  const fixtureHost = `trustlayer-fixture-${nonce}.test`;
  const fixtureNetworkName = `trustlayer-fixture-net-${nonce}`;
  const existingFiles = new Set(fs.readdirSync(screenshotRoot, { withFileTypes: true }).flatMap(entry => entry.isFile() ? [entry.name] : []));
  const operatorToken = randomBytes(32).toString('base64url');
  const cases = new Map();
  const createdCases = [];
  const collectors = [];
  const appRequests = [];
  const appResponses = [];
  const failedAppRequests = [];
  const blockedExternalRequests = [];
  const browserConsoleErrors = [];
  const interactiveCardObservations = [];
  const browserDialogs = [];
  const dialogFailures = [];
  const dialogTasks = new Set();
  const browserLifecycle = [];
  let workflowPhase = 'setup';
  let activeDialog = null;
  const recordBrowserLifecycle = (event, details = {}) => {
    browserLifecycle.push({ event, phase: workflowPhase, at: Date.now(), ...details });
    if (browserLifecycle.length > 20) browserLifecycle.shift();
  };
  const priorNodeEnv = process.env.NODE_ENV;
  const priorDnsResolve = DNSReconInvestigator.resolve;
  const previousFixturePolicy = globalJobController._testLocalFixturePolicy;
  const previousRuntimeFailureDiagnostics = globalJobController._testRuntimeFailureDiagnostics;
  const server = createApp({ apiToken: operatorToken, cases }).listen(0, '127.0.0.1');
  let fixtureAddress;
  let fixtureContainerId;
  let base;
  let uiBrowser;
  let uiBrowserServer;
  let uiBrowserProcess;
  let uiContext;
  let uiPage;
  let bodyError;
  try {
    await new Promise(resolve => server.once('listening', resolve));
    base = `http://127.0.0.1:${server.address().port}`;

    assert.equal(docker(['network', 'inspect', 'trustlayer-isolated-net', '--format={{.Internal}}']), 'true');
    docker(['network', 'create', '--driver', 'bridge', '--internal', fixtureNetworkName]);
    assert.equal(docker(['network', 'inspect', fixtureNetworkName, '--format={{.Driver}} {{.Internal}}']), 'bridge true');
    docker(['image', 'inspect', 'trustlayer-worker:latest', '--format={{.Id}}']);
    // Build only from the existing local image, with build networking disabled.
    docker(['build', '--network=none', '-t', 'trustlayer-worker:phase4-fixture-test',
      '-f', 'worker/Dockerfile.local-fixture-test', '.'], 120_000);
    fixtureContainerId = docker(['run', '-d', '--name', fixtureName, `--network=${fixtureNetworkName}`, `--network-alias=${fixtureHost}`,
      '--user=pwuser', '--read-only', '--tmpfs', '/tmp:rw,noexec,nosuid,size=4m', '--cap-drop=ALL',
      '--security-opt=no-new-privileges', '--pids-limit=8', '--memory=32m', '--cpus=0.25',
      '--entrypoint', 'node', 'trustlayer-worker:phase4-fixture-test', '-e', fixtureScript()]);
    const readinessTarget = `HTTP fixture endpoint http://127.0.0.1:${fixturePort}/ inside ${fixtureName}; listener marker confirms bind 0.0.0.0:${fixturePort} (network alias ${fixtureHost})`;
    try {
      await waitFor(() => {
        try {
          return docker(['logs', '--tail', '20', fixtureName], 3000).includes('TRUSTLAYER_FIXTURE_READY');
        } catch { return false; }
      }, 'fixture server readiness', 10_000);
    } catch (error) {
      printFixtureReadinessDiagnostics({ fixtureName, fixtureContainerId, fixtureNetworkName, readinessTarget });
      throw error;
    }
    const networkData = JSON.parse(docker(['inspect', fixtureName, '--format={{json .NetworkSettings.Networks}}']));
    const fixtureNetwork = networkData[fixtureNetworkName];
    assert.ok(fixtureNetwork, 'fixture must attach only to its internal local-fixture network');
    assert.deepEqual(Object.keys(networkData), [fixtureNetworkName]);
    assert.ok(fixtureNetwork.Aliases?.includes(fixtureHost), 'fixture hostname must be registered as an alias on its isolated network');
    fixtureAddress = fixtureNetwork.IPAddress;
    assert.match(fixtureAddress, /^(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.)/);
    globalJobController.configureLocalFixtureForTests({ hostname: fixtureHost, address: fixtureAddress,
      port: fixturePort, networkName: fixtureNetworkName }, {
      onRuntimeFailure: details => printRuntimeFailureDiagnostics({ ...details, fixtureName,
        fixtureNetworkName, fixtureHost, fixturePort })
    });

    // Mode C starts asynchronous DNS enrichment. Keep this exact synthetic
    // fixture hostname local and deterministic; every other name retains the
    // production resolver, and the test target contains no external links.
    DNSReconInvestigator.resolve = hostname => hostname.toLowerCase() === fixtureHost
      ? Promise.resolve({ status: 'SUCCESS', hostname: fixtureHost, ipAddresses: [fixtureAddress], dnsRecords: [],
        nameservers: [], asn: 'Docker local fixture', tlsMetadata: null, source: 'Test fixture mapping', timestamp: Date.now(), error: null })
      : priorDnsResolve.call(DNSReconInvestigator, hostname);

    const fixtureUrl = `http://${fixtureHost}:${fixturePort}/`;
    uiBrowserServer = await chromium.launchServer({ headless: true });
    uiBrowserProcess = uiBrowserServer.process();
    uiBrowserServer.on('close', (exitCode, signal) => recordBrowserLifecycle('browser-server-closed', {
      source: 'Playwright BrowserServer close event (launched ChildProcess onExit)',
      trackedProcessMatchesServer: uiBrowserServer.process() === uiBrowserProcess,
      exitCode: Number.isInteger(exitCode) ? exitCode : null,
      signal: typeof signal === 'string' ? signal : null,
      processExitCode: uiBrowserProcess.exitCode,
      processSignalCode: uiBrowserProcess.signalCode
    }));
    uiBrowserProcess.once('exit', (exitCode, signal) => recordBrowserLifecycle('child-process-exit', {
      exitCode: Number.isInteger(exitCode) ? exitCode : null, signal: typeof signal === 'string' ? signal : null
    }));
    uiBrowserProcess.once('close', (exitCode, signal) => recordBrowserLifecycle('child-process-close', {
      exitCode: Number.isInteger(exitCode) ? exitCode : null, signal: typeof signal === 'string' ? signal : null
    }));
    uiBrowser = await chromium.connect(uiBrowserServer.wsEndpoint());
    recordTimeline('playwright-browser-started');
    uiBrowser.on('disconnected', () => recordBrowserLifecycle('browser-disconnected'));
    uiContext = await uiBrowser.newContext();
    uiContext.on('close', () => recordBrowserLifecycle('context-closed'));
    // Observe messages delivered by the browser's native EventSource without
    // replacing the stream, its network request, or the frontend callback.
    await uiContext.addInitScript(() => {
      window.__trustLayerSseMessages = [];
      const descriptor = Object.getOwnPropertyDescriptor(EventSource.prototype, 'onmessage');
      if (!descriptor?.get || !descriptor?.set) return;
      Object.defineProperty(EventSource.prototype, 'onmessage', {
        configurable: descriptor.configurable,
        enumerable: descriptor.enumerable,
        get() { return descriptor.get.call(this); },
        set(handler) {
          descriptor.set.call(this, typeof handler === 'function' ? function(event) {
            window.__trustLayerSseMessages.push({ receivedAt: Date.now(), data: event.data });
            return handler.call(this, event);
          } : handler);
        }
      });
    });
    await uiContext.addInitScript(installInteractiveCardObserver);
    await uiContext.route('**/*', route => {
      const requestUrl = new URL(route.request().url());
      if (requestUrl.origin === base) return route.continue();
      if (['fonts.googleapis.com', 'fonts.gstatic.com'].includes(requestUrl.hostname)) {
        return route.fulfill({ status: 200, contentType: 'text/css', body: '' });
      }
      blockedExternalRequests.push(requestUrl.origin);
      return route.abort();
    });
    uiPage = await uiContext.newPage();
    uiPage.on('close', () => recordBrowserLifecycle('page-closed'));
    uiPage.on('crash', () => recordBrowserLifecycle('page-crashed'));
    uiPage.on('framenavigated', frame => {
      if (frame !== uiPage.mainFrame()) return;
      let path = 'unavailable';
      try { const url = new URL(frame.url()); path = `${url.origin}${url.pathname}`; } catch {}
      recordBrowserLifecycle('main-frame-navigated', { path });
    });
    uiPage.on('pageerror', error => recordBrowserLifecycle('page-error', {
      errorName: /^[A-Za-z][A-Za-z0-9]*$/.test(error?.name || '') ? error.name : 'Error'
    }));
    uiPage.on('request', request => {
      if (new URL(request.url()).origin === base) {
        const headers = request.headers();
        const cookies = headers.cookie || '';
        appRequests.push({ url: request.url(), path: new URL(request.url()).pathname,
          method: request.method(), phase: workflowPhase,
          resourceType: request.resourceType(),
          operatorSessionCookiePresent: /(?:^|;\s*)trustlayer_session=/.test(cookies),
          caseScopedCookiePresent: /(?:^|;\s*)trustlayer_case_TL-/.test(cookies),
          redirected: Boolean(request.redirectedFrom()) });
      }
    });
    uiPage.on('requestfailed', request => {
      if (new URL(request.url()).origin === base) {
        const failureText = request.failure()?.errorText || '';
        failedAppRequests.push({ path: new URL(request.url()).pathname, method: request.method(),
          resourceType: request.resourceType(),
          errorCode: /^net::ERR_[A-Z_]+$/.test(failureText) ? failureText : 'REQUEST_FAILED', phase: workflowPhase });
      }
    });
    uiPage.on('response', response => {
      if (new URL(response.url()).origin === base) {
        const responseCookies = response.request().headers().cookie || '';
        appResponses.push({ url: response.url(), path: new URL(response.url()).pathname,
          method: response.request().method(), resourceType: response.request().resourceType(),
          operatorSessionCookiePresent: /(?:^|;\s*)trustlayer_session=/.test(responseCookies),
          status: response.status(), phase: workflowPhase, response });
      }
    });
    uiPage.on('console', message => {
      if (message.type() === 'info' && message.text().startsWith('[trustlayer-ui-card-state]')) {
        try {
          const observation = JSON.parse(message.text().slice('[trustlayer-ui-card-state]'.length));
          interactiveCardObservations.push({ observedAt: Date.now(), ...observation });
          if (interactiveCardObservations.length > 16) interactiveCardObservations.shift();
        } catch {}
      }
      if (message.type() !== 'error') return;
      const source = message.location().url;
      if (!source || new URL(source).origin === base) {
        browserConsoleErrors.push(classifyConsoleError({ text: message.text(), sourceUrl: source, baseUrl: base, phase: workflowPhase }));
      }
    });
    uiPage.on('dialog', dialog => {
      const type = dialog.type();
      const phase = workflowPhase;
      browserDialogs.push(type);
      const dialogState = { type, phase, openedAt: Date.now() };
      activeDialog = dialogState;
      recordBrowserLifecycle(`dialog-${type}`);
      const task = (async () => {
        try {
          if (type === 'prompt' && phase === 'case-creation') {
            await dialog.accept(operatorToken);
            recordBrowserLifecycle('expected-auth-prompt-accepted');
            return;
          }
          await dialog.dismiss();
          dialogFailures.push({ type, phase, code: 'unexpected-dialog-dismissed' });
        } catch (error) {
          const failure = { type, phase, code: 'dialog-command-failed',
            errorName: /^[A-Za-z][A-Za-z0-9]*$/.test(error?.name || '') ? error.name : 'Error',
            pageClosed: uiPage?.isClosed() ?? null, browserConnected: uiBrowser?.isConnected() ?? null,
            lifecycle: browserLifecycle.slice(-8) };
          dialogFailures.push(failure);
          console.error(`[trustlayer-dialog-diagnostic] ${JSON.stringify(failure)}`);
        }
      })();
      dialogTasks.add(task);
      task.then(() => {
        dialogTasks.delete(task);
        if (activeDialog === dialogState) activeDialog = null;
      });
    });

    workflowPhase = 'home';
    const homeResponse = await uiPage.goto(`${base}/`, { waitUntil: 'domcontentloaded', timeout: 10_000 });
    assert.equal(homeResponse.status(), 200);
    assert.doesNotMatch(await uiPage.locator('body').innerText(), /Verified Safe Web Link/i);
    workflowPhase = 'console';
    const consoleResponse = await uiPage.goto(`${base}/investigation.html`, { waitUntil: 'domcontentloaded', timeout: 10_000 });
    assert.equal(consoleResponse.status(), 200);
    assert.equal(await uiPage.locator('#mode-c-interactive-optin').isChecked(), false,
      'interactive inspection must be unchecked by default');
    await uiPage.locator('#btn-hdr-mode-c').click();
    assert.equal(await uiPage.locator('input[name="inspection-mode"][value="ISOLATED_LIVE"]').isChecked(), true);
    await uiPage.locator('#intake-input').fill(fixtureUrl);
    await uiPage.locator('#intake-submit-btn').click();
    await uiPage.locator('#mode-c-consent-modal').waitFor({ state: 'visible', timeout: 5_000 });
    assert.equal(await uiPage.locator('#mode-c-interactive-optin').isChecked(), false,
      'interactive consent must require an explicit operator action');
    await uiPage.locator('#mode-c-interactive-optin').check();
    await uiPage.locator('#mode-c-capture-delay').selectOption('0');
    workflowPhase = 'case-creation';
    const authFlowResponseOffset = appResponses.length;
    const authFlowRequestOffset = appRequests.length;
    const authFlowFailureOffset = failedAppRequests.length;
    await uiPage.locator('#modal-confirm-btn').click({ timeout: 5_000 });
    const authFlow = await waitFor(() => {
      const responses = appResponses.slice(authFlowResponseOffset);
      const caseResponses = responses.filter(item => item.method === 'POST' && new URL(item.url).pathname === '/api/cases');
      const authResponses = responses.filter(item => item.method === 'POST' && new URL(item.url).pathname === '/api/auth/session');
      const finalCaseResponse = caseResponses.find(item => item.status !== 401);
      const failedLogin = authResponses.find(item => item.status !== 204);
      if (finalCaseResponse) return { caseResponses, authResponses, finalCaseResponse };
      if (failedLogin) return { caseResponses, authResponses, failedLogin };
      return null;
    }, 'operator authentication exchange and retried case creation', 20_000);
    if (authFlow.failedLogin) {
      throw new Error(`operator session exchange returned HTTP ${authFlow.failedLogin.status}`);
    }
    assert.equal(authFlow.caseResponses[0]?.status, 401,
      'fresh browser context must receive the initial authentication challenge');
    assert.equal(authFlow.authResponses.length, 1, 'the UI must submit one operator session exchange');
    assert.equal(authFlow.authResponses[0].status, 204, 'operator session exchange must succeed');
    assert.equal(authFlow.finalCaseResponse.status, 201, 'case creation retry must succeed after authentication');
    recordTimeline('authenticated-case-created');
    assert.equal(authFlow.caseResponses.length, 2, 'case creation must be retried once after the initial challenge');
    const authFlowRequests = appRequests.slice(authFlowRequestOffset);
    const createRequests = authFlowRequests.filter(item => item.method === 'POST' && new URL(item.url).pathname === '/api/cases');
    const sessionRequest = authFlowRequests.find(item => item.method === 'POST' && new URL(item.url).pathname === '/api/auth/session');
    assert.equal(createRequests.length, 2);
    assert.equal(createRequests[0].operatorSessionCookiePresent, false);
    assert.equal(createRequests[1].operatorSessionCookiePresent, true,
      'retried case creation must carry the HttpOnly operator session cookie');
    assert.equal(sessionRequest?.redirected, false);
    assert.ok(authFlowRequests.every(item => !item.redirected), 'operator authentication flow must not redirect');
    assert.equal(failedAppRequests.length, authFlowFailureOffset,
      'operator authentication flow must not fail at the browser transport layer');
    const createResponse = authFlow.finalCaseResponse.response;
    assert.equal(createResponse.status(), 201, `case creation returned HTTP ${createResponse.status()}`);
    const caseResponseBodyStartedAt = performance.now();
    const first = await createResponse.json();
    recordTimeline('case-creation-response-body-read', {
      durationMs: Math.max(0, Math.round(performance.now() - caseResponseBodyStartedAt))
    });
    createdCases.push(first);
    assert.equal(typeof first.caseAccessToken, 'string');
    assert.equal(first.caseAccessToken.length, 43);
    assert.equal(first.inspectionMode, 'ISOLATED_LIVE');
    assert.equal(JSON.stringify(first).includes(operatorToken), false);

    // Check the synchronous accepted-case UI state immediately. The UI builds
    // and renders its STARTING schema before opening SSE; the supplied run
    // showed ~64s between case creation and this assertion, while cookie and
    // other browser protocol checks were ahead of it. Their individual cost
    // was not recorded, so the specific slow operation is not established.
    recordTimeline('interactive-card-wait-started');
    const cardWaitStartedAt = performance.now();
    try {
      const card = uiPage.locator('#view-overview #ov-interactive-browser-card');
      await card.waitFor({ state: 'visible', timeout: 5_000 });
      const initialInteractiveStatus = await uiPage.locator('#view-overview #interactive-status').innerText({ timeout: 1_000 });
      assert.ok(['STARTING', 'RUNNING'].includes(initialInteractiveStatus),
        `accepted interactive case must render a recognized live state, got ${initialInteractiveStatus}`);
      if (initialInteractiveStatus === 'STARTING') {
        for (const id of ['interactive-navigate', 'interactive-click', 'interactive-type', 'interactive-screenshot', 'interactive-cancel']) {
          assert.equal(await card.locator(`#${id}`).isDisabled(), true,
            `${id} must remain disabled until the backend confirms the worker start handshake`);
        }
      }
      recordTimeline('interactive-card-visible', {
        durationMs: Math.max(0, Math.round(performance.now() - cardWaitStartedAt)),
        interactiveStatus: initialInteractiveStatus
      });
    } catch (error) {
      recordTimeline('interactive-card-wait-rejected', {
        durationMs: Math.max(0, Math.round(performance.now() - cardWaitStartedAt)),
        errorName: /^[A-Za-z][A-Za-z0-9]*$/.test(error?.name || '') ? error.name : 'Error'
      });
      const frontendReadStartedAt = performance.now();
      const frontendRead = await readInteractiveUiSnapshotBounded(uiPage);
      recordTimeline('interactive-card-failure-frontend-sample-finished', {
        durationMs: Math.max(0, Math.round(performance.now() - frontendReadStartedAt)),
        readStatus: frontendRead.readStatus
      });
      let backendRead = { readStatus: 'NOT_CAPTURED', schema: null };
      const backendReadStartedAt = performance.now();
      try { backendRead = await readCaseForFailureDiagnostic(base, operatorToken, first); }
      catch (diagnosticError) {
        backendRead = { readStatus: 'DIAGNOSTIC_FAILED',
          errorName: /^[A-Za-z][A-Za-z0-9]*$/.test(diagnosticError?.name || '') ? diagnosticError.name : 'Error', schema: null };
      }
      recordTimeline('interactive-card-failure-backend-read-finished', {
        durationMs: Math.max(0, Math.round(performance.now() - backendReadStartedAt)),
        readStatus: backendRead.readStatus
      });
      const summarizeSchema = schema => schema ? {
        status: schema.status || null,
        interactiveEnabled: schema.interactiveSession?.enabled === true,
        interactiveStatus: schema.interactiveSession?.status || null,
        endedReason: schema.interactiveSession?.endedReason || null,
        runtimeSessionActive: schema.liveInspection?.runtimeSessionActive ?? null,
        liveInspectionStatus: schema.liveInspection?.status || null
      } : null;
      const handle = [...globalJobController.activeJobs.values()].find(item => item.job?.caseId === first.caseId);
      recordBrowserLifecycle('interactive-card-startup-failure', {
        errorName: /^[A-Za-z][A-Za-z0-9]*$/.test(error?.name || '') ? error.name : 'Error'
      });
      logDiagnosticSafely('trustlayer-interactive-card-startup', () => ({
        type: 'interactive-card-startup-failure',
        testClock: {
          elapsedMonotonicMs: Math.max(0, Math.round(performance.now() - testStartedAt)),
          elapsedWallMs: Math.max(0, Date.now() - testStartedWallAt),
          startedWallAt: testStartedWallAt,
          sampledWallAt: Date.now()
        },
        frontendReadStatus: frontendRead.readStatus,
        frontend: frontendRead.value || null,
        backendRead: { readStatus: backendRead.readStatus, httpStatus: backendRead.httpStatus ?? null,
          errorName: backendRead.errorName || null, stage: backendRead.stage || null,
          elapsedMs: backendRead.elapsedMs ?? null },
        backend: summarizeSchema(backendRead.schema),
        browser: { pageClosed: uiPage.isClosed(), connected: uiBrowser.isConnected(),
          contextPageCount: uiContext.pages().length, processExitCode: uiBrowserProcess.exitCode,
          processSignalCode: uiBrowserProcess.signalCode, lifecycle: browserLifecycle.slice(-12) },
        uiCardObservations: interactiveCardObservations,
        worker: handle ? interactiveLifecycleEvidence(handle) : { activeHandle: false },
        apiRequests: appRequests.slice(-16).map(item => ({ method: item.method, path: new URL(item.url).pathname })),
        apiResponses: appResponses.slice(-16).map(item => ({ method: item.method, path: new URL(item.url).pathname, status: item.status })),
        apiRequestFailures: failedAppRequests.slice(-8).map(item => ({ path: new URL(item.url).pathname,
          errorCode: /ERR_[A-Z_]+/.exec(item.error || '')?.[0] || 'request-failed' })),
        timeline: timeline.slice(-20)
      }));
      throw error;
    }

    workflowPhase = 'worker-readiness';
    recordTimeline('waiting-for-case-and-worker-readiness');
    const firstReady = await waitReady(base, operatorToken, first);
    recordTimeline('case-reported-worker-ready');
    assert.equal(firstReady.liveInspection.isolationReport.chromiumSandboxVerification.status, 'VERIFIED',
      'fresh renderer evidence must pass before the inspected page is navigated');
    assert.equal(firstReady.liveInspection.httpStatus, 200);
    assert.equal(firstReady.liveInspection.finalUrl, `http://${fixtureHost}:${fixturePort}/`);
    assert.equal(firstReady.liveInspection.runtimeSessionActive, true);
    const firstHandle = [...globalJobController.activeJobs.values()].find(handle => handle.job?.caseId === first.caseId);
    assert.ok(firstHandle, 'real supervisor job must be active for the interactive session');
    assert.equal(firstHandle.interactiveReady, true, 'supervisor must have received the worker page-ready event');
    assert.ok(Number.isFinite(firstHandle.sessionReadyAt), 'supervisor must retain the current worker readiness time');
    assert.equal(interactiveLifecycleEvidence(firstHandle).readyEventReceived, true);
    assert.equal(firstHandle.interactiveStarted, true, 'worker must acknowledge the supervisor start command before controls are enabled');
    assert.ok(Number.isFinite(firstHandle.sessionStartedAt), 'finite user interaction deadline starts at supervisor acknowledgement');

    const uiReadinessSamples = [];
    let lastReadinessSnapshot = null;
    try {
      await waitFor(async () => {
        const snapshot = await readInteractiveUiSnapshot(uiPage);
        lastReadinessSnapshot = { observedAt: Date.now(),
          elapsedMs: Math.max(0, Math.round(performance.now() - testStartedAt)), ...snapshot };
        const sample = { observedAt: Date.now(), ...snapshot };
        sample.ready = isInteractiveUiReady(snapshot);
        uiReadinessSamples.push({ observedAt: sample.observedAt,
          elapsedMs: Math.max(0, Math.round(performance.now() - testStartedAt)),
          wallElapsedMs: Math.max(0, Date.now() - testStartedWallAt),
          displayedStatus: sample.displayedStatus,
          interactiveStatus: sample.interactiveStatus, runtimeSessionActive: sample.runtimeSessionActive,
          statusCount: sample.statusCount, cardCount: sample.cardCount, cardVisible: sample.cardVisible,
          controlCount: sample.controlCount, controlEnabled: sample.controlEnabled,
          activeViewId: sample.activeViewId, ready: sample.ready });
        if (uiReadinessSamples.length > 12) uiReadinessSamples.shift();
        return sample.ready;
      }, 'UI controls enabled after supervisor start acknowledgement', 5_000);
    } catch (error) {
      let backendRead = { readStatus: 'NOT_CAPTURED', schema: null };
      try { backendRead = await readCaseForFailureDiagnostic(base, operatorToken, first); }
      catch (diagnosticError) {
        backendRead = { readStatus: 'DIAGNOSTIC_FAILED',
          errorName: /^[A-Za-z][A-Za-z0-9]*$/.test(diagnosticError?.name || '') ? diagnosticError.name : 'Error', schema: null };
      }
      const summarizeSchema = schema => schema ? {
        status: schema.status || null,
        interactiveStatus: schema.interactiveSession?.status || null,
        endedReason: schema.interactiveSession?.endedReason || null,
        runtimeSessionActive: schema.liveInspection?.runtimeSessionActive ?? null,
        liveInspectionStatus: schema.liveInspection?.status || null
      } : null;
      const lifecycle = interactiveLifecycleEvidence(firstHandle);
      const readyStateObserved = Boolean(lastReadinessSnapshot?.sse?.some(item =>
        (item.event === 'stage' && item.stage === 'INTERACTIVE_SESSION_READY') || item.interactiveStatus === 'RUNNING'));
      const backendState = summarizeSchema(backendRead.schema);
      const uiState = lastReadinessSnapshot ? { ...lastReadinessSnapshot, sse: lastReadinessSnapshot.sse.slice(-12) } : null;
      recordBrowserLifecycle('interactive-ui-readiness-failure', {
        errorName: /^[A-Za-z][A-Za-z0-9]*$/.test(error?.name || '') ? error.name : 'Error'
      });
      logDiagnosticSafely('trustlayer-interactive-ui-startup', () => ({
        type: 'interactive-ui-startup-timeout',
        classification: classifyInteractiveUiReadiness({
          commandSentAt: lifecycle?.startCommandSentAt,
          acknowledgementReceivedAt: lifecycle?.startAcknowledgementReceivedAt,
          backendStatus: backendState?.interactiveStatus,
          frontendSchemaStatus: uiState?.interactiveStatus,
          displayedStatus: uiState?.displayedStatus,
          controlEnabled: uiState?.controlEnabled === true,
          readyStateObserved,
          endReason: lifecycle?.endReason || backendState?.endedReason
        }),
        backendRead: { readStatus: backendRead.readStatus, httpStatus: backendRead.httpStatus ?? null,
          errorName: backendRead.errorName || null, stage: backendRead.stage || null, elapsedMs: backendRead.elapsedMs ?? null },
        backend: backendState,
        frontend: uiState,
        readinessSamples: uiReadinessSamples,
        lifecycle,
        jobStillActive: [...globalJobController.activeJobs.values()].includes(firstHandle),
        apiRequests: appRequests.slice(-20).map(item => ({ method: item.method, path: new URL(item.url).pathname })),
        apiResponses: appResponses.slice(-20).map(item => ({ method: item.method, path: new URL(item.url).pathname, status: item.status })),
        apiRequestFailures: failedAppRequests.slice(-12).map(item => ({ path: new URL(item.url).pathname,
          errorCode: /ERR_[A-Z_]+/.exec(item.error || '')?.[0] || 'request-failed' })),
        timeline: timeline.slice(-16)
      }));
      throw error;
    }
    recordTimeline('ui-interaction-controls-enabled');
    workflowPhase = 'interaction-input-preflight';
    const typeInputPreparationStartedAt = performance.now();
    try {
      const inputSummary = await prepareTypingActionInputs(uiPage, {
        expectedSelector: '#note', text: 'local-only-note'
      });
      recordTimeline('interactive-type-inputs-prepared', {
        ...inputSummary,
        durationMs: Math.max(0, Math.round(performance.now() - typeInputPreparationStartedAt))
      });
    } catch (error) {
      recordTimeline('interactive-type-input-preparation-failed', {
        ...(error?.inputSummary || {}),
        errorName: /^[A-Za-z][A-Za-z0-9]*$/.test(error?.name || '') ? error.name : 'Error'
      });
      throw error;
    }
    workflowPhase = 'interaction-preflight';
    recordTimeline('typing-control-positioning-started');
    const positioningStartedAt = performance.now();
    let typingControl;
    let typingPreparationOperation = 'initialize-locators';
    let typingPreparationOperationStartedAt = performance.now();
    try {
      typingControl = await prepareTypingControlForClick(uiPage, operation => {
        typingPreparationOperation = operation;
        typingPreparationOperationStartedAt = performance.now();
        recordTimeline('typing-control-preparation-step', { operation });
      });
      recordTimeline('typing-control-positioned', {
        durationMs: Math.max(0, Math.round(performance.now() - positioningStartedAt))
      });
    } catch (error) {
      const errorName = /^[A-Za-z][A-Za-z0-9]*$/.test(error?.name || '') ? error.name : 'Error';
      recordBrowserLifecycle('typing-control-preparation-failure', { operation: typingPreparationOperation, errorName });
      recordTimeline('typing-control-preparation-failed', { operation: typingPreparationOperation,
        errorName, operationDurationMs: Math.max(0, Math.round(performance.now() - typingPreparationOperationStartedAt)) });
      logDiagnosticSafely('trustlayer-typing-position-diagnostic', () => buildTypingControlFailureDiagnostic({
        error, operation: typingPreparationOperation, phase: workflowPhase, url: uiPage.url(),
        elapsedMonotonicMs: Math.max(0, Math.round(performance.now() - testStartedAt)),
        elapsedWallMs: Math.max(0, Date.now() - testStartedWallAt), pageClosed: uiPage.isClosed(),
        browserConnected: uiBrowser.isConnected(), contextPageCount: uiContext.pages().length,
        serverProcessExitCode: uiBrowserProcess.exitCode, serverProcessSignalCode: uiBrowserProcess.signalCode,
        browserLifecycle, activeDialog, lastReadinessSample: lastReadinessSnapshot }));
      throw error;
    }
    const clickPosition = typingControl.state;
    const clickSessionElapsedMs = Number.isFinite(firstHandle.sessionStartedAt)
      ? Math.max(0, Date.now() - firstHandle.sessionStartedAt) : null;
    recordTimeline('typing-control-positioned-for-click', {
      interactiveStatusAtClick: clickPosition.interactiveStatus,
      displayedStatusAtClick: clickPosition.interactiveStatus,
      clickPosition,
      sessionElapsedMsAtClick: clickSessionElapsedMs
    });
    const clickPositionDiagnostic = JSON.stringify(clickPosition);
    assert.equal(clickPosition.interactiveStatus, 'RUNNING',
      `interactive session must still be running before the first click: ${clickPositionDiagnostic}`);
    assert.equal(clickPosition.enabled, true,
      `typing control must still be enabled before the first click: ${clickPositionDiagnostic}`);
    workflowPhase = 'interactive-actions';
    const typeResponse = await clickForApiResponse({ page: uiPage, button: typingControl.button,
      base, pathname: `/api/cases/${first.caseId}/interactions`, appRequests, appResponses,
      failedAppRequests, label: 'typing interaction', caseId: first.caseId, handleRef: firstHandle, timeline,
      recordTimeline: (step) => recordTimeline(step, {
        sessionElapsedMsAtClick: Number.isFinite(firstHandle.sessionStartedAt)
          ? Math.max(0, Date.now() - firstHandle.sessionStartedAt) : null
      }) });
    recordTimeline('first-typing-action-response');
    if (typeResponse.status() !== 200) {
      const interactionFailure = await summarizeInteractionFailure(typeResponse, { expectedFixtureSelector: '#note' });
      let caseState = null;
      try {
        const current = await getCase(base, operatorToken, first);
        caseState = {
          caseStatus: current.status || null,
          liveInspectionStatus: current.liveInspection?.status || null,
          interactiveStatus: current.interactiveSession?.status || null,
          interactiveEndReason: current.interactiveSession?.endedReason || null,
          workerLifecycle: current.interactiveSession?.workerLifecycle || null,
          eventSequence: (current.interactiveSession?.events || []).slice(-8).map(event => ({
            sequence: event.sequence, type: event.type
          }))
        };
      } catch { caseState = { unavailable: true }; }
      const handle = firstHandle;
      console.error('[trustlayer-interaction-failure]', JSON.stringify({
        ...interactionFailure, actionType: 'type',
        caseState,
        jobState: handle ? {
          interactive: handle.interactive === true,
          ready: handle.interactiveReady === true,
          childExitCode: handle.child?.exitCode ?? null,
          childSignalCode: handle.child?.signalCode ?? null,
          lifecycle: interactiveLifecycleEvidence(handle),
          sessionDeadlineExpired: Number.isFinite(handle.sessionDeadline) ? Date.now() >= handle.sessionDeadline : null,
          interactionCount: handle.interactionCount
        } : { activeHandle: false }
      }));
    }
    assert.equal(typeResponse.status(), 200, `typing interaction returned HTTP ${typeResponse.status()}`);

    // Inspect browser cookie metadata after the first live action. These
    // checks are required authorization assertions, but they are not a
    // prerequisite for rendering or issuing the already-authenticated case.
    const operatorCookieCheckStartedAt = performance.now();
    recordTimeline('operator-cookie-check-started');
    const sessionCookie = (await uiContext.cookies(`${base}/api/`)).find(cookie => cookie.name === 'trustlayer_session');
    recordTimeline('operator-cookie-check-finished', {
      durationMs: Math.max(0, Math.round(performance.now() - operatorCookieCheckStartedAt))
    });
    assert.ok(sessionCookie?.httpOnly, 'operator session must be held in an HttpOnly cookie');
    assert.equal(sessionCookie.path, '/api');
    assert.equal(sessionCookie.sameSite, 'Strict');
    assert.equal(sessionCookie.secure, false, 'test server uses HTTP; production adds Secure for HTTPS');
    const caseCookieCheckStartedAt = performance.now();
    recordTimeline('case-cookie-check-started');
    const firstCookie = (await uiContext.cookies(`${base}/api/`))
      .find(cookie => cookie.name === `trustlayer_case_${first.caseId}`);
    recordTimeline('case-cookie-check-finished', {
      durationMs: Math.max(0, Math.round(performance.now() - caseCookieCheckStartedAt))
    });
    assert.ok(firstCookie?.httpOnly, 'case credential must be stored in the HttpOnly case cookie');
    assert.ok(firstCookie.value === first.caseAccessToken, 'case cookie must contain the issued case credential');
    assert.equal(firstCookie.path, '/api');
    assert.equal(firstCookie.sameSite, 'Strict');
    assert.equal(firstCookie.secure, false, 'test server uses HTTP; production adds Secure for HTTPS');
    const optInCheckStartedAt = performance.now();
    assert.equal(await uiPage.locator('#mode-c-interactive-optin').isChecked(), true);
    recordTimeline('interactive-opt-in-confirmed', {
      durationMs: Math.max(0, Math.round(performance.now() - optInCheckStartedAt))
    });
    assert.equal(new URL(uiPage.url()).search.includes(first.caseAccessToken), false);
    await waitFor(() => uiPage.locator('#interactive-failure').innerText().then(value => /type completed/i.test(value)),
      'typing action result in the console', 10_000);
    const firstEvents = await openEvents(base, first.caseId, operatorToken, first.caseAccessToken);
    collectors.push(firstEvents);
    // Do not spend the bounded 120-second worker interaction window on
    // sequential Docker CLI diagnostics before the first user action.
    const [browserInspect, proxyInspect] = JSON.parse(docker(
      ['inspect', firstHandle.browserContainerName, firstHandle.egressContainerName], 10_000));
    assert.equal(browserInspect.State.Running, true);
    assert.equal(proxyInspect.State.Running, true);
    assert.deepEqual(Object.keys(browserInspect.NetworkSettings.Networks), ['trustlayer-isolated-net'],
      'browser must not share the fixture-only network');
    assert.deepEqual(Object.keys(proxyInspect.NetworkSettings.Networks).sort(),
      [fixtureNetworkName, 'trustlayer-isolated-net'].sort());
    const beforeClickSchema = await getCase(base, operatorToken, first);
    const beforeEvents = validateCaseEvents(beforeClickSchema);
    assert.ok(beforeEvents.some(event => event.type === 'dom_change' && /visibleTextLength/.test(event.observation)));

    const initialArtifactResponseCount = appResponses.filter(item =>
      new URL(item.url).pathname.startsWith(`/api/cases/${first.caseId}/interactive-artifacts/`)).length;
    const initialScreenshotAction = await clickForApiResponse({ page: uiPage, button: uiPage.locator('#interactive-screenshot'), caseId: first.caseId,
      base, pathname: `/api/cases/${first.caseId}/interactions`, appRequests, appResponses,
      failedAppRequests, label: 'initial screenshot interaction' });
    assert.equal(initialScreenshotAction.status(), 200,
      `initial screenshot interaction returned HTTP ${initialScreenshotAction.status()}`);
    const beforeScreenshotResponse = await waitFor(() => appResponses.filter(item =>
      new URL(item.url).pathname.startsWith(`/api/cases/${first.caseId}/interactive-artifacts/`))
      .slice(initialArtifactResponseCount).find(item => item.status === 200)?.response,
    'authorized initial screenshot API response', 15_000);
    const beforeScreenshotBytes = Buffer.from(await beforeScreenshotResponse.body());
    await waitFor(() => uiPage.locator('#interactive-screenshot-preview').evaluate(image => image.complete && image.naturalWidth > 0),
      'authorized screenshot rendered in the console', 10_000);
    assert.ok(beforeScreenshotBytes.length > 1000 && beforeScreenshotBytes.length <= 5 * 1024 * 1024);
    assert.deepEqual([...beforeScreenshotBytes.subarray(0, 8)], [137, 80, 78, 71, 13, 10, 26, 10]);

    await uiPage.locator('#interactive-selector').fill('#change');
    const clickResponse = await clickForApiResponse({ page: uiPage, button: uiPage.locator('#interactive-click'), caseId: first.caseId,
      base, pathname: `/api/cases/${first.caseId}/interactions`, appRequests, appResponses,
      failedAppRequests, label: 'button click interaction' });
    assert.equal(clickResponse.status(), 200, `button click interaction returned HTTP ${clickResponse.status()}`);
    await waitFor(() => uiPage.locator('#interactive-events').innerText().then(value => /dom_change|user_action/.test(value)),
      'SSE observation displayed in the console', 12_000);
    const uiSseMessages = await uiPage.evaluate(() => window.__trustLayerSseMessages.map(entry => {
      try { return JSON.parse(entry.data); } catch { return null; }
    }).filter(Boolean));
    assert.ok(uiSseMessages.some(message => message.event === 'evidence_event' &&
      message.data?.investigationId === first.caseId && ['dom_change', 'user_action'].includes(message.data?.type)),
    'the browser UI must receive a real evidence event through its native SSE connection');
    assert.ok(appRequests.some(request => new URL(request.url).pathname === `/api/cases/${first.caseId}/events`),
      'the UI must establish its authenticated case event stream');
    const afterClickSchema = await waitFor(async () => {
      const current = await getCase(base, operatorToken, first);
      const events = validateCaseEvents(current);
      const changes = events.filter(event => event.type === 'dom_change')
        .map(event => Number(/visibleTextLength":(\d+)/.exec(event.observation)?.[1])).filter(Number.isFinite);
      return changes.length >= 2 && changes.at(-1) > changes[0] ? current : null;
    }, 'observable fixture page state change');
    const browserEvent = await firstEvents.waitFor(message => message.event === 'evidence_event' &&
      ['dom_change', 'user_action'].includes(message.data?.type), 'browser event delivery over authenticated SSE');
    assert.ok(browserEvent.data.investigationId === first.caseId);
    assert.equal(JSON.stringify(browserEvent).includes(first.caseAccessToken), false,
      'case credential must not enter SSE payloads');
    validateCaseEvents(afterClickSchema);

    const postInteractionArtifactResponseCount = appResponses.filter(item =>
      new URL(item.url).pathname.startsWith(`/api/cases/${first.caseId}/interactive-artifacts/`)).length;
    const afterScreenshotAction = await clickForApiResponse({ page: uiPage, button: uiPage.locator('#interactive-screenshot'), caseId: first.caseId,
      base, pathname: `/api/cases/${first.caseId}/interactions`, appRequests, appResponses,
      failedAppRequests, label: 'post-interaction screenshot action' });
    assert.equal(afterScreenshotAction.status(), 200,
      `post-interaction screenshot action returned HTTP ${afterScreenshotAction.status()}`);
    const afterScreenshotResponse = await waitFor(() => appResponses.filter(item =>
      new URL(item.url).pathname.startsWith(`/api/cases/${first.caseId}/interactive-artifacts/`))
      .slice(postInteractionArtifactResponseCount).find(item => item.status === 200)?.response,
    'authorized post-interaction screenshot API response', 15_000);
    const artifactBytes = Buffer.from(await afterScreenshotResponse.body());
    const displayedArtifactUrl = await uiPage.locator('#interactive-screenshot-preview').getAttribute('src');
    const shot = { artifactId: new URL(displayedArtifactUrl, base).pathname.split('/').at(-1) };
    assert.match(shot.artifactId, /^[a-f0-9]{32}$/);
    await waitFor(() => uiPage.locator('#interactive-screenshot-preview').evaluate(image => image.complete && image.naturalWidth > 0),
      'post-interaction screenshot rendered in the console', 10_000);
    assert.ok(artifactBytes.length > 1000 && artifactBytes.length <= 5 * 1024 * 1024);
    assert.deepEqual([...artifactBytes.subarray(0, 8)], [137, 80, 78, 71, 13, 10, 26, 10]);
    assert.notEqual(createHash('sha256').update(beforeScreenshotBytes).digest('hex'),
      createHash('sha256').update(artifactBytes).digest('hex'), 'fixture click must produce a visually changed screenshot');

    const browserScreenshot = await uiPage.screenshot({ fullPage: true });
    assert.equal(JSON.stringify(afterClickSchema.interactiveSession.events).includes(first.caseAccessToken), false,
      'case credential must not enter evidence events');
    assert.equal(JSON.stringify(firstReady).includes(first.caseAccessToken), false,
      'case credential must not enter the case record');
    assert.equal((await uiPage.locator('body').innerText()).includes(first.caseAccessToken), false,
      'case credential must not appear in UI page content');
    assert.equal(browserScreenshot.includes(Buffer.from(first.caseAccessToken)), false,
      'case credential must not appear in the frontend screenshot');
    assert.equal(artifactBytes.includes(Buffer.from(first.caseAccessToken)), false,
      'case credential must not appear in the worker screenshot artifact');
    assert.ok(appRequests.every(request => !request.url.includes(first.caseAccessToken)), 'case credential must not enter request URLs');
    assert.equal(JSON.stringify(firstHandle.job).includes(first.caseAccessToken), false,
      'case credential must not be forwarded to the worker job');
    const fixtureLogs = docker(['logs', '--tail', '80', fixtureName]);
    const fixtureCredentialSummary = summarizeFixtureCredentialObservations(fixtureLogs);
    assert.ok(fixtureCredentialSummary.observationCount > 0 &&
      Object.values(fixtureCredentialSummary.received).every(received => !received),
    `fixture credential-isolation observations failed: ${JSON.stringify(fixtureCredentialSummary)}`);
    assert.equal(fixtureLogs.includes(first.caseAccessToken), false);
    assert.equal(docker(['logs', '--tail', '80', firstHandle.browserContainerName]).includes(first.caseAccessToken), false);
    assert.equal(docker(['logs', '--tail', '80', firstHandle.egressContainerName]).includes(first.caseAccessToken), false);

    const unauthenticatedCase = await fetch(`${base}/api/cases/${first.caseId}`);
    assert.equal(unauthenticatedCase.status, 401, 'unauthenticated case reads must be rejected');
    const operatorOnlyCase = await fetch(`${base}/api/cases/${first.caseId}`, { headers: { Authorization: `Bearer ${operatorToken}` } });
    assert.equal(operatorOnlyCase.status, 404, 'operator authentication without case access must be rejected');

    const unsafe = await createInvestigation(base, operatorToken, 'http://127.0.0.1/private/');
    createdCases.push(unsafe);
    const unsafeSchema = await waitFor(async () => {
      const schema = await getCase(base, operatorToken, unsafe);
      return schema.completedAt ? schema : null;
    }, 'unsafe destination rejection', 10_000);
    assert.equal(unsafeSchema.status, 'BLOCKED');
    assert.equal(unsafeSchema.assessment.verificationState, 'INVESTIGATION_INCOMPLETE');

    workflowPhase = 'cancellation';
    await uiPage.locator('#interactive-cancel').click();
    await waitFor(() => uiPage.locator('#interactive-failure').innerText().then(value => value === 'Browser stop requested.'),
      'cancellation confirmation in the console', 10_000);
    const cancelledFirstSchema = await waitFor(async () => {
      const current = await getCase(base, operatorToken, first);
      return current.interactiveSession?.status === 'CANCELLED' && current.liveInspection?.runtimeSessionActive === false &&
        ['COMPLETED', 'INCOMPLETE'].includes(current.status) ? current : null;
    }, 'cancelled investigation state', 10_000);
    assert.equal(await uiPage.locator('#interactive-status').innerText(), 'CANCELLED',
      'the console must display the actual cancelled session state');
    await firstEvents.close();
    const oldBrowserName = firstHandle.browserContainerName;
    const oldProxyName = firstHandle.egressContainerName;
    const oldTempDir = firstHandle.tempDir;
    const firstJobId = firstHandle.job.jobId;
    const firstEventIds = new Set(afterClickSchema.interactiveSession.events.map(event => event.eventId));
    await assertJobReleased(first.caseId, firstJobId);
    assert.throws(() => docker(['inspect', oldBrowserName, '--format={{.Id}}']));
    assert.throws(() => docker(['inspect', oldProxyName, '--format={{.Id}}']));
    assert.equal(fs.existsSync(oldTempDir), false);

    const second = await createInvestigation(base, operatorToken, `http://${fixtureHost}:${fixturePort}/`);
    createdCases.push(second);
    const secondReady = await waitReady(base, operatorToken, second);
    assert.equal(secondReady.liveInspection.isolationReport.chromiumSandboxVerification.status, 'VERIFIED');
    assert.equal(secondReady.liveInspection.httpStatus, 200);
    assert.equal(secondReady.interactiveSession.events.some(event => firstEventIds.has(event.eventId)), false,
      'new job must not inherit prior event IDs');
    const secondHandle = [...globalJobController.activeJobs.values()].find(handle => handle.job?.caseId === second.caseId);
    assert.ok(secondHandle && secondHandle.job.jobId !== firstHandle.job.jobId);
    const secondEvents = await openEvents(base, second.caseId, operatorToken, second.caseAccessToken);
    collectors.push(secondEvents);

    for (const route of [
      `/api/cases/${second.caseId}/events`,
      `/api/cases/${second.caseId}/interactive-artifacts/${shot.artifactId}`
    ]) {
      const denied = await fetch(`${base}${route}`, { headers: { Authorization: `Bearer ${operatorToken}`,
        'X-TrustLayer-Case-Access': first.caseAccessToken } });
      assert.equal(denied.status, 404, `case A credential must not access ${route}`);
    }
    const crossInteraction = await fetch(`${base}/api/cases/${second.caseId}/interactions`, {
      method: 'POST', headers: { Authorization: `Bearer ${operatorToken}`, 'X-TrustLayer-Case-Access': first.caseAccessToken,
        'Content-Type': 'application/json' }, body: JSON.stringify({ action: { type: 'click', selector: '#change' } })
    });
    assert.equal(crossInteraction.status, 404);

    const secondShot = await postAction(base, operatorToken, second, { type: 'screenshot' });
    assert.notEqual(secondShot.artifactId, shot.artifactId);
    const secondEventsSchema = await getCase(base, operatorToken, second);
    assert.equal(secondEventsSchema.interactiveSession.events.some(event => firstEventIds.has(event.eventId)), false);
    assert.equal(secondEventsSchema.interactiveSession.events.some(event => /State: changed for local test/.test(event.observation)), false);
    const secondArtifact = await fetch(`${base}/api/cases/${second.caseId}/interactive-artifacts/${secondShot.artifactId}`, {
      headers: { Authorization: `Bearer ${operatorToken}`, 'X-TrustLayer-Case-Access': second.caseAccessToken }
    });
    assert.equal(secondArtifact.status, 200);
    const secondBytes = Buffer.from(await secondArtifact.arrayBuffer());
    assert.ok(secondBytes.length > 1000);
    assert.notEqual(createHash('sha256').update(secondBytes).digest('hex'),
      createHash('sha256').update(artifactBytes).digest('hex'), 'second job screenshot must reflect its own initial fixture state');

    const cancelSecond = await fetch(`${base}/api/cases/${second.caseId}/cancel-live`, {
      method: 'POST', headers: { Authorization: `Bearer ${operatorToken}`, 'X-TrustLayer-Case-Access': second.caseAccessToken }
    });
    assert.equal(cancelSecond.status, 200);
    await secondEvents.close();
    const secondBrowserName = secondHandle.browserContainerName;
    const secondProxyName = secondHandle.egressContainerName;
    const secondTempDir = secondHandle.tempDir;
    const secondJobId = secondHandle.job.jobId;
    await assertJobReleased(second.caseId, secondJobId);
    assert.throws(() => docker(['inspect', secondBrowserName, '--format={{.Id}}']));
    assert.throws(() => docker(['inspect', secondProxyName, '--format={{.Id}}']));
    assert.equal(fs.existsSync(secondTempDir), false);
    const cancelLiveResponseStatus = appResponses.find(item => item.method === 'POST' &&
      new URL(item.url).pathname === `/api/cases/${first.caseId}/cancel-live`)?.status ?? null;
    const frontendEventStreamWasOpen = appRequests.some(request => request.method === 'GET' &&
      request.resourceType === 'eventsource' && new URL(request.url).pathname === `/api/cases/${first.caseId}/events`) &&
      appResponses.some(item => item.method === 'GET' && item.status === 200 &&
        new URL(item.url).pathname === `/api/cases/${first.caseId}/events`);
    const expectedCancellationAborts = failedAppRequests.filter(item => isExpectedCancelledEventStreamAbort(item, {
      caseId: first.caseId,
      eventStreamOpened: frontendEventStreamWasOpen,
      cancellationResponseStatus: cancelLiveResponseStatus,
      caseStatus: cancelledFirstSchema.status,
      interactiveStatus: cancelledFirstSchema.interactiveSession?.status,
      runtimeSessionActive: cancelledFirstSchema.liveInspection?.runtimeSessionActive
    }));
    const unexpectedAppRequestFailures = failedAppRequests.filter(item => !expectedCancellationAborts.includes(item));
    assert.deepEqual(unexpectedAppRequestFailures, [],
      'unexpected frontend request failures must remain visible; only the confirmed cancelled-case EventSource ERR_ABORTED is expected');
    assert.deepEqual(blockedExternalRequests, [], 'the frontend must not attempt unapproved external requests');
    const unauthenticatedCaseCreation401Count = appResponses.filter(item => item.phase === 'case-creation' &&
      item.method === 'POST' && item.path === '/api/cases' && item.status === 401 &&
      !item.operatorSessionCookiePresent).length;
    const authenticatedCaseCreation201Count = appResponses.filter(item => item.method === 'POST' &&
      item.path === '/api/cases' && item.status === 201 && item.phase === 'case-creation').length;
    const authSession204Count = appResponses.filter(item => item.method === 'POST' &&
      item.path === '/api/auth/session' && item.status === 204 && item.phase === 'case-creation').length;
    const allApplication401ResponseCount = appResponses.filter(item => item.status === 401).length;
    const expectedAuthChallengeErrors = browserConsoleErrors.filter(error => isExpectedCaseCreationAuthChallenge(error, {
      unauthenticatedCaseCreation401Count, authenticatedCaseCreation201Count, authSession204Count,
      allApplication401ResponseCount,
      authPromptAccepted: browserDialogs.includes('prompt') && browserLifecycle.some(item => item.event === 'expected-auth-prompt-accepted')
    }));
    const unexpectedConsoleErrors = browserConsoleErrors.filter(error => !expectedAuthChallengeErrors.includes(error));
    assert.ok(expectedAuthChallengeErrors.length <= 1, 'only one browser console error may correspond to the single initial authentication challenge');
    assert.deepEqual(unexpectedConsoleErrors, [],
      'frontend console errors must not occur except for the verified initial case-creation authentication challenge');
    assert.deepEqual(browserDialogs, ['prompt'], 'only the expected operator-authentication prompt should appear');
    assert.equal(appResponses.some(item => item.status >= 500), false, 'frontend API responses must not contain server errors');
    assert.equal(appResponses.some(item => item.status === 401 && !(item.method === 'POST' && new URL(item.url).pathname === '/api/cases')), false,
      'the only unauthenticated application response should be the expected case-creation challenge');
    for (const pathname of ['/api/auth/session', '/api/cases', `/api/cases/${first.caseId}/events`,
      `/api/cases/${first.caseId}/interactions`, `/api/cases/${first.caseId}/interactive-artifacts/`,
      `/api/cases/${first.caseId}/cancel-live`]) {
      assert.ok(appRequests.some(request => new URL(request.url).pathname.startsWith(pathname)),
        `the real frontend must call ${pathname}`);
    }
  } catch (error) {
    bodyError = error;
    recordTimeline('test-body-failed', { phase: workflowPhase,
      errorName: /^[A-Za-z][A-Za-z0-9]*$/.test(error?.name || '') ? error.name : 'Error' });
  } finally {
    recordTimeline('cleanup-started');
    const cleanupErrors = [];
    if (uiBrowserServer) {
      workflowPhase = 'pre-browser-teardown';
      if (dialogTasks.size) {
        const drained = await settleTasksWithin([...dialogTasks], 1_500);
        if (!drained) recordTimeline('dialog-drain-before-browser-close-deadline');
      }
      recordTimeline('ui-browser-close-started');
      const browserCloseStartedAt = performance.now();
      let shutdownOutcome;
      try {
        shutdownOutcome = await closeBrowserBounded({
          closeGracefully: async () => {
            if (uiContext) await uiContext.close();
            if (uiBrowser) await uiBrowser.close();
            await uiBrowserServer.close();
          },
          killBrowserServer: () => uiBrowserServer.kill(),
          process: uiBrowserProcess,
          gracefulTimeoutMs: 2_000,
          serverKillTimeoutMs: 1_500,
          processExitTimeoutMs: 1_500
        });
        console.log(`[trustlayer-browser-shutdown] ${JSON.stringify(shutdownOutcome)}`);
      } catch (error) {
        shutdownOutcome = error.outcome || { strategy: 'failed', errorCode: 'BROWSER_SHUTDOWN_FAILED' };
        cleanupErrors.push('Playwright browser shutdown failed; see structured shutdown diagnostic');
        console.error(`[trustlayer-browser-shutdown-failure] ${JSON.stringify(shutdownOutcome)}`);
      }
      recordTimeline('ui-browser-close-finished', {
        durationMs: Math.max(0, Math.round(performance.now() - browserCloseStartedAt)),
        ...(shutdownOutcome || { strategy: 'failed' })
      });
      if (dialogTasks.size && !(await settleTasksWithin([...dialogTasks], 500))) {
        cleanupErrors.push('dialog handlers remained pending after bounded browser shutdown');
      }
      if (dialogFailures.length) {
        const safeFailures = dialogFailures.map(({ type, phase, code, errorName, pageClosed, browserConnected }) =>
          ({ type, phase, code, errorName, pageClosed, browserConnected }));
        cleanupErrors.push(`dialog handling failed: ${JSON.stringify(safeFailures)}`);
      }
    }
    for (const events of collectors) {
      try { await events.close(); } catch { cleanupErrors.push('SSE disconnect'); }
    }
    const remainingJobs = [...globalJobController.activeJobs.entries()]
      .filter(([, handle]) => createdCases.some(item => item.caseId === handle.job?.caseId));
    for (const [jobId, handle] of remainingJobs) {
      try { await handle.cancel?.(); } catch { cleanupErrors.push('worker cancellation'); }
      try { await globalJobController._cleanup(jobId); } catch { cleanupErrors.push('supervisor cleanup'); }
      if (globalJobController.admittedJobs.has(jobId)) cleanupErrors.push('job reservation remained after cleanup');
      for (const name of [handle.browserContainerName, handle.egressContainerName]) {
        try { docker(['rm', '-f', name]); } catch {}
        try { docker(['inspect', name, '--format={{.Id}}']); cleanupErrors.push('container remained after cleanup'); } catch {}
      }
      if (fs.existsSync(handle.tempDir)) cleanupErrors.push('supervisor temporary directory remained after cleanup');
    }
    recordTimeline('supervisor-cleanup-finished');
    try { server.closeAllConnections(); } catch { cleanupErrors.push('API server connections'); }
    try { await new Promise((resolve, reject) => server.close(error => error ? reject(error) : resolve())); }
    catch { cleanupErrors.push('API server close'); }
    recordTimeline('api-server-close-finished');
    DNSReconInvestigator.resolve = priorDnsResolve;
    try { globalJobController.clearLocalFixtureForTests(); } catch { cleanupErrors.push('fixture policy reset'); }
    globalJobController._testLocalFixturePolicy = previousFixturePolicy;
    globalJobController._testRuntimeFailureDiagnostics = previousRuntimeFailureDiagnostics;
    if (priorNodeEnv === undefined) delete process.env.NODE_ENV;
    else process.env.NODE_ENV = priorNodeEnv;
    try { docker(['rm', '-f', fixtureName]); } catch {}
    try { docker(['inspect', fixtureName, '--format={{.Id}}']); cleanupErrors.push('fixture container remained after cleanup'); } catch {}
    try { docker(['network', 'rm', fixtureNetworkName]); } catch {}
    try { docker(['network', 'inspect', fixtureNetworkName, '--format={{.Id}}']); cleanupErrors.push('fixture network remained after cleanup'); } catch {}
    for (const created of createdCases) {
      const icase = cases.get(created.caseId);
      for (const artifactPath of icase?._interactiveArtifacts?.values() || []) {
        const resolved = path.resolve(artifactPath);
        if (resolved.startsWith(screenshotRoot + path.sep)) {
          try { fs.rmSync(resolved, { force: true }); } catch { cleanupErrors.push('case artifact cleanup'); }
        }
      }
      for (const name of [`${created.caseId}.png`, `${created.caseId}-initial.png`]) {
        if (!existingFiles.has(name)) {
          try { fs.rmSync(path.join(screenshotRoot, name), { force: true }); } catch { cleanupErrors.push('case screenshot cleanup'); }
        }
      }
    }
    recordTimeline('test-cleanup-finished', { cleanupErrorCount: cleanupErrors.length });
    if (bodyError) console.error(`[trustlayer-interactive-test-timeline] ${JSON.stringify({
      timeline: timeline.slice(-24), browserLifecycle: browserLifecycle.slice(-16)
    })}`);
    if (bodyError && cleanupErrors.length) throw new AggregateError([bodyError, new Error(`Cleanup failures: ${cleanupErrors.join(', ')}`)], 'Integration workflow and cleanup failed.');
    if (bodyError) throw bodyError;
    if (cleanupErrors.length) throw new Error(`Integration cleanup failed: ${cleanupErrors.join(', ')}`);
  }
});
