import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';
import test from 'node:test';
import { InvestigationEngine, publishInteractiveStartState } from '../core/investigation_engine.js';

const html = fs.readFileSync(new URL('../investigation.html', import.meta.url), 'utf8');

function loadInteractiveUiContract() {
  const helpersStart = html.indexOf('function interactiveSessionPhase(status) {');
  const helpersEnd = html.indexOf('\nasync function loadEvidenceReport', helpersStart);
  const rendererStart = html.indexOf('let interactiveViewportTimer = null;', helpersEnd);
  const rendererEnd = html.indexOf('\nasync function submitInteractiveAction', rendererStart);
  assert.ok(helpersStart >= 0 && helpersEnd > helpersStart && rendererStart > helpersEnd && rendererEnd > rendererStart,
    'interactive state helpers and panel renderer must be present');

  const ids = ['ov-interactive-browser-card', 'interactive-status', 'interactive-status-detail', 'interactive-events',
    'interactive-viewport-status', 'interactive-viewport-shell', 'interactive-live-viewport', 'interactive-viewport-placeholder',
    'interactive-viewport-input-status', 'interactive-screenshot-preview', 'interactive-navigate', 'interactive-click', 'interactive-type',
    'interactive-scroll', 'interactive-screenshot', 'interactive-cancel'];
  const elements = new Map(ids.map(id => [id, { id, style: {}, disabled: false, textContent: '', src: '', dataset: {}, removeAttribute() {} }]));
  elements.set('interactive-viewport-shell', null);
  const context = {
    window: {},
    activeCase: null,
    interactiveLiveEvents: [],
    setTimeout: () => 1,
    clearTimeout: () => {},
    document: { getElementById: id => elements.get(id) || null },
    updateCaseUI: schema => context.renderInteractivePanel(schema)
  };
  vm.createContext(context);
  vm.runInContext(`${html.slice(helpersStart, helpersEnd)}\n${html.slice(rendererStart, rendererEnd)}`, context);
  return { context, elements };
}

function interactiveCase() {
  const icase = InvestigationEngine.createCase('http://fixture.invalid/');
  icase.schema.interactiveSession = { enabled: true, status: 'STARTING', events: [] };
  icase.schema.liveInspection = { runtimeSessionActive: true };
  return icase;
}

test('missing worker start acknowledgement fails closed and does not publish RUNNING', () => {
  const icase = interactiveCase();
  const emitted = [];
  icase.on('*', message => emitted.push(message));
  const liveResult = { status: 'SUCCESS', runtimeSessionActive: true, runtimeSessionUntil: 123_000 };
  icase.schema.liveInspection = liveResult;
  assert.equal(publishInteractiveStartState(icase, liveResult, false, 100_000), false);
  assert.equal(icase.schema.interactiveSession.status, 'FAILED');
  assert.equal(liveResult.runtimeSessionActive, false);
  assert.equal(emitted.some(message => message.data?.stage === 'INTERACTIVE_SESSION_READY'), false);
});

test('worker start acknowledgement publishes a RUNNING schema in the consumed SSE stage envelope', () => {
  const icase = interactiveCase();
  const emitted = [];
  icase.on('*', message => emitted.push(message));
  const liveResult = { status: 'SUCCESS', runtimeSessionActive: true, runtimeSessionUntil: 123_000 };
  icase.schema.liveInspection = liveResult;
  assert.equal(publishInteractiveStartState(icase, liveResult, true, 101_000), true);
  assert.equal(icase.schema.interactiveSession.status, 'RUNNING');
  assert.equal(icase.schema.interactiveSession.collectionStatus, 'ready');
  const event = emitted.at(-1);
  assert.equal(event.event, 'stage');
  assert.equal(event.data.stage, 'INTERACTIVE_SESSION_READY');
  assert.equal(event.data.schema.id, icase.id);
  assert.equal(event.data.schema.interactiveSession.status, 'RUNNING');
  assert.equal(event.data.schema.liveInspection.runtimeSessionActive, true);
});

test('frontend consumes the confirmed SSE schema, keeps STARTING disabled, and resists stale snapshots', () => {
  const { context, elements } = loadInteractiveUiContract();
  const starting = { id: 'case-ui-order', target: 'http://fixture.invalid/', status: 'COMPLETED', evidence: [],
    interactiveSession: { enabled: true, status: 'STARTING', events: [] } };
  context.window.activeCase = context.activeCase = { id: starting.id, target: starting.target, schema: starting };
  context.renderInteractivePanel(starting);
  assert.equal(elements.get('ov-interactive-browser-card').style.display, 'block',
    'an accepted interactive case must display the card while the session is still starting');
  assert.equal(elements.get('interactive-status').textContent, 'STARTING');
  assert.match(elements.get('interactive-status-detail').textContent, /Controls unlock only after sandbox verification/);
  for (const id of ['interactive-navigate', 'interactive-click', 'interactive-type', 'interactive-scroll', 'interactive-screenshot', 'interactive-cancel']) {
    assert.equal(elements.get(id).disabled, true, `${id} must remain disabled before backend confirmation`);
  }

  const ready = { ...starting, interactiveSession: { ...starting.interactiveSession, status: 'RUNNING' } };
  const eventMessage = { event: 'stage', data: { stage: 'INTERACTIVE_SESSION_READY', schema: ready }, ts: 1 };
  const eventSchema = context.interactiveSchemaFromStreamMessage(eventMessage);
  assert.equal(eventSchema.interactiveSession.status, 'RUNNING');
  context.acceptCaseSchema(eventSchema);
  assert.equal(elements.get('interactive-status').textContent, 'RUNNING');
  assert.match(elements.get('interactive-status-detail').textContent, /Browser ready/);
  assert.equal(elements.get('interactive-type').disabled, false);
  assert.equal(elements.get('interactive-scroll').disabled, false);

  context.acceptCaseSchema(starting); // delayed pre-ready GET/SSE snapshot
  assert.equal(context.window.activeCase.schema.interactiveSession.status, 'RUNNING');
  assert.equal(elements.get('interactive-type').disabled, false);
});

test('terminal interactive state cannot be overwritten by stale RUNNING data', () => {
  const { context, elements } = loadInteractiveUiContract();
  const base = { id: 'case-ui-terminal', target: 'http://fixture.invalid/', status: 'COMPLETED', evidence: [] };
  const running = { ...base, interactiveSession: { enabled: true, status: 'RUNNING', events: [] } };
  const ended = { ...base, interactiveSession: { enabled: true, status: 'ENDED', endedReason: 'SESSION_LIMIT_REACHED', events: [] } };
  context.window.activeCase = context.activeCase = { id: base.id, target: base.target, schema: running };
  const endMessage = { event: 'stage', data: { stage: 'INTERACTIVE_SESSION_ENDED', schema: ended }, ts: 2 };
  const terminalSchema = context.interactiveSchemaFromStreamMessage(endMessage);
  assert.equal(terminalSchema.interactiveSession.status, 'ENDED');
  context.acceptCaseSchema(terminalSchema);
  assert.equal(elements.get('ov-interactive-browser-card').style.display, 'block',
    'terminal session state remains visible so the user can see the actual outcome');
  assert.equal(elements.get('interactive-status').textContent, 'ENDED');
  assert.match(elements.get('interactive-status-detail').textContent, /configured maximum interactive session duration was reached/,
    'the hard session expiry is reported distinctly from operator cancellation');
  assert.equal(elements.get('interactive-type').disabled, true);
  assert.equal(elements.get('interactive-scroll').disabled, true);
  context.acceptCaseSchema(running);
  assert.equal(context.window.activeCase.schema.interactiveSession.status, 'ENDED');
  assert.equal(elements.get('interactive-type').disabled, true);
});

test('live viewport maps displayed letterboxed image coordinates to normalized worker coordinates', () => {
  const start = html.indexOf('function viewportRatios(event) {');
  const end = html.indexOf('\nfunction isSensitiveViewportText', start);
  assert.ok(start >= 0 && end > start, 'frontend coordinate mapper must exist');
  const image = { naturalWidth: 1280, naturalHeight: 800,
    getBoundingClientRect: () => ({ left: 10, top: 20, width: 640, height: 480 }) };
  const context = { document: { getElementById: id => id === 'interactive-live-viewport' ? image : null } };
  vm.createContext(context);
  vm.runInContext(`${html.slice(start, end)}; globalThis.mapViewportPoint = viewportRatios;`, context);
  assert.deepEqual({ ...context.mapViewportPoint({ clientX: 330, clientY: 260 }) }, { x: 5000, y: 5000 },
    'letterbox offsets and 2x display scaling must map to the actual 1280x800 worker viewport');
  assert.equal(context.mapViewportPoint({ clientX: 330, clientY: 25 }), null,
    'clicks in the letterbox margin are not sent to the worker');
});

test('pointer movement coalesces to the latest position and never overlaps worker requests', async () => {
  const start = html.indexOf('let interactiveViewportTimer = null;');
  const end = html.indexOf('\nfunction bindInteractiveViewport()', start);
  assert.ok(start >= 0 && end > start, 'viewport movement scheduler must be present');
  const timers = [];
  const requests = [];
  let now = 10_000;
  let activeRequests = 0;
  let maxActiveRequests = 0;
  let resolveFirst;
  const context = {
    Date: { now: () => now },
    window: { activeCase: { id: 'case-pointer', schema: { interactiveSession: { status: 'RUNNING' } } } },
    document: { getElementById: () => ({ textContent: '' }) },
    setTimeout: (callback, delay) => { const timer = { callback, delay, id: timers.length + 1 }; timers.push(timer); return timer.id; },
    clearTimeout: id => { const timer = timers.find(item => item.id === id); if (timer) timer.cancelled = true; },
    submitInteractiveAction: action => {
      requests.push(action);
      activeRequests++;
      maxActiveRequests = Math.max(maxActiveRequests, activeRequests);
      if (requests.length === 1) return new Promise(resolve => { resolveFirst = value => { activeRequests--; resolve(value); }; });
      activeRequests--;
      return Promise.resolve(true);
    },
    interactiveViewportDisconnected: false
  };
  vm.createContext(context);
  vm.runInContext(`${html.slice(start, end)}\nglobalThis.queuePointer = queueInteractivePointerMove;`, context);

  context.queuePointer({ x: 1000, y: 1000 });
  context.queuePointer({ x: 2000, y: 2000 });
  const firstTimer = timers.find(item => !item.cancelled);
  const firstFlush = firstTimer.callback();
  await Promise.resolve();
  assert.equal(requests.length, 1);
  assert.equal(requests[0].x, 2000, 'intermediate pointer positions are replaced with the newest position');

  context.queuePointer({ x: 3000, y: 3000 });
  context.queuePointer({ x: 4000, y: 4000 });
  assert.equal(timers.filter(item => !item.cancelled).length, 1,
    'only one latest pointer position is retained while a worker request is active');
  resolveFirst(true);
  await firstFlush;
  now += 500;
  const secondTimer = timers.filter(item => !item.cancelled).at(-1);
  await secondTimer.callback();
  assert.deepEqual(requests.map(action => action.x), [2000, 4000]);
  assert.equal(maxActiveRequests, 1, 'pointer movement requests are serialized');
});

test('late viewport frames cannot repaint a terminal session and terminal no-content is handled quietly', async () => {
  const start = html.indexOf('let interactiveViewportTimer = null;');
  const end = html.indexOf('\nfunction bindInteractiveViewport()', start);
  assert.ok(start >= 0 && end > start, 'viewport polling lifecycle must be present');
  const timers = [];
  let resolveFetch;
  const image = { style: {}, src: '', onload: null, removeAttribute() {} };
  const placeholder = { style: {}, textContent: '' };
  const status = { textContent: '' };
  const elements = new Map([['interactive-live-viewport', image], ['interactive-viewport-placeholder', placeholder],
    ['interactive-viewport-status', status]]);
  const schema = { interactiveSession: { status: 'RUNNING' } };
  const context = {
    window: { activeCase: { id: 'case-cancel-race', schema } },
    document: { getElementById: id => elements.get(id) || { disabled: false } },
    URL: { createObjectURL: () => 'blob:stale-frame', revokeObjectURL() {} },
    setTimeout(callback) { const timer = { callback, id: timers.length + 1 }; timers.push(timer); return timer.id; },
    clearTimeout(id) { const timer = timers.find(item => item.id === id); if (timer) timer.cancelled = true; },
    fetch() { return new Promise(resolve => { resolveFetch = resolve; }); },
    trustLayerApiFetch() { return new Promise(resolve => { resolveFetch = resolve; }); },
    interactiveViewportDisconnected: false
  };
  context.window.trustLayerApiFetch = context.trustLayerApiFetch;
  vm.createContext(context);
  vm.runInContext(`${html.slice(start, end)}\nglobalThis.pollViewport = scheduleInteractiveViewport; globalThis.stopViewport = stopInteractiveViewport; globalThis.setViewportCaseId = value => interactiveViewportCaseId = value;`, context);

  context.setViewportCaseId('case-cancel-race');
  context.pollViewport('case-cancel-race');
  const pollPromise = timers.shift().callback();
  await Promise.resolve();
  schema.interactiveSession.status = 'CANCELLED';
  context.stopViewport('Viewport stopped (CANCELLED).');
  schema.interactiveSession.status = 'RUNNING'; // Same case starts a fresh authorized session.
  context.setViewportCaseId('case-cancel-race');
  resolveFetch({ status: 200, ok: true, blob: async () => ({ type: 'image/jpeg', size: 512 }) });
  await pollPromise;
  assert.equal(image.src, '', 'a successful but late frame must not replace terminal UI state');
  assert.equal(status.textContent, 'Viewport stopped (CANCELLED).', 'a late response cannot overwrite cancellation status');
  assert.equal(timers.filter(timer => !timer.cancelled).length, 1,
    'the fresh session may poll, but the old frame is not applied to it');

  schema.interactiveSession.status = 'CANCELLED';
  context.stopViewport('Viewport stopped (CANCELLED).');
  schema.interactiveSession.status = 'RUNNING';
  context.setViewportCaseId('case-cancel-race');
  context.pollViewport('case-cancel-race');
  const noContentTimer = timers.find(timer => !timer.cancelled);
  const noContentPoll = noContentTimer.callback();
  noContentTimer.cancelled = true;
  await Promise.resolve();
  schema.interactiveSession.status = 'CANCELLED';
  context.stopViewport('Viewport stopped (CANCELLED).');
  resolveFetch({ status: 204, ok: true });
  await noContentPoll;
  assert.equal(status.textContent, 'Viewport stopped (CANCELLED).', 'terminal no-content is not rendered as an error');
  assert.equal(timers.filter(timer => !timer.cancelled).length, 0, 'terminal sessions do not schedule another frame poll');
});
