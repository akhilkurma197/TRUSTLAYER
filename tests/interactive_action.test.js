import assert from 'node:assert/strict';
import { test } from 'node:test';
import { hasSensitiveText, isInteractiveSession, isSafeKeyboardTarget, isSafePointerTarget, isSafeTextTarget, validateInteractiveAction,
  MAX_INTERACTIVE_ACTIONS, MAX_INTERACTIVE_POINTER_MOVES } from '../core/interactive_action.js';
import { LiveJobController, markInteractiveSessionReady, markInteractiveSessionStarted } from '../core/investigators/live_job_controller.js';

test('interactive actions accept only bounded allowlisted parameters', () => {
  for (const action of [
    { type: 'back' }, { type: 'scroll', direction: 'down', pixels: 800 },
    { type: 'click', selector: '#continue' }, { type: 'type', selector: '[name="search"]', text: 'hello' },
    { type: 'navigate', url: 'https://example.invalid/path' }, { type: 'screenshot' },
    { type: 'pointer_move', x: 5000, y: 5000 }, { type: 'pointer_click', x: 5000, y: 5000 },
    { type: 'pointer_scroll', x: 0, y: 10000, direction: 'down', pixels: 800 },
    { type: 'type_focused', text: 'harmless local query' }, { type: 'key', key: 'Enter' },
    { type: 'key', key: 'Space' }, { type: 'key', key: 'Home' }, { type: 'key', key: 'PageDown' }
  ]) assert.equal(validateInteractiveAction(action).valid, true, JSON.stringify(action));
  for (const action of [null, {}, { type: 'evaluate', expression: 'alert(1)' },
    { type: 'reload', extra: true }, { type: 'navigate', url: 'https://user:pass@example.invalid/' },
    { type: 'scroll', direction: 'down', pixels: 801 }, { type: 'click', selector: 'button:has-text("go")' },
    { type: 'type', selector: '#search', text: 'x'.repeat(201) },
    { type: 'pointer_click', x: 10001, y: 0 },
    { type: 'pointer_scroll', x: 0, y: 0, direction: 'sideways', pixels: 801 },
    { type: 'type_focused', text: 'person@example.com' },
    { type: 'key', key: 'F12' }]) {
    assert.equal(validateInteractiveAction(action).valid, false);
  }
});

test('viewport input policy allows search and standalone text fields but rejects sensitive targets and actions', () => {
  assert.equal(isSafePointerTarget({ tagName: 'INPUT', type: 'search', name: 'q', withinForm: true }), true,
    'the isolated viewport can focus a normal search field inside its GET form');
  assert.equal(isSafePointerTarget({ tagName: 'BUTTON', type: 'button', label: 'More results' }), true);
  assert.equal(isSafePointerTarget({ tagName: 'BUTTON', type: 'submit', withinForm: true }), false);
  assert.equal(isSafeTextTarget({ tagName: 'INPUT', type: 'search', name: 'q', withinForm: true }), true);
  assert.equal(isSafeTextTarget({ tagName: 'TEXTAREA', name: 'q', withinForm: true }), true,
    'search query textareas are allowed while sensitive form controls remain blocked');
  assert.equal(isSafeTextTarget({ tagName: 'INPUT', type: 'text', name: 'q', withinForm: true, formMethod: 'get' }), true);
  assert.equal(isSafeTextTarget({ tagName: 'INPUT', type: 'text', name: 'q', withinForm: true, formMethod: 'post' }), false,
    'form search-like fields are accepted only for GET navigation');
  assert.equal(isSafeTextTarget({ tagName: 'INPUT', type: 'password', name: 'password' }), false);
  assert.equal(isSafeTextTarget({ tagName: 'INPUT', type: 'text', name: 'email' }), false);
  assert.equal(isSafeTextTarget({ tagName: 'INPUT', type: 'text', autocomplete: 'cc-number' }), false);
  assert.equal(isSafeTextTarget({ tagName: 'TEXTAREA', type: '', withinForm: true }), false);
  assert.equal(isSafePointerTarget({ tagName: 'A', href: 'https://wikipedia.test/article', target: '', label: 'Article' }), true,
    'ordinary credential-free HTTP(S) self-targeting article links are clickable; the enforced proxy validates destinations');
  assert.equal(isSafePointerTarget({ tagName: 'A', href: 'javascript:alert(1)', label: 'Article' }), false);
  assert.equal(isSafePointerTarget({ tagName: 'A', href: 'file:///secret', label: 'Article' }), false);
  assert.equal(isSafePointerTarget({ tagName: 'A', href: 'https://user:pass@wikipedia.test/article', label: 'Article' }), false);
  assert.equal(isSafePointerTarget({ tagName: 'A', href: 'https://wikipedia.test/article', target: '_blank', label: 'Article' }), false);
  assert.equal(isSafePointerTarget({ tagName: 'A', href: 'https://wikipedia.test/download', download: true, label: 'Article' }), false);
  assert.equal(hasSensitiveText('1234 5678 9012 3456'), true);
  assert.equal(hasSensitiveText('safe test query'), false);
});

test('pointer and keyboard policy permits ordinary native/custom controls but blocks consequential targets', () => {
  for (const target of [
    { tagName: 'INPUT', type: 'checkbox', name: 'updates' },
    { tagName: 'INPUT', type: 'radio', name: 'region' },
    { tagName: 'SELECT', name: 'category' },
    { tagName: 'SUMMARY', label: 'More details' },
    { tagName: 'BUTTON', type: 'button', role: 'tab', label: 'Overview' }
  ]) assert.equal(isSafePointerTarget(target), true, `${target.tagName}/${target.type || target.role || ''} should be operable`);
  assert.equal(isSafePointerTarget({ tagName: 'INPUT', type: 'checkbox', name: 'consent' }), false);
  assert.equal(isSafePointerTarget({ tagName: 'SELECT', name: 'payment_method' }), false);
  assert.equal(isSafePointerTarget({ tagName: 'SELECT', name: 'category', withinForm: true, formMethod: 'post' }), false);
  assert.equal(isSafePointerTarget({ tagName: 'BUTTON', type: 'button', disabled: true }), false);
  assert.equal(isSafePointerTarget({ tagName: 'BUTTON', type: 'button', ariaDisabled: true }), false);

  assert.equal(isSafeKeyboardTarget({ tagName: 'INPUT', type: 'checkbox', name: 'updates' }, 'Space'), true);
  assert.equal(isSafeKeyboardTarget({ tagName: 'INPUT', type: 'radio', name: 'region' }, 'ArrowDown'), true);
  assert.equal(isSafeKeyboardTarget({ tagName: 'SELECT', name: 'category' }, 'Enter'), true);
  assert.equal(isSafeKeyboardTarget({ tagName: 'BUTTON', type: 'button', role: 'tab' }, 'ArrowRight'), true);
  assert.equal(isSafeKeyboardTarget({ tagName: 'A', href: 'https://fixture.test/article' }, 'Enter'), true);
  assert.equal(isSafeKeyboardTarget({ tagName: 'INPUT', type: 'password', name: 'password' }, 'Enter'), false);
  assert.equal(isSafeKeyboardTarget({ tagName: 'BUTTON', type: 'submit', withinForm: true }, 'Enter'), false);
  assert.equal(isSafeKeyboardTarget({ tagName: 'BODY' }, 'Tab'), true);
});

test('interactive case state enables the isolated worker protocol only when explicitly enabled', () => {
  assert.equal(isInteractiveSession({ enabled: true, status: 'STARTING' }), true);
  assert.equal(isInteractiveSession({ enabled: false }), false);
  assert.equal(isInteractiveSession(undefined), false);
});

test('controller binds an interaction to its active case and enforces the action ceiling', async () => {
  const controller = Object.create(LiveJobController.prototype);
  const handle = {
    job: { caseId: 'TL-2026-1031-1200-ABC' }, interactive: true, interactionCount: 0,
    interactiveReady: true, interactiveStarted: true, sessionDeadline: Date.now() + 10_000, pendingInteractions: new Map(),
    child: { exitCode: null, stdin: { write(line) {
      const request = JSON.parse(line);
      queueMicrotask(() => {
        const pending = handle.pendingInteractions.get(request.requestId);
        if (pending) { handle.pendingInteractions.delete(request.requestId); clearTimeout(pending.timer); pending.resolve({ requestId: request.requestId, ok: true, action: 'back' }); }
      });
    } } }
  };
  controller.activeJobs = new Map([['job-a', handle]]);
  assert.equal((await controller.interact('TL-2026-1031-1200-OTHER', { type: 'back' })).ok, false);
  const accepted = await controller.interact('TL-2026-1031-1200-ABC', { type: 'back' });
  assert.equal(accepted.ok, true);
  assert.equal(accepted.action, 'back');
  const queued = await Promise.all(Array.from({ length: 10 }, () => controller.interact(handle.job.caseId, { type: 'pointer_move', x: 5000, y: 5000 })));
  assert.equal(queued.filter(result => result.ok).length, 8, 'the supervisor accepts only a bounded number of pending actions');
  assert.equal(queued.filter(result => /queue is full/.test(result.error || '')).length, 2);
  assert.equal(handle.pendingActionSlots, 0, 'completed actions release their queue reservations');
  handle.pointerMoveCount = MAX_INTERACTIVE_POINTER_MOVES - 1;
  assert.equal((await controller.interact(handle.job.caseId, { type: 'pointer_move', x: 5000, y: 5000 })).ok, true);
  assert.match((await controller.interact(handle.job.caseId, { type: 'pointer_move', x: 5000, y: 5000 })).error, /Pointer movement limit/);
  handle.interactionCount = MAX_INTERACTIVE_ACTIONS;
  assert.match((await controller.interact('TL-2026-1031-1200-ABC', { type: 'back' })).error, /limit/);
});

test('controller accepts 5000 sequential successful actions and rejects the next action', async () => {
  assert.ok(MAX_INTERACTIVE_ACTIONS >= 5_000);
  assert.ok(MAX_INTERACTIVE_POINTER_MOVES >= 5_000);
  const controller = Object.create(LiveJobController.prototype);
  const handle = { job: { caseId: 'TL-2026-1102-0900-BUD' }, interactive: true, interactionCount: 0,
    pendingDiscreteActions: 0, interactiveReady: true, interactiveStarted: true, sessionDeadline: Date.now() + 60_000,
    pendingInteractions: new Map(), child: { exitCode: null, stdin: { write(line) {
      const request = JSON.parse(line);
      queueMicrotask(() => {
        const pending = handle.pendingInteractions.get(request.requestId);
        if (pending) { handle.pendingInteractions.delete(request.requestId); clearTimeout(pending.timer); pending.resolve({ requestId: request.requestId, ok: true, action: 'back' }); }
      });
    } } } };
  controller.activeJobs = new Map([['job-budget', handle]]);
  for (let index = 0; index < MAX_INTERACTIVE_ACTIONS; index++) {
    const result = await controller.interact(handle.job.caseId, { type: 'back' });
    assert.equal(result.ok, true, `action ${index + 1} should be accepted`);
  }
  assert.equal(handle.interactionCount, 5_000);
  assert.equal((await controller.interact(handle.job.caseId, { type: 'back' })).error, 'Interaction limit reached.');
  assert.equal(handle.interactionCount, 5_000, 'the rejected action cannot increase the accepted-action counter');
});

test('worker-rejected actions release controller budget reservations', async () => {
  const controller = Object.create(LiveJobController.prototype);
  const handle = { job: { caseId: 'TL-2026-1102-0900-REJ' }, interactive: true, interactionCount: 0,
    pendingDiscreteActions: 0, interactiveReady: true, interactiveStarted: true, sessionDeadline: Date.now() + 10_000,
    pendingInteractions: new Map(), child: { exitCode: null, stdin: { write(line) {
      const request = JSON.parse(line);
      queueMicrotask(() => {
        const pending = handle.pendingInteractions.get(request.requestId);
        if (pending) { handle.pendingInteractions.delete(request.requestId); clearTimeout(pending.timer); pending.resolve({ requestId: request.requestId, ok: false, error: 'worker rejected' }); }
      });
    } } } };
  controller.activeJobs = new Map([['job-rejected', handle]]);
  assert.equal((await controller.interact(handle.job.caseId, { type: 'back' })).ok, false);
  assert.equal(handle.interactionCount, 0);
  assert.equal(handle.pendingDiscreteActions, 0);
});

test('viewport capture is case-bound, bounded, and does not consume a user interaction action', async () => {
  const controller = Object.create(LiveJobController.prototype);
  const handle = {
    job: { caseId: 'TL-2026-1031-1200-VIEW' }, interactive: true, interactionCount: 0,
    interactiveReady: true, interactiveStarted: true, sessionDeadline: Date.now() + 10_000,
    pendingInteractions: new Map(), viewportCaptureCount: 0, lastViewportCaptureAt: 0,
    child: { exitCode: null, stdin: { write(line) {
      const request = JSON.parse(line);
      assert.equal(request.command, 'CAPTURE_VIEWPORT');
      queueMicrotask(() => {
        const pending = handle.pendingInteractions.get(request.requestId);
        if (pending) { handle.pendingInteractions.delete(request.requestId); clearTimeout(pending.timer); pending.resolve({ ok: true, viewportBase64: Buffer.from('jpeg-frame').toString('base64') }); }
      });
    } } }
  };
  controller.activeJobs = new Map([['job-view', handle]]);
  assert.equal((await controller.captureViewport('TL-2026-1031-1200-OTHER')).ok, false);
  const frame = await controller.captureViewport(handle.job.caseId);
  assert.equal(frame.ok, true);
  assert.equal(Buffer.from(frame.viewportBase64, 'base64').toString(), 'jpeg-frame');
  assert.equal(handle.interactionCount, 0);
  assert.match((await controller.captureViewport(handle.job.caseId)).error, /rate limited/);
  assert.equal(handle.viewportCaptureCount, 1);
});

test('interactive session deadline starts at the supervisor start handshake, not worker page readiness', async () => {
  const controller = Object.create(LiveJobController.prototype);
  const handle = {
    job: { caseId: 'TL-2026-1031-1200-READY' }, interactive: true,
    interactionCount: 0, interactiveReady: false, sessionDurationMs: 120_000,
    sessionDeadline: null, pendingInteractions: new Map(),
    child: { exitCode: null, stdin: { write(line) {
      const request = JSON.parse(line);
      queueMicrotask(() => {
        const pending = handle.pendingInteractions.get(request.requestId);
        if (pending) {
          handle.pendingInteractions.delete(request.requestId);
          clearTimeout(pending.timer);
          pending.resolve({ requestId: request.requestId, ok: true, action: request.action.type });
        }
      });
    } } }
  };
  controller.activeJobs = new Map([['job-ready', handle]]);

  assert.equal((await controller.interact(handle.job.caseId, { type: 'type', selector: '#note', text: 'ok' })).ok, false);
  const workerReadyAt = Date.now();
  assert.equal(markInteractiveSessionReady(handle, { type: 'request_started' }, workerReadyAt), false);
  assert.equal(markInteractiveSessionReady(handle, { type: 'navigation_completed' }, workerReadyAt), true);
  assert.equal(handle.sessionReadyAt, workerReadyAt);
  assert.equal(handle.sessionDeadline, null, 'navigation readiness alone does not start the user interaction window');
  assert.equal(markInteractiveSessionReady(handle, { type: 'navigation_completed' }, workerReadyAt + 5_000), false,
    'duplicate readiness events must not extend the session');
  assert.equal((await controller.interact(handle.job.caseId, { type: 'type', selector: '#note', text: 'ok' })).ok, false,
    'user actions remain unavailable until the supervisor start command is acknowledged');
  const startCommandAt = workerReadyAt + 10;
  assert.equal(markInteractiveSessionStarted(handle, { type: 'interactive_session_started', timestamp: startCommandAt + 5 },
    startCommandAt, startCommandAt + 8), true);
  assert.equal(handle.sessionStartedAt, startCommandAt);
  assert.equal(handle.sessionDeadline, startCommandAt + 120_000);
  const result = await controller.interact(handle.job.caseId, { type: 'type', selector: '#note', text: 'ok' });
  assert.equal(result.ok, true);
  assert.equal(result.action, 'type');
});
