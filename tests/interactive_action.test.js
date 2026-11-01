import assert from 'node:assert/strict';
import { test } from 'node:test';
import { isInteractiveSession, validateInteractiveAction } from '../core/interactive_action.js';
import { LiveJobController, markInteractiveSessionReady, markInteractiveSessionStarted } from '../core/investigators/live_job_controller.js';

test('interactive actions accept only bounded allowlisted parameters', () => {
  for (const action of [
    { type: 'back' }, { type: 'scroll', direction: 'down', pixels: 800 },
    { type: 'click', selector: '#continue' }, { type: 'type', selector: '[name="search"]', text: 'hello' },
    { type: 'navigate', url: 'https://example.invalid/path' }, { type: 'screenshot' }
  ]) assert.equal(validateInteractiveAction(action).valid, true, JSON.stringify(action));
  for (const action of [null, {}, { type: 'evaluate', expression: 'alert(1)' },
    { type: 'reload', extra: true }, { type: 'navigate', url: 'https://user:pass@example.invalid/' },
    { type: 'scroll', direction: 'down', pixels: 801 }, { type: 'click', selector: 'button:has-text("go")' },
    { type: 'type', selector: '#search', text: 'x'.repeat(201) }]) {
    assert.equal(validateInteractiveAction(action).valid, false);
  }
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
  handle.interactionCount = 20;
  assert.match((await controller.interact('TL-2026-1031-1200-ABC', { type: 'back' })).error, /limit/);
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
