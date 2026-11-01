import test from 'node:test';
import assert from 'node:assert/strict';
import { classifyInteractiveUiReadiness, isInteractiveUiReady } from './helpers/interactive_startup_diagnostics.js';

const acknowledged = {
  commandSentAt: 100,
  acknowledgementReceivedAt: 120,
  backendStatus: 'RUNNING',
  frontendSchemaStatus: 'STARTING',
  displayedStatus: 'STARTING',
  controlEnabled: false,
  readyStateObserved: false,
  endReason: null
};

test('interactive startup diagnostic separates unsent and unacknowledged starts', () => {
  assert.equal(classifyInteractiveUiReadiness({ ...acknowledged, commandSentAt: null }), 'START_COMMAND_NOT_SENT');
  assert.equal(classifyInteractiveUiReadiness({ ...acknowledged, acknowledgementReceivedAt: null }), 'START_ACKNOWLEDGEMENT_NOT_RECEIVED');
});

test('interactive startup diagnostic does not confuse an unavailable case read with a terminal session', () => {
  assert.equal(classifyInteractiveUiReadiness({ ...acknowledged, backendStatus: null }), 'BACKEND_STATE_UNAVAILABLE');
});

test('interactive startup diagnostic separates termination, SSE delivery, stale state and disabled controls', () => {
  assert.equal(classifyInteractiveUiReadiness({ ...acknowledged, backendStatus: 'ENDED', endReason: 'SESSION_LIMIT_REACHED' }), 'SESSION_ENDED_BEFORE_UI_READY');
  assert.equal(classifyInteractiveUiReadiness({ ...acknowledged, readyStateObserved: false }), 'READY_STATE_NOT_OBSERVED_ON_FRONTEND_SSE');
  assert.equal(classifyInteractiveUiReadiness({ ...acknowledged, readyStateObserved: true }), 'FRONTEND_SCHEMA_NOT_UPDATED');
  assert.equal(classifyInteractiveUiReadiness({ ...acknowledged, readyStateObserved: true, frontendSchemaStatus: 'RUNNING' }), 'FRONTEND_STATUS_NOT_RENDERED');
  assert.equal(classifyInteractiveUiReadiness({ ...acknowledged, readyStateObserved: true, frontendSchemaStatus: 'RUNNING', displayedStatus: 'RUNNING' }), 'FRONTEND_CONTROL_NOT_ENABLED');
  assert.equal(classifyInteractiveUiReadiness({ ...acknowledged, readyStateObserved: true, frontendSchemaStatus: 'RUNNING', displayedStatus: 'RUNNING', controlEnabled: true }), 'UI_READY');
});

test('UI readiness evaluates the exact atomic DOM snapshot shape and ignores non-gating case/view state', () => {
  const observed = {
    statusCount: 1, displayedStatus: 'RUNNING', cardCount: 1, cardVisible: true,
    controlCount: 1, controlEnabled: true,
    caseStatus: 'COMPLETED', interactiveStatus: 'RUNNING', runtimeSessionActive: true,
    activeViewId: 'view-website'
  };
  assert.equal(isInteractiveUiReady(observed), true,
    'case pipeline completion and overview are not predicates in the wait condition');
  assert.equal(isInteractiveUiReady({ ...observed, statusText: 'STARTING' }), true,
    'readiness must use the snapshot field returned by the browser sampler');
  assert.equal(isInteractiveUiReady({ ...observed, statusCount: 2 }), false);
  assert.equal(isInteractiveUiReady({ ...observed, displayedStatus: 'STARTING' }), false);
  assert.equal(isInteractiveUiReady({ ...observed, cardCount: 2 }), false);
  assert.equal(isInteractiveUiReady({ ...observed, cardVisible: false }), false);
  assert.equal(isInteractiveUiReady({ ...observed, controlCount: 2 }), false,
    'strict Playwright locator calls fail when an ID unexpectedly matches multiple nodes');
  assert.equal(isInteractiveUiReady({ ...observed, controlEnabled: false }), false);
});
