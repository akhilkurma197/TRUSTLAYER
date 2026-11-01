import assert from 'node:assert/strict';
import test from 'node:test';
import { isExpectedCancelledEventStreamAbort } from './helpers/expected_sse_abort.js';

const cancelledCase = {
  caseId: 'TL-2026-1031-1200-ABC',
  cancellationResponseStatus: 200,
  caseStatus: 'COMPLETED',
  interactiveStatus: 'CANCELLED',
  runtimeSessionActive: false,
  eventStreamOpened: true
};
const expectedAbort = {
  path: `/api/cases/${cancelledCase.caseId}/events`,
  method: 'GET',
  resourceType: 'eventsource',
  errorCode: 'net::ERR_ABORTED',
  phase: 'cancellation'
};

test('only the case EventSource abort after confirmed interactive cancellation is expected', () => {
  assert.equal(isExpectedCancelledEventStreamAbort(expectedAbort, cancelledCase), true);
  for (const [patch, reason] of [
    [{ path: '/api/cases/other/events' }, 'different case'],
    [{ method: 'POST' }, 'non-GET'],
    [{ resourceType: 'fetch' }, 'non-EventSource request'],
    [{ errorCode: 'net::ERR_CONNECTION_RESET' }, 'different failure'],
    [{ phase: 'interactive-actions' }, 'failure outside cancellation'],
    [{}, 'cancellation response unavailable'],
    [{}, 'session still active'],
    [{}, 'event stream was never confirmed open']
  ]) {
    const state = reason === 'cancellation response unavailable'
      ? { ...cancelledCase, cancellationResponseStatus: null }
      : (reason === 'session still active' ? { ...cancelledCase, runtimeSessionActive: true }
        : (reason === 'event stream was never confirmed open' ? { ...cancelledCase, eventStreamOpened: false } : cancelledCase));
    assert.equal(isExpectedCancelledEventStreamAbort({ ...expectedAbort, ...patch }, state), false, reason);
  }
  for (const interactiveStatus of ['RUNNING', 'ENDED', 'FAILED']) {
    assert.equal(isExpectedCancelledEventStreamAbort(expectedAbort, { ...cancelledCase, interactiveStatus }), false,
      `non-cancelled session state ${interactiveStatus} must not excuse the abort`);
  }
});
