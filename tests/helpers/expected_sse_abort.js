export function isExpectedCancelledEventStreamAbort(failure, {
  caseId,
  cancellationResponseStatus,
  caseStatus,
  interactiveStatus,
  runtimeSessionActive,
  eventStreamOpened
} = {}) {
  return Boolean(failure && typeof caseId === 'string' &&
    failure.path === `/api/cases/${caseId}/events` &&
    failure.method === 'GET' && failure.resourceType === 'eventsource' &&
    failure.errorCode === 'net::ERR_ABORTED' && failure.phase === 'cancellation' && eventStreamOpened === true &&
    cancellationResponseStatus === 200 &&
    ['COMPLETED', 'INCOMPLETE'].includes(caseStatus) && interactiveStatus === 'CANCELLED' &&
    runtimeSessionActive === false);
}
