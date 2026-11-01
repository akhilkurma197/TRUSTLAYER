export function classifyInteractiveUiReadiness({
  commandSentAt, acknowledgementReceivedAt, backendStatus, frontendSchemaStatus,
  displayedStatus, controlEnabled, readyStateObserved, endReason
}) {
  if (!Number.isFinite(commandSentAt)) return 'START_COMMAND_NOT_SENT';
  if (!Number.isFinite(acknowledgementReceivedAt)) return 'START_ACKNOWLEDGEMENT_NOT_RECEIVED';
  if (!backendStatus) return 'BACKEND_STATE_UNAVAILABLE';
  if (endReason || ['ENDED', 'FAILED', 'CANCELLED'].includes(backendStatus)) return 'SESSION_ENDED_BEFORE_UI_READY';
  if (backendStatus !== 'RUNNING') return 'BACKEND_SESSION_NOT_RUNNING';
  if (!readyStateObserved) return 'READY_STATE_NOT_OBSERVED_ON_FRONTEND_SSE';
  if (frontendSchemaStatus !== 'RUNNING') return 'FRONTEND_SCHEMA_NOT_UPDATED';
  if (displayedStatus !== 'RUNNING') return 'FRONTEND_STATUS_NOT_RENDERED';
  if (!controlEnabled) return 'FRONTEND_CONTROL_NOT_ENABLED';
  return 'UI_READY';
}

// Mirrors the exact three-condition Playwright wait. Case pipeline status and
// the selected view are diagnostic context, not readiness requirements.
export function isInteractiveUiReady(snapshot) {
  return snapshot?.statusCount === 1 && snapshot.displayedStatus === 'RUNNING' &&
    snapshot.cardCount === 1 && snapshot.cardVisible === true &&
    snapshot.controlCount === 1 && snapshot.controlEnabled === true;
}
