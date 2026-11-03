export function classifyConsoleError({ text, sourceUrl, baseUrl, phase }) {
  let sourcePath = 'unavailable';
  try {
    const source = new URL(sourceUrl);
    const base = new URL(baseUrl);
    sourcePath = source.origin === base.origin ? source.pathname : 'external';
  } catch {}
  const messageCode = /^Failed to load resource: the server responded with a status of 401 \(Unauthorized\)$/.test(String(text))
    ? 'RESOURCE_HTTP_401'
    : (/Failed to load resource: the server responded with a status of 409(?: \([^)]*\))?$/.test(String(text))
      ? 'RESOURCE_HTTP_409'
      : (/Failed to load resource: net::ERR_ABORTED/.test(String(text)) ? 'RESOURCE_ABORTED' : 'CONSOLE_ERROR'));
  return { messageCode, sourcePath, phase };
}

export function isExpectedCaseCreationAuthChallenge(error, {
  unauthenticatedCaseCreation401Count,
  authenticatedCaseCreation201Count,
  authSession204Count,
  allApplication401ResponseCount,
  authSessionEstablished
} = {}) {
  return Boolean(error?.messageCode === 'RESOURCE_HTTP_401' && error.phase === 'case-creation' &&
    unauthenticatedCaseCreation401Count === 1 && authenticatedCaseCreation201Count === 1 &&
    authSession204Count === 1 && allApplication401ResponseCount === 1 && authSessionEstablished === true);
}

export function isExpectedUnsafeInteractiveRejection(error, { caseId, phase, responseStatus, errorCode } = {}) {
  return Boolean(error?.messageCode === 'RESOURCE_HTTP_409' && phase === 'interactive-actions' &&
    error.phase === phase && typeof caseId === 'string' &&
    error.sourcePath === `/api/cases/${caseId}/interactions` &&
    responseStatus === 409 && errorCode === 'TARGET_NOT_PERMITTED');
}
