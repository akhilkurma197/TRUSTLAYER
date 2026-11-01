function safeName(value) {
  return typeof value === 'string' && /^[A-Za-z][A-Za-z0-9]*$/.test(value) ? value : null;
}

export function logDiagnosticSafely(label, buildDiagnostic, write = console.error) {
  try {
    const diagnostic = buildDiagnostic();
    write(`[${label}] ${JSON.stringify(diagnostic)}`);
    return true;
  } catch (error) {
    try {
      write(`[${label}-failure] ${JSON.stringify({ type: 'diagnostic-failure',
        errorName: safeName(error?.name) || 'Error' })}`);
    } catch {}
    return false;
  }
}

export function safeUiPath(value) {
  try {
    const url = new URL(value);
    return `${url.origin}${url.pathname}`;
  } catch { return 'unavailable'; }
}

export async function withPlaywrightStepDeadline(operation, run, timeoutMs = 1_000) {
  let timer;
  const work = Promise.resolve().then(run);
  try {
    return await Promise.race([
      work,
      new Promise((_, reject) => {
        timer = setTimeout(() => {
          const error = new Error(`Playwright preflight step ${operation} exceeded its deadline.`);
          error.name = 'TimeoutError';
          reject(error);
        }, timeoutMs);
      })
    ]);
  } finally { clearTimeout(timer); }
}

/** Build diagnostics only from already observed state; this performs no page calls. */
export function buildTypingControlFailureDiagnostic({
  error, operation, phase, url, elapsedMonotonicMs, elapsedWallMs, pageClosed,
  browserConnected, contextPageCount, serverProcessExitCode, serverProcessSignalCode,
  browserLifecycle = [], activeDialog = null, lastReadinessSample = null
}) {
  return {
    type: 'typing-control-preparation-failure',
    errorName: safeName(error?.name) || 'Error',
    operation: typeof operation === 'string' && /^[a-z-]{1,48}$/.test(operation) ? operation : 'unknown',
    phase: typeof phase === 'string' && /^[a-z-]{1,48}$/.test(phase) ? phase : 'unknown',
    currentUrl: safeUiPath(url),
    testClock: { elapsedMonotonicMs, elapsedWallMs },
    browser: {
      pageClosed: pageClosed === true,
      connected: browserConnected === true,
      contextPageCount: Number.isInteger(contextPageCount) ? contextPageCount : null,
      serverProcessExited: serverProcessExitCode != null || serverProcessSignalCode != null,
      serverProcessExitCode: Number.isInteger(serverProcessExitCode) ? serverProcessExitCode : null,
      serverProcessSignalCode: typeof serverProcessSignalCode === 'string' ? serverProcessSignalCode : null,
      rendererHealth: 'UNKNOWN_NO_POST_FAILURE_PAGE_EVALUATION',
      lifecycle: browserLifecycle.slice(-12),
      activeDialog: activeDialog ? { type: activeDialog.type, phase: activeDialog.phase,
        ageMs: Math.max(0, Date.now() - activeDialog.openedAt) } : null
    },
    lastReadinessSample,
    lastReadinessSampleAgeMs: Number.isFinite(lastReadinessSample?.observedAt)
      ? Math.max(0, Date.now() - lastReadinessSample.observedAt) : null,
    freshPageEvaluation: 'NOT_ATTEMPTED_AFTER_FAILURE'
  };
}
