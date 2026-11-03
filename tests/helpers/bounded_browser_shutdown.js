import { performance } from 'node:perf_hooks';
import nodeProcess from 'node:process';

function errorName(error) {
  return /^[A-Za-z][A-Za-z0-9]*$/.test(error?.name || '') ? error.name : 'Error';
}

function elapsedMs(startedAt) {
  return Math.max(0, Math.round(performance.now() - startedAt));
}

function within(promise, timeoutMs) {
  let timer;
  const settled = Promise.resolve(promise).then(
    () => ({ status: 'COMPLETED' }),
    error => ({ status: 'FAILED', errorName: errorName(error) })
  );
  return Promise.race([
    settled,
    new Promise(resolve => { timer = setTimeout(() => resolve({ status: 'TIMED_OUT' }), timeoutMs); })
  ]).finally(() => clearTimeout(timer));
}

function processExited(child) {
  return Boolean(child && (child.exitCode != null || child.signalCode != null));
}

function probeTrackedPid(pid) {
  if (!Number.isInteger(pid) || pid <= 0) return 'UNAVAILABLE';
  try {
    nodeProcess.kill(pid, 0);
    return 'PRESENT';
  } catch (error) {
    if (error?.code === 'ESRCH') return 'NOT_FOUND';
    if (error?.code === 'EPERM') return 'ACCESS_DENIED';
    return 'PROBE_ERROR';
  }
}

function processSnapshot(child, probeProcess) {
  const pid = Number.isInteger(child?.pid) && child.pid > 0 ? child.pid : null;
  let pidProbe = 'UNAVAILABLE';
  if (pid !== null) {
    try { pidProbe = probeProcess(pid); } catch { pidProbe = 'PROBE_ERROR'; }
  }
  const exited = processExited(child);
  const lifecycleStatus = exited ? 'EXITED'
    : pidProbe === 'NOT_FOUND' ? 'ALREADY_GONE_NOT_REAPED'
      : pidProbe === 'PRESENT' ? 'STILL_RUNNING'
        : 'STILL_RUNNING_OR_UNCONFIRMED';
  return {
    pid,
    exitCode: Number.isInteger(child?.exitCode) ? child.exitCode : null,
    signalCode: typeof child?.signalCode === 'string' ? child.signalCode : null,
    killed: typeof child?.killed === 'boolean' ? child.killed : null,
    pidProbe,
    lifecycleStatus
  };
}

function waitForProcessExit(child, timeoutMs) {
  if (!child) return Promise.resolve(false);
  if (processExited(child)) return Promise.resolve(true);
  return new Promise(resolve => {
    let settled = false;
    const finish = exited => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      child.removeListener('exit', onExit);
      child.removeListener('close', onClose);
      resolve(exited);
    };
    const onExit = () => finish(true);
    const onClose = () => finish(true);
    const timer = setTimeout(() => finish(processExited(child)), timeoutMs);
    child.once('exit', onExit);
    child.once('close', onClose);
    if (processExited(child)) finish(true);
  });
}

/**
 * Close a Playwright-launched browser with bounded graceful and forced paths.
 * A timed-out operation remains handled, but resource cleanup is confirmed by
 * BrowserServer.kill() or by observing the spawned process exit after SIGKILL.
 */
export async function closeBrowserBounded({
  closeGracefully,
  killBrowserServer,
  process,
  gracefulTimeoutMs = 2_000,
  serverKillTimeoutMs = 1_500,
  processExitTimeoutMs = 1_500,
  probeProcess = probeTrackedPid
}) {
  if (typeof closeGracefully !== 'function' || typeof killBrowserServer !== 'function') {
    throw new TypeError('Browser shutdown callbacks are required.');
  }
  const gracefulStartedAt = performance.now();
  const graceful = await within(Promise.resolve().then(closeGracefully), gracefulTimeoutMs);
  const gracefulDurationMs = elapsedMs(gracefulStartedAt);
  if (graceful.status === 'COMPLETED' && processExited(process)) {
    return { strategy: 'graceful', gracefulStatus: 'COMPLETED', serverKillInvoked: false,
      directProcessTerminationAttempted: false, directProcessTerminationSent: false,
      directProcessTerminationStatus: 'NOT_NEEDED_GRACEFUL_EXIT_CONFIRMED', gracefulDurationMs,
      serverKillDurationMs: null, serverKillExitWaitMs: null, fallbackExitWaitMs: null,
      processExitConfirmed: true, processState: processSnapshot(process, probeProcess) };
  }

  const serverKillInvoked = true;
  const serverKillStartedAt = performance.now();
  const serverKill = await within(Promise.resolve().then(killBrowserServer), serverKillTimeoutMs);
  const serverKillDurationMs = elapsedMs(serverKillStartedAt);
  let serverKillExitWaitMs = null;
  let fallbackExitWaitMs = null;
  if (serverKill.status === 'COMPLETED') {
    const exitWaitStartedAt = performance.now();
    const processExitConfirmed = await waitForProcessExit(process, processExitTimeoutMs);
    serverKillExitWaitMs = elapsedMs(exitWaitStartedAt);
    if (processExitConfirmed) {
      return { strategy: 'browser-server-kill', gracefulStatus: graceful.status,
        ...(graceful.errorName ? { gracefulErrorName: graceful.errorName } : {}),
        serverKillInvoked, serverKillStatus: serverKill.status,
        directProcessTerminationAttempted: false, directProcessTerminationSent: false,
        directProcessTerminationStatus: 'NOT_NEEDED_SERVER_KILL_EXIT_CONFIRMED', gracefulDurationMs,
        serverKillDurationMs, serverKillExitWaitMs, fallbackExitWaitMs, processExitConfirmed: true,
        processState: processSnapshot(process, probeProcess) };
    }
  }

  if (!process || typeof process.kill !== 'function') {
    const error = new Error('Browser shutdown failed; no process termination handle is available.');
    error.code = 'BROWSER_SHUTDOWN_FAILED';
    error.outcome = { strategy: 'failed', gracefulStatus: graceful.status, serverKillInvoked,
      serverKillStatus: serverKill.status,
      gracefulDurationMs, serverKillDurationMs, serverKillExitWaitMs,
      ...(graceful.errorName ? { gracefulErrorName: graceful.errorName } : {}),
      ...(serverKill.errorName ? { serverKillErrorName: serverKill.errorName } : {}), processExitConfirmed: false };
    throw error;
  }

  // BrowserServer.kill() can time out while its underlying process shutdown
  // continues. Recheck the actual ChildProcess before sending SIGKILL.
  const alreadyExitedBeforeDirectTermination = processExited(process);
  const fallbackExitWaitStartedAt = performance.now();
  const exitPromise = waitForProcessExit(process, processExitTimeoutMs);
  let directProcessTerminationAttempted = false;
  let directProcessTerminationSent = false;
  let directProcessTerminationStatus = alreadyExitedBeforeDirectTermination
    ? 'NOT_NEEDED_PROCESS_ALREADY_EXITED' : 'NOT_SENT';
  let terminationErrorName = null;
  if (!alreadyExitedBeforeDirectTermination) {
    directProcessTerminationAttempted = true;
    try {
      directProcessTerminationSent = process.kill('SIGKILL') === true;
      directProcessTerminationStatus = directProcessTerminationSent ? 'SENT' : 'PROCESS_KILL_RETURNED_FALSE';
    } catch (error) {
      terminationErrorName = errorName(error);
      directProcessTerminationStatus = 'PROCESS_KILL_THREW';
    }
  }
  const processExitConfirmed = await exitPromise;
  fallbackExitWaitMs = elapsedMs(fallbackExitWaitStartedAt);
  if (!processExitConfirmed) {
    const processState = processSnapshot(process, probeProcess);
    if (processState.lifecycleStatus === 'ALREADY_GONE_NOT_REAPED') {
      return { strategy: 'process-already-gone-not-reaped', gracefulStatus: graceful.status,
        serverKillInvoked, serverKillStatus: serverKill.status,
        gracefulDurationMs, serverKillDurationMs, serverKillExitWaitMs, fallbackExitWaitMs,
        ...(graceful.errorName ? { gracefulErrorName: graceful.errorName } : {}),
        ...(serverKill.errorName ? { serverKillErrorName: serverKill.errorName } : {}),
        directProcessTerminationAttempted, directProcessTerminationSent, directProcessTerminationStatus,
        alreadyExitedBeforeDirectTermination, processExitConfirmed: false,
        processAbsenceConfirmed: true, processState };
    }
  }
  if (!processExitConfirmed) {
    const error = new Error('Browser shutdown failed; process exit was not confirmed within the deadline.');
    error.code = 'BROWSER_SHUTDOWN_FAILED';
    error.outcome = { strategy: 'failed', gracefulStatus: graceful.status, serverKillInvoked,
      serverKillStatus: serverKill.status,
      gracefulDurationMs, serverKillDurationMs, serverKillExitWaitMs, fallbackExitWaitMs,
      ...(graceful.errorName ? { gracefulErrorName: graceful.errorName } : {}),
      ...(serverKill.errorName ? { serverKillErrorName: serverKill.errorName } : {}),
      directProcessTerminationAttempted, directProcessTerminationSent, directProcessTerminationStatus,
      alreadyExitedBeforeDirectTermination,
      ...(terminationErrorName ? { terminationErrorName } : {}), processExitConfirmed: false,
      processState: processSnapshot(process, probeProcess) };
    throw error;
  }

  const strategy = directProcessTerminationSent ? 'process-kill'
    : (directProcessTerminationAttempted ? 'process-exit-observed-after-termination-attempt' : 'process-exit-observed');
  return { strategy, gracefulStatus: graceful.status, serverKillInvoked,
    serverKillStatus: serverKill.status,
    gracefulDurationMs, serverKillDurationMs, serverKillExitWaitMs, fallbackExitWaitMs,
    ...(graceful.errorName ? { gracefulErrorName: graceful.errorName } : {}),
    ...(serverKill.errorName ? { serverKillErrorName: serverKill.errorName } : {}),
    directProcessTerminationAttempted, directProcessTerminationSent, directProcessTerminationStatus,
    alreadyExitedBeforeDirectTermination,
    ...(terminationErrorName ? { terminationErrorName } : {}), processExitConfirmed: true,
    processState: processSnapshot(process, probeProcess) };
}
