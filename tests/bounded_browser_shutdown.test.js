import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import test from 'node:test';
import { closeBrowserBounded } from './helpers/bounded_browser_shutdown.js';

class FakeChild extends EventEmitter {
  exitCode = null;
  signalCode = null;
  killed = false;
  kill(signal) {
    this.killed = true;
    queueMicrotask(() => {
      this.signalCode = signal;
      this.emit('exit', null, signal);
    });
    return true;
  }
}

test('bounded browser shutdown reports graceful completion without termination', async () => {
  const child = new FakeChild();
  const exitDuringGracefulClose = async () => { child.exitCode = 0; child.emit('exit', 0, null); };
  const outcome = await closeBrowserBounded({
    closeGracefully: exitDuringGracefulClose,
    killBrowserServer: async () => { throw new Error('must not be called'); },
    process: child,
    gracefulTimeoutMs: 20
  });
  assert.equal(outcome.strategy, 'graceful');
  assert.equal(outcome.gracefulStatus, 'COMPLETED');
  assert.equal(outcome.serverKillInvoked, false);
  assert.equal(outcome.directProcessTerminationSent, false);
  assert.equal(outcome.processExitConfirmed, true);
  assert.equal(Number.isFinite(outcome.gracefulDurationMs), true);
  assert.equal(outcome.serverKillDurationMs, null);
  assert.equal(child.killed, false);
});

test('bounded browser shutdown uses Playwright BrowserServer.kill after graceful timeout', async () => {
  let serverKillCalls = 0;
  const child = new FakeChild();
  const outcome = await closeBrowserBounded({
    closeGracefully: () => new Promise(() => {}),
    killBrowserServer: async () => {
      serverKillCalls++;
      child.signalCode = 'SIGTERM';
      child.emit('exit', null, 'SIGTERM');
    },
    process: child,
    gracefulTimeoutMs: 5,
    serverKillTimeoutMs: 20
  });
  assert.equal(serverKillCalls, 1);
  assert.equal(outcome.strategy, 'browser-server-kill');
  assert.equal(outcome.gracefulStatus, 'TIMED_OUT');
  assert.equal(outcome.serverKillInvoked, true);
  assert.equal(outcome.serverKillStatus, 'COMPLETED');
  assert.equal(outcome.directProcessTerminationSent, false);
  assert.equal(outcome.processExitConfirmed, true);
  assert.equal(Number.isFinite(outcome.gracefulDurationMs), true);
  assert.equal(Number.isFinite(outcome.serverKillDurationMs), true);
  assert.equal(Number.isFinite(outcome.serverKillExitWaitMs), true);
});

test('bounded browser shutdown confirms child-process termination when BrowserServer.kill stalls', async () => {
  const child = new FakeChild();
  const outcome = await closeBrowserBounded({
    closeGracefully: async () => { throw Object.assign(new Error('opaque'), { name: 'CloseError' }); },
    killBrowserServer: () => new Promise(() => {}),
    process: child,
    gracefulTimeoutMs: 20,
    serverKillTimeoutMs: 5,
    processExitTimeoutMs: 20
  });
  assert.equal(outcome.strategy, 'process-kill');
  assert.equal(outcome.gracefulStatus, 'FAILED');
  assert.equal(outcome.gracefulErrorName, 'CloseError');
  assert.equal(outcome.serverKillStatus, 'TIMED_OUT');
  assert.equal(outcome.serverKillInvoked, true);
  assert.equal(outcome.directProcessTerminationAttempted, true);
  assert.equal(outcome.directProcessTerminationSent, true);
  assert.equal(outcome.directProcessTerminationStatus, 'SENT');
  assert.equal(outcome.alreadyExitedBeforeDirectTermination, false);
  assert.equal(outcome.processExitConfirmed, true);
  assert.equal(child.signalCode, 'SIGKILL');
});

test('bounded browser shutdown reports a timed-out server kill that exits before direct termination', async () => {
  const child = new FakeChild();
  let exitCodeReads = 0;
  Object.defineProperty(child, 'exitCode', { configurable: true, get() {
    exitCodeReads++;
    return exitCodeReads >= 1 ? 0 : null;
  } });
  const outcome = await closeBrowserBounded({
    closeGracefully: () => new Promise(() => {}),
    killBrowserServer: () => new Promise(resolve => setTimeout(() => {
      child.signalCode = 'SIGTERM';
      child.emit('exit', null, 'SIGTERM');
      resolve();
    }, 15)),
    process: child,
    gracefulTimeoutMs: 2,
    serverKillTimeoutMs: 5,
    processExitTimeoutMs: 20
  });
  assert.equal(outcome.strategy, 'process-exit-observed');
  assert.equal(outcome.serverKillInvoked, true);
  assert.equal(outcome.serverKillStatus, 'TIMED_OUT');
  assert.equal(outcome.alreadyExitedBeforeDirectTermination, true);
  assert.equal(outcome.directProcessTerminationAttempted, false);
  assert.equal(outcome.directProcessTerminationSent, false);
  assert.equal(outcome.directProcessTerminationStatus, 'NOT_NEEDED_PROCESS_ALREADY_EXITED');
  assert.equal(outcome.processExitConfirmed, true);
  assert.equal(child.killed, false);
});

test('bounded browser shutdown distinguishes a rejected direct termination from no attempt', async () => {
  const child = new EventEmitter();
  child.exitCode = null;
  child.signalCode = null;
  child.kill = () => {
    queueMicrotask(() => { child.signalCode = 'SIGTERM'; child.emit('exit', null, 'SIGTERM'); });
    return false;
  };
  const outcome = await closeBrowserBounded({
    closeGracefully: () => new Promise(() => {}),
    killBrowserServer: () => new Promise(() => {}),
    process: child,
    gracefulTimeoutMs: 2,
    serverKillTimeoutMs: 2,
    processExitTimeoutMs: 20
  });
  assert.equal(outcome.directProcessTerminationAttempted, true);
  assert.equal(outcome.directProcessTerminationSent, false);
  assert.equal(outcome.directProcessTerminationStatus, 'PROCESS_KILL_RETURNED_FALSE');
  assert.equal(outcome.strategy, 'process-exit-observed-after-termination-attempt');
  assert.equal(outcome.processExitConfirmed, true);
});

test('bounded browser shutdown does not claim process exit when a graceful callback outlives its process', async () => {
  const child = new FakeChild();
  const outcome = await closeBrowserBounded({
    closeGracefully: async () => {},
    killBrowserServer: async () => {
      child.signalCode = 'SIGTERM';
      child.emit('exit', null, 'SIGTERM');
    },
    process: child,
    gracefulTimeoutMs: 20,
    processExitTimeoutMs: 20
  });
  assert.equal(outcome.strategy, 'browser-server-kill');
  assert.equal(outcome.gracefulStatus, 'COMPLETED');
  assert.equal(outcome.serverKillInvoked, true);
  assert.equal(outcome.processExitConfirmed, true);
});

test('bounded browser shutdown surfaces failure when forced process exit cannot be confirmed', async () => {
  const child = new EventEmitter();
  child.exitCode = null;
  child.signalCode = null;
  child.kill = () => true;
  await assert.rejects(closeBrowserBounded({
    closeGracefully: () => new Promise(() => {}),
    killBrowserServer: () => new Promise(() => {}),
    process: child,
    gracefulTimeoutMs: 5,
    serverKillTimeoutMs: 5,
    processExitTimeoutMs: 5
  }), error => error.code === 'BROWSER_SHUTDOWN_FAILED' && error.outcome.processExitConfirmed === false);
});

test('bounded browser shutdown reports the exact tracked PID state when termination is unconfirmed', async () => {
  const child = new EventEmitter();
  child.pid = 43210;
  child.exitCode = null;
  child.signalCode = null;
  child.killed = false;
  child.kill = () => false;
  let probedPid = null;
  await assert.rejects(closeBrowserBounded({
    closeGracefully: () => new Promise(() => {}),
    killBrowserServer: () => new Promise(() => {}),
    process: child,
    probeProcess: pid => { probedPid = pid; return 'PRESENT'; },
    gracefulTimeoutMs: 2,
    serverKillTimeoutMs: 2,
    processExitTimeoutMs: 2
  }), error => {
    assert.equal(error.code, 'BROWSER_SHUTDOWN_FAILED');
    assert.equal(error.outcome.directProcessTerminationStatus, 'PROCESS_KILL_RETURNED_FALSE');
    assert.equal(error.outcome.processExitConfirmed, false);
    assert.deepEqual(error.outcome.processState, {
      pid: 43210, exitCode: null, signalCode: null, killed: false, pidProbe: 'PRESENT'
    });
    return true;
  });
  assert.equal(probedPid, 43210);
});

