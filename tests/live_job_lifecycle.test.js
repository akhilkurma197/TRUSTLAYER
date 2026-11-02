import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { test } from 'node:test';
import { JOB_STATUS, LiveJobController, interactiveLifecycleEvidence, markInteractiveSessionReady, markInteractiveSessionStarted } from '../core/investigators/live_job_controller.js';
import { serializeBoundedJson } from '../worker/resource_limits.js';

function ownedDirectory(jobId, token) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), `trustlayer-${jobId}-`));
  fs.writeFileSync(path.join(directory, '.trustlayer-owner'), token, { flag: 'wx' });
  return directory;
}

function fakeChild() {
  return { exitCode: null, signalCode: null, killed: false, kill() { this.killed = true; this.exitCode = 0; } };
}

test('interactive lifecycle evidence remains truthful after active-job cleanup', () => {
  const readyAt = 10_000;
  const handle = { interactive: true, sessionDurationMs: 120_000 };
  assert.equal(markInteractiveSessionReady(handle, { type: 'navigation_completed', timestamp: 9_990 }, readyAt), true);
  handle.interactiveEndReason = 'SESSION_LIMIT_REACHED';
  handle.workerEndEventAt = 129_990;
  handle.workerExitCode = 0;
  handle.workerSignalCode = null;
  handle.workerClosedAt = 130_010;
  const controller = new LiveJobController({ removeContainer: () => {}, terminateChild: async () => true });
  controller.activeJobs.set('finished', handle);
  controller.activeJobs.delete('finished');

  const evidence = interactiveLifecycleEvidence(handle, 130_020);
  assert.equal(controller.activeJobs.has('finished'), false);
  assert.equal(evidence.readyEventReceived, true,
    'absence from activeJobs must not erase the historical ready event');
  assert.equal(evidence.endReason, 'SESSION_LIMIT_REACHED');
  assert.equal(evidence.workerExitCode, 0);
  assert.equal(evidence.workerSignalCode, null);
  assert.equal(evidence.readyElapsedMs, 120_010);
});

test('interactive deadline starts only after supervisor start acknowledgement', () => {
  const handle = { interactive: true, sessionDurationMs: 120_000 };
  assert.equal(markInteractiveSessionReady(handle, { type: 'navigation_completed', timestamp: 9_990 }, 10_000), true);
  assert.equal(handle.sessionDeadline, undefined, 'navigation readiness alone must not consume user interaction time');
  assert.equal(markInteractiveSessionStarted(handle, { type: 'interactive_session_started', timestamp: 20_005 }, 20_000, 20_010), true);
  assert.equal(handle.sessionStartedAt, 20_000);
  assert.equal(handle.startCommandSentAt, 20_000);
  assert.equal(handle.startAcknowledgementReceivedAt, 20_010);
  assert.equal(handle.sessionDeadline, 140_000);
  assert.equal(markInteractiveSessionStarted(handle, { type: 'interactive_session_started' }, 30_000), false,
    'duplicate start acknowledgements must not extend the finite deadline');
  const evidence = interactiveLifecycleEvidence(handle, 20_100);
  assert.equal(evidence.readyEventReceived, true);
  assert.equal(evidence.startAcknowledgementElapsedMs, 10);
  assert.equal(evidence.sessionElapsedMs, 100);
  assert.equal(evidence.deadlineElapsedMs, -119_900);

  const workerSource = fs.readFileSync(new URL('../worker/browser_worker.js', import.meta.url), 'utf8');
  const sessionStart = workerSource.indexOf('async function runInteractiveSession');
  const navigationReady = workerSource.indexOf("emit('navigation_completed'", sessionStart);
  const startCommand = workerSource.indexOf("message?.command === 'START_INTERACTIVE'", sessionStart);
  const workerDeadline = workerSource.indexOf('endsAt = Date.now() + durationMs', startCommand);
  const workerTimer = workerSource.indexOf('sessionTimer = setTimeout', startCommand);
  assert.ok(sessionStart >= 0 && navigationReady > sessionStart && startCommand > navigationReady &&
    workerDeadline > startCommand && workerTimer > workerDeadline,
  'worker must wait for the supervisor start command before beginning its finite timer');
});

test('startup failure cleanup reports errors and still removes owned output', async () => {
  const removed = [];
  let failRemoval = true;
  const controller = new LiveJobController({
    removeContainer: name => {
      removed.push(name);
      if (failRemoval) throw Object.assign(new Error('private details'), { code: 'ETIMEDOUT' });
    }
  });
  const token = 'startup-owned';
  const directory = ownedDirectory('startup', token);
  try {
    const job = { jobId: 'startup-job', outputOwnerToken: token };
    controller.admittedJobs.add(job.jobId);
    const diagnostics = await controller._cleanupFailedStart(job, ['proxy-startup'], directory);
    assert.deepEqual(removed, ['proxy-startup']);
    assert.equal(diagnostics.status, 'FAILED');
    assert.deepEqual(diagnostics.operations, [{ operation: 'remove_startup_container_1', code: 'ETIMEDOUT' }]);
    assert.equal(fs.existsSync(directory), false);
    assert.equal(controller.admittedJobs.has(job.jobId), true, 'failed cleanup must retain the capacity reservation');
    failRemoval = false;
    assert.equal((await controller.retryCleanup(job.jobId)).status, 'CLEANED');
    assert.equal(controller.admittedJobs.has(job.jobId), false);
  } finally { fs.rmSync(directory, { recursive: true, force: true }); }
});

test('proxy readiness failure removes proxy resources and never starts a browser worker', async () => {
  const dockerCommands = [];
  const removedContainers = [];
  const removedDirectories = [];
  let workerSpawnCount = 0;
  const controller = new LiveJobController({
    runDocker: async args => {
      dockerCommands.push(args);
      if (args[0] === 'exec') throw Object.assign(new Error('proxy readiness probe failed'), { code: 'ECONNREFUSED' });
      return '';
    },
    spawnWorker: () => { workerSpawnCount++; throw new Error('browser worker must not start'); },
    removeContainer: name => removedContainers.push(name),
    removeTempDir: (directory, ownerToken) => {
      assert.ok(ownerToken, 'startup cleanup must provide the job ownership token');
      assert.equal(fs.readFileSync(path.join(directory, '.trustlayer-owner'), 'utf8'), ownerToken,
        'startup cleanup must target the owned temporary directory');
      removedDirectories.push({ directory, ownerToken });
      fs.rmSync(directory, { recursive: true, force: true });
    }
  });
  controller._ensureDockerRuntime = async () => {};

  const job = await controller._executeJob({
    jobId: 'proxy-readiness-failure', caseId: 'case-proxy-readiness-failure',
    targetUrl: 'https://example.invalid/', timeoutMs: 10_000,
    options: { interactive: false, captureDelayMs: 0 }
  });

  assert.equal(job.status, JOB_STATUS.FAILED);
  assert.match(job.error, /Failed to start isolated egress proxy/);
  assert.equal(dockerCommands.some(args => args[0] === 'run' && args.includes('worker/egress_proxy_worker.js')), true,
    'the proxy container is created before readiness is checked');
  assert.equal(dockerCommands.filter(args => args[0] === 'exec').length, 20,
    'the bounded readiness probes all fail before startup is refused');
  assert.deepEqual(removedContainers, [`trustlayer-egress-${job.jobId}`]);
  assert.equal(workerSpawnCount, 0, 'browser worker must not spawn after proxy readiness failure');
  assert.equal(job.cleanupDiagnostics.status, 'CLEANED');
  assert.equal(removedDirectories.length, 1, 'startup failure cleanup must remove the owned temporary directory');
  assert.equal(fs.existsSync(removedDirectories[0].directory), false);
});

test('timeout, cancellation, crash, and output-limit outcomes all run terminal cleanup', async t => {
  for (const scenario of ['timeout', 'cancellation', 'worker-crash', 'output-limit']) {
    await t.test(scenario, async () => {
      const removed = [];
      const controller = new LiveJobController({
        removeContainer: name => removed.push(name),
        terminateChild: async child => { child.kill('SIGTERM'); return true; }
      });
      const token = `owner-${scenario}`;
      const directory = ownedDirectory(scenario, token);
      const job = { status: scenario === 'timeout' ? JOB_STATUS.TIMED_OUT
        : (scenario === 'cancellation' ? JOB_STATUS.CANCELLED : JOB_STATUS.FAILED), outputOwnerToken: token };
      if (scenario === 'output-limit') assert.throws(() => serializeBoundedJson({ data: 'x'.repeat(100) }, 10), /output limit/);
      const handle = { job, tempDir: directory, browserContainerName: `browser-${scenario}`,
        egressContainerName: `proxy-${scenario}`, child: fakeChild() };
      controller.activeJobs.set(scenario, handle);
      controller.admittedJobs.add(scenario);
      const diagnostics = await controller._cleanup(scenario);
      assert.equal(diagnostics.status, 'CLEANED');
      assert.deepEqual(removed, [`browser-${scenario}`, `proxy-${scenario}`]);
      assert.equal(handle.child.killed, true);
      assert.equal(fs.existsSync(directory), false);
      assert.equal(controller.activeJobs.has(scenario), false);
      assert.equal(controller.admittedJobs.has(scenario), false);
    });
  }
});

test('separate job directories and ownership tokens prevent stale artifact reuse', async () => {
  const controller = new LiveJobController({ removeContainer: () => {}, terminateChild: async () => true });
  const firstToken = 'first-owner';
  const secondToken = 'second-owner';
  const firstDir = ownedDirectory('repeat-first', firstToken);
  const secondDir = ownedDirectory('repeat-second', secondToken);
  try {
    fs.writeFileSync(path.join(firstDir, 'result.json'), JSON.stringify({ jobId: 'first', dom: 'old', telemetry: ['old'], screenshot: 'old.png' }));
    fs.writeFileSync(path.join(secondDir, 'result.json'), JSON.stringify({ jobId: 'second', dom: 'new', telemetry: ['new'], screenshot: 'new.png' }));
    assert.notEqual(firstDir, secondDir);
    assert.deepEqual(JSON.parse(fs.readFileSync(path.join(secondDir, 'result.json'))), {
      jobId: 'second', dom: 'new', telemetry: ['new'], screenshot: 'new.png'
    });
    for (const [id, directory, token] of [['first', firstDir, firstToken], ['second', secondDir, secondToken]]) {
      controller.activeJobs.set(id, { job: { outputOwnerToken: token }, tempDir: directory });
      assert.equal((await controller._cleanup(id)).status, 'CLEANED');
    }
    assert.equal(fs.existsSync(firstDir), false);
    assert.equal(fs.existsSync(secondDir), false);
  } finally {
    fs.rmSync(firstDir, { recursive: true, force: true });
    fs.rmSync(secondDir, { recursive: true, force: true });
  }
});

test('ownership mismatch is observable and does not delete another job directory', async () => {
  const controller = new LiveJobController({ removeContainer: () => {}, terminateChild: async () => true });
  const directory = ownedDirectory('ownership-mismatch', 'actual-owner');
  const job = { status: JOB_STATUS.COMPLETED, outputOwnerToken: 'different-owner' };
  controller.activeJobs.set('mismatch', { job, tempDir: directory });
  try {
    const diagnostics = await controller._cleanup('mismatch');
    assert.equal(diagnostics.status, 'FAILED');
    assert.deepEqual(diagnostics.operations, [{ operation: 'remove_job_directory', code: 'OWNER_MISMATCH' }]);
    assert.equal(job.status, JOB_STATUS.FAILED);
    assert.equal(fs.existsSync(directory), true);
  } finally { fs.rmSync(directory, { recursive: true, force: true }); }
});
