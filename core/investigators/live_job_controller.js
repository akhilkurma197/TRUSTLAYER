/**
 * Trust Layer — Trusted Live Job Controller v2.0
 * Control Plane Supervisor & Queue for Isolated Browser Inspections.
 * 
 * Guarantees:
 * 1. Express process NEVER fetches target URLs or launches browsers in-process.
 * 2. Launches an isolated Docker worker only; refuses when Docker is unavailable.
 * 3. Starts and pins a dedicated Controlled Egress Proxy for every job.
 * 4. Strips environment variables (no application secrets / credentials in worker).
 * 5. Captures, validates, and stores webpage screenshots safely.
 * 6. Bounded concurrency, timeout enforcement, and clean process lifecycle.
 */

import { spawn } from 'node:child_process';
import { createHash, randomUUID } from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { fileURLToPath } from 'node:url';
import { execFileAsync } from '../async_process.js';
import { SSRFGuard } from './ssrf_guard.js';
import { hasVerifiedChromiumSandbox } from './chromium_sandbox_status.js';
import { validateInteractiveAction, MAX_INTERACTIVE_ACTIONS, MAX_INTERACTIVE_POINTER_MOVES,
  MAX_PENDING_INTERACTIVE_ACTIONS, INTERACTION_TIMEOUT_MS, MAX_SESSION_MS } from '../interactive_action.js';
import { INTERACTIVE_VIEWPORT_FRAME_WINDOW_MS, MAX_INTERACTIVE_VIEWPORT_FRAMES_PER_MINUTE } from '../interactive_action.js';
import { validateTestLocalFixturePolicyFromProcess, validateTestLocalFixtureUrl } from './test_local_fixture.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const rootDir = path.resolve(__dirname, '../..');
const screenshotsDir = path.join(rootDir, 'data', 'screenshots');

export const JOB_STATUS = {
  QUEUED: 'QUEUED',
  RUNNING: 'RUNNING',
  COMPLETED: 'COMPLETED',
  PARTIAL: 'PARTIAL',
  BLOCKED: 'BLOCKED',
  BUSY: 'BUSY',
  HTTP_ERROR: 'HTTP_ERROR',
  FAILED: 'FAILED',
  TIMED_OUT: 'TIMED_OUT',
  CANCELLED: 'CANCELLED'
};

// Worker navigation readiness is necessary but does not start the user's clock.
// The finite allowance starts only after validated result handoff and an
// explicit supervisor command, acknowledged by the worker.
export function markInteractiveSessionReady(handle, event, readyAt = Date.now()) {
  if (!handle?.interactive || handle.interactiveReady || event?.type !== 'navigation_completed') return false;
  if (!Number.isFinite(readyAt)) return false;
  handle.interactiveReady = true;
  handle.sessionReadyAt = readyAt;
  handle.workerReadyEventAt = Number.isFinite(event.timestamp) ? event.timestamp : null;
  return true;
}

export function markInteractiveSessionStarted(handle, event, requestedAt = Date.now(), receivedAt = Date.now()) {
  if (!handle?.interactive || !handle.interactiveReady || handle.interactiveStarted ||
      event?.type !== 'interactive_session_started' || !Number.isFinite(requestedAt) || !Number.isFinite(receivedAt)) return false;
  const durationMs = Math.min(MAX_SESSION_MS, Math.max(0, Number(handle.sessionDurationMs) || 0));
  if (durationMs <= 0) return false;
  handle.interactiveStarted = true;
  handle.startCommandSentAt = requestedAt;
  handle.startAcknowledgementReceivedAt = receivedAt;
  handle.sessionStartedAt = requestedAt;
  handle.workerSessionStartedAt = Number.isFinite(event.timestamp) ? event.timestamp : null;
  handle.sessionDeadline = requestedAt + durationMs;
  return true;
}

export function armInteractiveSessionSafetyWatchdog(handle, onTimeout, setTimer = setTimeout) {
  const durationMs = Math.min(MAX_SESSION_MS, Math.max(0, Number(handle?.sessionDurationMs) || 0));
  if (!handle?.interactive || durationMs <= 0 || typeof onTimeout !== 'function') return null;
  return setTimer(() => {
    if (handle.interactiveEnded || !handle.child || handle.child.exitCode !== null) return;
    handle.interactiveEndReason = 'SUPERVISOR_TIMEOUT';
    onTimeout();
  }, durationMs + 60_000);
}

export function reserveInteractiveViewportFrame(handle, now = Date.now()) {
  if (!handle || !Number.isFinite(now)) return false;
  const recent = (Array.isArray(handle.viewportCaptureTimestamps) ? handle.viewportCaptureTimestamps : [])
    .filter(timestamp => Number.isFinite(timestamp) && timestamp > now - INTERACTIVE_VIEWPORT_FRAME_WINDOW_MS);
  handle.viewportCaptureTimestamps = recent;
  handle.viewportCaptureCount = Number.isSafeInteger(handle.viewportCaptureCount) ? handle.viewportCaptureCount : 0;
  handle.lastViewportCaptureAt = Number.isFinite(handle.lastViewportCaptureAt) ? handle.lastViewportCaptureAt : 0;
  if (now - handle.lastViewportCaptureAt < 400 || recent.length >= MAX_INTERACTIVE_VIEWPORT_FRAMES_PER_MINUTE) return false;
  handle.lastViewportCaptureAt = now;
  handle.viewportCaptureCount++;
  recent.push(now);
  return true;
}

// Keep a bounded lifecycle summary on the job handle so diagnostics can still
// explain a completed job after it has been removed from activeJobs.
export function interactiveLifecycleEvidence(handle, now = Date.now()) {
  if (!handle?.interactive) return null;
  const readyAt = Number.isFinite(handle.sessionReadyAt) ? handle.sessionReadyAt : null;
  const endedAt = Number.isFinite(handle.workerClosedAt) ? handle.workerClosedAt
    : (Number.isFinite(handle.interactiveEndedAt) ? handle.interactiveEndedAt : null);
  return {
    readyEventReceived: handle.interactiveReady === true,
    workerReadyEventAt: Number.isFinite(handle.workerReadyEventAt) ? handle.workerReadyEventAt : null,
    readinessEventReceivedAt: readyAt,
    sessionStartedAt: Number.isFinite(handle.sessionStartedAt) ? handle.sessionStartedAt : null,
    startCommandSentAt: Number.isFinite(handle.startCommandSentAt) ? handle.startCommandSentAt : null,
    startAcknowledgementReceivedAt: Number.isFinite(handle.startAcknowledgementReceivedAt) ? handle.startAcknowledgementReceivedAt : null,
    startAcknowledgementElapsedMs: Number.isFinite(handle.startCommandSentAt) && Number.isFinite(handle.startAcknowledgementReceivedAt)
      ? Math.max(0, Math.min(10_000, handle.startAcknowledgementReceivedAt - handle.startCommandSentAt)) : null,
    workerSessionStartedAt: Number.isFinite(handle.workerSessionStartedAt) ? handle.workerSessionStartedAt : null,
    workerEndEventAt: Number.isFinite(handle.workerEndEventAt) ? handle.workerEndEventAt : null,
    endedAt,
    endReason: ['SESSION_LIMIT_REACHED', 'INPUT_CLOSED', 'SUPERVISOR_TIMEOUT', 'SUPERVISOR_START_FAILED', 'OPERATOR_CANCELLED', 'CLEANUP_FAILED', 'WORKER_EXITED'].includes(handle.interactiveEndReason)
      ? handle.interactiveEndReason : null,
    workerExitCode: Number.isInteger(handle.workerExitCode) ? handle.workerExitCode : null,
    workerSignalCode: typeof handle.workerSignalCode === 'string' && /^[A-Z0-9]+$/.test(handle.workerSignalCode)
      ? handle.workerSignalCode : null,
    readyElapsedMs: readyAt === null ? null : Math.max(0, Math.min(MAX_SESSION_MS + 10_000, (endedAt ?? now) - readyAt)),
    sessionElapsedMs: Number.isFinite(handle.sessionStartedAt)
      ? Math.max(0, Math.min(MAX_SESSION_MS + 10_000, (endedAt ?? now) - handle.sessionStartedAt)) : null,
    deadlineElapsedMs: Number.isFinite(handle.sessionDeadline) ? Math.max(-MAX_SESSION_MS, Math.min(10_000, now - handle.sessionDeadline)) : null
  };
}

/**
 * Check if Docker daemon is running
 */
async function isDockerAvailable() {
  try {
    await runDocker(['info'], { timeout: 1500 });
    return true;
  } catch {
    return false;
  }
}

async function runDocker(args, options = {}) {
  const { stdout } = await execFileAsync('docker', args, {
    cwd: rootDir,
    encoding: 'utf8',
    timeout: options.timeout || 15000,
    maxBuffer: options.maxBuffer || 4 * 1024 * 1024,
    windowsHide: true
  });
  return stdout.trim();
}

async function copyContainerOutput(containerName, fileName, destination, maxBytes) {
  const safeNames = new Set(['result.json', 'result.json.ready', 'result.json.capture-status.json',
    'screenshot.png', 'screenshot-initial.png', 'egress.json']);
  if (!safeNames.has(fileName)) throw new Error('Output file is not allowlisted.');
  const partial = `${destination}.partial`;
  try { fs.rmSync(partial, { force: true }); } catch {}
  const { stdout: bytes } = await execFileAsync('docker', ['exec', containerName, 'node', '-e',
    `process.stdout.write(require('node:fs').readFileSync('/output/${fileName}'))`], {
    cwd: rootDir, encoding: null, timeout: 10000,
    maxBuffer: maxBytes + 1024 * 1024, windowsHide: true
  });
  if (!Buffer.isBuffer(bytes) || bytes.length > maxBytes) throw new Error('Container output exceeded its supervisor transfer ceiling.');
  fs.writeFileSync(partial, bytes, { flag: 'wx' });
  try { fs.rmSync(destination, { force: true }); } catch {}
  fs.renameSync(partial, destination);
}

function safeCleanupError(operation, error) {
  const code = /^[A-Z0-9_]+$/.test(String(error?.code || '')) ? error.code : 'OPERATION_FAILED';
  return { operation, code };
}

function isBoundedPng(bytes) {
  return Buffer.isBuffer(bytes) && bytes.length >= 1000 && bytes.length <= 5 * 1024 * 1024 &&
    bytes.subarray(0, 8).equals(Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a])) &&
    bytes.readUInt32BE(16) > 0 && bytes.readUInt32BE(16) <= 1280 &&
    bytes.readUInt32BE(20) > 0 && bytes.readUInt32BE(20) <= 800;
}

async function terminateChildProcess(child) {
  if (!child || (child.exitCode !== null && child.exitCode !== undefined) ||
      (child.signalCode !== null && child.signalCode !== undefined)) return true;
  const waitForClose = (timeoutMs) => new Promise(resolve => {
    let done = false;
    const finish = value => { if (done) return; done = true; clearTimeout(timer); child.off('close', onClose); resolve(value); };
    const onClose = () => finish(true);
    const timer = setTimeout(() => finish(false), timeoutMs);
    child.once('close', onClose);
    if (child.exitCode !== null || child.signalCode !== null) finish(true);
  });
  try { child.kill('SIGTERM'); } catch {}
  if (await waitForClose(1500)) return true;
  try { child.kill('SIGKILL'); } catch {}
  return waitForClose(1000);
}

function removeOwnedTempDir(directory, ownerToken) {
  if (!fs.existsSync(directory)) return;
  const marker = path.join(directory, '.trustlayer-owner');
  const observed = fs.readFileSync(marker, 'utf8');
  if (!ownerToken || observed !== ownerToken) throw Object.assign(new Error('Job directory ownership could not be confirmed.'), { code: 'OWNER_MISMATCH' });
  fs.rmSync(directory, { recursive: true, force: true });
}

function collectFilesRecursively(relativeDir) {
  const absoluteDir = path.join(rootDir, relativeDir);
  return fs.readdirSync(absoluteDir, { withFileTypes: true }).flatMap((entry) => {
    const relativePath = path.join(relativeDir, entry.name);
    return entry.isDirectory()
      ? collectFilesRecursively(relativePath)
      : [relativePath];
  });
}

async function ensureDockerRuntime(workerImage = 'trustlayer-worker:latest', rebuildWorkerImage = true, testFixtureNetwork = null) {
  if (!await isDockerAvailable()) throw new Error('Docker daemon is not running or this process cannot access it.');

  let isolatedNetwork = '';
  try {
    isolatedNetwork = await runDocker(['network', 'inspect', 'trustlayer-isolated-net', '--format', '{{.Driver}} {{.Internal}}']);
  } catch {
    await runDocker(['network', 'create', '--driver', 'bridge', '--internal', 'trustlayer-isolated-net']);
    isolatedNetwork = 'bridge true';
  }
  if (isolatedNetwork !== 'bridge true') {
    throw new Error('Docker network trustlayer-isolated-net must be an internal bridge; refusing to run browser worker.');
  }

  if (testFixtureNetwork) {
    const fixtureNetwork = await runDocker(['network', 'inspect', testFixtureNetwork, '--format', '{{.Driver}} {{.Internal}}']);
    if (fixtureNetwork !== 'bridge true') throw new Error('The test fixture network must be an internal bridge.');
  } else {
    let egressNetwork = '';
    try {
      egressNetwork = await runDocker(['network', 'inspect', 'trustlayer-egress-net', '--format', '{{.Driver}} {{.Internal}}']);
    } catch {
      await runDocker(['network', 'create', '--driver', 'bridge', 'trustlayer-egress-net']);
      egressNetwork = 'bridge false';
    }
    if (egressNetwork !== 'bridge false') {
      throw new Error('Docker network trustlayer-egress-net must be an outbound bridge used only by the validated proxy.');
    }
  }

  // Invoke BuildKit only when an executable worker/security input changed.
  const buildInputs = [...collectFilesRecursively('worker').sort(),
    ...collectFilesRecursively('core').sort()];
  const fingerprint = createHash('sha256').update(buildInputs.map(file => fs.readFileSync(path.join(rootDir, file))).join('')).digest('hex');
  let imageFingerprint = '';
  try {
    imageFingerprint = await runDocker(['image', 'inspect', workerImage, '--format={{ index .Config.Labels "trustlayer.source-hash" }}']);
  } catch {}
  if (rebuildWorkerImage && imageFingerprint !== fingerprint) {
    await runDocker(['build', '-t', workerImage, `--label=trustlayer.source-hash=${fingerprint}`, '-f', 'worker/Dockerfile', '.'], { timeout: 300000 });
  } else if (!rebuildWorkerImage) {
    try { await runDocker(['image', 'inspect', workerImage, '--format={{.Id}}']); }
    catch { throw new Error('The offline test worker image is unavailable; build it from the existing trustlayer-worker:latest image first.'); }
  }
}

export class LiveJobController {
  constructor(options = {}) {
    this.maxConcurrent = Math.min(16, Math.max(1, Number(options.maxConcurrent) || 3));
    this.defaultTimeoutMs = options.defaultTimeoutMs || 25000;
    this.activeJobs = new Map();
    this.admittedJobs = new Set();
    this.cleanupRecovery = new Map();
    this._testLocalFixturePolicy = null;
    this._testRuntimeFailureDiagnostics = null;
    // Injectable only to exercise startup ordering without a Docker daemon.
    this._runDocker = options.runDocker || runDocker;
    this._spawnWorker = options.spawnWorker || ((args, spawnOptions) => spawn('docker', args, spawnOptions));
    this.removeContainer = options.removeContainer || (name => runDocker(['rm', '-f', name], { timeout: 5000 }));
    this.removeTempDir = options.removeTempDir || removeOwnedTempDir;
    this.terminateChild = options.terminateChild || terminateChildProcess;
    // Recheck for every job. Docker Desktop is commonly started after this
    // control plane, so a constructor-time snapshot stays stale forever.
    // Runtime availability is checked asynchronously for each job. Probing
    // Docker in the constructor used to block the API event loop at startup.
    this.dockerAvailable = null;
    fs.mkdirSync(screenshotsDir, { recursive: true });
  }

  async _ensureDockerRuntime() {
    await ensureDockerRuntime(this._testLocalFixturePolicy ? 'trustlayer-worker:phase4-fixture-test' : 'trustlayer-worker:latest',
      !this._testLocalFixturePolicy, this._testLocalFixturePolicy?.networkName || null);
  }

  configureLocalFixtureForTests(policy, options = {}) {
    this._testLocalFixturePolicy = validateTestLocalFixturePolicyFromProcess(policy);
    if (options.onRuntimeFailure !== undefined && typeof options.onRuntimeFailure !== 'function') {
      throw new TypeError('Test runtime failure diagnostics must be a function.');
    }
    this._testRuntimeFailureDiagnostics = options.onRuntimeFailure || null;
  }

  clearLocalFixtureForTests() {
    if (process.env.NODE_ENV !== 'test') throw new Error('Test fixture policy is available only in NODE_ENV=test.');
    this._testLocalFixturePolicy = null;
    this._testRuntimeFailureDiagnostics = null;
  }

  validateDestination(url, options = {}) {
    if (this._testLocalFixturePolicy) {
      const fixtureResult = validateTestLocalFixtureUrl(url, this._testLocalFixturePolicy);
      if (fixtureResult) return Promise.resolve(fixtureResult);
      return Promise.resolve({ allowed: false, blockedReason: 'Destination is outside the pinned test fixture origin.', resolvedIps: [], canonicalUrl: url });
    }
    return SSRFGuard.validateAndResolve(url, options);
  }

  /**
   * Submit a new live inspection job
   */
  async submitJob(targetUrl, caseId, options = {}, prevalidatedSsrfResult = null) {
    const jobId = `job-${Date.now()}-${Math.random().toString(36).slice(2, 7)}`;
    if (this.admittedJobs.size >= this.maxConcurrent) {
      return { jobId, caseId, targetUrl, status: JOB_STATUS.BUSY,
        error: 'Concurrent inspection limit reached.', durationMs: 0, result: null };
    }
    this.admittedJobs.add(jobId);
    const timeoutMs = Math.min(180000, Math.max(1000, Number(options.timeoutMs) || this.defaultTimeoutMs));

    // 1. Initial destination pre-validation via SSRFGuard
    const canonicalTarget = (() => { try { return new URL(targetUrl).href; } catch { return ''; } })();
    const reusablePrecheck = prevalidatedSsrfResult?.allowed === true &&
      prevalidatedSsrfResult.canonicalUrl === canonicalTarget &&
      Array.isArray(prevalidatedSsrfResult.resolvedIps) && prevalidatedSsrfResult.resolvedIps.length > 0;
    let preCheck;
    try {
      preCheck = reusablePrecheck
        ? prevalidatedSsrfResult
        : await this.validateDestination(targetUrl, options);
    } catch (error) {
      this.admittedJobs.delete(jobId);
      return { jobId, caseId, targetUrl, status: JOB_STATUS.FAILED,
        error: `Destination validation failed: ${error.message}`, durationMs: 0, result: null };
    }
    if (!preCheck.allowed) {
      this.admittedJobs.delete(jobId);
      return {
        jobId,
        caseId,
        targetUrl,
        status: JOB_STATUS.BLOCKED,
        blockedReason: preCheck.blockedReason,
        resolvedIps: preCheck.resolvedIps,
        durationMs: 0,
        result: null
      };
    }

    const job = {
      jobId,
      caseId,
      targetUrl,
      status: JOB_STATUS.QUEUED,
      createdAt: Date.now(),
      startedAt: null,
      completedAt: null,
      timeoutMs,
      options,
      result: null,
      error: null
    };

    try {
      const result = await this._executeJob(job);
      if (!this.activeJobs.has(jobId)) this.admittedJobs.delete(jobId);
      return result;
    } catch (error) {
      this.admittedJobs.delete(jobId);
      throw error;
    }
  }

  /**
   * Execute an inspection job inside a disposable Docker worker.
   */
  async _executeJob(job) {
    job.status = JOB_STATUS.RUNNING;
    job.startedAt = Date.now();

    const jobTempRoot = path.join(os.tmpdir(), 'trustlayer-jobs');
    fs.mkdirSync(jobTempRoot, { recursive: true });
    const tempDir = fs.mkdtempSync(path.join(jobTempRoot, `${job.jobId}-`));
    job.outputOwnerToken = randomUUID();
    fs.writeFileSync(path.join(tempDir, '.trustlayer-owner'), job.outputOwnerToken, { flag: 'wx' });
    const resultFile = path.join(tempDir, 'result.json');
    const readyResultFile = `${resultFile}.ready`;
    const screenshotFile = path.join(tempDir, 'screenshot.png');
    const initialScreenshotFile = path.join(tempDir, 'screenshot-initial.png');
    const captureStatusFile = path.join(tempDir, 'result.json.capture-status.json');
    const stageTimings = { container_start_ms: 0, proxy_ready_ms: 0, browser_launch_ms: 0,
      navigation_ms: 0, render_readiness_ms: 0, user_countdown_ms: 0,
      screenshot_capture_ms: 0, screenshot_transfer_ms: 0, ocr_analysis_ms: 0 };

    // 1. Confirm the runtime, isolated network, and worker image are ready.
    const runtimeSetupAt = Date.now();
    try {
      await this._ensureDockerRuntime();
      stageTimings.container_start_ms += Date.now() - runtimeSetupAt;
      this.dockerAvailable = true;
    } catch (err) {
      this.dockerAvailable = false;
      job.status = JOB_STATUS.FAILED;
      job.error = `Mode C container runtime unavailable: ${err.message}`;
      job.cleanupDiagnostics = await this._cleanupFailedStart(job, [], tempDir);
      if (job.cleanupDiagnostics.status === 'CLEANED') this.admittedJobs.delete(job.jobId);
      if (job.cleanupDiagnostics.status === 'FAILED') job.error = 'Mode C runtime unavailable; startup cleanup failed. See cleanupDiagnostics.';
      job.completedAt = Date.now();
      job.durationMs = Date.now() - job.startedAt;
      job.result = { status: 'FAILED', error: job.error, isolationReport: { containerAvailable: false, runtimeMode: 'REFUSED_INSECURE_RUNTIME' } };
      return job;
    }

    // 2. Start the validated egress proxy as a dual-homed container. The
    // browser can reach it on the internal-only network, while only this
    // authenticated proxy has a second, outbound-connected interface.
    const egressContainerName = `trustlayer-egress-${job.jobId}`;
    // A shared Docker DNS alias lets stale or concurrent proxies answer a
    // worker's lookup with the wrong per-job credentials. Give every proxy a
    // unique address on the isolated network.
    const proxyAlias = `trustlayer-egress-${job.jobId}`;
    const browserContainerName = `trustlayer-browser-${job.jobId}`;
    const proxyUsername = randomUUID();
    const proxyPassword = randomUUID();
    const workerImage = this._testLocalFixturePolicy ? 'trustlayer-worker:phase4-fixture-test' : 'trustlayer-worker:latest';
    const outputLimits = new Map([
      ['result.json', 2 * 1024 * 1024], ['result.json.ready', 2 * 1024 * 1024],
      ['result.json.capture-status.json', 64 * 1024], ['screenshot.png', 5 * 1024 * 1024],
      ['screenshot-initial.png', 5 * 1024 * 1024], ['egress.json', 7 * 1024 * 1024]
    ]);
    const synchronizedFiles = new Map();
    let lastOutputSyncAt = 0;
    let outputSyncPromise = null;
    const syncBrowserOutput = (force = false) => {
      if (outputSyncPromise) return force
        ? outputSyncPromise.then(() => syncBrowserOutput(true))
        : outputSyncPromise;
      if (!force && Date.now() - lastOutputSyncAt < 200) return Promise.resolve();
      lastOutputSyncAt = Date.now();
      const task = (async () => {
        const names = [...outputLimits.keys()].filter(name => name !== 'egress.json');
        if (force) {
          for (const name of names) {
            try { await copyContainerOutput(browserContainerName, name, path.join(tempDir, name), outputLimits.get(name)); } catch {}
          }
          return;
        }
        const probe = `const f=require('node:fs');const a=${JSON.stringify(names)};const o={};for(const n of a){try{const s=f.statSync('/output/'+n);o[n]={size:s.size,mtime:s.mtimeMs}}catch{}}console.log(JSON.stringify(o))`;
        let remote;
        try { remote = JSON.parse(await runDocker(['exec', browserContainerName, 'node', '-e', probe], { timeout: 3000 })); }
        catch { return; }
        for (const [name, stat] of Object.entries(remote)) {
          if (stat.size > outputLimits.get(name)) continue;
          const stamp = `${stat.size}:${stat.mtime}`;
          if (synchronizedFiles.get(name) === stamp) continue;
          try {
            await copyContainerOutput(browserContainerName, name, path.join(tempDir, name), outputLimits.get(name));
            synchronizedFiles.set(name, stamp);
          } catch {}
        }
        try {
          const proxyProbe = "const f=require('node:fs');try{const s=f.statSync('/output/egress.json');console.log(JSON.stringify({size:s.size,mtime:s.mtimeMs}))}catch{console.log('{}')}";
          const proxyStat = JSON.parse(await runDocker(['exec', egressContainerName, 'node', '-e', proxyProbe], { timeout: 3000 }));
          if (proxyStat.size <= outputLimits.get('egress.json')) {
            const stamp = `${proxyStat.size}:${proxyStat.mtime}`;
            if (synchronizedFiles.get('egress.json') !== stamp) {
              await copyContainerOutput(egressContainerName, 'egress.json', path.join(tempDir, 'egress.json'), outputLimits.get('egress.json'));
              synchronizedFiles.set('egress.json', stamp);
            }
          }
        } catch {}
      })();
      outputSyncPromise = task;
      void task.finally(() => { if (outputSyncPromise === task) outputSyncPromise = null; }).catch(() => {});
      return task;
    };
    const containerStartAt = Date.now();
    try {
      await this._runDocker([
        'run', '-d', '--name', egressContainerName,
        '--network=trustlayer-isolated-net', `--network-alias=${proxyAlias}`,
        '--user=pwuser', '--read-only', '--tmpfs', '/tmp:rw,noexec,nosuid,size=32m',
        '--tmpfs', '/output:rw,noexec,nosuid,size=16m,uid=1001,gid=1001,mode=0700',
        '--cap-drop=ALL', '--security-opt=no-new-privileges', '--pids-limit=32', '--memory=128m', '--cpus=0.25',
        ...(this._testLocalFixturePolicy ? ['--env=NODE_ENV=test'] : []),
        '--entrypoint', 'node', workerImage,
        'worker/egress_proxy_worker.js', `--username=${proxyUsername}`,
        `--password=${proxyPassword}`, `--correlationId=${job.jobId}`, '--output=/output/egress.json',
        ...(this._testLocalFixturePolicy ? [`--test-fixture-host=${this._testLocalFixturePolicy.hostname}`,
          `--test-fixture-address=${this._testLocalFixturePolicy.address}`,
          `--test-fixture-port=${this._testLocalFixturePolicy.port}`,
          `--test-fixture-network=${this._testLocalFixturePolicy.networkName}`] : [])
      ]);
      stageTimings.container_start_ms += Date.now() - containerStartAt;
      const proxyStartAt = Date.now();
      await this._runDocker(['network', 'connect', this._testLocalFixturePolicy?.networkName || 'trustlayer-egress-net', egressContainerName]);

      let proxyReady = false;
      for (let attempt = 0; attempt < 20 && !proxyReady; attempt++) {
        try {
          await this._runDocker(['exec', egressContainerName, 'node', '-e',
            "const n=require('node:net').connect(3128,'127.0.0.1');n.on('connect',()=>{n.destroy();process.exit(0)});n.on('error',()=>process.exit(1))"]);
          proxyReady = true;
        } catch {
          await new Promise(resolve => setTimeout(resolve, 100));
        }
      }
      if (!proxyReady) throw new Error('Egress proxy container did not become ready.');
      stageTimings.proxy_ready_ms = Date.now() - proxyStartAt;
    } catch (err) {
      job.status = JOB_STATUS.FAILED;
      job.error = `Failed to start isolated egress proxy: ${err.message}`;
      job.cleanupDiagnostics = await this._cleanupFailedStart(job, [egressContainerName], tempDir);
      if (job.cleanupDiagnostics.status === 'CLEANED') this.admittedJobs.delete(job.jobId);
      if (job.cleanupDiagnostics.status === 'FAILED') job.error = 'Egress proxy startup failed; cleanup failed. See cleanupDiagnostics.';
      job.completedAt = Date.now();
      job.durationMs = job.completedAt - job.startedAt;
      return job;
    }

    let child;
    let timer;
    let sessionSafetyTimer;
    let initialScreenshotWatcher;
    let readyResultWatcher;
    let captureStatusWatcher;
    let earlyResultPublished = false;
    let initialScreenshotPublished = false;
    const publishInitialScreenshot = () => {
      if (initialScreenshotPublished || !fs.existsSync(initialScreenshotFile)) return false;
      try {
        const bytes = fs.readFileSync(initialScreenshotFile);
        const isPng = isBoundedPng(bytes);
        if (!isPng) return false;

        const artifactUrl = `/api/cases/${job.caseId}/screenshot?type=initial`;
        fs.writeFileSync(path.join(screenshotsDir, `${job.caseId}-initial.png`), bytes);
        let renderStatus = 'RENDER_PARTIAL';
        try { renderStatus = JSON.parse(fs.readFileSync(captureStatusFile, 'utf8')).renderStatus || renderStatus; } catch {}
        initialScreenshotPublished = true;
        if (job.options?.onInitialScreenshot) {
          try {
            job.options.onInitialScreenshot({
              caseId: job.caseId,
              artifactUrl,
              screenshotBytes: bytes.length,
              renderStatus,
              capturedAt: Date.now(),
              sha256: createHash('sha256').update(bytes).digest('hex')
            });
          } catch {}
        }
        return true;
      } catch {
        return false;
      }
    };

    return new Promise((resolve) => {
      let isSettled = false;

      // Watchdog wall-clock timer
      timer = setTimeout(async () => {
        if (!isSettled) {
          isSettled = true;
          if (!earlyResultPublished) {
            job.status = JOB_STATUS.TIMED_OUT;
            job.error = `Inspection exceeded wall-clock limit of ${job.timeoutMs}ms`;
          } else if (job.result) {
            job.result.runtimeSessionActive = false;
            job.result.runtimeSessionEndedAt = Date.now();
          }
          job.cleanupDiagnostics = await this._cleanup(job.jobId);
          markInteractiveEnded(job.cleanupDiagnostics?.status === 'FAILED' ? 'CLEANUP_FAILED' : 'TIMED_OUT');
          resolve(job);
        }
      }, job.timeoutMs + 3000);

      // Containerized Worker Execution
      const dockerArgs = [
        'run', ...(job.options?.interactive ? ['-i'] : []), '--name', browserContainerName,
        '--network=trustlayer-isolated-net',
        '--user=pwuser',
        '--init',
        '--read-only',
        '--tmpfs', '/tmp:rw,noexec,nosuid,size=64m',
        '--tmpfs', '/dev/shm:rw,noexec,nosuid,size=64m',
        '--tmpfs', '/output:rw,noexec,nosuid,size=24m,uid=1001,gid=1001,mode=0700',
        '--cap-drop=ALL',
        '--cap-add=SYS_CHROOT',
        '--security-opt=seccomp=worker/chromium-seccomp.json',
        '--security-opt=no-new-privileges',
        '--pids-limit=128',
        '--memory=512m',
        '--cpus=1.0',
        workerImage,
        `--url=${job.targetUrl}`,
        `--jobId=${job.jobId}`,
        `--proxy=http://${proxyAlias}:3128`,
        `--proxyUsername=${proxyUsername}`,
        `--proxyPassword=${proxyPassword}`,
        `--output=/output/result.json`,
        `--screenshot=/output/screenshot.png`,
        `--initialScreenshot=/output/screenshot-initial.png`,
        `--captureStatus=/output/result.json.capture-status.json`,
        `--captureDelayMs=${[0, 5000, 10000].includes(job.options.captureDelayMs) ? job.options.captureDelayMs : 10000}`,
        `--timeout=${job.timeoutMs}`,
        `--maxBytes=${Math.min(5 * 1024 * 1024, Math.max(16 * 1024, Number(job.options.maxResponseBytes ?? job.options.maxBytes) || 1024 * 1024))}`,
        `--keepAlive=${Math.min(MAX_SESSION_MS, Math.max(0, job.options.keepAliveMs || 0))}`,
        ...(job.options?.interactive ? ['--interactive=1'] : []),
        '--handoffGrace=2500'
      ];
      child = this._spawnWorker(dockerArgs, { stdio: [job.options?.interactive ? 'pipe' : 'ignore', 'pipe', 'pipe'] });

      let stderr = '';
      const appendBounded = (current, chunk) => (current + chunk.toString('utf8')).slice(-64 * 1024);
      if (child.stderr) child.stderr.on('data', (d) => { stderr = appendBounded(stderr, d); });

      const jobHandle = {
        job,
        child,
        browserContainerName,
        egressContainerName,
        tempDir,
        outputLimits,
        timer,
        interactive: job.options?.interactive === true,
        interactionCount: 0,
        sessionDurationMs: Math.min(MAX_SESSION_MS, Math.max(0, Number(job.options.keepAliveMs) || 0)),
        interactiveReady: false,
        interactiveStarted: false,
        sessionReadyAt: null,
        sessionStartedAt: null,
        startCommandSentAt: null,
        startAcknowledgementReceivedAt: null,
        sessionDeadline: null,
        interactiveEndReason: null,
        workerReadyEventAt: null,
        workerSessionStartedAt: null,
        workerEndEventAt: null,
        workerExitCode: null,
        workerSignalCode: null,
        workerClosedAt: null,
        interactiveEndedAt: null,
        pendingInteractions: new Map(),
        pendingActionSlots: 0,
        pointerMoveCount: 0,
        viewportCaptureCount: 0,
        lastViewportCaptureAt: 0,
        publishInitialScreenshot,
        get initialScreenshotWatcher() { return initialScreenshotWatcher; },
        get readyResultWatcher() { return readyResultWatcher; },
      get captureStatusWatcher() { return captureStatusWatcher; },
        cancel: async () => {
          if (!isSettled) {
            isSettled = true;
            if (timer) clearTimeout(timer);
            if (sessionSafetyTimer) clearTimeout(sessionSafetyTimer);
            for (const pending of jobHandle.pendingInteractions.values()) { clearTimeout(pending.timer); pending.resolve({ ok: false, error: 'Interactive browser session stopped.' }); }
            jobHandle.pendingInteractions.clear();
            if (earlyResultPublished && job.result) {
              job.result.runtimeSessionActive = false;
              job.result.runtimeSessionEndedAt = Date.now();
            } else {
              job.status = JOB_STATUS.CANCELLED;
              job.error = 'Investigation halted by operator';
            }
            job.cleanupDiagnostics = await this._cleanup(job.jobId);
            markInteractiveEnded(job.cleanupDiagnostics?.status === 'FAILED' ? 'CLEANUP_FAILED' : (jobHandle.startFailure ? 'FAILED' : 'CANCELLED'));
            resolve(job);
          }
        }
      };
      const markInteractiveEnded = (status) => {
        if (!jobHandle.interactive || jobHandle.interactiveEnded) return;
        jobHandle.interactiveEnded = true;
        jobHandle.interactiveEndedAt = Date.now();
        if (jobHandle.startAcknowledgement) {
          clearTimeout(jobHandle.startAcknowledgement.timer);
          jobHandle.startAcknowledgement.resolve(false);
          jobHandle.startAcknowledgement = null;
        }
        jobHandle.interactiveEndReason ||= status === 'TIMED_OUT' ? 'SUPERVISOR_TIMEOUT'
          : (status === 'FAILED' && jobHandle.startFailure ? 'SUPERVISOR_START_FAILED'
            : (status === 'CANCELLED' ? 'OPERATOR_CANCELLED'
              : (status === 'CLEANUP_FAILED' ? 'CLEANUP_FAILED' : 'WORKER_EXITED')));
        for (const pending of jobHandle.pendingInteractions.values()) { clearTimeout(pending.timer); pending.resolve({ ok: false, error: 'Interactive browser session ended.' }); }
        jobHandle.pendingInteractions.clear();
        try { job.options?.onInteractiveEnd?.(status, {
          reason: jobHandle.interactiveEndReason,
          lifecycle: interactiveLifecycleEvidence(jobHandle)
        }); } catch {}
      };
      this.activeJobs.set(job.jobId, jobHandle);
      if (jobHandle.interactive && child.stdout) {
        let frameBuffer = '';
        child.stdout.on('data', chunk => {
          frameBuffer += chunk.toString('utf8');
          if (frameBuffer.length > 9 * 1024 * 1024) { frameBuffer = ''; return; }
          let newline;
          while ((newline = frameBuffer.indexOf('\n')) >= 0) {
            const line = frameBuffer.slice(0, newline).trim(); frameBuffer = frameBuffer.slice(newline + 1);
            try {
              if (line.startsWith('TL_EVENT:')) {
                const event = JSON.parse(line.slice(9));
                markInteractiveSessionReady(jobHandle, event);
                if (event.type === 'interactive_session_started' && jobHandle.startAcknowledgement) {
                  const pendingStart = jobHandle.startAcknowledgement;
                  clearTimeout(pendingStart.timer);
                  jobHandle.startAcknowledgement = null;
                  const started = markInteractiveSessionStarted(jobHandle, event, pendingStart.requestedAt, Date.now());
                  if (started && jobHandle.job?.result) {
                    jobHandle.job.result.runtimeSessionUntil = jobHandle.sessionDeadline;
                    sessionSafetyTimer = armInteractiveSessionSafetyWatchdog(jobHandle, () => jobHandle.cancel?.());
                    sessionSafetyTimer.unref?.();
                  }
                  pendingStart.resolve(started ? jobHandle.sessionDeadline : null);
                }
                if (event.type === 'interactive_session_ended' &&
                    ['SESSION_LIMIT_REACHED', 'INPUT_CLOSED'].includes(event.reason)) {
                  jobHandle.interactiveEndReason = event.reason;
                  jobHandle.workerEndEventAt = Number.isFinite(event.timestamp) ? event.timestamp : Date.now();
                }
                job.options.onInteractiveEvent?.(event);
                // The result file may be written before the worker enters its
                // interactive loop. Publish RUNNING only after the worker has
                // emitted its page-ready event and can accept commands.
                if (jobHandle.interactiveReady) void publishReadyResult();
              }
              else if (line.startsWith('TL_RESPONSE:')) {
                const response = JSON.parse(line.slice(12));
                const pending = jobHandle.pendingInteractions.get(response.requestId);
                if (pending) { jobHandle.pendingInteractions.delete(response.requestId); clearTimeout(pending.timer); pending.resolve(response); }
              }
            } catch {}
          }
        });
      }
      initialScreenshotWatcher = setInterval(() => {
        void syncBrowserOutput().then(publishInitialScreenshot).catch(() => {});
      }, 250);
      publishInitialScreenshot();

      let lastCaptureStatus = '';
      captureStatusWatcher = setInterval(() => {
        try {
          if (!fs.existsSync(captureStatusFile)) return;
          const captureStatus = JSON.parse(fs.readFileSync(captureStatusFile, 'utf8'));
          if (captureStatus.status !== lastCaptureStatus) {
            lastCaptureStatus = captureStatus.status;
            job.options?.onCaptureStatus?.(captureStatus);
          }
        } catch {}
      }, 250);

      let readyResultPublishInProgress = false;
      const publishReadyResult = async () => {
        if (readyResultPublishInProgress) return false;
        readyResultPublishInProgress = true;
        try {
          await syncBrowserOutput();
          if (earlyResultPublished || !fs.existsSync(readyResultFile)) return false;
          const result = JSON.parse(fs.readFileSync(readyResultFile, 'utf8'));
          if (jobHandle.interactive && !jobHandle.interactiveReady) return false;
          if (result.jobId !== job.jobId || result.targetUrl !== job.targetUrl ||
              !hasVerifiedChromiumSandbox(result)) return false;
          if (!fs.existsSync(screenshotFile)) return false;
          const transferStartedAt = Date.now();
          const bytes = fs.readFileSync(screenshotFile);
          const isPng = bytes.length >= 1000 && bytes.length <= 5 * 1024 * 1024 &&
            bytes[0] === 0x89 && bytes[1] === 0x50 && bytes[2] === 0x4e && bytes[3] === 0x47 &&
            bytes[4] === 0x0d && bytes[5] === 0x0a && bytes[6] === 0x1a && bytes[7] === 0x0a;
          if (!isPng) return false;

          fs.writeFileSync(path.join(screenshotsDir, `${job.caseId}.png`), bytes);
          stageTimings.screenshot_transfer_ms = Date.now() - transferStartedAt;
          result.screenshotCaptured = true;
          result.screenshotBytes = bytes.length;
          result.correlationId = result.correlationId || job.jobId;
          try {
            const egressPath = path.join(tempDir, 'egress.json');
            if (fs.existsSync(egressPath)) result.egressObservations = JSON.parse(fs.readFileSync(egressPath, 'utf8'));
          } catch (egressError) {
            result.egressObservationError = egressError.message;
          }
          result.modeCTimings = { ...stageTimings, ...(result.modeCTimings || {}) };
          job.options?.onTimings?.(result.modeCTimings);
          result.pageExtraction = result.pageExtraction || {};
          result.pageExtraction.screenshotAvailable = true;
          result.pageExtraction.screenshotUrl = `/api/cases/${job.caseId}/screenshot`;
          result.pageExtraction.screenshotBytes = bytes.length;
          result.isolationReport.runtimeMode = 'CONTAINER_DOCKER';
          result.isolationReport.containerAvailable = true;
          result.isolationReport.capabilityPolicy = 'ALL_DROPPED_EXCEPT_SYS_CHROOT';
          result.isolationReport.networkIsolated = true;
          result.isolationReport.containerImage = 'trustlayer-worker:latest';
          const keepAliveDuration = Math.min(MAX_SESSION_MS, Math.max(0, Number(job.options.keepAliveMs) || 0));
          result.runtimeSessionActive = jobHandle.interactive ? jobHandle.interactiveReady : keepAliveDuration > 0;
          result.runtimeSessionUntil = jobHandle.interactive ? null
            : (result.runtimeSessionActive ? Date.now() + keepAliveDuration : null);
          job.result = result;
          const readyStatus = String(result.status).toUpperCase();
          job.status = readyStatus === 'SUCCESS' ? JOB_STATUS.COMPLETED
            : (readyStatus === 'PARTIAL' ? JOB_STATUS.PARTIAL
              : (readyStatus === 'BLOCKED' ? JOB_STATUS.BLOCKED
                : (readyStatus === 'HTTP_ERROR' ? JOB_STATUS.HTTP_ERROR : JOB_STATUS.FAILED)));
          if (job.status === JOB_STATUS.FAILED) return false;
          job.completedAt = Date.now();
          job.durationMs = job.completedAt - job.startedAt;
          earlyResultPublished = true;
          // Startup/rendering is now complete. The acknowledged interactive
          // session has a separate finite watchdog tied to its own deadline.
          if (jobHandle.interactive && timer) { clearTimeout(timer); timer = null; }
          job.cleanupDiagnostics = { status: 'PENDING', operations: [] };
          resolve(job);
          return true;
        } catch {
          return false;
        } finally {
          readyResultPublishInProgress = false;
        }
      };
      readyResultWatcher = setInterval(() => { void publishReadyResult(); }, 250);
      void publishReadyResult();

      child.on('close', async (code) => {
        if (sessionSafetyTimer) { clearTimeout(sessionSafetyTimer); sessionSafetyTimer = null; }
        jobHandle.workerExitCode = Number.isInteger(code) ? code : null;
        jobHandle.workerSignalCode = typeof child.signalCode === 'string' ? child.signalCode : null;
        jobHandle.workerClosedAt = Date.now();
        if (isSettled) return;
        isSettled = true;
        await syncBrowserOutput(true);
        clearTimeout(timer);
        clearInterval(initialScreenshotWatcher);
        clearInterval(readyResultWatcher);
        clearInterval(captureStatusWatcher);
        if (earlyResultPublished) {
          if (job.result) {
            job.result.runtimeSessionActive = false;
            job.result.runtimeSessionEndedAt = Date.now();
          }
          job.cleanupDiagnostics = await this._cleanup(job.jobId);
          markInteractiveEnded(job.cleanupDiagnostics?.status === 'FAILED' ? 'CLEANUP_FAILED' : 'ENDED');
          resolve(job);
          return;
        }
        publishInitialScreenshot();

        job.completedAt = Date.now();
        job.durationMs = job.completedAt - job.startedAt;

        // 1. Process result JSON artifact
        if (fs.existsSync(resultFile)) {
          try {
            const rawResult = fs.readFileSync(resultFile, 'utf8');
            job.result = JSON.parse(rawResult);
            if (job.result.jobId !== job.jobId || job.result.targetUrl !== job.targetUrl) {
              throw new Error('Worker output job/target association does not match the submitted case.');
            }
            const workerStatus = String(job.result.status || '').toUpperCase();
            job.status = workerStatus === 'SUCCESS' ? JOB_STATUS.COMPLETED
              : (workerStatus === 'PARTIAL' ? JOB_STATUS.PARTIAL
              : (workerStatus === 'BLOCKED' ? JOB_STATUS.BLOCKED
              : (workerStatus === 'HTTP_ERROR' ? JOB_STATUS.HTTP_ERROR
              : (workerStatus === 'CANCELLED' ? JOB_STATUS.CANCELLED
              : (workerStatus === 'TIMEOUT' || workerStatus === 'TIMED_OUT' ? JOB_STATUS.TIMED_OUT
              : (workerStatus === 'FAILED' ? JOB_STATUS.FAILED
              : (code === 0 ? JOB_STATUS.COMPLETED : JOB_STATUS.FAILED)))))));
          } catch (e) {
            job.status = JOB_STATUS.FAILED;
            job.error = `Failed to parse worker output: ${e.message}`;
          }
        } else {
          job.status = JOB_STATUS.FAILED;
          job.error = stderr || `Worker exited with code ${code} without producing result artifact`;
        }

        // 2. Validate and store screenshot artifact
        if (fs.existsSync(screenshotFile)) {
          try {
            const shotBuf = fs.readFileSync(screenshotFile);
            if (isBoundedPng(shotBuf)) {
              const destPath = path.join(screenshotsDir, `${job.caseId}.png`);
              fs.writeFileSync(destPath, shotBuf);
              stageTimings.screenshot_transfer_ms = Date.now() - job.startedAt;
              if (job.result) {
                if (!job.result.pageExtraction) job.result.pageExtraction = {};
                job.result.pageExtraction.screenshotAvailable = true;
                job.result.pageExtraction.screenshotUrl = `/api/cases/${job.caseId}/screenshot`;
                job.result.pageExtraction.screenshotBytes = shotBuf.length;
                job.result.screenshotCaptured = true;
                job.result.modeCTimings = { ...stageTimings, ...(job.result.modeCTimings || {}) };
                job.options?.onTimings?.(job.result.modeCTimings);
              }
            }
          } catch (shotErr) {
            if (job.result) job.result.screenshotError = shotErr.message;
          }
        }

        if (job.status === JOB_STATUS.COMPLETED && job.result?.screenshotCaptured !== true) {
          job.status = JOB_STATUS.FAILED;
          job.error = 'Rendered inspection did not produce a validated screenshot artifact.';
        }

        if (fs.existsSync(initialScreenshotFile)) {
          try {
            const initialBuf = fs.readFileSync(initialScreenshotFile);
            if (isBoundedPng(initialBuf)) {
              fs.writeFileSync(path.join(screenshotsDir, `${job.caseId}-initial.png`), initialBuf);
              if (job.result?.pageExtraction) job.result.pageExtraction.initialScreenshotAvailable = true;
            }
          } catch (initialError) {
            if (job.result) job.result.initialScreenshotError = initialError.message;
          }
        }

        // 3. Attach egress proxy blocked requests
        const egressObservationPath = path.join(tempDir, 'egress.json');
        try { await copyContainerOutput(egressContainerName, 'egress.json', egressObservationPath, outputLimits.get('egress.json')); } catch {}
        try { await runDocker(['stop', '--time', '2', egressContainerName]); } catch {}
        if (job.result && fs.existsSync(egressObservationPath)) {
          try {
            const observations = JSON.parse(fs.readFileSync(egressObservationPath, 'utf8'));
            job.result.egressObservations = observations;
            if (observations.blockedRequests?.length) {
              if (!job.result.blockedRequests) job.result.blockedRequests = [];
              job.result.blockedRequests.push(...observations.blockedRequests);
            }
          } catch (observationError) {
            job.result.egressObservationError = observationError.message;
          }
        }

        // 4. Update isolation report with truthful runtime metadata
        if (job.result) {
          if (!job.result.isolationReport) job.result.isolationReport = {};
          job.result.isolationReport.runtimeMode = 'CONTAINER_DOCKER';
          job.result.isolationReport.containerAvailable = true;
          job.result.isolationReport.capabilityPolicy = 'ALL_DROPPED_EXCEPT_SYS_CHROOT';
          if (!hasVerifiedChromiumSandbox(job.result)) {
            job.result.isolationReport.chromiumSandboxEnabled = false;
            job.status = JOB_STATUS.FAILED;
            job.error = 'Worker did not verify the required Chromium renderer sandbox protections.';
          }
          job.result.isolationReport.networkIsolated = true;
          job.result.isolationReport.containerImage = 'trustlayer-worker:latest';
        }

        job.cleanupDiagnostics = await this._cleanup(job.jobId);
        markInteractiveEnded(job.cleanupDiagnostics?.status === 'FAILED' ? 'CLEANUP_FAILED' : 'ENDED');
        resolve(job);
      });

      child.on('error', async (err) => {
        if (isSettled) return;
        isSettled = true;
        clearTimeout(timer);
        clearInterval(initialScreenshotWatcher);
        clearInterval(readyResultWatcher);
        clearInterval(captureStatusWatcher);
        job.status = JOB_STATUS.FAILED;
        job.error = `Worker process failed: ${err.message}`;
        job.cleanupDiagnostics = await this._cleanup(job.jobId);
        markInteractiveEnded(job.cleanupDiagnostics?.status === 'FAILED' ? 'CLEANUP_FAILED' : 'FAILED');
        resolve(job);
      });

      if (job.options?.abortSignal) {
        const abortActiveJob = () => jobHandle.cancel();
        if (job.options.abortSignal.aborted) abortActiveJob();
        else job.options.abortSignal.addEventListener('abort', abortActiveJob, { once: true });
      }
    });
  }

  /**
   * Cancel an active inspection job
   */
  cancelJob(jobId) {
    const handle = this.activeJobs.get(jobId);
    if (handle) {
      if (handle.cleanupDiagnostics?.status === 'FAILED') this._cleanup(jobId);
      else handle.cancel?.();
      return true;
    }
    return false;
  }

  async interact(caseId, action) {
    const validation = validateInteractiveAction(action);
    if (!validation.valid) return { ok: false, error: 'Invalid interaction action.' };
    const handle = [...this.activeJobs.values()].find(item => item.job?.caseId === caseId && item.interactive);
    if (!handle || !handle.interactiveReady || !handle.interactiveStarted || !handle.child?.stdin || handle.child.exitCode !== null ||
        !Number.isFinite(handle.sessionDeadline) || Date.now() >= handle.sessionDeadline) {
      return { ok: false, error: 'Interactive browser session is unavailable.' };
    }
    handle.pendingActionSlots = Number.isSafeInteger(handle.pendingActionSlots) ? handle.pendingActionSlots : 0;
    if (handle.pendingActionSlots >= MAX_PENDING_INTERACTIVE_ACTIONS) return { ok: false, error: 'Interactive action queue is full; wait for an action to complete.' };
    handle.pendingActionSlots++;
    const pointerMove = action.type === 'pointer_move';
    const budgetCount = pointerMove ? 'pointerMoveCount' : 'interactionCount';
    const budgetPending = pointerMove ? 'pendingPointerMoves' : 'pendingDiscreteActions';
    handle[budgetCount] = Number.isSafeInteger(handle[budgetCount]) ? handle[budgetCount] : 0;
    handle[budgetPending] = Number.isSafeInteger(handle[budgetPending]) ? handle[budgetPending] : 0;
    const budgetLimit = pointerMove ? MAX_INTERACTIVE_POINTER_MOVES : MAX_INTERACTIVE_ACTIONS;
    if (handle[budgetCount] + handle[budgetPending] >= budgetLimit) {
      handle.pendingActionSlots--;
      return { ok: false, error: pointerMove ? 'Pointer movement limit reached.' : 'Interaction limit reached.' };
    }
    handle[budgetPending]++;
    let slotReleased = false;
    const releaseSlot = result => {
      if (slotReleased) return;
      slotReleased = true;
      handle.pendingActionSlots = Math.max(0, handle.pendingActionSlots - 1);
      handle[budgetPending] = Math.max(0, handle[budgetPending] - 1);
      if (result?.ok) handle[budgetCount]++;
    };
    if (action.type === 'navigate') {
      let checked;
      try { checked = await this.validateDestination(action.url); }
      catch { releaseSlot(); return { ok: false, error: 'Navigation destination could not be validated.' }; }
      if (!checked.allowed) { releaseSlot(); return { ok: false, error: 'Navigation was blocked by destination policy.' }; }
      action = { type: 'navigate', url: checked.canonicalUrl };
    }
    const requestId = randomUUID();
    return new Promise(resolve => {
      const finish = result => { releaseSlot(result); resolve(result); };
      const timer = setTimeout(() => {
        handle.pendingInteractions.delete(requestId);
        finish({ ok: false, error: 'Interaction timed out; the isolated session was stopped.' });
        handle.cancel?.();
      }, INTERACTION_TIMEOUT_MS);
      handle.pendingInteractions.set(requestId, { kind: 'action', resolve: finish, timer });
      try { handle.child.stdin.write(`${JSON.stringify({ requestId, action })}\n`); }
      catch { clearTimeout(timer); handle.pendingInteractions.delete(requestId); finish({ ok: false, error: 'Interactive browser session is unavailable.' }); }
    });
  }

  async captureViewport(caseId) {
    const handle = [...this.activeJobs.values()].find(item => item.job?.caseId === caseId && item.interactive);
    if (!handle || !handle.interactiveReady || !handle.interactiveStarted || !handle.child?.stdin || handle.child.exitCode !== null ||
        !Number.isFinite(handle.sessionDeadline) || Date.now() >= handle.sessionDeadline) {
      return { ok: false, error: 'Interactive browser session is unavailable.' };
    }
    if (!reserveInteractiveViewportFrame(handle)) {
      return { ok: false, error: 'Viewport capture is rate limited.' };
    }
    const requestId = randomUUID();
    return new Promise(resolve => {
      const timer = setTimeout(() => {
        handle.pendingInteractions.delete(requestId);
        resolve({ ok: false, error: 'Viewport capture timed out.' });
      }, INTERACTION_TIMEOUT_MS);
      handle.pendingInteractions.set(requestId, { kind: 'viewport', resolve, timer });
      try { handle.child.stdin.write(`${JSON.stringify({ command: 'CAPTURE_VIEWPORT', requestId })}\n`); }
      catch {
        clearTimeout(timer);
        handle.pendingInteractions.delete(requestId);
        resolve({ ok: false, error: 'Interactive browser session is unavailable.' });
      }
    });
  }

  async startInteractiveSession(caseId) {
    const handle = [...this.activeJobs.values()].find(item => item.job?.caseId === caseId && item.interactive);
    if (!handle || !handle.interactiveReady || handle.interactiveStarted || !handle.child?.stdin || handle.child.exitCode !== null) return false;
    const requestedAt = Date.now();
    const durationMs = Math.min(MAX_SESSION_MS, Math.max(0, Number(handle.sessionDurationMs) || 0));
    if (durationMs <= 0) return false;
    return new Promise(resolve => {
      const timer = setTimeout(() => {
        handle.startAcknowledgement = null;
        handle.startFailure = true;
        handle.interactiveEndReason = 'SUPERVISOR_START_FAILED';
        resolve(null);
        handle.cancel?.();
      }, 5_000);
      handle.startAcknowledgement = { requestedAt, timer, resolve };
      handle.sessionDeadline = requestedAt + durationMs;
      try {
        handle.child.stdin.write(`${JSON.stringify({ command: 'START_INTERACTIVE' })}\n`);
        handle.startCommandSentAt = requestedAt;
      } catch {
        clearTimeout(timer);
        handle.startAcknowledgement = null;
        handle.sessionDeadline = null;
        handle.startFailure = true;
        handle.interactiveEndReason = 'SUPERVISOR_START_FAILED';
        resolve(null);
        handle.cancel?.();
      }
    });
  }

  async _cleanupFailedStart(job, containerNames, tempDir) {
    const errors = [];
    if (this._testLocalFixturePolicy && this._testRuntimeFailureDiagnostics &&
        ['FAILED', 'TIMED_OUT'].includes(job.status)) {
      try {
        await this._testRuntimeFailureDiagnostics({
          caseId: job.caseId,
          status: job.status,
          error: job.error || '',
          workerError: job.result?.error || '',
          workerStatus: job.result?.status || '',
          workerHttpStatus: job.result?.httpStatus ?? null,
          sandboxVerification: job.result?.isolationReport?.chromiumSandboxVerification
            ? { status: job.result.isolationReport.chromiumSandboxVerification.status,
              failures: (job.result.isolationReport.chromiumSandboxVerification.failures || []).slice(0, 12),
              rendererCount: (job.result.isolationReport.chromiumSandboxVerification.rendererChecks || []).length,
              verifiedRendererCount: (job.result.isolationReport.chromiumSandboxVerification.rendererChecks || []).filter(item => item.verified === true).length }
            : null,
          networkFailures: (job.result?.networkEvents || []).filter(item => item.status === 'FAILED').slice(-12)
            .map(({ method, type, status, error: networkError }) => ({ method, type, status, error: networkError })),
          browserContainerName: `trustlayer-browser-${job.jobId}`,
          egressContainerName: containerNames.find(name => name.startsWith('trustlayer-egress-')) || `trustlayer-egress-${job.jobId}`,
          tempDir
        });
      } catch {}
    }
    for (const [index, name] of containerNames.entries()) {
      try { await this.removeContainer(name); }
      catch (error) { errors.push(safeCleanupError(`remove_startup_container_${index + 1}`, error)); }
    }
    try {
      this.removeTempDir(tempDir, job.outputOwnerToken);
      if (fs.existsSync(tempDir)) errors.push({ operation: 'remove_job_directory', code: 'PATH_REMAINS' });
    } catch (error) { errors.push(safeCleanupError('remove_job_directory', error)); }
    const diagnostics = { status: errors.length ? 'FAILED' : 'CLEANED', operations: errors };
    job.cleanupDiagnostics = diagnostics;
    if (errors.length) {
      this.cleanupRecovery.set(job.jobId, () => this._cleanupFailedStart(job, containerNames, tempDir));
    } else {
      this.cleanupRecovery.delete(job.jobId);
      this.admittedJobs.delete(job.jobId);
    }
    return diagnostics;
  }

  async retryCleanup(jobId) {
    const active = this.activeJobs.get(jobId);
    if (active?.cleanupDiagnostics?.status === 'FAILED') return this._cleanup(jobId);
    const retry = this.cleanupRecovery.get(jobId);
    if (!retry) return { status: 'UNAVAILABLE', operations: [] };
    return retry();
  }

  /**
   * Clean up worker resources
   */
  async _cleanup(jobId) {
    const handle = this.activeJobs.get(jobId);
    if (!handle) {
      this.admittedJobs.delete(jobId);
      return { status: 'CLEANED', operations: [] };
    }
    if (handle.cleanupPromise) return handle.cleanupPromise;
    handle.cleanupPromise = (async () => {
      const errors = [];
      if (this._testLocalFixturePolicy && this._testRuntimeFailureDiagnostics &&
          ['FAILED', 'TIMED_OUT'].includes(handle.job?.status)) {
        try {
          await this._testRuntimeFailureDiagnostics({
            caseId: handle.job.caseId,
            status: handle.job.status,
            error: handle.job.error || '',
            workerError: handle.job.result?.error || '',
            workerStatus: handle.job.result?.status || '',
            workerHttpStatus: handle.job.result?.httpStatus ?? null,
            sandboxVerification: handle.job.result?.isolationReport?.chromiumSandboxVerification
              ? { status: handle.job.result.isolationReport.chromiumSandboxVerification.status,
                failures: (handle.job.result.isolationReport.chromiumSandboxVerification.failures || []).slice(0, 12),
                rendererCount: (handle.job.result.isolationReport.chromiumSandboxVerification.rendererChecks || []).length,
                verifiedRendererCount: (handle.job.result.isolationReport.chromiumSandboxVerification.rendererChecks || []).filter(item => item.verified === true).length }
              : null,
            networkFailures: (handle.job.result?.networkEvents || []).filter(item => item.status === 'FAILED').slice(-12)
              .map(({ method, type, status, error: networkError }) => ({ method, type, status, error: networkError })),
            browserContainerName: handle.browserContainerName,
            egressContainerName: handle.egressContainerName,
            tempDir: handle.tempDir
          });
        } catch {}
      }
      for (const [name, clear] of [
        ['initialScreenshotWatcher', handle.initialScreenshotWatcher],
        ['readyResultWatcher', handle.readyResultWatcher],
        ['captureStatusWatcher', handle.captureStatusWatcher]
      ]) {
        if (clear) {
          try { clearInterval(clear); } catch (error) { errors.push(safeCleanupError(`clear_${name}`, error)); }
        }
      }
      try { handle.publishInitialScreenshot?.(); }
      catch (error) { errors.push(safeCleanupError('publish_initial_screenshot', error)); }

      for (const [operation, name] of [
        ['remove_browser_container', handle.browserContainerName],
        ['remove_egress_container', handle.egressContainerName]
      ]) {
        if (!name) continue;
        try { await this.removeContainer(name); }
        catch (error) { errors.push(safeCleanupError(operation, error)); }
      }

      if (handle.child) {
        try {
          if (!(await this.terminateChild(handle.child))) errors.push({ operation: 'terminate_docker_client', code: 'TERMINATION_TIMEOUT' });
        } catch (error) { errors.push(safeCleanupError('terminate_docker_client', error)); }
      }

      if (handle.tempDir) {
        try {
          this.removeTempDir(handle.tempDir, handle.job?.outputOwnerToken);
          if (fs.existsSync(handle.tempDir)) errors.push({ operation: 'remove_job_directory', code: 'PATH_REMAINS' });
        } catch (error) { errors.push(safeCleanupError('remove_job_directory', error)); }
      }
      const diagnostics = { status: errors.length ? 'FAILED' : 'CLEANED', operations: errors };
      if (handle.job) {
        handle.job.cleanupDiagnostics = diagnostics;
        if (errors.length) {
          handle.job.status = JOB_STATUS.FAILED;
          handle.job.error = 'Investigation cleanup failed; resources may remain. See cleanupDiagnostics.';
        }
      }
      if (errors.length) {
        handle.cleanupPromise = null;
      } else {
        this.admittedJobs.delete(jobId);
        this.activeJobs.delete(jobId);
      }
      return diagnostics;
    })();
    return handle.cleanupPromise;
  }
}

export const globalJobController = new LiveJobController();
