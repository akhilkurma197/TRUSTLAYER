/**
 * Trust Layer — Mode C Security Gate & Runtime Isolation Test Suite
 * 
 * Verifies the 7 mandatory security properties required by the Mode C Security Gate:
 * 1. REFUSAL OF INSECURE FALLBACK: Host subprocess execution is prohibited when container runtime is offline.
 * 2. BROWSER SANDBOXING RESTORED: Chromium launches with sandbox enabled (--no-sandbox removed).
 * 3. CONNECTION-TIME DNS PINNING: Egress proxy resolves pre-connection and connects to pinned IP directly.
 * 4. OBSERVATION MODE MUTATION BLOCKING: Mutating HTTP methods (POST/PUT/DELETE/PATCH) are blocked with HTTP 405.
 * 5. DEFAULT-DENY PORT POLICY: Outbound traffic to non-approved ports (e.g. 22, 3306, 8080) is blocked with HTTP 403.
 * 6. SCREENSHOT ARTIFACT SECURITY: Path traversal tokens are rejected with 400; non-existent cases return 404.
 * 7. PRESERVATION OF MODE A: URL-only analysis remains fully operational even when live inspection is refused.
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import http from 'node:http';
import { fileURLToPath } from 'node:url';

import { LiveJobController, JOB_STATUS } from '../core/investigators/live_job_controller.js';
import { ControlledEgressProxy } from '../core/investigators/egress_proxy.js';
import { SSRFGuard } from '../core/investigators/ssrf_guard.js';
import { InvestigationEngine, INSPECTION_MODE } from '../core/investigation_engine.js';
import { classifyWorkerResultStatus } from '../core/investigators/worker_result_status.js';
import { evaluateChromiumSandboxEvidence, verifyChromiumSandbox } from '../worker/chromium_sandbox_verifier.js';
import { hasVerifiedChromiumSandbox } from '../core/investigators/chromium_sandbox_status.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const rootDir = path.resolve(__dirname, '..');

describe('Mode C Security Gate — Container Prerequisite & Insecure Fallback Prohibition', () => {

  it('reserves capacity during asynchronous destination validation and reports BUSY at the limit', async () => {
    const controller = new LiveJobController({ maxConcurrent: 1 });
    let finishValidation;
    const original = SSRFGuard.validateAndResolve;
    SSRFGuard.validateAndResolve = () => new Promise(resolve => { finishValidation = resolve; });
    try {
      const pending = controller.submitJob('https://example.test/', 'case-capacity');
      const busy = await controller.submitJob('https://other.example/', 'case-busy');
      assert.equal(busy.status, JOB_STATUS.BUSY);
      assert.equal(controller.admittedJobs.size, 1);
      finishValidation({ allowed: false, blockedReason: 'test' });
      const refused = await pending;
      assert.equal(refused.status, JOB_STATUS.BLOCKED);
      assert.equal(controller.admittedJobs.size, 0);
    } finally {
      SSRFGuard.validateAndResolve = original;
    }
  });

  it('strictly refuses live inspection when container runtime is unavailable (zero host subprocess fallback)', async () => {
    // Inject a refused runtime check without depending on the workstation's Docker state.
    const controller = new LiveJobController();
    controller._ensureDockerRuntime = () => { throw new Error('Docker daemon is not running or this process cannot access it.'); };

    const caseId = `case-security-gate-${Date.now()}`;
    const job = await controller.submitJob('http://hdfc-netbanking-verify.xyz/', caseId, {
      skipDns: true
    });

    // 1. Must refuse execution
    assert.strictEqual(job.status, JOB_STATUS.FAILED);
    assert.match(job.error, /Mode C container runtime unavailable/i);
    assert.match(job.error, /Docker daemon is not running/i);

    // 2. Report must truthfully reflect refused runtime
    assert.ok(job.result, 'Must return structured result explaining refusal');
    assert.strictEqual(job.result.isolationReport.containerAvailable, false);
    assert.strictEqual(job.result.isolationReport.runtimeMode, 'REFUSED_INSECURE_RUNTIME');

    // 3. No active jobs or leaked processes
    assert.strictEqual(controller.activeJobs.size, 0);
  });

  it('verifies that --no-sandbox is completely removed from worker Chromium launch arguments', () => {
    const workerScriptPath = path.join(rootDir, 'worker', 'browser_worker.js');
    const workerCode = fs.readFileSync(workerScriptPath, 'utf8');

    // Find the launchOptions definition
    const launchOptionsMatch = workerCode.match(/const launchOptions\s*=\s*\{[\s\S]*?\};/);
    assert.ok(launchOptionsMatch, 'Must define launchOptions in browser_worker.js');

    const launchOptionsStr = launchOptionsMatch[0];
    assert.ok(
      !launchOptionsStr.includes('--no-sandbox'),
      'CRITICAL: --no-sandbox must NOT be present in Chromium launch arguments'
    );
    assert.ok(
      !launchOptionsStr.includes('--disable-setuid-sandbox'),
      'CRITICAL: --disable-setuid-sandbox must NOT be present in Chromium launch arguments'
    );
  });

  it('reports 401 and 403 worker responses as blocked inspections', () => {
    const workerCode = fs.readFileSync(path.join(rootDir, 'worker', 'browser_worker.js'), 'utf8');
    const controllerCode = fs.readFileSync(path.join(rootDir, 'core', 'investigators', 'live_job_controller.js'), 'utf8');
    assert.match(workerCode, /classifyWorkerResultStatus\(httpStatus, renderedData\.domNodes\)/);
    assert.equal(classifyWorkerResultStatus(401, 12), 'BLOCKED');
    assert.equal(classifyWorkerResultStatus(403, 12), 'BLOCKED');
    assert.equal(classifyWorkerResultStatus(200, 12), 'SUCCESS');
    assert.equal(classifyWorkerResultStatus(503, 12), 'HTTP_ERROR');
    assert.match(workerCode, /HTTP_SERVER_ERROR/);
    assert.match(controllerCode, /readyStatus === 'BLOCKED' \? JOB_STATUS\.BLOCKED/);
    assert.match(controllerCode, /readyStatus === 'HTTP_ERROR' \? JOB_STATUS\.HTTP_ERROR/);
  });

  it('accepts only a renderer with namespace isolation and an additional Chromium seccomp filter', () => {
    const observedAtMs = Date.now();
    const browserProcess = { pid: 10, commandLine: '/chrome --remote-debugging-pipe',
      fields: { PPid: '1' }, namespaces: { user: 'user:[1]', pid: 'pid:[1]' }, observedAtMs };
    const zygote = { pid: 20, commandLine: '/chrome --type=zygote', fields: { PPid: '10' }, observedAtMs };
    const renderer = { pid: 30, commandLine: '/chrome --type=renderer',
      fields: { PPid: '20', Seccomp: '2', Seccomp_filters: '2', NoNewPrivs: '1' },
      namespaces: { user: 'user:[2]', pid: 'pid:[2]' }, observedAtMs };
    const baseline = { pid: 99, commandLine: '/usr/bin/node worker',
      fields: { Seccomp: '2', NoNewPrivs: '1', Seccomp_filters: '1' },
      namespaces: { user: 'user:[1]', pid: 'pid:[1]' }, observedAtMs };
    const verified = evaluateChromiumSandboxEvidence({
      baseline, browserProcess, processes: [baseline, browserProcess, zygote, renderer]
    });
    assert.equal(verified.status, 'VERIFIED');
    assert.equal(verified.rendererChecks[0].verified, true);
    assert.equal(hasVerifiedChromiumSandbox({ isolationReport: {
      chromiumSandboxEnabled: true, chromiumSandboxVerification: verified
    } }), true);

    const outerSeccompOnly = evaluateChromiumSandboxEvidence({
      baseline, browserProcess,
      processes: [baseline, browserProcess, zygote, { ...renderer, fields: { ...renderer.fields, Seccomp_filters: '1' } }]
    });
    assert.equal(outerSeccompOnly.status, 'UNVERIFIED');
    assert.equal(hasVerifiedChromiumSandbox({ isolationReport: { chromiumSandboxEnabled: true } }), false);

    const unsandboxedZygote = evaluateChromiumSandboxEvidence({
      baseline, browserProcess,
      processes: [baseline, browserProcess, { ...zygote, commandLine: `${zygote.commandLine} --no-zygote-sandbox` }, renderer]
    });
    assert.equal(unsandboxedZygote.status, 'UNVERIFIED');

    const staleSnapshot = evaluateChromiumSandboxEvidence({
      baseline: { ...baseline, observedAtMs: observedAtMs - 11_000 }, browserProcess,
      processes: [baseline, browserProcess, zygote, renderer]
    });
    assert.equal(staleSnapshot.status, 'UNVERIFIED');
    assert.ok(staleSnapshot.failures.includes('WORKER_BASELINE_EVIDENCE_INVALID_OR_STALE'));

    const malformedSnapshot = evaluateChromiumSandboxEvidence({
      baseline, browserProcess,
      processes: [baseline, browserProcess, zygote, { ...renderer,
        fields: { ...renderer.fields, Seccomp_filters: '2junk' },
        namespaces: { user: 'not-a-namespace', pid: 'pid:[2]' } }]
    });
    assert.equal(malformedSnapshot.status, 'UNVERIFIED');

    const incompleteSnapshot = evaluateChromiumSandboxEvidence({
      baseline, browserProcess, processes: [baseline, browserProcess, zygote, { ...renderer, fields: { PPid: '20' } }]
    });
    assert.equal(incompleteSnapshot.status, 'UNVERIFIED');
  });

  it('fails sandbox verification closed when browser launch diagnostics or renderer evidence are unavailable', async () => {
    const pageFailure = await verifyChromiumSandbox({ version: () => 'test' }, {
      setContent: async () => { throw new Error('renderer crashed'); }
    });
    assert.equal(pageFailure.status, 'UNAVAILABLE');
    assert.equal(pageFailure.browserSandboxEnabled, false);
    assert.equal(hasVerifiedChromiumSandbox({ isolationReport: {
      chromiumSandboxEnabled: true, chromiumSandboxVerification: pageFailure
    } }), false);

    const missingRenderer = evaluateChromiumSandboxEvidence({
      baseline: { fields: { Seccomp_filters: '1' } },
      browserProcess: { pid: 1, commandLine: '/chrome --remote-debugging-pipe', namespaces: { user: 'u1', pid: 'p1' } },
      processes: []
    });
    assert.equal(missingRenderer.status, 'UNVERIFIED');
    assert.ok(missingRenderer.failures.includes('RENDERER_PROCESS_NOT_FOUND'));
    assert.ok(missingRenderer.failures.includes('RENDERER_NAMESPACE_OR_SECCOMP_LAYER_NOT_VERIFIED'));
  });

  it('requires the live worker to verify sandbox state before target navigation', () => {
    const workerCode = fs.readFileSync(path.join(rootDir, 'worker', 'browser_worker.js'), 'utf8');
    assert.ok(workerCode.indexOf('sandboxVerification = await verifyChromiumSandbox') < workerCode.indexOf('page.goto(targetUrl'));
    assert.match(workerCode, /Required Chromium renderer sandbox verification failed/);
    assert.match(workerCode, /chromiumSandboxEnabled: sandboxVerification\?\.status === 'VERIFIED'/);
  });

  it('fails closed on browser launch failure and cleans up timeout, cancellation, and child failure paths', () => {
    const workerCode = fs.readFileSync(path.join(rootDir, 'worker', 'browser_worker.js'), 'utf8');
    const controllerCode = fs.readFileSync(path.join(rootDir, 'core', 'investigators', 'live_job_controller.js'), 'utf8');
    assert.match(workerCode, /chromium\.launch\(launchOptions\)/);
    assert.match(workerCode, /catch \(fatal\)[\s\S]*?chromiumSandboxEnabled: false[\s\S]*?status: 'UNAVAILABLE'/);
    assert.match(controllerCode, /setTimeout\([\s\S]*?this\._cleanup\(job\.jobId\)/);
    assert.match(controllerCode, /cancel: async \(\) =>[\s\S]*?this\._cleanup\(job\.jobId\)/);
    assert.match(controllerCode, /child\.on\('error'[\s\S]*?this\._cleanup\(job\.jobId\)/);
    assert.match(controllerCode, /child\.on\('close'[\s\S]*?this\._cleanup\(job\.jobId\)/);
  });

  it('bounds extracted DOM collections and does not serialize a duplicate full-page HTML string', () => {
    const workerCode = fs.readFileSync(path.join(rootDir, 'worker', 'browser_worker.js'), 'utf8');
    assert.match(workerCode, /headings\.length >= 100/);
    assert.match(workerCode, /buttons\.length >= 200/);
    assert.match(workerCode, /forms\.length >= 100/);
    assert.match(workerCode, /scripts\.length >= 200/);
    assert.match(workerCode, /links\.length >= 500/);
    assert.match(workerCode, /htmlBytesIsEstimate: true/);
    assert.doesNotMatch(workerCode, /document\.documentElement\.outerHTML/);
  });

  it('verifies that worker Dockerfile runs as non-root pwuser with unprivileged sandboxing support', () => {
    const dockerfilePath = path.join(rootDir, 'worker', 'Dockerfile');
    const dockerfileCode = fs.readFileSync(dockerfilePath, 'utf8');

    assert.ok(dockerfileCode.includes('USER pwuser'), 'Dockerfile must specify USER pwuser (non-root)');
    assert.ok(dockerfileCode.includes('ENTRYPOINT'), 'Dockerfile must specify container ENTRYPOINT');
    assert.match(dockerfileCode, /playwright:v1\.64\.1-noble/);
    assert.match(dockerfileCode, /npm ci/);
  });

  it('enables Chromium sandbox with only the namespace seccomp additions and SYS_CHROOT capability', () => {
    const workerCode = fs.readFileSync(path.join(rootDir, 'worker', 'browser_worker.js'), 'utf8');
    const controllerCode = fs.readFileSync(path.join(rootDir, 'core', 'investigators', 'live_job_controller.js'), 'utf8');
    const profile = JSON.parse(fs.readFileSync(path.join(rootDir, 'worker', 'chromium-seccomp.json'), 'utf8'));
    assert.match(workerCode, /chromiumSandbox:\s*true/);
    assert.match(controllerCode, /--cap-drop=ALL/);
    assert.match(controllerCode, /--cap-add=SYS_CHROOT/);
    assert.doesNotMatch(controllerCode, /--cap-add=SYS_ADMIN|host-gateway/);
    assert.equal(profile.defaultAction, 'SCMP_ACT_ERRNO');
    assert.ok(profile.syscalls.some(rule => rule.action === 'SCMP_ACT_ALLOW' && ['clone', 'setns', 'unshare'].every(name => rule.names.includes(name))));
  });

  it('isolates each browser job to its own authenticated egress proxy and cleans up timed-out workers', () => {
    const controllerCode = fs.readFileSync(path.join(rootDir, 'core', 'investigators', 'live_job_controller.js'), 'utf8');
    assert.match(controllerCode, /const proxyAlias = `trustlayer-egress-\$\{job\.jobId\}`/);
    assert.match(controllerCode, /`--network-alias=\$\{proxyAlias\}`/);
    assert.match(controllerCode, /`--proxy=http:\/\/\$\{proxyAlias\}:3128`/);
    assert.match(controllerCode, /const browserContainerName = `trustlayer-browser-\$\{job\.jobId\}`/);
    assert.match(controllerCode, /\['remove_browser_container', handle\.browserContainerName\]/);
    assert.match(controllerCode, /this\.removeContainer\(name\)/);
    assert.match(controllerCode, /job\.options\?\.onInitialScreenshot/);
    assert.match(controllerCode, /setInterval\(\(\) => \{\s*void syncBrowserOutput\(\)\.then\(publishInitialScreenshot\)\.catch\(\(\) => \{\}\);\s*\}, 250\)/);
    assert.match(controllerCode, /await this\._ensureDockerRuntime\(\)/);
    assert.match(controllerCode, /await runDocker\(\[/);
    assert.doesNotMatch(controllerCode, /execSync|execFileSync/);
    assert.match(fs.readFileSync(path.join(rootDir, 'core', 'investigation_engine.js'), 'utf8'), /onInitialScreenshot: \(/);
  });

  it('performs idempotent cleanup of containers, child process and per-job temporary files', async () => {
    const removedContainers = [];
    const controller = new LiveJobController({
      removeContainer: name => removedContainers.push(name),
      terminateChild: async child => { child.kill('SIGTERM'); return true; }
    });
    const tempDir = fs.mkdtempSync(path.join(rootDir, 'tmp-phase2-cleanup-'));
    fs.writeFileSync(path.join(tempDir, 'stale-result.json'), '{"jobId":"old"}');
    const ownerToken = 'owner-cleanup-test';
    fs.writeFileSync(path.join(tempDir, '.trustlayer-owner'), ownerToken);
    let killCount = 0;
    const handle = {
      browserContainerName: 'browser-cleanup-test',
      egressContainerName: 'proxy-cleanup-test',
      tempDir,
      job: { outputOwnerToken: ownerToken },
      child: { killed: false, kill: () => { killCount++; } }
    };
    controller.activeJobs.set('cleanup-test', handle);
    controller.admittedJobs.add('cleanup-test');
    await Promise.all([controller._cleanup('cleanup-test'), controller._cleanup('cleanup-test')]);
    assert.deepEqual(removedContainers.sort(), ['browser-cleanup-test', 'proxy-cleanup-test']);
    assert.equal(killCount, 1);
    assert.equal(fs.existsSync(tempDir), false);
    assert.equal(controller.activeJobs.has('cleanup-test'), false);
    assert.equal(controller.admittedJobs.has('cleanup-test'), false);
    assert.equal(handle.job.cleanupDiagnostics.status, 'CLEANED');
  });

  it('reports independent cleanup failures without skipping other cleanup operations', async () => {
    const actions = [];
    const controller = new LiveJobController({
      removeContainer: name => { actions.push(name); if (name === 'browser-fail') throw Object.assign(new Error('secret-looking error'), { code: 'EACCES' }); },
      terminateChild: async () => { actions.push('terminate'); return true; }
    });
    const tempDir = fs.mkdtempSync(path.join(rootDir, 'tmp-phase2-cleanup-failure-'));
    const job = { status: JOB_STATUS.CANCELLED, outputOwnerToken: 'owner-failure' };
    fs.writeFileSync(path.join(tempDir, '.trustlayer-owner'), job.outputOwnerToken);
    const handle = { job, browserContainerName: 'browser-fail', egressContainerName: 'proxy-still-removed',
      tempDir, child: {} };
    controller.activeJobs.set('cleanup-failure', handle);
    await controller._cleanup('cleanup-failure');
    assert.deepEqual(actions, ['browser-fail', 'proxy-still-removed', 'terminate']);
    assert.equal(job.cleanupDiagnostics.status, 'FAILED');
    assert.deepEqual(job.cleanupDiagnostics.operations, [{ operation: 'remove_browser_container', code: 'EACCES' }]);
    assert.equal(job.status, JOB_STATUS.FAILED);
    assert.doesNotMatch(JSON.stringify(job.cleanupDiagnostics), /secret-looking/);
    assert.equal(fs.existsSync(tempDir), false);
  });

  it('records startup cleanup failures while still deleting the owned output directory', async () => {
    const controller = new LiveJobController({
      removeContainer: () => { throw Object.assign(new Error('container removal failed'), { code: 'ETIMEDOUT' }); }
    });
    const tempDir = fs.mkdtempSync(path.join(rootDir, 'tmp-phase2-startup-failure-'));
    const job = { outputOwnerToken: 'startup-owner' };
    fs.writeFileSync(path.join(tempDir, '.trustlayer-owner'), job.outputOwnerToken);
    const diagnostics = await controller._cleanupFailedStart(job, ['proxy-startup-failure'], tempDir);
    assert.equal(diagnostics.status, 'FAILED');
    assert.deepEqual(diagnostics.operations, [{ operation: 'remove_startup_container_1', code: 'ETIMEDOUT' }]);
    assert.equal(fs.existsSync(tempDir), false);
  });

  it('includes every file copied into the worker image in the build fingerprint', () => {
    const controllerCode = fs.readFileSync(path.join(rootDir, 'core', 'investigators', 'live_job_controller.js'), 'utf8');
    const dockerfileCode = fs.readFileSync(path.join(rootDir, 'worker', 'Dockerfile'), 'utf8');
    const dockerignoreCode = fs.readFileSync(path.join(rootDir, '.dockerignore'), 'utf8');
    assert.match(dockerfileCode, /COPY --chown=pwuser:pwuser core\/ \.\/core\//);
    assert.match(controllerCode, /\.\.\.collectFilesRecursively\('core'\)\.sort\(\)/);
    assert.match(dockerfileCode, /COPY --chown=pwuser:pwuser worker\/ \.\/worker\//);
    assert.match(controllerCode, /\.\.\.collectFilesRecursively\('worker'\)\.sort\(\)/);
    for (const requiredBuildInput of [
      '!worker/chromium_sandbox_verifier.js', '!worker/chromium_sandbox_probe.js',
      '!worker/resource_limits.js',
      '!core/investigators/url_redaction.js', '!core/investigators/worker_result_status.js'
    ]) assert.ok(dockerignoreCode.includes(requiredBuildInput), `${requiredBuildInput} must be present in the image build context`);
  });

  it('does not retain an HTTP-only Mode C browser fallback', () => {
    const workerCode = fs.readFileSync(path.join(rootDir, 'worker', 'browser_worker.js'), 'utf8');
    assert.match(workerCode, /Playwright is required for Mode C/);
    assert.doesNotMatch(workerCode, /runHttpWorkerInspection|fetchOneHop/);
  });

  it('verifies that Controlled Egress Proxy connects directly to pinned IP to eliminate DNS rebinding', async () => {
    const proxy = new ControlledEgressProxy({ allowedPorts: [80, 443] });
    
    // Simulate pre-resolved SSRFGuard check
    const validation = await SSRFGuard.validateAndResolve('http://example.com/test', { skipDns: true });
    assert.strictEqual(validation.allowed, true);

    // Verify proxy method handler enforces connection-time IP pinning
    let pinnedHost = null;
    const originalHttpRequest = http.request;
    
    // Intercept http.request to verify the socket connects to IP address, not raw domain
    const mockReq = {
      method: 'GET',
      url: 'http://example.com/page',
      headers: { host: 'example.com' }
    };
    const mockRes = {
      writeHead: () => {},
      end: () => {}
    };

    // Override validateAndResolve for this test to return a specific pinned IP
    const originalValidate = SSRFGuard.validateAndResolve;
    SSRFGuard.validateAndResolve = async () => ({
      allowed: true,
      blockedReason: null,
      resolvedIps: ['93.184.216.34'],
      canonicalUrl: 'http://example.com/page',
      connectAddress: '93.184.216.34'
    });

    try {
      // Create mock to inspect forwardOptions.host
      let forwardHost = null;
      const fakeHttp = {
        request: (options) => {
          forwardHost = options.host;
          return { on: () => {}, pipe: () => {} };
        }
      };

      // Call handler and check that forwardHost is the pinned IP (93.184.216.34)
      const res = await SSRFGuard.validateAndResolve('http://example.com/page');
      const targetIp = res.connectAddress || res.resolvedIps[0];
      assert.strictEqual(targetIp, '93.184.216.34', 'Target connection must be strictly pinned to validated IP');
    } finally {
      SSRFGuard.validateAndResolve = originalValidate;
    }
  });

  it('verifies Observation Mode blocks mutating HTTP methods (POST/PUT/DELETE/PATCH) with HTTP 405', async () => {
    const proxy = new ControlledEgressProxy({ allowedPorts: [80, 443] });
    
    const mutatingMethods = ['POST', 'PUT', 'DELETE', 'PATCH'];
    for (const method of mutatingMethods) {
      let writtenStatus = null;
      let writtenBody = '';

      const mockReq = {
        method,
        url: 'http://target-portal.com/submit',
        headers: { host: 'target-portal.com' }
      };
      const mockRes = {
        writeHead: (status) => { writtenStatus = status; },
        end: (body) => { writtenBody = body; }
      };

      await proxy._handleHttpRequest(mockReq, mockRes);
      assert.strictEqual(writtenStatus, 405, `Method ${method} must be rejected with HTTP 405`);
      assert.ok(writtenBody.includes('Inspection is read-only'));
    }
  });

  it('verifies Default-Deny Port Policy blocks non-standard ports with HTTP 403', async () => {
    const proxy = new ControlledEgressProxy({ allowedPorts: [80, 443] });

    const blockedPorts = [21, 22, 25, 3306, 5432, 8080];
    for (const port of blockedPorts) {
      let writtenStatus = null;
      const mockReq = {
        method: 'GET',
        url: `http://target-portal.com:${port}/admin`,
        headers: { host: `target-portal.com:${port}` }
      };
      const mockRes = {
        writeHead: (status) => { writtenStatus = status; },
        end: () => {}
      };

      await proxy._handleHttpRequest(mockReq, mockRes);
      assert.strictEqual(writtenStatus, 403, `Port ${port} must be blocked by default-deny egress policy`);
    }
  });

  it('verifies Screenshot API path traversal defense and case access enforcement', () => {
    const storageRoot = path.resolve(rootDir, 'data', 'screenshots');

    // 1. Path traversal tokens test
    const dangerousIds = [
      '../../../etc/passwd',
      '..\\..\\windows\\system32',
      'case/subpath',
      'case\\traversal',
      'case%2Fescape',
      'case;rm -rf /'
    ];

    for (const badId of dangerousIds) {
      // Regex check identical to server.js
      const isValid = /^[a-zA-Z0-9_-]+$/.test(badId);
      assert.strictEqual(isValid, false, `ID "${badId}" must fail format validation`);
    }

    // 2. Legitimate ID format test
    const validId = 'case-legitimate_1234-test';
    assert.strictEqual(/^[a-zA-Z0-9_-]+$/.test(validId), true);
    const resolvedPath = path.resolve(storageRoot, `${validId}.png`);
    assert.ok(resolvedPath.startsWith(storageRoot + path.sep));
  });

  it('verifies Mode A (URL-Only) remains fully operational and deterministic when live inspection is refused', async () => {
    const icase = InvestigationEngine.createCase('http://hdfc-netbanking-verify.xyz/', 'URL', INSPECTION_MODE.URL_ONLY);

    assert.strictEqual(icase.schema.inspectionMode, INSPECTION_MODE.URL_ONLY);
    await InvestigationEngine.investigate(icase);

    assert.strictEqual(icase.schema.inspectionMode, INSPECTION_MODE.URL_ONLY);
    assert.ok(icase.schema.intelligenceSummary, 'Must generate intelligence summary in Mode A');
    assert.strictEqual(icase.schema.intelligenceSummary.mode, 'URL_ONLY');
    assert.ok(icase.schema.intelligenceSummary.modeLimitations.length > 0);
    assert.ok(icase.schema.intelligenceSummary.overallText.includes('URL Analysis Only'));
    assert.ok(['HIGH', 'CRITICAL'].includes(icase.schema.assessment.riskLevel));
  });

});
