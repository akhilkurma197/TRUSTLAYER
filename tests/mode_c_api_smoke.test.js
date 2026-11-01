import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { test } from 'node:test';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { LiveJobController } from '../core/investigators/live_job_controller.js';

const rootDir = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const enabled = process.env.TRUSTLAYER_DOCKER_API_INTEGRATION === '1';
const captureDelayMs = Number(process.env.TRUSTLAYER_CAPTURE_DELAY_MS || 10000);
const targetUrl = process.env.TRUSTLAYER_MODE_C_TARGET || 'https://www.google.com';

test('Mode C API returns a case-linked rendered screenshot artifact', { skip: !enabled }, async () => {
  // Image preparation is deployment/setup work, not part of the user's click
  // to screenshot latency measurement below.
  new LiveJobController()._ensureDockerRuntime();
  const port = 43000 + (process.pid % 1000);
  const apiToken = randomBytes(32).toString('base64url');
  const server = spawn(process.execPath, ['backend/server.js'], {
    cwd: rootDir,
    env: { ...process.env, PORT: String(port), TRUSTLAYER_API_TOKEN: apiToken },
    windowsHide: true,
    stdio: ['ignore', 'pipe', 'pipe']
  });
  let serverOutput = '';
  let cleanupCaseId = null;
  server.stdout.on('data', chunk => { serverOutput += chunk; });
  server.stderr.on('data', chunk => { serverOutput += chunk; });
  const baseUrl = `http://127.0.0.1:${port}`;
  let caseAccessToken = null;
  const apiFetch = (url, options = {}) => fetch(url, {
    ...options,
    headers: { ...options.headers, Authorization: `Bearer ${apiToken}`,
      ...(caseAccessToken ? { 'X-TrustLayer-Case-Access': caseAccessToken } : {}) }
  });
  try {
    let ready = false;
    for (let attempt = 0; attempt < 60 && !ready; attempt++) {
      try {
        const anonymous = await fetch(`${baseUrl}/api/cases`);
        assert.equal(anonymous.status, 401);
        const response = await apiFetch(`${baseUrl}/api/cases`);
        ready = response.ok;
      } catch {}
      if (!ready) await new Promise(resolve => setTimeout(resolve, 250));
    }
    assert.ok(ready, 'backend API should start');

    const scanStartedAt = Date.now();
    const createdResponse = await apiFetch(`${baseUrl}/api/cases`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        target: targetUrl,
        inspectionMode: 'ISOLATED_LIVE',
        consentConfirmed: true,
        captureDelayMs
      })
    });
    assert.equal(createdResponse.status, 201);
    const created = await createdResponse.json();
    cleanupCaseId = created.caseId;
    caseAccessToken = created.caseAccessToken;
    assert.equal(typeof caseAccessToken, 'string', 'case creation must return its scoped access credential');
    const invalidDelayResponse = await apiFetch(`${baseUrl}/api/cases`, {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ target: 'https://example.com', inspectionMode: 'ISOLATED_LIVE', consentConfirmed: true, captureDelayMs: 1234 })
    });
    assert.equal(invalidDelayResponse.status, 400, 'backend must reject unapproved screenshot delays');

    let schema;
    let earlyScreenshotReadyMs = null;
    let earlyScreenshotObservedWhileRunning = false;
    for (let attempt = 0; attempt < 600; attempt++) {
      let response;
      try {
        response = await apiFetch(`${baseUrl}/api/cases/${created.caseId}`);
      } catch (error) {
        throw new Error(`Backend connection failed while waiting for case. ${error.message}; cause=${error.cause?.code || ''} ${error.cause?.message || ''}; exited=${server.exitCode}; signal=${server.signalCode}\n${serverOutput}`);
      }
      schema = await response.json();
      if (schema.initialScreenshotUrl && earlyScreenshotReadyMs === null) {
        const earlyImage = await apiFetch(`${baseUrl}${schema.initialScreenshotUrl}`);
        if (earlyImage.ok && /image\/png/.test(earlyImage.headers.get('content-type') || '')) {
          const earlyBytes = Buffer.from(await earlyImage.arrayBuffer());
          assert.ok(earlyBytes.length > 1000, 'initial screenshot must contain image data');
          assert.deepEqual([...earlyBytes.subarray(0, 8)], [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);
          earlyScreenshotReadyMs = Date.now() - scanStartedAt;
          earlyScreenshotObservedWhileRunning = !['COMPLETED', 'INCOMPLETE', 'FAILED', 'BLOCKED'].includes(schema.status);
        }
      }
      if (['COMPLETED', 'INCOMPLETE', 'FAILED', 'BLOCKED'].includes(schema.status)) break;
      await new Promise(resolve => setTimeout(resolve, 100));
    }

    assert.equal(schema.status, 'COMPLETED', `Case did not complete: ${JSON.stringify({ status: schema.status, currentStage: schema.currentStage, initialScreenshotUrl: schema.initialScreenshotUrl, liveStatus: schema.liveInspection?.status, liveErrors: schema.liveInspection?.errors, renderStatus: schema.renderStatus, errors: schema.errors, logs: schema.logs?.slice(-10) })}\n${serverOutput}`);
    assert.equal(schema.inspectionMode, 'ISOLATED_LIVE');
    if ([401, 403].includes(schema.liveInspection?.httpStatus)) assert.equal(schema.liveInspection?.status, 'BLOCKED');
    else if (Number(schema.liveInspection?.httpStatus) >= 400) assert.equal(schema.liveInspection?.status, 'HTTP_ERROR');
    else assert.equal(schema.liveInspection?.status, 'SUCCESS');
    assert.equal(schema.liveInspection?.isolationReport?.runtimeMode, 'CONTAINER_DOCKER');
    assert.equal(schema.liveInspection?.isolationReport?.chromiumSandboxEnabled, true);
    assert.equal(schema.liveInspection?.isolationReport?.capabilityPolicy, 'ALL_DROPPED_EXCEPT_SYS_CHROOT');
    assert.equal(schema.liveInspection?.pageExtraction?.screenshotAvailable, true);
    if (schema.liveInspection?.httpStatus === 403) {
      assert.equal(schema.accessStatus, 'BLOCKED_HTTP_403');
      assert.equal(schema.inspectionStatus, 'CONTENT_UNAVAILABLE');
      assert.equal(schema.screenshotStatus, 'CAPTURED');
      assert.equal(schema.httpAnalysis?.statusText, 'HTTP_403_ACCESS_RESTRICTION');
      assert.equal(schema.httpAnalysis?.accessRestriction?.status, 403);
      assert.equal(schema.httpAnalysis?.responseDiagnostics?.origin, 'TARGET_TLS_TUNNEL');
      assert.equal(schema.httpAnalysis?.responseDiagnostics?.tls?.protocol, 'TLS 1.3');
      assert.ok(schema.httpAnalysis?.responseDiagnostics?.tls?.subjectName, 'TLS peer certificate subject should be recorded when available');
      assert.equal(schema.httpAnalysis?.responseDiagnostics?.browserPeerRole, 'CONFIGURED_EGRESS_PROXY_SOCKET');
      assert.notEqual(schema.pageContentAssessment?.verdict, 'PHISHING', 'an HTTP 403 alone must not be called phishing');
      assert.notEqual(schema.overallAssessment?.finalVerdict, 'PHISHING', 'HTTP 403 alone must not force an overall phishing verdict');
      assert.equal(schema.pageContentAssessment?.status, 'CONTENT_UNAVAILABLE');
      assert.equal(schema.pageContentAssessment?.fullRenderedInspection, false);
      assert.equal(schema.pageAnalysis?.intent?.primary, 'NOT_ASSESSED');
      assert.match(schema.intelligenceSummary?.whatIsThis || '', /HTTP 403/i);
      const connect = schema.liveInspection?.egressObservations?.allowedRequests?.find(item => item.method === 'CONNECT' && item.status === 200);
      assert.ok(connect, 'the target tunnel should be established through the controlled egress proxy');
      assert.ok(connect.targetIp && connect.resolvedIps?.includes(connect.targetIp), 'the proxy should record its pinned DNS destination');
    } else if (Number(schema.liveInspection?.httpStatus) >= 400) {
      assert.equal(schema.accessStatus, 'HTTP_ERROR');
      assert.equal(schema.inspectionStatus, 'HTTP_ERROR_DOCUMENT');
      assert.equal(schema.screenshotStatus, 'CAPTURED');
      assert.equal(schema.pageContentAssessment?.status, 'HTTP_ERROR_DOCUMENT');
      assert.equal(schema.pageContentAssessment?.fullRenderedInspection, false);
      assert.equal(schema.pageAnalysis?.intent?.primary, 'NOT_ASSESSED');
      assert.notEqual(schema.pageContentAssessment?.verdict, 'PHISHING');
    } else {
      assert.equal(schema.accessStatus, 'ACCESSIBLE');
      assert.equal(schema.inspectionStatus, 'CONTENT_INSPECTED');
      assert.equal(schema.pageContentAssessment?.status, 'COMPLETED');
    }
    if (/google\.com/i.test(targetUrl)) assert.equal(schema.pageAnalysis?.intent?.primary, 'SEARCH');
    for (const field of ['whatIsThis', 'whatCanVisitorsDo', 'whatInfoRequested', 'whereCouldItGo', 'networkActivity', 'behaviourMatch', 'suspicionIndicators', 'notInspected']) {
      assert.ok(schema.intelligenceSummary?.[field], `website intelligence summary should populate ${field}`);
    }
    assert.ok(earlyScreenshotReadyMs !== null, 'initial screenshot should be published while live inspection is still running');
    assert.ok(earlyScreenshotReadyMs <= 10000, `initial screenshot must appear within 10s; it appeared after ${earlyScreenshotReadyMs}ms`);
    assert.equal(earlyScreenshotObservedWhileRunning, true, 'the initial screenshot should be available before case finalization');
    console.log(`Mode C diagnostic: ${JSON.stringify({ targetUrl, correlationId: schema.liveInspection?.correlationId,
      browserDiagnostics: schema.liveInspection?.browserDiagnostics,
      httpStatus: schema.liveInspection?.httpStatus, finalUrl: schema.liveInspection?.finalUrl,
      requestHeaders: schema.liveInspection?.requestHeaders,
      responseHeaders: schema.liveInspection?.httpHeaders, responseBodyExcerpt: schema.liveInspection?.responseBodyExcerpt,
      redirectChain: schema.liveInspection?.redirectChain, egressObservations: schema.liveInspection?.egressObservations,
      screenshotCaptured: schema.liveInspection?.screenshotCaptured, screenshotUrl: schema.screenshotArtifactUrl,
      pageIntent: schema.pageAnalysis?.intent?.primary, accessRestriction: schema.httpAnalysis?.accessRestriction })}`);
    assert.equal(schema.screenshotCapture?.captureDelayMs, captureDelayMs);
    assert.ok(schema.screenshotCapture?.countdownStartedAt, 'backend should record the post-render countdown start');
    assert.ok(schema.screenshotCapture?.capturedAt >= schema.screenshotCapture?.countdownEndsAt, 'capture must occur after countdown deadline');
    assert.ok(schema.liveInspection?.modeCTimings?.user_countdown_ms >= Math.max(0, captureDelayMs - 100), `worker timing should include the selected delay: ${JSON.stringify(schema.liveInspection?.modeCTimings)}`);
    assert.ok(schema.liveInspection?.modeCTimings?.screenshot_capture_ms >= 0);
    for (const timing of ['container_start_ms', 'proxy_ready_ms', 'browser_launch_ms', 'navigation_ms',
      'render_readiness_ms', 'user_countdown_ms', 'screenshot_capture_ms', 'screenshot_transfer_ms',
      'ocr_analysis_ms', 'total_investigation_ms']) {
      assert.ok(Number.isFinite(schema.modeCTimings?.[timing]), `case should expose ${timing}: ${JSON.stringify(schema.modeCTimings)}`);
    }
    console.log(`Initial screenshot was available after ${earlyScreenshotReadyMs}ms; backend countdown ran ${schema.liveInspection.modeCTimings.user_countdown_ms}ms after render readiness (configured ${captureDelayMs}ms).`);
    console.log(`Mode C stage timings (ms): ${JSON.stringify(schema.modeCTimings)}`);
    const initialEvidence = schema.evidence.find(item => item.id === schema.initialScreenshotEvidenceId);
    assert.equal(initialEvidence?.data?.artifactUrl, schema.initialScreenshotUrl);
    assert.match(initialEvidence?.data?.sha256 || '', /^[a-f0-9]{64}$/);
    assert.ok(initialEvidence, 'initial screenshot must have an evidence ledger entry');
    assert.equal(schema.screenshotArtifactUrl, `/api/cases/${created.caseId}/screenshot`);
    const evidence = schema.evidence.find(item => item.id === schema.screenshotArtifactEvidenceId);
    assert.equal(evidence?.data?.artifactUrl, schema.screenshotArtifactUrl);
    assert.match(evidence?.data?.sha256 || '', /^[a-f0-9]{64}$/);

    const screenshotResponse = await apiFetch(`${baseUrl}${schema.screenshotArtifactUrl}`);
    assert.equal(screenshotResponse.status, 200);
    assert.match(screenshotResponse.headers.get('content-type') || '', /image\/png/);
    const bytes = Buffer.from(await screenshotResponse.arrayBuffer());
    assert.ok(bytes.length > 1000);
    assert.deepEqual([...bytes.subarray(0, 8)], [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);
    assert.equal(schema.liveInspection?.runtimeSessionActive, true, 'isolated browser should remain available after case results are published');
    const stopSession = await apiFetch(`${baseUrl}/api/cases/${created.caseId}/cancel-live`, { method: 'POST' });
    assert.equal(stopSession.status, 200);
    const stoppedCase = await (await apiFetch(`${baseUrl}/api/cases/${created.caseId}`)).json();
    assert.equal(stoppedCase.status, 'COMPLETED', 'stopping the retained browser session must preserve the finished case');
    assert.equal(stoppedCase.liveInspection?.runtimeSessionActive, false);
  } finally {
    if (cleanupCaseId) {
      try { await apiFetch(`${baseUrl}/api/cases/${cleanupCaseId}/cancel-live`, { method: 'POST' }); } catch {}
    }
    server.kill();
  }
});
