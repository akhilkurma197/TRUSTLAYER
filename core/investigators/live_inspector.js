/**
 * Trust Layer — Real Isolated Live Inspector v2.0
 * Mode C: ISOLATED_LIVE inspection orchestrator.
 * 
 * Architecture:
 * 1. Delegates execution to LiveJobController (Control Plane -> Worker boundary).
 * 2. Delegates to a disposable Docker worker with no app secrets.
 * 3. Enforces Controlled Egress Proxy with connection-time DNS pinning.
 * 4. Captures real DOM extraction, redirect hops, network events, and blocked requests.
 */

import { randomUUID } from 'node:crypto';
import { DEFAULT_INTERACTIVE_SESSION_MS } from '../interactive_action.js';
import { globalJobController, JOB_STATUS } from './live_job_controller.js';
import { PageStructureExtractor } from './page_extractor.js';

const BUDGETS = {
  // Leave time for navigation, bounded readiness checks, and screenshot capture.
  timeoutMs: 160000,
  keepAliveMs: DEFAULT_INTERACTIVE_SESSION_MS,
  maxRedirects: 5,
  maxResponseBytes: 500000
};

export class LiveInspector {
  static startInteractiveSession(caseId) {
    return globalJobController.startInteractiveSession(caseId);
  }

  /**
   * Perform an isolated live inspection of the given URL.
   * @param {string} url
   * @param {object} options — { timeoutMs, caseId, skipWorkerProcess }
   * @param {AbortSignal|null} abortSignal
   * @returns {Promise<object>}
   */
  static async inspect(url, options = {}, abortSignal = null) {
    const inspectionId = randomUUID();
    const startTime = Date.now();
    const timeoutMs = options.timeoutMs || BUDGETS.timeoutMs;
    const caseId = options.caseId || `case-${Date.now()}`;
    const warnings = [];
    const errors = [];

    const defaultLimitations = [
      'Headless browser runs in an isolated ephemeral execution worker',
      'Observation mode active: All mutating requests (POST, PUT, DELETE) are strictly blocked',
      'No user credentials, cookies, or session tokens are transferred to or from the target',
      'Downloads, popups, permissions, and background sync are disabled by policy',
      'Outbound traffic strictly constrained through Controlled Egress Proxy with DNS pinning'
    ];

    // ── Pre-flight abort check ──
    if (abortSignal?.aborted) {
      return {
        status: 'CANCELLED',
        mode: 'ISOLATED_LIVE',
        isolationReport: {
          sandboxType: 'RUNTIME_NOT_VERIFIED',
          workerPid: process.pid,
          inspectionId
        },
        ssrfResult: { allowed: false, blockedReason: 'Cancelled by operator before start', resolvedIps: [] },
        finalUrl: url,
        redirectChain: [],
        httpStatus: null,
        httpHeaders: {},
        contentType: '',
        responseSizeBytes: 0,
        pageExtraction: null,
        networkEvents: [],
        blockedRequests: [],
        timingMs: 0,
        warnings,
        errors: ['Inspection cancelled before start'],
        limitations: defaultLimitations,
        evidenceProvenance: 'OBSERVED_LIVE'
      };
    }

    // ── Step 1: Pre-connection SSRF Check ──
    const ssrfResult = await globalJobController.validateDestination(url, options);
    if (!ssrfResult.allowed) {
      return {
        status: 'BLOCKED',
        mode: 'ISOLATED_LIVE',
        isolationReport: {
          sandboxType: 'RUNTIME_NOT_VERIFIED',
          workerPid: process.pid,
          inspectionId,
          ssrfProtection: 'PRE_CONNECTION_DNS_VALIDATION'
        },
        ssrfResult,
        finalUrl: url,
        redirectChain: [],
        httpStatus: null,
        httpHeaders: {},
        contentType: '',
        responseSizeBytes: 0,
        pageExtraction: null,
        networkEvents: [],
        blockedRequests: [],
        timingMs: Date.now() - startTime,
        warnings,
        errors: [`SSRF Guard blocked target: ${ssrfResult.blockedReason}`],
        limitations: defaultLimitations,
        evidenceProvenance: 'OBSERVED_LIVE'
      };
    }

    // ── Step 2: Execute inspection through LiveJobController ──
    let jobRecord;
    try {
      // Connect abort signal to controller job cancellation
      if (abortSignal) {
        abortSignal.addEventListener('abort', () => {
          if (jobRecord?.jobId) {
            globalJobController.cancelJob(jobRecord.jobId);
          }
        }, { once: true });
      }

      jobRecord = await globalJobController.submitJob(url, caseId, {
        timeoutMs,
        keepAliveMs: options.keepAliveMs ?? BUDGETS.keepAliveMs,
        abortSignal,
        maxRedirects: BUDGETS.maxRedirects,
        maxBytes: BUDGETS.maxResponseBytes,
        ...options
      }, ssrfResult);
      if (abortSignal?.aborted && jobRecord.jobId) {
        globalJobController.cancelJob(jobRecord.jobId);
      }
    } catch (err) {
      return {
        status: 'FAILED',
        mode: 'ISOLATED_LIVE',
        isolationReport: {
          sandboxType: 'RUNTIME_NOT_VERIFIED',
          workerPid: process.pid,
          inspectionId
        },
        ssrfResult,
        finalUrl: url,
        redirectChain: [],
        httpStatus: null,
        httpHeaders: {},
        contentType: '',
        responseSizeBytes: 0,
        pageExtraction: null,
        networkEvents: [],
        blockedRequests: [],
        timingMs: Date.now() - startTime,
        warnings,
        errors: [`Job execution failed: ${err.message}`],
        limitations: defaultLimitations,
        evidenceProvenance: 'OBSERVED_LIVE'
      };
    }

    const workerResult = jobRecord.result || {};
    const finalStatus = jobRecord.status === JOB_STATUS.COMPLETED ? 'SUCCESS'
      : (jobRecord.status === JOB_STATUS.PARTIAL ? 'PARTIAL'
      : (jobRecord.status === JOB_STATUS.CANCELLED ? 'CANCELLED'
      : (jobRecord.status === JOB_STATUS.TIMED_OUT ? 'TIMEOUT'
      : (jobRecord.status === JOB_STATUS.BLOCKED ? 'BLOCKED'
      : (jobRecord.status === JOB_STATUS.HTTP_ERROR ? 'HTTP_ERROR'
      : (jobRecord.status === JOB_STATUS.BUSY ? 'BUSY' : 'FAILED'))))));

    if (workerResult.warnings) warnings.push(...workerResult.warnings);
    if (workerResult.errors) errors.push(...workerResult.errors);
    if (jobRecord.error) errors.push(jobRecord.error);

    const limitations = workerResult.limitations && workerResult.limitations.length > 0
      ? workerResult.limitations
      : defaultLimitations;

    return {
      status: finalStatus,
      mode: 'ISOLATED_LIVE',
      isolationReport: workerResult.isolationReport || {
        sandboxType: 'RUNTIME_NOT_VERIFIED',
        playwrightAvailable: false,
        credentialsIsolated: true,
        cookiesIsolated: true,
        downloadsBlocked: true,
        storageEphemeral: true,
        proxyEnforced: true,
        workerPid: process.pid,
        inspectionId
      },
      ssrfResult,
      finalUrl: workerResult.finalUrl || url,
      redirectChain: workerResult.redirectChain || [],
      httpStatus: workerResult.httpStatus || null,
      httpHeaders: workerResult.responseHeaders || workerResult.headers || {},
      requestHeaders: workerResult.requestHeaders || {},
      responseBodyExcerpt: workerResult.responseBodyExcerpt || '',
      responseDiagnostics: workerResult.responseDiagnostics || null,
      browserDiagnostics: workerResult.browserDiagnostics || null,
      correlationId: workerResult.correlationId || jobRecord.jobId,
      egressObservations: workerResult.egressObservations || null,
      contentType: workerResult.contentType || '',
      responseSizeBytes: workerResult.pageExtraction?.htmlBytes || 0,
      renderStatus: workerResult.renderStatus || workerResult.pageExtraction?.renderStatus || 'RENDER_PARTIAL',
      readinessDiagnostics: workerResult.readinessDiagnostics || null,
      screenshotCapture: workerResult.screenshotCapture || null,
      screenshotCaptured: workerResult.screenshotCaptured === true,
      modeCTimings: workerResult.modeCTimings || {},
      runtimeSessionActive: workerResult.runtimeSessionActive === true,
      runtimeSessionUntil: workerResult.runtimeSessionUntil || null,
      pageExtraction: workerResult.pageExtraction || null,
      networkEvents: workerResult.networkEvents || [],
      blockedRequests: workerResult.blockedRequests || [],
      timingMs: jobRecord.durationMs || (Date.now() - startTime),
      warnings,
      errors,
      limitations,
      evidenceProvenance: 'OBSERVED_LIVE'
    };
  }
}
