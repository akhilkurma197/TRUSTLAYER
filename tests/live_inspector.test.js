/**
 * Trust Layer — Mode C (Isolated Live Inspection) Test Suite
 * Validates SSRFGuard, Controlled Egress Proxy, LiveJobController,
 * 8-Question Intelligence Summary, and Case Mode Routing.
 */

import { describe, it } from 'node:test';
import assert from 'node:assert';
import http from 'node:http';
import dns from 'node:dns/promises';
import { SSRFGuard } from '../core/investigators/ssrf_guard.js';
import { ControlledEgressProxy } from '../core/investigators/egress_proxy.js';
import { redactSensitiveUrl } from '../core/investigators/url_redaction.js';
import { classifyWorkerResultStatus } from '../core/investigators/worker_result_status.js';
import { LiveJobController, JOB_STATUS } from '../core/investigators/live_job_controller.js';
import { IntelligenceSummaryBuilder } from '../core/investigators/intelligence_summary.js';
import { InvestigationEngine, INSPECTION_MODE } from '../core/investigation_engine.js';

describe('SSRFGuard — Destination Validation & IP Pinning', () => {
  it('blocks IPv4 loopback (127.0.0.1)', async () => {
    const res = await SSRFGuard.validateAndResolve('http://127.0.0.1/admin');
    assert.strictEqual(res.allowed, false);
    assert.match(res.blockedReason, /Loopback/i);
  });

  it('blocks alternative decimal integer IP encoding (2130706433 = 127.0.0.1)', async () => {
    const res = await SSRFGuard.validateAndResolve('http://2130706433/');
    assert.strictEqual(res.allowed, false);
    assert.match(res.blockedReason, /Loopback/i);
  });

  it('blocks octal IP encoding (0177.0.0.1 = 127.0.0.1)', async () => {
    const res = await SSRFGuard.validateAndResolve('http://0177.0.0.1/');
    assert.strictEqual(res.allowed, false);
    assert.match(res.blockedReason, /Loopback/i);
  });

  it('blocks private class A range (10.0.0.0/8)', async () => {
    const res = await SSRFGuard.validateAndResolve('http://10.0.0.1/internal');
    assert.strictEqual(res.allowed, false);
    assert.match(res.blockedReason, /Private/i);
  });

  it('blocks private class B range (172.16.0.0/12)', async () => {
    const res = await SSRFGuard.validateAndResolve('http://172.16.50.1/');
    assert.strictEqual(res.allowed, false);
    assert.match(res.blockedReason, /Private/i);
  });

  it('blocks private class C range (192.168.0.0/16)', async () => {
    const res = await SSRFGuard.validateAndResolve('http://192.168.1.1/router');
    assert.strictEqual(res.allowed, false);
    assert.match(res.blockedReason, /Private/i);
  });

  it('blocks cloud metadata endpoint (169.254.169.254)', async () => {
    const res = await SSRFGuard.validateAndResolve('http://169.254.169.254/latest/meta-data/');
    assert.strictEqual(res.allowed, false);
    assert.match(res.blockedReason, /Link-local|metadata/i);
  });

  it('blocks IPv6 loopback ([::1])', async () => {
    const res = await SSRFGuard.validateAndResolve('http://[::1]/');
    assert.strictEqual(res.allowed, false);
    assert.match(res.blockedReason, /Loopback/i);
  });

  it('blocks IPv4-mapped IPv6 loopback ([::ffff:127.0.0.1])', async () => {
    const res = await SSRFGuard.validateAndResolve('http://[::ffff:127.0.0.1]/');
    assert.strictEqual(res.allowed, false);
    assert.match(res.blockedReason, /IPv4-mapped/i);
  });

  it('blocks IPv4-mapped IPv6 private address ([::ffff:10.0.0.1])', async () => {
    const res = await SSRFGuard.validateAndResolve('http://[::ffff:10.0.0.1]/');
    assert.strictEqual(res.allowed, false);
    assert.match(res.blockedReason, /IPv4-mapped/i);
  });

  it('blocks IPv4 documentation and reserved destinations', async () => {
    for (const address of ['192.0.2.10', '192.88.99.2', '198.51.100.10', '203.0.113.10', '198.18.0.1', '240.0.0.1', '192.0.0.9']) {
      const res = await SSRFGuard.validateAndResolve(`http://${address}/`);
      assert.strictEqual(res.allowed, false, `${address} should not be treated as a public destination`);
    }
  });

  it('blocks IPv6 documentation and non-global-unicast destinations', async () => {
    for (const address of ['2001:db8::1', '3fff::1', 'fe80::1']) {
      const res = await SSRFGuard.validateAndResolve(`http://[${address}]/`);
      assert.strictEqual(res.allowed, false, `${address} should not be treated as a public destination`);
    }
  });

  it('blocks IPv6 unique-local, link-local, multicast, and mapped private ranges', async () => {
    for (const address of ['fc00::1', 'fd12:3456::1', 'fe80::1', 'ff02::1', '::ffff:192.168.1.1']) {
      const result = await SSRFGuard.validateAndResolve(`http://[${address}]/`);
      assert.equal(result.allowed, false, `${address} must be blocked`);
    }
  });

  it('blocks non-canonical IPv4 literals normalized by the URL parser', async () => {
    for (const address of ['http://127.1/', 'http://0x7f000001/', 'http://0177.0.0.1/', 'http://2130706433/']) {
      const result = await SSRFGuard.validateAndResolve(address);
      assert.equal(result.allowed, false, `${address} must be blocked`);
    }
  });

  it('rejects hostnames with mixed public and prohibited DNS answers', async () => {
    const originalResolve4 = dns.resolve4;
    const originalResolve6 = dns.resolve6;
    dns.resolve4 = async () => ['93.184.216.34', '127.0.0.1'];
    dns.resolve6 = async () => { throw Object.assign(new Error('no AAAA'), { code: 'ENODATA' }); };
    try {
      const result = await SSRFGuard.validateAndResolve('https://mixed-answer.fixture/');
      assert.equal(result.allowed, false);
      assert.match(result.blockedReason, /resolves to blocked IP 127\.0\.0\.1/i);
      assert.deepEqual(result.resolvedIps, ['93.184.216.34', '127.0.0.1']);
    } finally {
      dns.resolve4 = originalResolve4;
      dns.resolve6 = originalResolve6;
    }
  });

  it('blocks non-HTTP protocols (ftp:)', async () => {
    const res = await SSRFGuard.validateAndResolve('ftp://example.com/file');
    assert.strictEqual(res.allowed, false);
    assert.match(res.blockedReason, /Disallowed URL scheme/i);
  });

  it('blocks embedded credentials in target URL', async () => {
    const res = await SSRFGuard.validateAndResolve('http://admin:secret@example.com/');
    assert.strictEqual(res.allowed, false);
    assert.match(res.blockedReason, /Embedded credentials/i);
  });

  it('permits valid public HTTP URLs with DNS skip in test mode', async () => {
    const res = await SSRFGuard.validateAndResolve('https://example.com/path', { skipDns: true });
    assert.strictEqual(res.allowed, true);
    assert.strictEqual(res.blockedReason, null);
  });
});

describe('Controlled Egress Proxy — Network Boundaries & Method Enforcement', () => {
  it('redacts URL credentials and sensitive path/query data, including relative redirects', () => {
    assert.equal(redactSensitiveUrl('https://analyst:secret@example.com/account/alice?token=private#fragment'),
      'https://example.com/[path-redacted]');
    assert.equal(redactSensitiveUrl('/oauth/callback?code=private', 'https://example.com/start'),
      'https://example.com/[path-redacted]');
  });

  it('starts on an ephemeral loopback port and stops cleanly', async () => {
    const proxy = new ControlledEgressProxy();
    const info = await proxy.start();
    assert.ok(info.port > 0);
    assert.strictEqual(info.host, '127.0.0.1');
    assert.match(info.proxyUrl, /^http:\/\/127\.0\.0\.1:\d+$/);
    await proxy.stop();
  });

  it('blocks mutating HTTP methods (POST) in observation mode via proxy handler', async () => {
    const proxy = new ControlledEgressProxy();
    let writtenStatus = null;
    let writtenBody = '';

    const mockReq = {
      method: 'POST',
      url: 'http://example.com/api/submit',
      headers: { host: 'example.com' }
    };

    const mockRes = {
      writeHead: (status) => { writtenStatus = status; },
      end: (data) => { writtenBody = data; }
    };

    await proxy._handleHttpRequest(mockReq, mockRes);

    assert.strictEqual(writtenStatus, 405);
    assert.strictEqual(proxy.blockedRequests.length, 1);
    assert.strictEqual(proxy.blockedRequests[0].type, 'MUTATING_REQUEST_BLOCKED');
  });

  it('redacts credentials, paths, and query values from blocked-request logs', async () => {
    const proxy = new ControlledEgressProxy();
    const mockReq = {
      method: 'POST',
      url: 'http://analyst:secret@example.com/account/alice?token=private&email=a%40b.test',
      headers: { host: 'example.com' }
    };
    const mockRes = { writeHead() {}, end() {} };

    await proxy._handleHttpRequest(mockReq, mockRes);

    const record = proxy.blockedRequests[0];
    assert.match(record.url, /^http:\/\/example\.com\//);
    assert.doesNotMatch(JSON.stringify(record), /secret|alice|private|a%40b\.test/i);
  });

  it('rejects malformed CONNECT authorities before opening an upstream socket', async () => {
    const proxy = new ControlledEgressProxy();
    for (const authority of ['example.com:not-a-port', 'example.com:443/private?token=secret']) {
      let response = '';
      let destroyed = false;
      const socket = {
        write: value => { response += value; },
        destroy: () => { destroyed = true; }
      };

      await proxy._handleHttpsConnect({ url: authority, headers: {} }, socket, Buffer.alloc(0));

      assert.match(response, /^HTTP\/1\.1 400 Bad Request/);
      assert.strictEqual(destroyed, true);
    }
    assert.equal(proxy.blockedRequests.length, 2);
    assert.ok(proxy.blockedRequests.every(item => item.type === 'MALFORMED_CONNECT_TARGET'));
    assert.doesNotMatch(JSON.stringify(proxy.blockedRequests), /not-a-port|private|secret/i);
  });

  it('blocks requests to disallowed ports (e.g. port 22 SSH) via proxy handler', async () => {
    const proxy = new ControlledEgressProxy({ allowedPorts: [80, 443] });
    let writtenStatus = null;
    let writtenBody = '';

    const mockReq = {
      method: 'GET',
      url: 'http://example.com:22/ssh-banner',
      headers: { host: 'example.com:22' }
    };

    const mockRes = {
      writeHead: (status) => { writtenStatus = status; },
      end: (data) => { writtenBody = data; }
    };

    await proxy._handleHttpRequest(mockReq, mockRes);

    assert.strictEqual(writtenStatus, 403);
    assert.ok(proxy.blockedRequests.some(b => b.type === 'PORT_DISALLOWED'));
  });
});

describe('LiveJobController — Worker Supervisor & Queue Boundary', () => {
  it('rejects forbidden SSRF destinations immediately without spawning child process', async () => {
    const controller = new LiveJobController();
    const job = await controller.submitJob('http://192.168.1.1/banking', 'case-test-1');
    assert.strictEqual(job.status, JOB_STATUS.BLOCKED);
    assert.match(job.blockedReason, /Private network/i);
    assert.strictEqual(controller.activeJobs.size, 0);
  });

  it('handles cancellation of active jobs', async () => {
    const controller = new LiveJobController();
    const fakeJobId = 'job-fake-cancel';
    let cancelled = false;

    controller.activeJobs.set(fakeJobId, {
      cancel: () => { cancelled = true; }
    });

    const didCancel = controller.cancelJob(fakeJobId);
    assert.strictEqual(didCancel, true);
    assert.strictEqual(cancelled, true);
  });
});

describe('IntelligenceSummaryBuilder — 8 Core Questions Synthesizer', () => {
  it('keeps HTTP access denials out of the successful inspection status', () => {
    assert.equal(classifyWorkerResultStatus(200, 20), 'SUCCESS');
    assert.equal(classifyWorkerResultStatus(401, 20), 'BLOCKED');
    assert.equal(classifyWorkerResultStatus(403, 20), 'BLOCKED');
    assert.equal(classifyWorkerResultStatus(404, 20), 'HTTP_ERROR');
    assert.equal(classifyWorkerResultStatus(503, 20), 'HTTP_ERROR');
    assert.equal(classifyWorkerResultStatus(null, 20), 'PARTIAL');
    assert.equal(classifyWorkerResultStatus(null, 0), 'FAILED');
  });

  it('truthfully reports zero live network connection in URL_ONLY mode', () => {
    const mockSchema = {
      target: 'http://example.com',
      urlAnalysis: { hostname: 'example.com' },
      identityAnalysis: { claimedEntity: 'Example Inc', observedEntity: 'example.com', identityContinuity: 'MATCH' },
      pageAnalysis: { status: 'NOT_RUN', title: null, forms: [], buttons: [] },
      networkAnalysis: { requests: [] },
      trustBreakpoints: [],
      assessment: { riskLevel: 'LOW', headline: 'URL Analysis Completed', limitations: ['No HTTP connection'] }
    };

    const summary = IntelligenceSummaryBuilder.build(mockSchema, 'URL_ONLY');
    assert.strictEqual(summary.mode, 'URL_ONLY');
    assert.match(summary.whatIsThis, /URL analysis only/i);
    assert.match(summary.whatCanVisitorsDo, /No live page was inspected/i);
    assert.match(summary.whatInfoRequested, /No page was fetched/i);
    assert.match(summary.whereCouldItGo, /No live page was fetched/i);
    assert.match(summary.networkActivity, /No network requests were made/i);
    assert.ok(summary.notInspected.some(l => l.includes('No live network connection')));
  });

  it('synthesizes real extracted DOM evidence in ISOLATED_LIVE mode', () => {
    const mockLiveSchema = {
      target: 'http://collector-portal.xyz/login',
      urlAnalysis: { hostname: 'collector-portal.xyz' },
      identityAnalysis: { claimedEntity: 'PayPal', observedEntity: 'collector-portal.xyz', identityContinuity: 'MISMATCH' },
      pageAnalysis: {
        status: 'COMPLETED',
        title: 'PayPal — Security Verification',
        buttons: ['Submit Verification', 'Cancel'],
        forms: [
          {
            action: 'https://exfiltrate-data.xyz/submit',
            method: 'POST',
            isExternal: true,
            hasPassword: true,
            hasSensitive: true,
            inputs: [
              { name: 'email', type: 'text', isSensitive: false },
              { name: 'password', type: 'password', isSensitive: true },
              { name: 'csrf_token', type: 'hidden', isSensitive: false }
            ]
          }
        ],
        intent: {
          primary: 'LOGIN',
          purposeConsistency: 'MISMATCH',
          purposeMismatch: true,
          mismatchReason: 'Claimed PayPal official portal but hosted on unrelated apex domain',
          requestedActions: ['AUTHENTICATE'],
          requestedData: ['PASSWORD']
        }
      },
      networkAnalysis: {
        requests: [
          { method: 'GET', url: 'http://collector-portal.xyz/login', status: 200, type: 'document' }
        ]
      },
      trustBreakpoints: [
        { type: 'IDENTITY_DISCONTINUITY', description: 'Domain claims PayPal but resolves to collector-portal.xyz' }
      ],
      assessment: { riskLevel: 'CRITICAL', headline: 'High-Risk Impersonation Confirmed' }
    };

    const summary = IntelligenceSummaryBuilder.build(mockLiveSchema, 'ISOLATED_LIVE');
    assert.strictEqual(summary.mode, 'ISOLATED_LIVE');
    assert.match(summary.whatIsThis, /PayPal — Security Verification/);
    assert.match(summary.whatCanVisitorsDo, /Submit Verification/);
    assert.match(summary.whatInfoRequested, /Visible user-input fields/i);
    assert.match(summary.whatInfoRequested, /password/i);
    assert.match(summary.whereCouldItGo, /https:\/\/exfiltrate-data\.xyz\/submit/);
    assert.match(summary.whereCouldItGo, /EXTERNAL HOST/i);
    assert.match(summary.behaviourMatch, /MISMATCH/);
    assert.ok(summary.suspicionIndicators.length > 0);
  });

  it('reports HTTP 403 as an access restriction without attributing the error page to the website', () => {
    const summary = IntelligenceSummaryBuilder.build({
      accessStatus: 'BLOCKED_HTTP_403',
      target: 'https://rvce.edu.in/',
      httpAnalysis: { statusCode: 403, finalUrl: 'https://rvce.edu.in/' },
      liveInspection: { accessStatus: 'BLOCKED_HTTP_403', finalUrl: 'https://rvce.edu.in/' },
      pageAnalysis: {
        title: '403 Forbidden', buttons: ['Retry'], forms: [{ action: 'https://unrelated.invalid', isExternal: true }],
        intent: { primary: 'LOGIN', requestedData: ['PASSWORD'] }
      },
      assessment: { limitations: [] }, networkAnalysis: { requests: [] }, trustBreakpoints: [], evidence: []
    }, 'ISOLATED_LIVE');
    assert.match(summary.whatIsThis, /HTTP 403/i);
    assert.match(summary.whatIsThis, /could not be assessed/i);
    assert.match(summary.whatInfoRequested, /Not assessed/i);
    assert.match(summary.whereCouldItGo, /Not assessed/i);
    assert.equal(summary.suspicionIndicators.length, 0);
    assert.ok(summary.notInspected.some(item => /HTTP 403/i.test(item)));
  });
});

describe('InvestigationEngine — Mode C Integration & Case Schema', () => {
  it('creates cases with configurable inspectionMode (default URL_ONLY)', () => {
    const caseA = InvestigationEngine.createCase('https://example.com');
    assert.strictEqual(caseA.schema.inspectionMode, 'URL_ONLY');

    const caseC = InvestigationEngine.createCase('https://example.com', 'URL', INSPECTION_MODE.ISOLATED_LIVE);
    assert.strictEqual(caseC.schema.inspectionMode, 'ISOLATED_LIVE');
    assert.ok(caseC._abortController);
    assert.ok(caseC._abortSignal);
  });

  it('runs URL_ONLY mode deterministically on controlled vector and creates 8-question intelligenceSummary', async () => {
    const icase = InvestigationEngine.createCase('http://paypal-security-update.top/account/verify', 'URL', 'URL_ONLY');
    await InvestigationEngine.investigate(icase);

    assert.ok(icase.schema.intelligenceSummary);
    assert.strictEqual(icase.schema.intelligenceSummary.mode, 'URL_ONLY');
    assert.ok(icase.schema.intelligenceSummary.whatIsThis);
    assert.ok(icase.schema.intelligenceSummary.whatCanVisitorsDo);
    assert.ok(icase.schema.intelligenceSummary.whatInfoRequested);
    assert.ok(icase.schema.intelligenceSummary.whereCouldItGo);
    assert.ok(icase.schema.intelligenceSummary.networkActivity);
    assert.ok(icase.schema.intelligenceSummary.behaviourMatch);
    assert.ok(icase.schema.intelligenceSummary.overallText.includes('TRUST LAYER — WEBSITE INTELLIGENCE SUMMARY'));
  });
});
