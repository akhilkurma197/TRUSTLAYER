import test from 'node:test';
import assert from 'node:assert/strict';
import { OverallRiskAggregator } from '../core/rules/risk_aggregator.js';
import { buildEvidenceReport } from '../core/evidence_report.js';

const completePage = { status: 'COMPLETED', fullRenderedInspection: true, riskLevel: 'LOW', verdict: null };

test('access denied and incomplete live inspection remain inconclusive', () => {
  const denied = OverallRiskAggregator.aggregate({
    urlAssessment: { ruleScore: 0, classification: 'SAFE' },
    pageContentAssessment: { status: 'CONTENT_UNAVAILABLE', accessStatus: 'BLOCKED_HTTP_403', riskLevel: 'NOT_RUN' },
    inspectionMode: 'ISOLATED_LIVE'
  });
  assert.equal(denied.finalVerdict, 'UNDER_REVIEW');
  assert.equal(denied.verifiedThreat, false);
  assert.equal(denied.verdictBasis, 'ACCESS_RESTRICTED');
  const incomplete = OverallRiskAggregator.aggregate({
    urlAssessment: { ruleScore: 0, classification: 'SAFE' },
    pageContentAssessment: { status: 'NOT_RUN', riskLevel: 'NOT_RUN' },
    inspectionMode: 'ISOLATED_LIVE'
  });
  assert.equal(incomplete.finalVerdict, 'UNDER_REVIEW');
});

test('URL-only and URL model predictions cannot produce a verified safe or threat finding', () => {
  const urlOnly = OverallRiskAggregator.aggregate({ urlAssessment: { ruleScore: 0, classification: 'SAFE' } });
  assert.equal(urlOnly.finalVerdict, 'UNDER_REVIEW');
  assert.equal(urlOnly.verifiedThreat, false);
  const prediction = OverallRiskAggregator.aggregate({
    urlAssessment: { ruleScore: 0, classification: 'SAFE' },
    modelPrediction: 'PHISHING', modelProbability: 0.91,
    pageContentAssessment: { status: 'NOT_RUN', riskLevel: 'NOT_RUN' }
  });
  assert.equal(prediction.finalVerdict, 'UNDER_REVIEW');
  assert.equal(prediction.verdictBasis, 'MODEL_PREDICTION');
  assert.match(prediction.summary, /prediction, not verified page evidence/);
});

test('completed checks with no indicators do not issue a universal SAFE verdict', () => {
  const result = OverallRiskAggregator.aggregate({
    urlAssessment: { ruleScore: 0, classification: 'SAFE' },
    pageContentAssessment: { ...completePage }
  });
  assert.equal(result.finalVerdict, 'NO_THREAT_OBSERVED');
  assert.match(result.summary, /does not establish that the site is safe/);
  assert.equal(result.verifiedThreat, false);
});

test('observed page threat takes precedence over weak benign signals and reports disagreement', () => {
  const result = OverallRiskAggregator.aggregate({
    urlAssessment: { ruleScore: 0, classification: 'SAFE' },
    modelPrediction: 'LEGITIMATE',
    pageContentAssessment: { ...completePage, riskLevel: 'CRITICAL', verdict: 'PHISHING', summary: 'Observed credential exfiltration.' }
  });
  assert.equal(result.finalVerdict, 'PHISHING');
  assert.equal(result.verifiedThreat, true);
  assert.deepEqual(result.conflicts, [
    'URL model predicted LEGITIMATE while completed page inspection observed phishing behavior.',
    'URL rules found no high-risk URL pattern while completed page inspection observed phishing behavior.'
  ]);
});

test('heuristic URL phishing indicators are not marked verified', () => {
  const result = OverallRiskAggregator.aggregate({
    urlAssessment: { ruleScore: 78, classification: 'PHISHING' },
    pageContentAssessment: { status: 'NOT_RUN', riskLevel: 'NOT_RUN' },
    inspectionMode: 'ISOLATED_LIVE'
  });
  assert.equal(result.finalVerdict, 'UNDER_REVIEW');
  assert.equal(result.verdictBasis, 'URL_HEURISTIC');
  assert.equal(result.verifiedThreat, false);
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
  assert.equal(report.categories.phishing.status, 'INDICATORS_ONLY');
});

test('phishing, malware and scam remain separate report categories', () => {
  const report = buildEvidenceReport({ id: 'case-categories', status: 'INCOMPLETE', assessment: {}, evidence: [] }, 1200);
  assert.equal(report.categories.phishing.status, 'NO_CONFIRMED_THREAT');
  assert.equal(report.categories.malware.status, 'NOT_ASSESSED');
  assert.equal(report.categories.scam.status, 'NOT_ASSESSED');
  assert.equal(report.categories.deceptiveDownloads.status, 'NOT_ASSESSED');
  assert.equal(report.categories.piracyCopyright.status, 'NOT_ASSESSED');
});
