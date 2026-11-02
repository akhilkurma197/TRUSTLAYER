const LIMITATIONS_BY_CATEGORY = Object.freeze({
  phishing: 'A low-signal result is not proof that the destination is safe.',
  malware: 'Malware scanning is not implemented; malware status is not assessed.',
  scam: 'Scam verification is not implemented; scam status is not assessed.',
  deceptive_downloads: 'Download behavior is not executed or classified by this report.',
  piracy_copyright: 'Piracy and copyright status are outside this investigation.'
});

function scopeFor(schema, overall) {
  if (overall?.verdictBasis === 'CONTENT_INDICATORS') return 'RENDERED_PAGE_INDICATORS';
  if (overall?.verdictBasis === 'URL_HEURISTIC') return 'URL_STRUCTURE_HEURISTIC';
  if (overall?.verdictBasis === 'REDIRECT_HEURISTIC') return 'REDIRECT_TRACE_HEURISTIC';
  if (overall?.verdictBasis === 'MODEL_PREDICTION') return 'URL_MODEL_PREDICTION';
  if (schema?.accessStatus === 'BLOCKED_HTTP_403' || schema?.pageContentAssessment?.status === 'CONTENT_UNAVAILABLE') return 'PAGE_CONTENT_UNAVAILABLE';
  if (schema?.pageContentAssessment?.fullRenderedInspection === true) return 'RENDERED_PAGE';
  if (schema?.inspectionMode === 'MODE_B') return 'REDIRECT_TRACE';
  return 'URL_ONLY';
}

/** Build a bounded report from one completed case schema without treating missing checks as clean. */
export function buildEvidenceReport(schema, generatedAt = Date.now()) {
  const evidence = Array.isArray(schema?.evidence) ? schema.evidence : [];
  const assessment = schema?.assessment || {};
  const overall = schema?.overallAssessment || {};
  const model = schema?.modelResult || {};
  const scope = scopeFor(schema, overall);
  const modeCCompleted = schema?.pageContentAssessment?.fullRenderedInspection === true &&
    schema?.pageContentAssessment?.status === 'COMPLETED';
  const accessDenied = schema?.accessStatus === 'BLOCKED_HTTP_403' || schema?.httpAnalysis?.statusCode === 403;
  const incomplete = ['INCOMPLETE', 'FAILED', 'BLOCKED'].includes(schema?.status) ||
    schema?.assessment?.verificationState === 'INVESTIGATION_INCOMPLETE' || accessDenied;

  const evidenceItems = evidence.slice(0, 256).map(item => {
    const observedAt = Number.isFinite(item.data?.observedAt) ? item.data.observedAt : item.ts;
    return {
      id: String(item.id || '').slice(0, 160),
      source: String(item.type || 'UNKNOWN').slice(0, 40),
      category: String(item.category || 'unknown').slice(0, 40),
      title: String(item.title || 'Evidence recorded').slice(0, 240),
      observedAt: Number.isFinite(observedAt) ? observedAt : null,
      freshness: !Number.isFinite(observedAt) || observedAt < 0 || observedAt > generatedAt ? 'TIME_INVALID'
        : (Number.isFinite(schema?.createdAt) && observedAt < schema.createdAt ? 'STALE' : 'CURRENT'),
      confidence: item.type === 'MODEL' && Number.isFinite(item.data?.probabilityPhishing)
        ? item.data.probabilityPhishing : null
    };
  });
  const hasCurrentObservedPageEvidence = evidenceItems.some(item => item.freshness === 'CURRENT' && item.source === 'OBSERVED' &&
    ['page', 'network', 'breakpoint'].includes(item.category));
  const verifiedThreat = overall.verifiedThreat === true && modeCCompleted && hasCurrentObservedPageEvidence;
  const reasons = [];
  const contentFindingReasons = overall.verdictBasis === 'CONTENT_INDICATORS'
    ? (Array.isArray(overall.findings) ? overall.findings.filter(item => item?.kind === 'HEURISTIC' && item?.description)
      .map(item => item.description) : []) : [];
  const reasonText = contentFindingReasons.length ? contentFindingReasons
    : (Array.isArray(overall.reasons) && overall.reasons.length
      ? overall.reasons : (Array.isArray(assessment.reasons) ? assessment.reasons : []));
  for (const reason of reasonText.slice(0, 24)) {
    const finding = (Array.isArray(overall.findings) ? overall.findings : []).find(item =>
      item?.description === reason || item?.code === reason);
    let supportingEvidence = evidenceItems.filter(item => {
      const original = evidence.find(entry => entry.id === item.id);
      return item.freshness === 'CURRENT' && original && (String(original.detail || '').includes(String(reason)) || String(original.title || '').includes(String(reason)));
    }).map(item => item.id);
    const heuristic = ['URL_HEURISTIC', 'REDIRECT_HEURISTIC'].includes(overall.verdictBasis) || /rule|heuristic|indicator/i.test(String(reason));
    const modelPrediction = /model predicted/i.test(String(reason)) || overall.verdictBasis === 'MODEL_PREDICTION';
    if (!supportingEvidence.length && overall.verdictBasis === 'URL_HEURISTIC') supportingEvidence = evidenceItems.filter(item => item.freshness === 'CURRENT' && item.category === 'url').map(item => item.id);
    if (!supportingEvidence.length && overall.verdictBasis === 'REDIRECT_HEURISTIC') supportingEvidence = evidenceItems.filter(item => item.freshness === 'CURRENT' && ['http', 'redirect'].includes(item.category)).map(item => item.id);
    if (!supportingEvidence.length && modelPrediction) supportingEvidence = evidenceItems.filter(item => item.freshness === 'CURRENT' && item.source === 'MODEL').map(item => item.id);
    if (!supportingEvidence.length && finding?.evidenceRefs?.length) {
      supportingEvidence = finding.evidenceRefs.filter(id => evidenceItems.some(item => item.id === id && item.freshness === 'CURRENT'));
    }
    if (!supportingEvidence.length && finding?.evidenceId && evidenceItems.some(item => item.id === finding.evidenceId && item.freshness === 'CURRENT')) {
      supportingEvidence = [finding.evidenceId];
    }
    if (finding?.evidenceRefs?.length) {
      supportingEvidence = [...new Set([...supportingEvidence, ...finding.evidenceRefs.filter(id =>
        evidenceItems.some(item => item.id === id && item.freshness === 'CURRENT'))])];
    }
    if (!supportingEvidence.length && overall.verdictBasis === 'CONTENT_INDICATORS') {
      supportingEvidence = evidenceItems.filter(item => item.freshness === 'CURRENT' && item.source === 'INFERRED' && item.category === 'page').map(item => item.id);
    }
    if (!supportingEvidence.length && overall.verdictBasis === 'OBSERVED_PAGE_BEHAVIOR') {
      supportingEvidence = evidenceItems.filter(item => item.freshness === 'CURRENT' && item.source === 'OBSERVED' && ['page', 'network', 'breakpoint'].includes(item.category)).map(item => item.id);
    }
    reasons.push({
      text: String(reason).slice(0, 600),
      kind: finding?.kind || (modelPrediction ? 'MODEL_PREDICTION' : (heuristic || overall.verdictBasis === 'CONTENT_INDICATORS' ? 'HEURISTIC' : (supportingEvidence.length ? 'EVIDENCE_BACKED' : 'DERIVED'))),
      evidenceRefs: supportingEvidence,
      reasonCode: finding?.code || null,
      reasonCodes: finding?.code ? [finding.code] : (Array.isArray(overall.reasonCodes) ? overall.reasonCodes.slice(0, 12) : []),
      source: finding?.source || (overall.verdictBasis === 'CONTENT_INDICATORS' ? 'Rendered-page indicator analysis'
        : (modelPrediction ? 'URL model' : (overall.verdictBasis === 'REDIRECT_HEURISTIC' ? 'Redirect observations' : (heuristic ? 'URL rules' : (supportingEvidence.length ? 'Investigation evidence ledger' : 'Verdict aggregation'))))),
      observedAt: finding?.observedAt ?? null,
      confidenceLevel: finding?.confidenceLevel || null
    });
  }
  if (!reasons.length && evidenceItems.length) {
    reasons.push({ text: 'Evidence was collected, but no final assessment reason was recorded.', kind: 'EVIDENCE_BACKED', evidenceRefs: evidenceItems.slice(0, 8).map(item => item.id), source: 'Investigation evidence ledger' });
  }

  const reportOutcome = verifiedThreat ? 'MALICIOUS'
    : (overall.outcome === 'SUSPICIOUS' || overall.finalVerdict === 'PHISHING' ? 'SUSPICIOUS'
      : (overall.outcome === 'NO_THREAT_DETECTED' && modeCCompleted ? 'NO_THREAT_DETECTED' : 'UNVERIFIED'));

  const limitations = [...new Set([
    ...(Array.isArray(assessment.limitations) ? assessment.limitations : []),
    ...(evidenceItems.some(item => item.freshness !== 'CURRENT') ? ['Some evidence has a missing, invalid, or pre-investigation timestamp and is not treated as current support.'] : []),
    ...(accessDenied ? ['HTTP 403 denied access; the response document does not establish the target page content or intent.'] : []),
    ...(!modeCCompleted ? ['Rendered page behavior was not fully inspected.'] : []),
    LIMITATIONS_BY_CATEGORY.phishing,
    LIMITATIONS_BY_CATEGORY.malware,
    LIMITATIONS_BY_CATEGORY.scam,
    LIMITATIONS_BY_CATEGORY.deceptive_downloads,
    LIMITATIONS_BY_CATEGORY.piracy_copyright
  ])].slice(0, 24);

  let recommendation = 'Review the evidence and verify important claims through an independent trusted channel.';
  if (accessDenied || incomplete) recommendation = 'Treat the result as inconclusive; retry only through an authorized inspection path or verify the destination independently.';
  else if (['URL_HEURISTIC', 'REDIRECT_HEURISTIC', 'MODEL_PREDICTION'].includes(overall.verdictBasis)) recommendation = 'Treat this as an indicator, not a confirmed page verdict; do not enter sensitive information until independently verified.';
  else if (verifiedThreat) recommendation = 'Avoid interacting with the page and escalate the evidence for security review.';

  return {
    version: 1,
    generatedAt,
    investigationId: String(schema?.id || ''),
    status: String(schema?.status || 'UNKNOWN'),
    verdict: {
      value: String(overall.finalVerdict || assessment.verdict || 'INCONCLUSIVE'),
      outcome: reportOutcome,
      legacyValue: String(overall.finalVerdict || assessment.verdict || 'INCONCLUSIVE'),
      headline: String(overall.headline || assessment.headline || 'Investigation incomplete'),
      scope,
      basis: String(overall.verdictBasis || 'UNAVAILABLE'),
      verifiedThreat,
      riskLevel: String(overall.finalRiskLevel || assessment.riskLevel || 'UNKNOWN'),
      confidenceLevel: overall.confidenceLevel || null,
      modelPrediction: model.prediction || null,
      modelProbability: Number.isFinite(model.probabilityPhishing) ? model.probabilityPhishing : null
    },
    reasons,
    conflicts: Array.isArray(overall.conflicts) ? overall.conflicts.slice(0, 12) : [],
    evidence: evidenceItems,
    categories: {
      phishing: { status: verifiedThreat ? 'OBSERVED_THREAT'
        : (['URL_HEURISTIC', 'REDIRECT_HEURISTIC', 'CONTENT_INDICATORS', 'MODEL_PREDICTION'].includes(overall.verdictBasis) || overall.finalVerdict === 'PHISHING' ? 'INDICATORS_ONLY' : 'NO_CONFIRMED_THREAT'), scope },
      malware: { status: 'NOT_ASSESSED' },
      scam: { status: 'NOT_ASSESSED' },
      deceptiveDownloads: { status: 'NOT_ASSESSED' },
      piracyCopyright: { status: 'NOT_ASSESSED' }
    },
    inspection: {
      accessDenied,
      renderStatus: schema?.renderStatus || 'NOT_AVAILABLE',
      pageStatus: schema?.pageContentAssessment?.status || 'NOT_RUN',
      modeCCompleted,
      missingEvidence: Array.isArray(assessment.missing_evidence) ? assessment.missing_evidence.slice(0, 24) : [],
      limitations
    },
    recommendation
  };
}
