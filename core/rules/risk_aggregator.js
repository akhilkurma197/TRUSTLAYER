/**
 * Trust Layer — Deterministic URL Risk Aggregator
 * Combines triggered rule contributions, applies anti-correlation category caps,
 * and produces reproducible risk scores [0 - 100] with explicit categorization.
 */

export class RiskAggregator {
  /**
   * Aggregates evaluated rules into a bounded, calibrated score.
   * @param {Array<object>} evaluatedRules List of evaluated rule records
   * @param {object} config Rule configuration containing categoryCaps and thresholds
   * @returns {{
   *   score: number,
   *   classification: 'SAFE' | 'UNDER_REVIEW' | 'PHISHING',
   *   categoryBreakdown: object,
   *   triggeredRules: Array<object>,
   *   totalUncappedContribution: number,
   *   configVersion: string
   * }}
   */
  static aggregate(evaluatedRules, config) {
    const categoryCaps = config.categoryCaps || {};
    const thresholds = config.thresholds || { safeMax: 24, reviewMax: 59, phishingMin: 60 };
    const triggeredRules = evaluatedRules.filter(r => r.triggered);

    // Group contributions by category to apply anti-correlation caps
    const categoryTotals = {};
    const categoryCapped = {};
    let totalUncapped = 0;

    for (const rule of triggeredRules) {
      const cat = rule.category || 'OTHER';
      categoryTotals[cat] = (categoryTotals[cat] || 0) + rule.contribution;
      totalUncapped += rule.contribution;
    }

    let aggregatedScore = 0;
    const categoryBreakdown = {};

    for (const [cat, rawTotal] of Object.entries(categoryTotals)) {
      const cap = categoryCaps[cat] !== undefined ? categoryCaps[cat] : 50;
      const effective = Math.min(rawTotal, cap);
      categoryCapped[cat] = effective;
      aggregatedScore += effective;

      categoryBreakdown[cat] = {
        rawScore: rawTotal,
        cappedScore: effective,
        categoryCap: cap,
        rulesTriggeredCount: triggeredRules.filter(r => r.category === cat).length
      };
    }

    // Clamp total score between 0 and 100
    const finalScore = Math.min(Math.max(Math.round(aggregatedScore), 0), 100);

    // 3-way transparent classification
    let classification = 'SAFE';
    if (finalScore >= thresholds.phishingMin) {
      classification = 'PHISHING';
    } else if (finalScore > thresholds.safeMax) {
      classification = 'UNDER_REVIEW';
    }

    return {
      score: finalScore,
      classification,
      categoryBreakdown,
      triggeredRules,
      totalUncappedContribution: totalUncapped,
      configVersion: config.version || '1.0.0'
    };
  }
}

export class OverallRiskAggregator {
  static aggregate({ urlAssessment = null, redirectAssessment = null, pageContentAssessment = null,
    isTestFixture = false, inspectionMode = 'URL_ONLY', modelPrediction = null, modelProbability = null,
    modelConfidenceLevel = null, now = Date.now(), maxEvidenceAgeMs = 24 * 60 * 60 * 1000 } = {}) {
    const urlScore = Number.isFinite(urlAssessment?.ruleScore) ? urlAssessment.ruleScore : 0;
    const urlVerdict = urlAssessment?.classification || 'UNAVAILABLE';
    const redirectScore = Number.isFinite(redirectAssessment?.riskScore) ? redirectAssessment.riskScore : 0;
    const redirectVerdict = redirectAssessment?.riskLevel || null;
    const pageRisk = pageContentAssessment?.riskLevel || 'NOT_RUN';
    const fullPageInspected = pageContentAssessment?.fullRenderedInspection === true && pageContentAssessment?.status === 'COMPLETED';
    const accessDenied = pageContentAssessment?.accessStatus === 'BLOCKED_HTTP_403' || pageContentAssessment?.status === 'CONTENT_UNAVAILABLE';
    const urlIndicator = ['PHISHING', 'UNDER_REVIEW'].includes(urlVerdict);
    const redirectIndicator = ['PHISHING', 'UNDER_REVIEW'].includes(redirectVerdict);
    const modelIndicator = modelPrediction === 'PHISHING';
    const contentSignals = Array.isArray(pageContentAssessment?.signals) ? pageContentAssessment.signals : [];
    const verifiedEvidence = (Array.isArray(pageContentAssessment?.verifiedMaliciousEvidence)
      ? pageContentAssessment.verifiedMaliciousEvidence : []).filter(item => item?.verified === true &&
      item.provenance === 'OBSERVED' && item.confidenceLevel === 'HIGH' && typeof item.group === 'string' &&
      Number.isFinite(item.observedAt) && item.observedAt >= 0 &&
      item.observedAt <= now && now - item.observedAt <= maxEvidenceAgeMs);
    const suppliedVerifiedEvidence = Array.isArray(pageContentAssessment?.verifiedMaliciousEvidence)
      ? pageContentAssessment.verifiedMaliciousEvidence.filter(item => item?.verified === true) : [];
    const invalidVerifiedEvidence = suppliedVerifiedEvidence.length > verifiedEvidence.length;
    const distinctVerifiedGroups = new Set(verifiedEvidence.map(item => item.group));
    const malicious = !isTestFixture && fullPageInspected && distinctVerifiedGroups.size >= 2;
    const contentIndicator = contentSignals.length > 0 || ['SUSPICIOUS', 'CRITICAL', 'HIGH', 'MODERATE'].includes(pageRisk) ||
      ['PHISHING', 'UNDER_REVIEW'].includes(pageContentAssessment?.verdict || pageContentAssessment?.classification);

    let outcome = 'UNVERIFIED';
    let legacyFinalVerdict = 'UNDER_REVIEW';
    let finalRiskLevel = 'LOW';
    let determiningComponent = 'Evidence availability';
    let headline = 'Inspection Unverified';
    let summary = 'Available evidence is incomplete; no final website safety conclusion is available.';
    let verdictBasis = 'INSPECTION_INCOMPLETE';
    let confidenceLevel = 'NONE';
    const reasons = [];

    if (malicious) {
      outcome = 'MALICIOUS'; legacyFinalVerdict = 'PHISHING'; finalRiskLevel = 'CRITICAL';
      determiningComponent = 'Corroborated rendered-page evidence';
      headline = 'Malicious behavior supported by independent observed evidence';
      summary = 'At least two independent, current, high-confidence observed evidence groups support this finding.';
      verdictBasis = 'CORROBORATED_OBSERVED_EVIDENCE'; confidenceLevel = 'HIGH';
      reasons.push(summary);
    } else if (isTestFixture) {
      legacyFinalVerdict = 'KNOWN_SECURITY_TEST_FIXTURE'; finalRiskLevel = 'LOW';
      determiningComponent = 'Security Test Fixture Policy';
      headline = 'Known Security Test Fixture';
      summary = 'This is a designated security demonstration fixture, not a verdict about its hosting operator.';
      verdictBasis = 'TEST_FIXTURE_POLICY'; confidenceLevel = 'HIGH';
      reasons.push(summary);
    } else if (urlIndicator || redirectIndicator || modelIndicator || contentIndicator) {
      outcome = 'SUSPICIOUS'; legacyFinalVerdict = 'UNDER_REVIEW';
      const urlOnly = !fullPageInspected;
      finalRiskLevel = urlVerdict === 'PHISHING' || redirectVerdict === 'PHISHING' || pageRisk === 'HIGH'
        ? 'HIGH' : (pageRisk === 'MODERATE' || new Set(contentSignals.map(item => item.group).filter(Boolean)).size > 1 ? 'MODERATE' : 'LOW');
      determiningComponent = contentIndicator ? 'Rendered page content indicators'
        : (urlIndicator ? 'URL structure heuristics' : (redirectIndicator ? 'Redirect observations' : 'URL model prediction'));
      headline = urlOnly ? 'Suspicious indicators — page not fully verified' : 'Suspicious indicators observed';
      summary = accessDenied
        ? 'Access was denied; the URL indicators remain suspicious, but target page content is unavailable.'
        : (contentIndicator ? (pageContentAssessment?.summary || 'Page features warrant review; no single feature is treated as proof of phishing.')
          : (modelIndicator
            ? `The URL model predicted phishing${Number.isFinite(modelProbability) ? ` (${(modelProbability * 100).toFixed(1)}%)` : ''}; this is a prediction, not verified page evidence.`
            : (urlAssessment?.summary || redirectAssessment?.summary || 'Structural or redirect indicators warrant review; they do not prove malicious page behavior.')));
      verdictBasis = contentIndicator ? 'CONTENT_INDICATORS'
        : (urlIndicator ? 'URL_HEURISTIC' : (redirectIndicator ? 'REDIRECT_HEURISTIC' : 'MODEL_PREDICTION'));
      confidenceLevel = contentIndicator ? (pageContentAssessment?.confidenceLevel || 'LOW')
        : (modelIndicator ? (modelConfidenceLevel || 'LOW') : 'LOW');
      reasons.push(summary);
    } else if (accessDenied || !fullPageInspected || invalidVerifiedEvidence) {
      outcome = 'UNVERIFIED'; legacyFinalVerdict = 'UNDER_REVIEW';
      determiningComponent = accessDenied ? 'Live inspection access restriction' : 'Rendered page evidence unavailable';
      headline = accessDenied ? 'Access denied — target content unavailable' : 'Inspection incomplete — no safety conclusion';
      summary = accessDenied
        ? 'The target returned an access restriction. This does not establish whether the page is malicious or safe.'
        : (pageContentAssessment?.summary || (inspectionMode === 'MODE_B'
          ? 'Redirect tracing did not render or inspect page content; the page remains unverified.'
          : 'URL structure and model predictions are preliminary; page content was not fully inspected.'));
      if (invalidVerifiedEvidence && !accessDenied) {
        headline = 'Evidence unavailable or stale — no conclusion';
        summary = 'Evidence presented as verified was stale, future-dated, or incomplete; no final conclusion is available.';
      }
      verdictBasis = accessDenied ? 'ACCESS_RESTRICTED' : (invalidVerifiedEvidence ? 'EVIDENCE_INVALID' : 'INSPECTION_INCOMPLETE');
      reasons.push(summary);
    } else {
      outcome = 'NO_THREAT_DETECTED'; legacyFinalVerdict = 'NO_THREAT_OBSERVED'; finalRiskLevel = 'LOW';
      determiningComponent = 'Completed rendered-page checks';
      headline = 'No threat indicators detected in completed checks';
      summary = pageContentAssessment?.summary || 'No threat indicators were detected in the completed rendered-page checks; this is not a universal safety guarantee.';
      verdictBasis = 'COMPLETED_RENDERED_CHECKS'; confidenceLevel = 'LIMITED';
      reasons.push(summary);
    }

    const findings = [...contentSignals];
    if (urlIndicator) findings.push({ code: `URL_${urlVerdict}_INDICATOR`, group: 'url_intelligence', source: 'URL_RULES',
      provenance: 'HEURISTIC', confidenceLevel: 'LOW', observedAt: urlAssessment?.timestamp || null,
      description: urlAssessment?.summary || 'URL structure indicators; not proof of page behavior.' });
    if (redirectIndicator) findings.push({ code: `REDIRECT_${redirectVerdict}_INDICATOR`, group: 'redirect_intelligence', source: 'REDIRECT_TRACER',
      provenance: 'OBSERVED', confidenceLevel: 'LOW', observedAt: redirectAssessment?.timestamp || null,
      description: redirectAssessment?.summary || 'Redirect observations require context.' });
    if (modelIndicator) findings.push({ code: 'URL_MODEL_PHISHING_PREDICTION', group: 'url_intelligence', source: 'URL_MODEL',
      provenance: 'MODEL_PREDICTION', confidenceLevel: modelConfidenceLevel || 'LOW', observedAt: null,
      description: 'Model prediction is an indicator, not verified page evidence.' });

    const modeScores = {
      modeA: urlScore,
      modeB: redirectAssessment?.status === 'SUCCESS' ? redirectScore : null,
      modeC: fullPageInspected ? (pageRisk === 'CRITICAL' ? 95 : (pageRisk === 'HIGH' ? 70 : (pageRisk === 'MODERATE' ? 45 : 10))) : null
    };
    const validScores = [urlScore];
    if (modeScores.modeB !== null) validScores.push(modeScores.modeB);
    if (modeScores.modeC !== null) validScores.push(modeScores.modeC);
    const verifiedThreat = outcome === 'MALICIOUS';
    const conflicts = [];
    if (verifiedThreat && modelPrediction === 'LEGITIMATE') conflicts.push('URL model predicted LEGITIMATE while independent rendered-page evidence supports a malicious finding.');
    if (verifiedThreat && urlVerdict === 'SAFE') conflicts.push('URL rules found no high-risk URL pattern while independent rendered-page evidence supports a malicious finding.');
    if (outcome === 'SUSPICIOUS' && modelPrediction === 'LEGITIMATE' && contentIndicator) {
      conflicts.push('URL model predicted LEGITIMATE while page heuristics recorded suspicious indicators; neither alone settles the verdict.');
    }

    return {
      outcome, finalVerdict: legacyFinalVerdict, legacyFinalVerdict, finalRiskLevel,
      combinedScore: isTestFixture && !verifiedThreat ? 0 : Math.max(...validScores),
      determiningComponent, headline, summary, reasons, findings,
      reasonCodes: findings.map(item => item.code), confidenceLevel,
      verdictBasis, verifiedThreat, conflicts,
      modeScores,
      modeStatuses: {
        modeA: urlAssessment ? 'COMPLETED' : 'NOT_RUN',
        modeB: redirectAssessment?.status || 'NOT_RUN',
        modeC: fullPageInspected ? 'COMPLETED' : (pageContentAssessment?.status || 'NOT_RUN')
      },
      phishingPrecedenceApplied: verifiedThreat
    };
  }
}
