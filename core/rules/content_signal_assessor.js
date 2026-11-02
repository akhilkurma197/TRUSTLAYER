const MAX_ITEMS = 200;
const MAX_OBSERVATIONS = 500;
const MAX_EVIDENCE_AGE_MS = 24 * 60 * 60 * 1000;

const SENSITIVE_INPUT = input => input?.isPassword === true || input?.isSensitive === true ||
  input?.type === 'password' || input?.isUserEditable === true &&
  /pass|pwd|otp|pin|card|cvv|cvc|ssn|aadhaar|pan|token/i.test(`${input.name || ''} ${input.placeholder || ''}`);

function parseUrl(value, base) {
  try { return new URL(value, base); } catch { return null; }
}

function observationTimestamp(value) {
  const timestamp = value?.timestamp ?? value?.observedAt ?? value?.ts ?? value?.time;
  if (Number.isFinite(timestamp)) return timestamp;
  if (typeof timestamp === 'string') {
    const parsed = Date.parse(timestamp);
    if (Number.isFinite(parsed)) return parsed;
  }
  return null;
}

function isCurrentTimestamp(value, now, maxAgeMs) {
  if (value === undefined || value === null) return true;
  const timestamp = Number.isFinite(value) ? value
    : (typeof value === 'string' && Number.isFinite(Date.parse(value)) ? Date.parse(value) : null);
  return Number.isFinite(timestamp) && timestamp >= 0 && timestamp <= now && now - timestamp <= maxAgeMs;
}

function currentObservation(value, now, maxAgeMs) {
  const timestamp = value?.timestamp ?? value?.observedAt ?? value?.ts ?? value?.time;
  return isCurrentTimestamp(timestamp, now, maxAgeMs);
}

function observationId(ref) {
  return `DOM_OBS_${String(ref).replace(/[^a-z0-9]+/gi, '_').replace(/^_|_$/g, '').toUpperCase()}`;
}

function isValidPageExtraction(pageExtraction) {
  return ['SUCCESS', 'COMPLETED'].includes(pageExtraction?.status) &&
    Array.isArray(pageExtraction.forms) && Array.isArray(pageExtraction.scripts) &&
    Number.isFinite(pageExtraction.domNodes) && pageExtraction.domNodes > 0;
}

export function hasCompleteRenderedEvidence({ isAccessRestricted = false, isHttpSuccess = false,
  inspectionMode = 'URL_ONLY', liveInspection = null, pageExtraction = null,
  now = Date.now(), maxEvidenceAgeMs = MAX_EVIDENCE_AGE_MS } = {}) {
  const extractedAt = pageExtraction?.observedAt ?? pageExtraction?.capturedAt ?? pageExtraction?.screenshotMetadata?.capturedAt;
  const extractionIsCurrent = isCurrentTimestamp(extractedAt, now, maxEvidenceAgeMs);
  return !isAccessRestricted && isHttpSuccess && inspectionMode === 'ISOLATED_LIVE' &&
    liveInspection?.status === 'SUCCESS' && liveInspection?.renderStatus === 'RENDER_COMPLETE' &&
    isValidPageExtraction(pageExtraction) && extractionIsCurrent;
}

/**
 * Separates facts read from the isolated inspection artifacts from heuristic
 * interpretations. References are stable indices into the bounded extractor
 * and event arrays; no input values or full URLs are retained.
 */
export function assessContentSignals({
  complete = false,
  pageExtraction = null,
  networkEvents = [],
  blockedRequests = [],
  visualFindings = [],
  redirectChain = [],
  targetUrl = null,
  finalUrl = null,
  identityMismatch = false,
  purposeMismatch = false,
  verifiedMaliciousEvidence = [],
  observedAt = Date.now(),
  maxEvidenceAgeMs = MAX_EVIDENCE_AGE_MS
} = {}) {
  const observations = [];
  const signals = [];
  const now = Number.isFinite(observedAt) ? observedAt : Date.now();
  const bounded = values => Array.isArray(values) ? values.slice(0, MAX_ITEMS) : [];
  const addObservation = (ref, code, source, category, details = {}, sourceTime = null) => {
    if (observations.length >= MAX_OBSERVATIONS) return null;
    const timestamp = Number.isFinite(sourceTime) && sourceTime >= 0 && sourceTime <= now && now - sourceTime <= maxEvidenceAgeMs
      ? sourceTime : now;
    const id = observationId(ref);
    observations.push({ id, ref, code, source, category, provenance: 'OBSERVED', observedAt: timestamp, details });
    return id;
  };
  const addSignal = (code, group, source, confidenceLevel, description, refs = [], sourceReferences = []) => {
    signals.push({ code, group, source, provenance: 'INFERRED', kind: 'HEURISTIC',
      confidenceLevel, observedAt: now, observationRefs: [...new Set(refs.filter(ref => typeof ref === 'string'))].slice(0, 24),
      sourceReferences: sourceReferences.slice(0, 8), description });
  };

  const extractionTimestamp = pageExtraction?.observedAt ?? pageExtraction?.capturedAt ?? pageExtraction?.screenshotMetadata?.capturedAt;
  const extractionIsCurrent = isCurrentTimestamp(extractionTimestamp, now, maxEvidenceAgeMs);
  if (!complete || !isValidPageExtraction(pageExtraction) || !extractionIsCurrent) {
    return { outcome: 'UNVERIFIED', riskLevel: 'NOT_RUN', confidenceLevel: 'NONE', observations, signals,
      summary: 'Rendered content evidence is incomplete or unavailable.' };
  }

  const pageUrl = finalUrl || targetUrl || 'https://unavailable.invalid/';
  const base = parseUrl(pageUrl);
  const forms = bounded(pageExtraction.forms);
  const sensitiveFormRefs = [];
  const crossOriginFormRefs = [];
  for (const [formIndex, form] of forms.entries()) {
    const formRef = `dom.forms[${formIndex}]`;
    const action = typeof form?.action === 'string' ? form.action : '';
    const destination = action && action !== '(same-origin)' && action !== '(unattached-dom-inputs)'
      ? parseUrl(action, pageUrl) : base;
    const isCrossOrigin = Boolean(base && destination && destination.origin !== base.origin);
    const destinationFacts = addObservation(formRef, 'FORM_CONFIGURATION', 'LIVE_DOM', 'page', {
      method: String(form?.method || 'GET').toUpperCase().slice(0, 12),
      hasSensitiveInput: Boolean(form?.hasPassword || form?.hasSensitive || bounded(form?.inputs).some(SENSITIVE_INPUT)),
      destinationOrigin: destination?.origin || null,
      crossOrigin: isCrossOrigin,
      inputCount: bounded(form?.inputs).length
    });
    const inputs = bounded(form?.inputs);
    const sensitiveInputs = inputs.flatMap((input, inputIndex) => SENSITIVE_INPUT(input)
      ? [addObservation(`${formRef}.inputs[${inputIndex}]`, 'SENSITIVE_INPUT_TYPE_OR_LABEL', 'LIVE_DOM', 'page', {
        type: String(input?.type || '').slice(0, 24).toLowerCase(),
        isPassword: input?.isPassword === true || input?.type === 'password',
        isSensitive: input?.isSensitive === true,
        userEditable: input?.isUserEditable !== false,
        hidden: input?.isHidden === true
      })] : []);
    if (isCrossOrigin) crossOriginFormRefs.push(destinationFacts);
    if (isCrossOrigin && sensitiveInputs.length) sensitiveFormRefs.push(destinationFacts, ...sensitiveInputs);
  }
  if (sensitiveFormRefs.length) {
    addSignal('SENSITIVE_FORM_CROSS_DOMAIN_DESTINATION', 'form_destination', 'LIVE_DOM', 'LOW',
      'A form configured with sensitive-field indicators targets a different page origin; no data was submitted.', sensitiveFormRefs);
  } else if (crossOriginFormRefs.length) {
    addSignal('CROSS_DOMAIN_FORM_DESTINATION', 'form_destination', 'LIVE_DOM', 'LOW',
      'A form targets a different page origin; this configuration alone does not establish malicious intent.', crossOriginFormRefs);
  }

  if (identityMismatch) addSignal('IDENTITY_CONTINUITY_MISMATCH', 'identity_purpose', 'IDENTITY_ANALYSIS', 'MODERATE',
    'The observed domain did not match the claimed organization signals.', [], [{ ref: 'identityAnalysis.identityContinuity', source: 'IDENTITY_ANALYSIS' }]);
  if (purposeMismatch) addSignal('PAGE_PURPOSE_MISMATCH', 'identity_purpose', 'PAGE_INTENT', 'MODERATE',
    'Observed page intent conflicts with its stated or inferred purpose.', [], [{ ref: 'pageAnalysis.intent', source: 'PAGE_INTENT' }]);

  const resourceRefs = [];
  for (const [index, script] of bounded(pageExtraction.scripts).entries()) {
    const src = typeof script?.src === 'string' ? script.src : '';
    const resource = src ? parseUrl(src, pageUrl) : null;
    if (resource && base && resource.origin !== base.origin) {
      resourceRefs.push(addObservation(`dom.scripts[${index}]`, 'CROSS_ORIGIN_SCRIPT_RESOURCE', 'LIVE_DOM', 'page', {
        resourceOrigin: resource.origin, resourceHost: resource.hostname
      }));
    }
  }
  for (const [index, event] of bounded(networkEvents).entries()) {
    if (!event || !currentObservation(event, now, maxEvidenceAgeMs)) continue;
    const requestUrl = parseUrl(event.url || event.targetUrl || '', pageUrl);
    if (requestUrl && base && requestUrl.origin !== base.origin) {
      resourceRefs.push(addObservation(`network.events[${index}]`, 'CROSS_ORIGIN_REQUEST', 'LIVE_NETWORK', 'network', {
        resourceOrigin: requestUrl.origin,
        method: String(event.method || 'GET').toUpperCase().slice(0, 12),
        resourceType: String(event.resourceType || event.type || 'unknown').slice(0, 32)
      }, observationTimestamp(event)));
    }
  }
  if (resourceRefs.length) addSignal('CROSS_ORIGIN_PAGE_RESOURCES', 'page_resources', 'LIVE_DOM_AND_NETWORK', 'LOW',
    'The page referenced or requested cross-origin resources; this is common on legitimate sites and is not proof of phishing.', resourceRefs);

  const blockedMutationRefs = [];
  for (const [index, request] of bounded(blockedRequests).entries()) {
    const method = String(request?.method || '').toUpperCase();
    if (request && !['GET', 'HEAD'].includes(method) && currentObservation(request, now, maxEvidenceAgeMs)) {
      blockedMutationRefs.push(addObservation(`network.blockedRequests[${index}]`, 'MUTATING_REQUEST_BLOCKED', 'WORKER_NETWORK_POLICY', 'network', {
        method: method.slice(0, 12), blocked: true
      }, observationTimestamp(request)));
    }
  }
  if (blockedMutationRefs.length) addSignal('BLOCKED_MUTATING_PAGE_REQUEST', 'page_behavior', 'WORKER_NETWORK_POLICY', 'LOW',
    'The read-only browser blocked a state-changing request; no submission was performed.', blockedMutationRefs);

  const allowedVisualCategories = new Set(['CREDENTIAL_HARVESTING', 'FAKE_SOFTWARE_UPDATE', 'SOCIAL_ENGINEERING']);
  const visualGroups = new Map();
  for (const [index, item] of bounded(visualFindings).entries()) {
    if (!allowedVisualCategories.has(item?.category) || !currentObservation(item, now, maxEvidenceAgeMs)) continue;
    const ref = addObservation(`screenshot.findings[${index}]`, 'SCREENSHOT_HEURISTIC', 'SCREENSHOT_INTELLIGENCE', 'screenshot', {
      category: item.category
    }, observationTimestamp(item));
    if (!visualGroups.has(item.category)) visualGroups.set(item.category, []);
    visualGroups.get(item.category).push(ref);
  }
  for (const [category, refs] of visualGroups) addSignal(`VISUAL_${category}`, 'visual_social_engineering', 'SCREENSHOT_INTELLIGENCE', 'LOW',
    `Screenshot analysis reported a ${category.toLowerCase().replaceAll('_', ' ')} heuristic; visual clues require corroboration and do not alone prove malicious intent.`, refs);

  let prior = parseUrl(targetUrl || pageUrl);
  let crossOriginRedirect = false;
  let httpsDowngrade = false;
  const redirectRefs = [];
  for (const [index, hop] of bounded(redirectChain).entries()) {
    if (!hop || !currentObservation(hop, now, maxEvidenceAgeMs)) continue;
    const hopBase = hop.url || hop.fromUrl || hop.from || prior?.href || pageUrl;
    const next = parseUrl(hop.toUrl || (hop.location ? parseUrl(hop.location, hopBase)?.href : null) || hop.url || hop.to || '', hopBase);
    if (!next) continue;
    const from = prior || parseUrl(hop.fromUrl || hop.from || '', pageUrl);
    const crossOrigin = Boolean(from && from.origin !== next.origin);
    const downgrade = Boolean(from?.protocol === 'https:' && next.protocol === 'http:');
    if (crossOrigin || downgrade) {
      crossOriginRedirect ||= crossOrigin;
      httpsDowngrade ||= downgrade;
      redirectRefs.push(addObservation(`inspection.redirectChain[${index}]`, 'REDIRECT_HOP', 'LIVE_REDIRECT_TRACE', 'redirect', {
        fromOrigin: from?.origin || null, toOrigin: next.origin,
        status: Number.isInteger(hop.status) ? hop.status : null,
        crossOrigin, httpsDowngrade: downgrade,
        blocked: hop.blocked === true
      }, observationTimestamp(hop)));
    }
    prior = next;
  }
  if (httpsDowngrade) addSignal('HTTPS_TO_HTTP_REDIRECT', 'redirect_behavior', 'LIVE_REDIRECT_TRACE', 'MODERATE',
    'The observed redirect chain downgraded from HTTPS to HTTP.', redirectRefs);
  else if (crossOriginRedirect) addSignal('CROSS_ORIGIN_REDIRECT', 'redirect_behavior', 'LIVE_REDIRECT_TRACE', 'LOW',
    'Navigation crossed origins; redirects are common and require context.', redirectRefs);

  const currentVerifiedEvidence = (Array.isArray(verifiedMaliciousEvidence) ? verifiedMaliciousEvidence : [])
    .filter(item => item?.verified === true && item.provenance === 'OBSERVED' &&
      item.confidenceLevel === 'HIGH' && typeof item.group === 'string' && Number.isFinite(item.observedAt) &&
      item.observedAt >= 0 && item.observedAt <= now && now - item.observedAt <= maxEvidenceAgeMs);
  const verifiedGroups = new Set(currentVerifiedEvidence.map(item => item.group));
  if (verifiedGroups.size >= 2) {
    return { outcome: 'MALICIOUS', riskLevel: 'CRITICAL', confidenceLevel: 'HIGH', observations, signals,
      verifiedMaliciousEvidence: currentVerifiedEvidence,
      summary: 'Independent, current high-confidence observed evidence supports a malicious page finding.' };
  }
  if (signals.length) {
    const groups = new Set(signals.map(signal => signal.group));
    return { outcome: 'SUSPICIOUS', riskLevel: groups.size >= 2 ? 'HIGH' : 'MODERATE',
      confidenceLevel: groups.size >= 2 ? 'MODERATE' : 'LOW', observations, signals,
      summary: 'Content indicators warrant caution but do not by themselves establish phishing or malicious intent.' };
  }
  return { outcome: 'NO_THREAT_DETECTED', riskLevel: 'LOW', confidenceLevel: 'LIMITED', observations, signals,
    summary: 'No threat indicators were detected in the completed rendered-page checks; this is not a universal safety guarantee.' };
}

/** Add fact and finding records to the case ledger and attach their ledger IDs. */
export function recordContentEvidence(assessment, addEvidence) {
  if (!assessment || typeof addEvidence !== 'function') return assessment;
  const evidenceIds = new Map();
  for (const observation of assessment.observations || []) {
    const item = addEvidence('OBSERVED', observation.category, `Page observation: ${observation.code}`,
      `Observed ${observation.code.toLowerCase().replaceAll('_', ' ')} at ${observation.ref}.`, {
        observationId: observation.id, reference: observation.ref, factCode: observation.code,
        source: observation.source, provenance: observation.provenance, observedAt: observation.observedAt,
        ...observation.details
      });
    if (item?.id) evidenceIds.set(observation.id, item.id);
  }
  for (const signal of assessment.signals || []) {
    signal.evidenceRefs = (signal.observationRefs || []).map(ref => evidenceIds.get(ref)).filter(Boolean);
    const item = addEvidence('INFERRED', 'page', `Content indicator: ${signal.code}`, signal.description, {
      reasonCode: signal.code, group: signal.group, source: signal.source, kind: signal.kind,
      provenance: signal.provenance, confidenceLevel: signal.confidenceLevel,
      observedAt: signal.observedAt, evidenceRefs: signal.evidenceRefs,
      sourceReferences: signal.sourceReferences
    });
    signal.evidenceId = item?.id || null;
  }
  return assessment;
}
