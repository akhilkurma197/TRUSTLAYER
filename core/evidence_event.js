/** Versioned, investigation-scoped event contract for collected evidence. */
export const EVIDENCE_EVENT_VERSION = 1;
export const EVIDENCE_EVENT_TYPES = Object.freeze([
  'user_action', 'redirect', 'network_observation', 'dom_change', 'screenshot', 'risk_finding'
]);
export const EVIDENCE_COLLECTION_STATUS = Object.freeze(['complete', 'partial', 'failed', 'missing']);
export const EVIDENCE_FRESHNESS = Object.freeze(['live', 'replayed', 'stored']);

const SECRET_KEY = /(?:password|passwd|cookie|authorization|token|secret|form.?value|input.?value|credential)/i;
const LIMITS = Object.freeze({ text: 2048, references: 64, reference: 160 });

export function validateEvidenceEvent(event, { investigationId, knownEvidenceIds, expectedSequence, knownEventIds } = {}) {
  const errors = [];
  const fail = message => errors.push(message);
  if (!event || typeof event !== 'object' || Array.isArray(event)) return { valid: false, errors: ['event must be an object'] };
  if (event.version !== EVIDENCE_EVENT_VERSION) fail('unsupported event version');
  if (typeof investigationId !== 'string' || event.investigationId !== investigationId) fail('investigation scope mismatch');
  if (typeof event.eventId !== 'string' || !/^[A-Za-z0-9_-]{1,80}$/.test(event.eventId)) fail('invalid event id');
  if (!Number.isSafeInteger(event.sequence) || event.sequence < 1) fail('invalid sequence');
  if (!Number.isSafeInteger(expectedSequence) || expectedSequence < 1 || event.sequence !== expectedSequence) fail('sequence does not match the expected next event');
  if (!(knownEventIds instanceof Set)) fail('known event IDs are required to validate event uniqueness');
  else if (knownEventIds.has(event.eventId)) fail('duplicate event id');
  if (!Number.isFinite(event.timestamp) || event.timestamp <= 0) fail('invalid timestamp');
  if (!EVIDENCE_EVENT_TYPES.includes(event.type)) fail('invalid event type');
  if (!['browser', 'proxy', 'supervisor', 'operator', 'analysis'].includes(event.source)) fail('invalid event source');
  if (!EVIDENCE_COLLECTION_STATUS.includes(event.collectionStatus)) fail('invalid collection status');
  if (!Array.isArray(event.limitations) || event.limitations.length > 20 || event.limitations.some(value => typeof value !== 'string' || value.length > 512)) fail('invalid collection limitations');
  if (event.collectionStatus !== 'complete' && (!Array.isArray(event.limitations) || event.limitations.length === 0)) fail('partial or failed collection must state its limitations');
  if (!EVIDENCE_FRESHNESS.includes(event.freshness)) fail('invalid freshness');
  if (!['observed', 'inferred'].includes(event.kind)) fail('kind must distinguish observed from inferred');
  if (event.url !== undefined) {
    try {
      const url = new URL(event.url);
      if (!['http:', 'https:'].includes(url.protocol) || url.username || url.password || url.search || url.hash) fail('url must be credential-free HTTP(S) without query or fragment data');
    } catch { fail('invalid URL'); }
  }
  if (!Array.isArray(event.evidenceRefs) || event.evidenceRefs.length > LIMITS.references) fail('invalid evidence references');
  if (!(knownEvidenceIds instanceof Set)) fail('known evidence IDs are required to validate reference scope');
  else for (const ref of event.evidenceRefs) {
    if (typeof ref !== 'string' || ref.length > LIMITS.reference || !/^[A-Za-z0-9:_-]+$/.test(ref)) fail('invalid evidence reference');
    else if (knownEvidenceIds && !knownEvidenceIds.has(ref)) fail('evidence reference is outside this investigation');
  }
  if (event.finding !== undefined && (typeof event.finding !== 'string' || event.finding.length > LIMITS.text)) fail('finding exceeds the text limit');
  if (event.observation !== undefined && (typeof event.observation !== 'string' || event.observation.length > LIMITS.text)) fail('observation exceeds the text limit');
  if (event.confidence !== undefined && (!Number.isFinite(event.confidence) || event.confidence < 0 || event.confidence > 1)) fail('confidence must be between 0 and 1');
  if (event.severity !== undefined && !['info', 'low', 'medium', 'high', 'critical', 'unknown'].includes(event.severity)) fail('invalid severity');
  const serialized = JSON.stringify(event);
  if (Buffer.byteLength(serialized, 'utf8') > 16 * 1024) fail('event exceeds the 16 KiB limit');
  const inspect = value => {
    if (!value || typeof value !== 'object') return;
    for (const [key, child] of Object.entries(value)) {
      if (SECRET_KEY.test(key)) fail('event contains a prohibited sensitive field');
      if (child && typeof child === 'object') inspect(child);
    }
  };
  inspect(event);
  return { valid: errors.length === 0, errors: [...new Set(errors)] };
}

export const INVESTIGATION_LIFECYCLE = Object.freeze(['created', 'queued', 'running', 'completed', 'failed', 'cancelled', 'timed_out']);

export function validateLifecycleTransition(from, to) {
  const allowed = {
    created: ['queued', 'running', 'failed', 'cancelled'],
    queued: ['running', 'failed', 'cancelled', 'timed_out'],
    running: ['completed', 'failed', 'cancelled', 'timed_out'],
    completed: [], failed: [], cancelled: [], timed_out: []
  };
  return INVESTIGATION_LIFECYCLE.includes(from) && allowed[from].includes(to);
}
