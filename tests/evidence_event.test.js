import assert from 'node:assert/strict';
import { test } from 'node:test';
import { validateEvidenceEvent, validateLifecycleTransition } from '../core/evidence_event.js';
import { redactOperationalText } from '../core/log_redaction.js';

const fixture = overrides => ({
  version: 1,
  investigationId: 'TL-2026-1031-1202-GHI',
  eventId: 'evt_1',
  timestamp: Date.now(),
  sequence: 1,
  type: 'network_observation',
  source: 'proxy',
  url: 'https://example.invalid/path',
  evidenceRefs: ['E-001'],
  kind: 'observed',
  observation: 'Received a local fixture response.',
  collectionStatus: 'complete',
  limitations: [],
  freshness: 'live',
  confidence: 0.99,
  severity: 'info',
  ...overrides
});

test('validates versioned evidence events and rejects cross-investigation references', () => {
  assert.deepEqual(validateEvidenceEvent(fixture(), {
    investigationId: 'TL-2026-1031-1202-GHI', knownEvidenceIds: new Set(['E-001']),
    expectedSequence: 1, knownEventIds: new Set()
  }), { valid: true, errors: [] });
  const crossCase = validateEvidenceEvent(fixture(), {
    investigationId: 'TL-2026-1031-1202-OTHER', knownEvidenceIds: new Set(['E-001']),
    expectedSequence: 1, knownEventIds: new Set()
  });
  assert.equal(crossCase.valid, false);
  assert.ok(crossCase.errors.includes('investigation scope mismatch'));
  assert.equal(validateEvidenceEvent(fixture(), {
    investigationId: 'TL-2026-1031-1202-GHI', knownEvidenceIds: new Set(['E-OTHER'])
  }).valid, false);
  assert.equal(validateEvidenceEvent(fixture(), {
    investigationId: 'TL-2026-1031-1202-GHI', knownEvidenceIds: new Set(['E-001']),
    expectedSequence: 1, knownEventIds: new Set(['evt_1'])
  }).valid, false);
});

test('requires explicit observed/inferred, freshness, collection state, and blocks sensitive fields', () => {
  assert.equal(validateEvidenceEvent(fixture({ kind: 'maybe' }), { investigationId: 'TL-2026-1031-1202-GHI' }).valid, false);
  assert.equal(validateEvidenceEvent(fixture({ freshness: 'unknown' }), { investigationId: 'TL-2026-1031-1202-GHI' }).valid, false);
  assert.equal(validateEvidenceEvent(fixture({ collectionStatus: 'unknown' }), { investigationId: 'TL-2026-1031-1202-GHI' }).valid, false);
  assert.equal(validateEvidenceEvent(fixture({ collectionStatus: 'partial' }), { investigationId: 'TL-2026-1031-1202-GHI' }).valid, false);
  assert.equal(validateEvidenceEvent(fixture({ url: 'https://example.invalid/path?token=synthetic' }), { investigationId: 'TL-2026-1031-1202-GHI' }).valid, false);
  assert.equal(validateEvidenceEvent(fixture({ formValue: 'synthetic-secret' }), { investigationId: 'TL-2026-1031-1202-GHI' }).valid, false);
  assert.equal(validateEvidenceEvent(fixture({ url: 'https://user:pass@example.invalid/' }), { investigationId: 'TL-2026-1031-1202-GHI' }).valid, false);
});

test('validates investigation lifecycle progression including cancellation and timeout', () => {
  assert.equal(validateLifecycleTransition('created', 'queued'), true);
  assert.equal(validateLifecycleTransition('queued', 'running'), true);
  assert.equal(validateLifecycleTransition('running', 'timed_out'), true);
  assert.equal(validateLifecycleTransition('running', 'cancelled'), true);
  assert.equal(validateLifecycleTransition('completed', 'running'), false);
  assert.equal(validateLifecycleTransition('unknown', 'running'), false);
});

test('redacts synthetic secrets and URL-specific data from operational log messages', () => {
  const syntheticSecret = 'SYNTHETIC_SECRET_VALUE';
  const redacted = redactOperationalText(`request https://user:pass@example.invalid/private/path?token=${syntheticSecret} Authorization: Bearer ${syntheticSecret} cookie=${syntheticSecret}`);
  assert.equal(redacted.includes(syntheticSecret), false);
  assert.equal(redacted.includes('/private/path'), false);
  assert.equal(redacted.includes('user:pass'), false);
  assert.match(redacted, /Authorization=\[REDACTED\]/);
});
