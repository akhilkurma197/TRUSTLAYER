import assert from 'node:assert/strict';
import test from 'node:test';
import { hasVisibleTextChangeAfter, latestVisibleTextState } from './helpers/fixture_dom_change.js';

test('fixture state observer accepts a real text-length change in either direction after the baseline event', () => {
  const events = [
    { type: 'dom_change', sequence: 4, observation: 'Page state metadata: {"visibleTextLength":74}.' },
    { type: 'dom_change', sequence: 5, observation: 'Page state metadata: {"visibleTextLength":39}.' }
  ];
  const baseline = latestVisibleTextState(events.slice(0, 1));
  assert.deepEqual(baseline, { sequence: 4, visibleTextLength: 74 });
  assert.equal(hasVisibleTextChangeAfter(events, baseline), true,
    'a click that replaces longer text with shorter text is still an observable state change');
});

test('fixture state observer rejects unchanged, stale, and malformed observations', () => {
  const baseline = { sequence: 8, visibleTextLength: 39 };
  assert.equal(hasVisibleTextChangeAfter([
    { type: 'dom_change', sequence: 9, observation: 'Page state metadata: {"visibleTextLength":39}.' }
  ], baseline), false);
  assert.equal(hasVisibleTextChangeAfter([
    { type: 'dom_change', sequence: 8, observation: 'Page state metadata: {"visibleTextLength":20}.' }
  ], baseline), false);
  assert.equal(hasVisibleTextChangeAfter([
    { type: 'dom_change', sequence: 9, observation: 'Page state metadata unavailable.' }
  ], baseline), false);
  assert.equal(latestVisibleTextState([{ type: 'network_observation', sequence: 1, observation: 'x' }]), null);
});
