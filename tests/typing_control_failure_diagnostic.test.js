import assert from 'node:assert/strict';
import test from 'node:test';
import { withPlaywrightStepDeadline } from './helpers/typing_control_failure_diagnostic.js';

test('typing preflight deadline preserves a completed locator result', async () => {
  assert.equal(await withPlaywrightStepDeadline('count-button', async () => 1, 20), 1);
});

test('typing preflight deadline identifies a hung locator operation', async () => {
  await assert.rejects(withPlaywrightStepDeadline('count-button', () => new Promise(() => {}), 5), error =>
    error.name === 'TimeoutError' && /count-button/.test(error.message));
});

test('typing preflight deadline preserves the locator exception type', async () => {
  const error = Object.assign(new Error('locator failed'), { name: 'TargetClosedError' });
  await assert.rejects(withPlaywrightStepDeadline('check-button-enabled', () => Promise.reject(error), 50), received =>
    received === error && received.name === 'TargetClosedError');
});
