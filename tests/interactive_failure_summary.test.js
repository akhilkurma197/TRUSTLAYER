import assert from 'node:assert/strict';
import test from 'node:test';
import { summarizeInteractionFailure } from './helpers/interactive_failure_summary.js';

function responseFor(action, details = []) {
  return {
    status: () => 400,
    json: async () => ({ error: 'Invalid interaction action.', details }),
    request: () => ({ postDataJSON: () => ({ action }) })
  };
}

test('interaction failure summary exposes bounded validator reasons without selector or text values', async () => {
  const summary = await summarizeInteractionFailure(responseFor({
    type: 'type', selector: '#note', text: 'private-looking sample', extra: 'do-not-log'
  }, ['Unexpected action parameter.']));

  assert.equal(summary.errorCode, 'INVALID_INTERACTION');
  assert.deepEqual(summary.validationDetails, ['UNEXPECTED_PARAMETER']);
  assert.deepEqual(summary.requestShape, {
    actionType: 'type', actionKeys: ['extra', 'selector', 'text', 'type'],
    selectorPresent: true, selectorType: 'string',
    selectorLength: 5, textLength: 22, locallyValid: false,
    selectorMatchesExpectedFixture: null,
    localValidationErrors: ['UNEXPECTED_PARAMETER']
  });
  assert.equal(JSON.stringify(summary).includes('#note'), false);
  assert.equal(JSON.stringify(summary).includes('private-looking sample'), false);
  assert.equal(JSON.stringify(summary).includes('do-not-log'), false);
});

test('the intended local fixture typing payload passes the current API validator', async () => {
  const summary = await summarizeInteractionFailure(responseFor({
    type: 'type', selector: '#note', text: 'local-only-note'
  }));

  assert.equal(summary.requestShape.locallyValid, true);
  assert.deepEqual(summary.requestShape.localValidationErrors, []);
  assert.deepEqual(summary.validationDetails, []);
  assert.equal(JSON.stringify(summary).includes('local-only-note'), false);
});

test('interaction failure summary retains server/local validator disagreement without values', async () => {
  const summary = await summarizeInteractionFailure(responseFor({
    type: 'type', selector: '#note', text: 'local-only-note'
  }, ['A single bounded CSS selector is required.']));

  assert.equal(summary.requestShape.locallyValid, true);
  assert.deepEqual(summary.requestShape.localValidationErrors, []);
  assert.deepEqual(summary.validationDetails, ['INVALID_SELECTOR']);
});
