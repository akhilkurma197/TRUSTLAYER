import assert from 'node:assert/strict';
import test from 'node:test';
import { prepareTypingActionInputs } from './helpers/typing_action_inputs.js';

function pageWithInputs({ ignoreSelectorFill = false } = {}) {
  const values = new Map([
    ['#interactive-type-selector', ''],
    ['#interactive-type-text', '']
  ]);
  const calls = [];
  return {
    calls,
    locator(selector) {
      return {
        async fill(value) {
          calls.push(`fill:${selector}`);
          if (!(ignoreSelectorFill && selector === '#interactive-type-selector')) values.set(selector, value);
        },
        async inputValue() {
          calls.push(`read:${selector}`);
          return values.get(selector);
        }
      };
    }
  };
}

test('typing inputs are populated sequentially and read back immediately before submission', async () => {
  const page = pageWithInputs();
  const summary = await prepareTypingActionInputs(page, { expectedSelector: '#note', text: 'local-only-note' });

  assert.deepEqual(page.calls, [
    'fill:#interactive-type-selector', 'fill:#interactive-type-text',
    'read:#interactive-type-selector', 'read:#interactive-type-text'
  ]);
  assert.deepEqual(summary, {
    selectorPresent: true, selectorType: 'string', selectorLength: 5,
    selectorMatchesExpectedFixture: true, textPresent: true, textLength: 15,
    textMatchesPreparedValue: true
  });
  assert.equal(JSON.stringify(summary).includes('#note'), false);
  assert.equal(JSON.stringify(summary).includes('local-only-note'), false);
});

test('typing preflight rejects a cleared selector before the API request', async () => {
  const page = pageWithInputs({ ignoreSelectorFill: true });
  await assert.rejects(
    prepareTypingActionInputs(page, { expectedSelector: '#note', text: 'local-only-note' }),
    error => {
      assert.equal(error.message, 'Typing fixture inputs were not retained before submission.');
      assert.deepEqual(error.inputSummary, {
        selectorPresent: false, selectorType: 'string', selectorLength: 0,
        selectorMatchesExpectedFixture: false, textPresent: true, textLength: 15,
        textMatchesPreparedValue: true
      });
      return true;
    }
  );
});
