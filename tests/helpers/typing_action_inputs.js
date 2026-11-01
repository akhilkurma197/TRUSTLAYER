const SELECTOR_INPUT = '#interactive-type-selector';
const TEXT_INPUT = '#interactive-type-text';

export async function prepareTypingActionInputs(page, { expectedSelector, text }) {
  if (typeof expectedSelector !== 'string' || typeof text !== 'string') {
    throw new TypeError('Typing fixture inputs must be strings.');
  }

  const selectorInput = page.locator(SELECTOR_INPUT);
  const textInput = page.locator(TEXT_INPUT);
  await selectorInput.fill(expectedSelector, { timeout: 5_000 });
  await textInput.fill(text, { timeout: 5_000 });

  const observedSelector = await selectorInput.inputValue({ timeout: 1_000 });
  const observedText = await textInput.inputValue({ timeout: 1_000 });
  const summary = {
    selectorPresent: observedSelector.length > 0,
    selectorType: 'string',
    selectorLength: observedSelector.length,
    selectorMatchesExpectedFixture: observedSelector === expectedSelector,
    textPresent: observedText.length > 0,
    textLength: observedText.length,
    textMatchesPreparedValue: observedText === text
  };
  if (!summary.selectorMatchesExpectedFixture || !summary.textMatchesPreparedValue) {
    const error = new Error('Typing fixture inputs were not retained before submission.');
    error.inputSummary = summary;
    throw error;
  }
  return summary;
}
