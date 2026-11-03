import { hasSensitiveText, isSafeKeyboardTarget, isSafePointerTarget, isSafeTextTarget } from './interactive_action.js';

export class InteractiveActionPolicyError extends Error {
  constructor(code) {
    super(code === 'TARGET_UNAVAILABLE' ? 'The selected control is no longer available.'
      : code === 'KEY_NOT_PERMITTED' ? 'That key is not permitted for the focused control.'
        : 'The selected control is not permitted.');
    this.name = 'InteractiveActionPolicyError';
    this.code = code;
  }
}

// This function is serialized by Playwright into the isolated page. It reads
// only policy metadata and never returns form values or entered text.
export function inspectInteractiveElement(element) {
  if (!(element instanceof Element) || !element.isConnected || !element.getClientRects().length) return null;
  const labels = element.labels ? [...element.labels].map(label => label.innerText || label.textContent || '') : [];
  const form = element.closest('form');
  const role = element.getAttribute('role') || '';
  const tagName = element.tagName;
  const ownLabel = ['A', 'BUTTON', 'SUMMARY'].includes(tagName) || ['button', 'tab', 'checkbox', 'radio', 'switch', 'combobox'].includes(role)
    ? (element.innerText || element.textContent || '') : '';
  return {
    tagName,
    type: element.getAttribute('type') || '',
    name: element.getAttribute('name') || '',
    id: element.id || '',
    autocomplete: element.getAttribute('autocomplete') || '',
    ariaLabel: element.getAttribute('aria-label') || '',
    label: [...labels, ownLabel].join(' ').replace(/\s+/g, ' ').slice(0, 240),
    role,
    ariaChecked: element.getAttribute('aria-checked') || '',
    withinForm: Boolean(form),
    formMethod: form?.method || '',
    disabled: Boolean(element.disabled),
    ariaDisabled: element.getAttribute('aria-disabled') === 'true',
    readOnly: Boolean(element.readOnly),
    download: element.hasAttribute('download'),
    contentEditable: element.getAttribute('contenteditable') === 'true',
    href: element.href || '',
    target: element.getAttribute('target') || ''
  };
}

function controlKind(target) {
  const tag = String(target?.tagName || '').toLowerCase();
  const type = String(target?.type || '').toLowerCase();
  if (tag === 'input' && type === 'checkbox') return 'checkbox';
  if (tag === 'input' && type === 'radio') return 'radio';
  if (target?.role === 'checkbox' || target?.role === 'switch') return 'checkbox';
  if (target?.role === 'radio') return 'radio';
  if (target?.role === 'combobox') return 'select';
  if (tag === 'select') return 'select';
  if (tag === 'summary') return 'disclosure';
  if (tag === 'a') return 'link';
  if (target?.role === 'tab') return 'tab';
  if (tag === 'button' || target?.role === 'button') return 'button';
  if (['input', 'textarea'].includes(tag)) return 'text';
  return 'other';
}

export async function inspectFocusedInteractiveTarget(page) {
  const handle = await page.evaluateHandle(() => document.activeElement);
  try {
    const element = handle.asElement();
    return element ? await element.evaluate(inspectInteractiveElement) : null;
  } finally {
    await handle.dispose();
  }
}

export async function inspectPointerInteractiveTarget(page, x, y) {
  const handle = await page.evaluateHandle(({ x: pointX, y: pointY }) => {
    const hit = document.elementFromPoint(pointX, pointY);
    const labelControl = hit?.closest('label')?.control;
    return labelControl || hit?.closest('a[href],button,[role="button"],[role="tab"],[role="checkbox"],[role="radio"],[role="switch"],[role="combobox"],input[type="search"],input[type="text"],input[type="checkbox"],input[type="radio"],textarea,select,summary') || hit;
  }, { x, y });
  try {
    const element = handle.asElement();
    return element ? await element.evaluate(inspectInteractiveElement) : null;
  } finally {
    await handle.dispose();
  }
}

export async function inspectSelectedInteractiveTarget(page, selector) {
  const locator = page.locator(selector).first();
  const target = await locator.evaluate(inspectInteractiveElement);
  return { locator, target };
}

export async function clickPointerInteractiveTarget(page, x, y) {
  const target = await inspectPointerInteractiveTarget(page, x, y);
  if (!target) throw new InteractiveActionPolicyError('TARGET_UNAVAILABLE');
  if (!isSafePointerTarget(target)) throw new InteractiveActionPolicyError('TARGET_NOT_PERMITTED');
  const initialUrl = page.url();
  await page.mouse.click(x, y);
  let navigationChanged = page.url() !== initialUrl;
  if (!navigationChanged && controlKind(target) === 'link') {
    try {
      // mouse.click() can resolve before either a fragment commit or a full
      // navigation. Wait briefly for an actual URL change, without returning
      // the destination (which may contain sensitive path/query/fragment data).
      await page.waitForURL(url => url.href !== initialUrl, { timeout: 1_000 });
      navigationChanged = true;
    } catch { /* A permitted click need not navigate; report only an observed URL change. */ }
  }
  return { targetKind: controlKind(target), navigationChanged };
}

export async function clickSelectedInteractiveTarget(page, selector, timeout) {
  const { locator, target } = await inspectSelectedInteractiveTarget(page, selector);
  if (!target) throw new InteractiveActionPolicyError('TARGET_UNAVAILABLE');
  if (!isSafePointerTarget(target)) throw new InteractiveActionPolicyError('TARGET_NOT_PERMITTED');
  await locator.click(timeout);
  return { targetKind: controlKind(target) };
}

export async function pressFocusedInteractiveKey(page, key) {
  const target = await inspectFocusedInteractiveTarget(page);
  if (!target) throw new InteractiveActionPolicyError('TARGET_UNAVAILABLE');
  if (!isSafeKeyboardTarget(target, key)) throw new InteractiveActionPolicyError('KEY_NOT_PERMITTED');
  const initialUrl = page.url();
  let mainFrameNavigated = false;
  const onFrameNavigated = frame => { if (frame === page.mainFrame()) mainFrameNavigated = true; };
  page.on('framenavigated', onFrameNavigated);
  try { await page.keyboard.press(key); }
  finally { page.off('framenavigated', onFrameNavigated); }
  if (mainFrameNavigated || page.url() !== initialUrl) return { targetKind: 'unknown', navigationChanged: true };
  // Enter commits the highlighted option on a standalone native select. Its
  // identity was validated before dispatch, so report that known target
  // without evaluating a document that could have navigated during the key.
  // A select inside even a permitted GET form remains unknown because Enter
  // may submit that form.
  if (key === 'Enter' && String(target.tagName || '').toLowerCase() === 'select' && !target.withinForm) {
    return { targetKind: 'select' };
  }
  // Enter can submit a permitted GET search or activate a same-tab link/button.
  // Do not evaluate the old document after dispatch because Chromium may have
  // replaced its execution context before the navigation event is observable.
  if (key === 'Enter') return { targetKind: 'unknown', contextMayChange: true };
  const focusedTarget = await inspectFocusedInteractiveTarget(page);
  return { targetKind: controlKind(focusedTarget) };
}

export async function typeFocusedInteractiveText(page, text) {
  const target = await inspectFocusedInteractiveTarget(page);
  if (!target) throw new InteractiveActionPolicyError('TARGET_UNAVAILABLE');
  if (!isSafeTextTarget(target) || hasSensitiveText(text)) throw new InteractiveActionPolicyError('TARGET_NOT_PERMITTED');
  await page.keyboard.press('Control+A');
  await page.keyboard.type(text);
  return { targetKind: 'text' };
}
