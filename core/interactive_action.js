export const INTERACTIVE_ACTIONS = Object.freeze(['navigate', 'back', 'forward', 'reload', 'scroll', 'click', 'type', 'screenshot',
  'pointer_move', 'pointer_click', 'pointer_scroll', 'type_focused', 'key']);
export const MAX_INTERACTIVE_ACTIONS = 5_000;
// Pointer movement remains independently bounded from session lifetime.
export const MAX_INTERACTIVE_POINTER_MOVES = 5_000;
export const INTERACTION_DISCRETE_BURST = 30;
export const INTERACTION_DISCRETE_PER_MINUTE = 180;
export const INTERACTION_POINTER_BURST = 10;
export const INTERACTION_POINTER_PER_MINUTE = 120;
export const MAX_PENDING_INTERACTIVE_ACTIONS = 8;
export const MAX_INTERACTIVE_SCREENSHOTS = 5;
export const MAX_INTERACTIVE_VIEWPORT_FRAMES_PER_MINUTE = 120;
// Retained as a compatibility alias; enforcement is rolling-window based.
export const MAX_INTERACTIVE_VIEWPORT_FRAMES = MAX_INTERACTIVE_VIEWPORT_FRAMES_PER_MINUTE;
export const INTERACTIVE_VIEWPORT_FRAME_WINDOW_MS = 60_000;
export const MAX_INTERACTIVE_VIEWPORT_FRAME_BYTES = 512 * 1024;
export const MAX_INTERACTION_TEXT = 200;
export const INTERACTION_TIMEOUT_MS = 5000;
// Interactive browser lifetime is independent from the per-action timeout.
// The operator may stop earlier; this finite ceiling bounds abandoned jobs.
export const MAX_SESSION_MS = 30 * 60_000;
const configuredSessionLimit = process.env.TRUSTLAYER_INTERACTIVE_SESSION_MAX_MS;
if (configuredSessionLimit !== undefined &&
    (!/^\d+$/.test(configuredSessionLimit) || Number(configuredSessionLimit) < 60_000 || Number(configuredSessionLimit) > MAX_SESSION_MS)) {
  throw new Error(`TRUSTLAYER_INTERACTIVE_SESSION_MAX_MS must be an integer from 60000 to ${MAX_SESSION_MS}.`);
}
export const DEFAULT_INTERACTIVE_SESSION_MS = configuredSessionLimit === undefined
  ? MAX_SESSION_MS : Number(configuredSessionLimit);

export function isInteractiveSession(session) {
  return session?.enabled === true;
}

const SELECTOR = /^(?:#[A-Za-z_][A-Za-z0-9_-]{0,63}|\.[A-Za-z_][A-Za-z0-9_-]{0,63}|[A-Za-z][A-Za-z0-9-]{0,31}|\[(?:name|type|role|aria-label|data-testid)(?:=(?:"[A-Za-z0-9 _-]{1,64}"|'[A-Za-z0-9 _-]{1,64}'|[A-Za-z0-9_-]{1,64}))?\])$/;
const ALLOWED_KEYS = {
  navigate: new Set(['type', 'url']),
  back: new Set(['type']),
  forward: new Set(['type']),
  reload: new Set(['type']),
  scroll: new Set(['type', 'direction', 'pixels']),
  click: new Set(['type', 'selector']),
  type: new Set(['type', 'selector', 'text']),
  screenshot: new Set(['type']),
  pointer_move: new Set(['type', 'x', 'y']),
  pointer_click: new Set(['type', 'x', 'y']),
  pointer_scroll: new Set(['type', 'x', 'y', 'direction', 'pixels']),
  type_focused: new Set(['type', 'text']),
  key: new Set(['type', 'key'])
};

export function hasSensitiveText(value) {
  if (typeof value !== 'string') return true;
  const compact = value.replace(/[\s-]/g, '');
  if (/[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/i.test(value)) return true;
  if (/\b(?:password|passwd|secret|api[_ -]?key|access[_ -]?token|private[_ -]?key)\b/i.test(value)) return true;
  if (/\+?\d{10,15}/.test(compact)) return true;
  const digits = compact.replace(/\D/g, '');
  if (digits.length >= 13 && digits.length <= 19) {
    let sum = 0, double = false;
    for (let i = digits.length - 1; i >= 0; i--) {
      let n = Number(digits[i]);
      if (double && (n *= 2) > 9) n -= 9;
      sum += n;
      double = !double;
    }
    if (sum % 10 === 0) return true;
  }
  if (value.length >= 24 && /^[A-Za-z0-9_./+=-]+$/.test(value)) {
    const unique = new Set(value).size;
    if (unique / value.length > 0.55) return true;
  }
  return false;
}

const SENSITIVE_FIELD = /(password|passwd|user|email|account|login|auth|otp|one.?time|code|card|cc-(?:number|name|exp|csc|type)|cvv|security|phone|mobile|bank|iban|routing|secret|token)/i;
const DANGEROUS_CONTROL = /(pay|payment|submit|download|permission|install|delete|remove|authorize|grant|verify|checkout|purchase|transfer|consent|login|sign.?in|authenticate)/i;

export function isSafeTextTarget(target) {
  if (!target || target.disabled || target.readOnly || SENSITIVE_FIELD.test(`${target.name || ''} ${target.id || ''} ${target.autocomplete || ''} ${target.ariaLabel || ''}`)) return false;
  const tag = String(target.tagName || '').toLowerCase();
  const type = String(target.type || '').toLowerCase();
  if (tag === 'input' && type === 'search') return true;
  if (/^(q|query|search)$/i.test(String(target.name || '')) && target.withinForm && String(target.formMethod || 'get').toLowerCase() === 'get' &&
      ((tag === 'textarea') || (tag === 'input' && type === 'text'))) return true;
  return !target.withinForm && ((tag === 'input' && type === 'text') || tag === 'textarea');
}

export function isSafePointerTarget(target) {
  if (!target || DANGEROUS_CONTROL.test(`${target.label || ''} ${target.ariaLabel || ''} ${target.name || ''} ${target.id || ''}`)) return false;
  const tag = String(target.tagName || '').toLowerCase();
  const type = String(target.type || '').toLowerCase();
  if ((tag === 'input' && ['search', 'text'].includes(type)) || tag === 'textarea') return isSafeTextTarget(target);
  if (tag === 'a') {
    if (target.withinForm || target.download || target.contentEditable ||
        (target.target && String(target.target).toLowerCase() !== '_self') || typeof target.href !== 'string') return false;
    try {
      const url = new URL(target.href);
      return ['http:', 'https:'].includes(url.protocol) && !url.username && !url.password;
    } catch { return false; }
  }
  if (target.withinForm || target.download || target.contentEditable) return false;
  if (tag === 'button') return (type || 'submit') === 'button';
  return target.role === 'button';
}

export function validateInteractiveAction(action) {
  const errors = [];
  if (!action || typeof action !== 'object' || Array.isArray(action)) return { valid: false, errors: ['Action must be an object.'] };
  if (!INTERACTIVE_ACTIONS.includes(action.type)) return { valid: false, errors: ['Unsupported interaction action.'] };
  for (const key of Object.keys(action)) if (!ALLOWED_KEYS[action.type].has(key)) errors.push('Unexpected action parameter.');
  if (action.type === 'navigate') {
    if (typeof action.url !== 'string' || action.url.length > 2048) errors.push('Navigation URL must be at most 2048 characters.');
    else {
      try {
        const url = new URL(action.url);
        if (!['http:', 'https:'].includes(url.protocol) || url.username || url.password) errors.push('Only credential-free HTTP(S) navigation is allowed.');
      } catch { errors.push('Navigation URL is invalid.'); }
    }
  }
  if (action.type === 'scroll' && (!['up', 'down'].includes(action.direction) || !Number.isInteger(action.pixels) || action.pixels < 1 || action.pixels > 800)) {
    errors.push('Scroll must be 1–800 pixels up or down.');
  }
  for (const type of ['pointer_move', 'pointer_click', 'pointer_scroll']) {
    if (action.type === type && (!Number.isInteger(action.x) || !Number.isInteger(action.y) || action.x < 0 || action.x > 10000 || action.y < 0 || action.y > 10000)) {
      errors.push('Pointer coordinates must be integer viewport ratios from 0 to 10000.');
      break;
    }
  }
  if (action.type === 'pointer_scroll' && (!['up', 'down'].includes(action.direction) || !Number.isInteger(action.pixels) || action.pixels < 1 || action.pixels > 800)) {
    errors.push('Pointer scroll must be 1–800 pixels up or down.');
  }
  if (action.type === 'type_focused' && (typeof action.text !== 'string' || action.text.length < 1 || action.text.length > MAX_INTERACTION_TEXT || /[\u0000-\u0008\u000B\u000C\u000E-\u001F]/.test(action.text) || hasSensitiveText(action.text))) {
    errors.push('Text is empty, too long, contains control characters, or matches a sensitive-input pattern.');
  }
  if (action.type === 'key' && !['Enter', 'Tab', 'Escape', 'Backspace', 'ArrowUp', 'ArrowDown', 'ArrowLeft', 'ArrowRight'].includes(action.key)) {
    errors.push('Keyboard key is not allowed.');
  }
  if (['click', 'type'].includes(action.type) && (typeof action.selector !== 'string' || action.selector.length > 128 || !SELECTOR.test(action.selector))) {
    errors.push('A single bounded CSS selector is required.');
  }
  if (action.type === 'type' && (typeof action.text !== 'string' || action.text.length < 1 || action.text.length > MAX_INTERACTION_TEXT ||
      /[\u0000-\u0008\u000B\u000C\u000E-\u001F]/.test(action.text) || hasSensitiveText(action.text))) {
    errors.push(`Typed text must contain 1–${MAX_INTERACTION_TEXT} printable characters.`);
  }
  return { valid: errors.length === 0, errors };
}
