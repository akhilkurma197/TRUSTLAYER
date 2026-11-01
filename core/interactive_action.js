export const INTERACTIVE_ACTIONS = Object.freeze(['navigate', 'back', 'forward', 'reload', 'scroll', 'click', 'type', 'screenshot']);
export const MAX_INTERACTIVE_ACTIONS = 20;
export const MAX_INTERACTIVE_SCREENSHOTS = 5;
export const MAX_INTERACTION_TEXT = 200;
export const INTERACTION_TIMEOUT_MS = 5000;
export const MAX_SESSION_MS = 120_000;

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
  screenshot: new Set(['type'])
};

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
  if (['click', 'type'].includes(action.type) && (typeof action.selector !== 'string' || action.selector.length > 128 || !SELECTOR.test(action.selector))) {
    errors.push('A single bounded CSS selector is required.');
  }
  if (action.type === 'type' && (typeof action.text !== 'string' || action.text.length < 1 || action.text.length > MAX_INTERACTION_TEXT || /[\u0000-\u0008\u000B\u000C\u000E-\u001F]/.test(action.text))) {
    errors.push(`Typed text must contain 1–${MAX_INTERACTION_TEXT} printable characters.`);
  }
  return { valid: errors.length === 0, errors };
}
