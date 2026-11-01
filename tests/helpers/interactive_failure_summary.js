import { validateInteractiveAction } from '../../core/interactive_action.js';

function validationCode(value) {
  const message = String(value);
  if (/Action must be an object/i.test(message)) return 'ACTION_NOT_OBJECT';
  if (/Unsupported interaction action/i.test(message)) return 'UNSUPPORTED_ACTION';
  if (/Unexpected action parameter/i.test(message)) return 'UNEXPECTED_PARAMETER';
  if (/Navigation URL must be/i.test(message)) return 'NAVIGATION_URL_TOO_LONG';
  if (/credential-free HTTP/i.test(message)) return 'UNSAFE_NAVIGATION_URL';
  if (/Navigation URL is invalid/i.test(message)) return 'INVALID_NAVIGATION_URL';
  if (/Scroll must be/i.test(message)) return 'INVALID_SCROLL';
  if (/bounded CSS selector/i.test(message)) return 'INVALID_SELECTOR';
  if (/Typed text must contain/i.test(message)) return 'INVALID_TYPED_TEXT';
  return 'OTHER_VALIDATION_ERROR';
}

function boundedLength(value) {
  return typeof value === 'string' ? Math.min(value.length, 4096) : null;
}

export async function summarizeInteractionFailure(response, { expectedFixtureSelector = null } = {}) {
  let body = null;
  try { body = await response.json(); } catch {}

  let action = null;
  try { action = response.request().postDataJSON()?.action; } catch {}

  const validator = validateInteractiveAction(action);
  const details = Array.isArray(body?.details)
    ? body.details.filter(item => typeof item === 'string').slice(0, 8).map(validationCode)
    : [];
  const actionKeys = action && typeof action === 'object' && !Array.isArray(action)
    ? Object.keys(action).filter(key => /^[A-Za-z][A-Za-z0-9]{0,31}$/.test(key)).sort().slice(0, 8)
    : [];

  return {
    status: Number.isInteger(response.status()) ? response.status() : null,
    errorCode: /invalid interaction/i.test(String(body?.error || '')) ? 'INVALID_INTERACTION' : 'OTHER',
    validationDetails: details,
    requestShape: {
      actionType: typeof action?.type === 'string' && /^[a-z_]{1,24}$/.test(action.type) ? action.type : 'INVALID',
      actionKeys,
      selectorPresent: Boolean(action && Object.hasOwn(action, 'selector')),
      selectorType: action?.selector === undefined ? 'undefined'
        : (typeof action.selector === 'string' ? 'string' : typeof action.selector),
      selectorLength: boundedLength(action?.selector),
      selectorMatchesExpectedFixture: typeof expectedFixtureSelector === 'string'
        ? action?.selector === expectedFixtureSelector : null,
      textLength: boundedLength(action?.text),
      locallyValid: validator.valid,
      localValidationErrors: validator.errors.slice(0, 8).map(validationCode)
    }
  };
}
