import { redactSensitiveUrl } from './investigators/url_redaction.js';

const SECRET_ASSIGNMENT = /\b(authorization|cookie|set-cookie|password|passwd|token|secret|api[_-]?key)\b\s*[:=]\s*[^\s,;]+/gi;

export function redactOperationalText(value) {
  if (typeof value !== 'string') return '[message omitted]';
  return value
    .replace(/\bBearer\s+[A-Za-z0-9._~+/=-]+/gi, 'Bearer [REDACTED]')
    .replace(SECRET_ASSIGNMENT, '$1=[REDACTED]')
    .replace(/\bhttps?:\/\/[^\s"'<>]+/gi, token => {
      const trailing = /[),.;]+$/.exec(token)?.[0] || '';
      const url = trailing ? token.slice(0, -trailing.length) : token;
      return `${redactSensitiveUrl(url)}${trailing}`;
    });
}
