/**
 * Remove URL credentials and user-specific path/query/fragment data from
 * operational network logs while retaining the scheme, host, and port.
 */
export function redactSensitiveUrl(value, baseUrl) {
  if (typeof value !== 'string') return '[URL omitted]';
  try {
    const parsed = baseUrl ? new URL(value, baseUrl) : new URL(value);
    if (!['http:', 'https:'].includes(parsed.protocol)) return `[${parsed.protocol} URL omitted]`;
    parsed.username = '';
    parsed.password = '';
    parsed.pathname = parsed.pathname === '/' ? '/' : '/[path-redacted]';
    parsed.search = '';
    parsed.hash = '';
    return parsed.href;
  } catch {
    return '[URL omitted]';
  }
}
