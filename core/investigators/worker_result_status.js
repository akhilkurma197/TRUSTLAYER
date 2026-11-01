/** Classify the final browser response without treating error documents as renders. */
export function classifyWorkerResultStatus(httpStatus, domNodes = 0) {
  const status = Number(httpStatus);
  if ([401, 403].includes(status)) return 'BLOCKED';
  if (Number.isInteger(status) && status >= 400) return 'HTTP_ERROR';
  if (Number.isInteger(status) && status >= 200 && status < 400) return 'SUCCESS';
  return domNodes > 0 ? 'PARTIAL' : 'FAILED';
}
