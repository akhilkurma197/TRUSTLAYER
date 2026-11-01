export function latestVisibleTextState(events) {
  if (!Array.isArray(events)) return null;
  for (let index = events.length - 1; index >= 0; index--) {
    const event = events[index];
    if (event?.type !== 'dom_change' || !Number.isSafeInteger(event.sequence)) continue;
    const match = /visibleTextLength\":(\d+)/.exec(String(event.observation || ''));
    if (match) return { sequence: event.sequence, visibleTextLength: Number(match[1]) };
  }
  return null;
}

export function hasVisibleTextChangeAfter(events, baseline) {
  if (!baseline || !Number.isSafeInteger(baseline.sequence) || !Number.isSafeInteger(baseline.visibleTextLength) || !Array.isArray(events)) return false;
  return events.some(event => {
    if (event?.type !== 'dom_change' || !Number.isSafeInteger(event.sequence) || event.sequence <= baseline.sequence) return false;
    const match = /visibleTextLength\":(\d+)/.exec(String(event.observation || ''));
    return Boolean(match && Number(match[1]) !== baseline.visibleTextLength);
  });
}
