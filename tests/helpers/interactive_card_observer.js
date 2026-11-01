export function installInteractiveCardObserver() {
  const marker = '[trustlayer-ui-card-state]';
  const snapshot = reason => {
    const view = document.getElementById('view-overview');
    const card = document.getElementById('ov-interactive-browser-card');
    const status = document.getElementById('interactive-status');
    const cardStyle = card ? getComputedStyle(card) : null;
    console.info(marker + JSON.stringify({
      reason,
      path: location.pathname,
      overviewActive: view?.classList.contains('active') ?? false,
      cardExists: Boolean(card),
      cardParentId: card?.parentElement?.id || null,
      cardDisplay: cardStyle?.display || null,
      cardVisibility: cardStyle?.visibility || null,
      interactiveStatus: status?.textContent?.trim().slice(0, 24) || null
    }));
  };

  const observe = () => {
    const view = document.getElementById('view-overview');
    const card = document.getElementById('ov-interactive-browser-card');
    if (!view || !card) return;
    snapshot('initial');
    const observer = new MutationObserver(records => {
      if (records.some(record => record.target === view || record.target === card)) snapshot('attribute-change');
    });
    observer.observe(view, { attributes: true, attributeFilter: ['class'] });
    observer.observe(card, { attributes: true, attributeFilter: ['style', 'class'] });
  };
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', observe, { once: true });
  else observe();
}
