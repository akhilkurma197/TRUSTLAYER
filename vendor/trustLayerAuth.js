(() => {
  let authPromise = null;
  let promptSuppressed = false;

  const sameOriginFetch = (url, options = {}) => fetch(url, {
    ...options,
    credentials: options.credentials || 'same-origin'
  });

  async function establishLocalSession() {
    return sameOriginFetch('/api/auth/session', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: '{}'
    });
  }

  async function establishSession(token) {
    const response = await sameOriginFetch('/api/auth/session', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ token })
    });
    if (!response.ok) window.alert('Trust Layer API authentication failed. Check the configured token and try again.');
    return response.ok;
  }

  async function authenticateBrowser() {
    // Local development accepts this empty, same-origin exchange only when the
    // backend is explicitly configured for loopback development and the TCP
    // peer is loopback. Production continues to fall through to token auth.
    const local = await establishLocalSession();
    if (local.ok) return true;
    const token = window.prompt('Enter the Trust Layer API token configured by the server operator:');
    if (!token) return false;
    return establishSession(token);
  }

  window.trustLayerApiFetch = async function(url, options = {}) {
    const response = await sameOriginFetch(url, options);
    if (response.status !== 401 || promptSuppressed) return response;
    if (!authPromise) {
      authPromise = (async () => {
        return authenticateBrowser();
      })();
    }
    let authenticated;
    try { authenticated = await authPromise; }
    catch (error) { authPromise = null; throw error; }
    if (!authenticated) {
      authPromise = null;
      promptSuppressed = true;
      return response;
    }
    const retry = await sameOriginFetch(url, options);
    if (retry.status === 401) {
      authPromise = null;
      promptSuppressed = true;
      window.alert('Trust Layer API session expired. Authenticate again to continue.');
    }
    return retry;
  };

  window.trustLayerClearApiSession = async function() {
    const response = await sameOriginFetch('/api/auth/clear', { method: 'POST' });
    if (!response.ok) {
      window.alert('Trust Layer could not clear the API session.');
      return false;
    }
    authPromise = null;
    promptSuppressed = true;
    window.alert('API session cleared. Use Replace API token to sign in again.');
    return true;
  };

  window.trustLayerReplaceApiToken = async function() {
    const cleared = await sameOriginFetch('/api/auth/clear', { method: 'POST' });
    if (!cleared.ok) {
      window.alert('Trust Layer could not replace the API session.');
      return false;
    }
    authPromise = null;
    promptSuppressed = false;
    let authenticated;
    try { authenticated = await authenticateBrowser(); }
    catch { window.alert('Trust Layer API authentication could not be completed.'); return false; }
    if (!authenticated) { promptSuppressed = true; return false; }
    promptSuppressed = false;
    authPromise = Promise.resolve(true);
    window.alert('Trust Layer API session replaced.');
    return true;
  };
})();
