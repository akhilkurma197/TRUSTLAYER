export function fixtureCredentialMarker(headers) {
  return `TRUSTLAYER_FIXTURE_CREDENTIALS cookie=${Boolean(headers?.cookie)} authorization=${Boolean(headers?.authorization)} proxyAuth=${Boolean(headers?.['proxy-authorization'])}`;
}

export function summarizeFixtureCredentialObservations(logs) {
  const observations = [];
  const marker = /^TRUSTLAYER_FIXTURE_CREDENTIALS cookie=(true|false) authorization=(true|false) proxyAuth=(true|false)$/gm;
  for (const match of String(logs).matchAll(marker)) {
    observations.push({ cookie: match[1] === 'true', authorization: match[2] === 'true', proxyAuth: match[3] === 'true' });
  }
  return {
    observationCount: observations.length,
    received: {
      cookie: observations.some(item => item.cookie),
      authorization: observations.some(item => item.authorization),
      proxyAuth: observations.some(item => item.proxyAuth)
    }
  };
}
