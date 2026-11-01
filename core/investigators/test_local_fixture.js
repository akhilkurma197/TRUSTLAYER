import net from 'node:net';

function isPrivateFixtureAddress(address) {
  if (net.isIPv4(address)) {
    const octets = address.split('.').map(Number);
    return octets[0] === 127 || octets[0] === 10 ||
      (octets[0] === 172 && octets[1] >= 16 && octets[1] <= 31) ||
      (octets[0] === 192 && octets[1] === 168);
  }
  return address === '::1' || /^f[cd][0-9a-f]{2}:/i.test(address);
}

export function normalizeTestLocalFixturePolicy(input) {
  if (!input || typeof input !== 'object' || Array.isArray(input) ||
      typeof input.hostname !== 'string' || !/^trustlayer-fixture-[a-z0-9-]{8,40}\.test$/.test(input.hostname) ||
      typeof input.address !== 'string' || !net.isIP(input.address) || !isPrivateFixtureAddress(input.address) ||
      !Number.isInteger(input.port) || input.port < 1024 || input.port > 65535 ||
      typeof input.networkName !== 'string' || !/^trustlayer-fixture-net-[a-f0-9]{8,24}$/.test(input.networkName)) {
    throw new TypeError('Invalid test-only local fixture policy.');
  }
  return Object.freeze({ hostname: input.hostname, address: input.address, port: input.port, networkName: input.networkName });
}

export function validateTestLocalFixtureUrl(urlValue, policy) {
  if (!policy) return null;
  let url;
  try { url = new URL(urlValue); } catch { return null; }
  const port = url.port ? Number(url.port) : (url.protocol === 'https:' ? 443 : 80);
  if (url.protocol !== 'http:' || url.username || url.password || url.hostname.toLowerCase() !== policy.hostname ||
      port !== policy.port || !isPrivateFixtureAddress(policy.address)) return null;
  return {
    allowed: true,
    blockedReason: null,
    resolvedIps: [policy.address],
    canonicalUrl: url.href,
    connectAddress: policy.address,
    testFixture: true
  };
}

export function validateTestLocalFixturePolicyFromProcess(input) {
  if (process.env.NODE_ENV !== 'test') throw new Error('Test fixture policy is available only in NODE_ENV=test.');
  return normalizeTestLocalFixturePolicy(input);
}
