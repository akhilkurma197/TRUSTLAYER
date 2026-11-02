import http from 'node:http';
import https from 'node:https';
import tls from 'node:tls';
import dns from 'node:dns/promises';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import { randomUUID } from 'node:crypto';

const MAX_RESPONSE_BYTES = 64 * 1024;
const DEFAULT_TIMEOUT_MS = 5000;

export function parseAuthorizedProbeUrls(httpValue, httpsValue) {
  const parse = (value, protocol, label) => {
    if (!value) throw new Error(`${label} probe URL is required.`);
    let url;
    try { url = new URL(value); } catch { throw new Error(`${label} probe URL is invalid.`); }
    if (url.protocol !== protocol || url.username || url.password || url.hash || url.href.length > 2048) {
      throw new Error(`${label} probe URL must be an explicit ${protocol} URL without credentials or a fragment.`);
    }
    const permittedPort = protocol === 'http:' ? '80' : '443';
    if (url.port && url.port !== permittedPort) throw new Error(`${label} probe URL port is outside the production proxy allowlist.`);
    return url.href;
  };
  return {
    httpUrl: parse(httpValue, 'http:', 'HTTP'),
    httpsUrl: parse(httpsValue, 'https:', 'HTTPS')
  };
}

function markerFor(mode, protocol) {
  return `tl-egress-${mode}-${protocol}-${randomUUID()}`;
}

function safeError(error) {
  const code = /^[A-Z0-9_]+$/.test(String(error?.code || '')) ? error.code : null;
  const name = /^[A-Za-z][A-Za-z0-9]*$/.test(String(error?.name || '')) ? error.name : 'Error';
  return { errorName: name, errorCode: code,
    tlsError: Boolean(error?.code && /^(?:ERR_TLS|CERT_|DEPTH_ZERO|SELF_SIGNED|UNABLE_TO_VERIFY)/.test(String(error.code))) };
}

function collect(response, marker, startedAt, timeoutMs) {
  return new Promise(resolve => {
    let bytes = 0;
    let overflow = false;
    const timer = setTimeout(() => {
      response.destroy(Object.assign(new Error('response timeout'), { code: 'ETIMEDOUT' }));
    }, timeoutMs);
    response.on('data', chunk => {
      bytes += chunk.length;
      if (bytes > MAX_RESPONSE_BYTES) {
        overflow = true;
        response.destroy(Object.assign(new Error('response limit exceeded'), { code: 'RESPONSE_TOO_LARGE' }));
      }
    });
    response.on('end', () => {
      clearTimeout(timer);
      resolve({ status: response.statusCode || null, bytes, overflow,
        markerAcknowledged: response.headers?.['x-trustlayer-probe-ack'] === marker,
        ...(response.socket?.encrypted ? { tlsVerified: response.socket.authorized === true } : {}),
        durationMs: Date.now() - startedAt });
    });
    response.on('error', error => {
      clearTimeout(timer);
      resolve({ ...safeError(error), bytes, overflow, durationMs: Date.now() - startedAt });
    });
  });
}

export async function probeDirect(urlValue, { timeoutMs = DEFAULT_TIMEOUT_MS, marker = markerFor('direct', new URL(urlValue).protocol.slice(0, -1)) } = {}) {
  const url = new URL(urlValue);
  const startedAt = Date.now();
  let addresses;
  try {
    let dnsTimer;
    try {
      addresses = await Promise.race([
        dns.lookup(url.hostname, { all: true, verbatim: true }),
        new Promise((_, reject) => { dnsTimer = setTimeout(() => reject(Object.assign(new Error('DNS timeout'), { code: 'DNS_TIMEOUT' })), Math.min(timeoutMs, 2000)); })
      ]);
    } finally { clearTimeout(dnsTimer); }
    if (!addresses.length) throw Object.assign(new Error('No DNS addresses'), { code: 'ENODATA' });
  } catch (error) {
    return { markerId: marker, transport: 'direct', dnsStatus: 'FAILED', dnsAddressCount: 0,
      ...safeError(error), errorCode: error?.code || 'DNS_ERROR', durationMs: Date.now() - startedAt };
  }
  const selectedAddress = addresses[0];
  const options = { protocol: url.protocol, hostname: url.hostname, port: url.port || undefined,
    path: `${url.pathname}${url.search}`, method: 'GET', agent: false, timeout: timeoutMs,
    rejectUnauthorized: true,
    lookup: (_hostname, lookupOptions, callback) => lookupOptions?.all
      ? callback(null, [selectedAddress])
      : callback(null, selectedAddress.address, selectedAddress.family),
    headers: { 'x-trustlayer-egress-probe': marker, connection: 'close' } };
  try {
    const response = await new Promise((resolve, reject) => {
      const request = (url.protocol === 'https:' ? https : http).request(options, resolve);
      request.setTimeout(timeoutMs, () => request.destroy(Object.assign(new Error('request timeout'), { code: 'ETIMEDOUT' })));
      request.once('error', reject);
      request.end();
    });
    return { markerId: marker, transport: 'direct', dnsStatus: 'RESOLVED', dnsAddressCount: addresses.length,
      dnsFamilies: [...new Set(addresses.map(item => item.family))].sort(), ...await collect(response, marker, startedAt, timeoutMs) };
  } catch (error) {
    return { markerId: marker, transport: 'direct', dnsStatus: 'RESOLVED', dnsAddressCount: addresses.length,
      dnsFamilies: [...new Set(addresses.map(item => item.family))].sort(), ...safeError(error), durationMs: Date.now() - startedAt };
  }
}

function requestViaHttpProxy(url, proxy, marker, timeoutMs) {
  const startedAt = Date.now();
  return new Promise(resolve => {
    const request = http.request({ hostname: proxy.host, port: proxy.port, method: 'GET', path: url.href,
      agent: false, timeout: timeoutMs,
      headers: { host: url.host, 'proxy-authorization': `Basic ${Buffer.from(`${proxy.username}:${proxy.password}`).toString('base64')}`,
        'x-trustlayer-egress-probe': marker, connection: 'close' } }, response => {
      void collect(response, marker, startedAt, timeoutMs).then(result => resolve(result));
    });
    request.setTimeout(timeoutMs, () => request.destroy(Object.assign(new Error('proxy request timeout'), { code: 'ETIMEDOUT' })));
    request.once('error', error => resolve({ ...safeError(error), durationMs: Date.now() - startedAt }));
    request.end();
  });
}

function requestViaHttpsProxy(url, proxy, marker, timeoutMs) {
  const startedAt = Date.now();
  return new Promise(resolve => {
    let settled = false;
    const finish = value => { if (settled) return; settled = true; resolve(value); };
    const authority = `${url.hostname}:${url.port || 443}`;
    const connect = http.request({ hostname: proxy.host, port: proxy.port, method: 'CONNECT', path: authority,
      agent: false, timeout: timeoutMs,
      headers: { 'proxy-authorization': `Basic ${Buffer.from(`${proxy.username}:${proxy.password}`).toString('base64')}` } });
    connect.setTimeout(timeoutMs, () => connect.destroy(Object.assign(new Error('proxy CONNECT timeout'), { code: 'ETIMEDOUT' })));
    connect.once('connect', (response, socket) => {
      if (response.statusCode !== 200) {
        socket.destroy();
        finish({ status: response.statusCode || null, bytes: 0, markerAcknowledged: false, durationMs: Date.now() - startedAt });
        return;
      }
      const secure = tls.connect({ socket, servername: url.hostname, rejectUnauthorized: true });
      secure.setTimeout(timeoutMs, () => secure.destroy(Object.assign(new Error('TLS response timeout'), { code: 'ETIMEDOUT' })));
      secure.once('secureConnect', () => {
        secure.write(`GET ${url.pathname}${url.search} HTTP/1.1\r\nHost: ${url.host}\r\nX-TrustLayer-Egress-Probe: ${marker}\r\nConnection: close\r\n\r\n`);
      });
      let raw = Buffer.alloc(0);
      secure.on('data', chunk => {
        raw = Buffer.concat([raw, chunk]);
        if (raw.length > MAX_RESPONSE_BYTES + 16 * 1024) secure.destroy(Object.assign(new Error('response limit exceeded'), { code: 'RESPONSE_TOO_LARGE' }));
      });
      secure.once('end', () => {
        const headerEnd = raw.indexOf('\r\n\r\n');
        const header = headerEnd < 0 ? '' : raw.subarray(0, headerEnd).toString('latin1');
        const status = Number(header.match(/^HTTP\/\d(?:\.\d)?\s+(\d{3})/m)?.[1]) || null;
        const ack = header.match(/^x-trustlayer-probe-ack:\s*(.*?)\s*$/im)?.[1] === marker;
        finish({ status, bytes: Math.max(0, raw.length - Math.max(0, headerEnd + 4)),
          markerAcknowledged: ack, tlsVerified: secure.authorized, durationMs: Date.now() - startedAt });
      });
      secure.once('error', error => finish({ ...safeError(error), tlsVerified: secure.authorized, durationMs: Date.now() - startedAt }));
    });
    connect.once('error', error => finish({ ...safeError(error), durationMs: Date.now() - startedAt }));
    connect.end();
  });
}

export async function probeThroughProxy(urlValue, proxy, { timeoutMs = DEFAULT_TIMEOUT_MS,
  marker = markerFor('proxy', new URL(urlValue).protocol.slice(0, -1)) } = {}) {
  const url = new URL(urlValue);
  const result = url.protocol === 'https:'
    ? await requestViaHttpsProxy(url, proxy, marker, timeoutMs)
    : await requestViaHttpProxy(url, proxy, marker, timeoutMs);
  return { markerId: marker, transport: 'authenticated-proxy', transportProtocol: url.protocol === 'https:' ? 'https' : 'http', ...result };
}

export function classifyProbe(result, { expectedProxySuccess = false } = {}) {
  if (result.transport === 'direct') {
    if (Number.isInteger(result.status)) return 'FAIL';
    if (result.dnsStatus === 'RESOLVED' && ['ENETUNREACH', 'EHOSTUNREACH', 'ENETDOWN'].includes(result.errorCode)) return 'PASS';
    return 'NOT VERIFIED';
  }
  if (expectedProxySuccess) {
    return Number.isInteger(result.status) && result.status >= 200 && result.status < 300 && result.markerAcknowledged &&
      (result.transportProtocol !== 'https' || result.tlsVerified === true)
      ? 'PASS' : 'NOT VERIFIED';
  }
  return result.errorCode === 'ECONNREFUSED' ? 'PASS' : 'NOT VERIFIED';
}

export async function runProbeSet(config) {
  const urls = parseAuthorizedProbeUrls(config.httpUrl, config.httpsUrl);
  const timeoutMs = Math.max(500, Math.min(10000, Number(config.timeoutMs) || DEFAULT_TIMEOUT_MS));
  const outcomes = {};
  for (const [protocol, url] of [['http', urls.httpUrl], ['https', urls.httpsUrl]]) {
    const direct = await probeDirect(url, { timeoutMs });
    const proxied = await probeThroughProxy(url, config.proxy, { timeoutMs });
    outcomes[`direct_${protocol}`] = { ...direct, verdict: classifyProbe(direct) };
    outcomes[`proxy_${protocol}`] = { ...proxied, verdict: classifyProbe(proxied, { expectedProxySuccess: true }) };
  }
  return outcomes;
}

export async function runProxyUnavailableSet(config) {
  const urls = parseAuthorizedProbeUrls(config.httpUrl, config.httpsUrl);
  const timeoutMs = Math.max(500, Math.min(10000, Number(config.timeoutMs) || DEFAULT_TIMEOUT_MS));
  const outcomes = {};
  for (const [protocol, url] of [['http', urls.httpUrl], ['https', urls.httpsUrl]]) {
    const result = await probeThroughProxy(url, config.proxy, { timeoutMs });
    outcomes[`proxy_unavailable_${protocol}`] = { ...result,
      verdict: classifyProbe(result, { expectedProxySuccess: false }) };
  }
  return outcomes;
}

async function runAsContainerCli() {
  const mode = process.argv[2];
  if (!['runProbeSet', 'runProxyUnavailableSet'].includes(mode)) {
    process.stderr.write('Invalid probe mode.\n');
    process.exitCode = 2;
    return;
  }
  try {
    let raw = '';
    for await (const chunk of process.stdin) raw += chunk;
    const result = await ({ runProbeSet, runProxyUnavailableSet })[mode](JSON.parse(raw));
    process.stdout.write(JSON.stringify(result));
  } catch {
    process.stderr.write('Probe execution failed; details redacted.\n');
    process.exitCode = 2;
  }
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  await runAsContainerCli();
}
