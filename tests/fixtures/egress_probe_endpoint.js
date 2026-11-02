import fs from 'node:fs';
import http from 'node:http';
import https from 'node:https';
import path from 'node:path';
import tls from 'node:tls';
import { fileURLToPath } from 'node:url';

const ACK_HEADER = 'X-TrustLayer-Probe-Ack';
const MARKER_HEADER = 'x-trustlayer-egress-probe';
const RESPONSE_BODY = 'Trust Layer controlled egress probe acknowledged.\n';
const MAX_MARKER_LENGTH = 128;

function parseMarker(value, scheme) {
  if (typeof value !== 'string' || value.length > MAX_MARKER_LENGTH) return null;
  const markerPattern = /^tl-egress-(direct|proxy)-(http|https)-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
  if (!markerPattern.test(value) || !value.toLowerCase().includes(`-${scheme}-`)) return null;
  return value;
}

export function createEgressProbeHandler({ scheme, logger = line => process.stdout.write(`${line}\n`) } = {}) {
  if (scheme !== 'http' && scheme !== 'https') throw new Error('Probe endpoint scheme must be http or https.');
  return (request, response) => {
    const marker = parseMarker(request.headers[MARKER_HEADER], scheme);
    if (request.method !== 'GET' || request.url !== '/probe' || !marker) {
      response.writeHead(400, { 'content-type': 'text/plain; charset=utf-8', 'cache-control': 'no-store',
        'content-length': String(Buffer.byteLength('Invalid probe')), connection: 'close' });
      response.end('Invalid probe');
      return;
    }

    const peerIp = request.socket.remoteAddress || 'unknown';
    logger(JSON.stringify({ event: 'trustlayer-egress-probe', scheme, marker, peerIp }));
    response.writeHead(200, {
      [ACK_HEADER]: marker,
      'content-type': 'text/plain; charset=utf-8',
      'cache-control': 'no-store, no-cache, must-revalidate',
      'content-length': Buffer.byteLength(RESPONSE_BODY),
      connection: 'close'
    });
    response.end(RESPONSE_BODY);
  };
}

function validPort(value, name) {
  const port = Number(value);
  if (!Number.isInteger(port) || port < 0 || port > 65535) throw new Error(`${name} must be an integer from 0 to 65535.`);
  return port;
}

export function createEgressProbeServers({ host = '127.0.0.1', httpPort = 8080, httpsPort = 8443,
  tlsKey, tlsCert, logger } = {}) {
  if (!tlsKey || !tlsCert) throw new Error('HTTPS requires an explicit TLS key and certificate.');
  const key = Buffer.isBuffer(tlsKey) ? tlsKey : fs.readFileSync(tlsKey);
  const cert = Buffer.isBuffer(tlsCert) ? tlsCert : fs.readFileSync(tlsCert);
  // Parse at startup so malformed or mismatched TLS material fails before either listener is exposed.
  tls.createSecureContext({ key, cert });
  const httpServer = http.createServer(createEgressProbeHandler({ scheme: 'http', logger }));
  const httpsServer = https.createServer({ key, cert, minVersion: 'TLSv1.2' },
    createEgressProbeHandler({ scheme: 'https', logger }));
  return [
    { server: httpServer, host, port: validPort(httpPort, 'HTTP port'), scheme: 'http' },
    { server: httpsServer, host, port: validPort(httpsPort, 'HTTPS port'), scheme: 'https' }
  ];
}

function listen(server, host, port) {
  return new Promise((resolve, reject) => {
    const onError = error => { server.off('listening', onListening); reject(error); };
    const onListening = () => { server.off('error', onError); resolve(server.address()); };
    server.once('error', onError);
    server.once('listening', onListening);
    server.listen(port, host);
  });
}

async function main() {
  const host = process.env.TRUSTLAYER_EGRESS_BIND_HOST || '127.0.0.1';
  const servers = createEgressProbeServers({
    host,
    httpPort: process.env.TRUSTLAYER_EGRESS_HTTP_PORT || '8080',
    httpsPort: process.env.TRUSTLAYER_EGRESS_HTTPS_PORT || '8443',
    tlsKey: process.env.TRUSTLAYER_EGRESS_TLS_KEY,
    tlsCert: process.env.TRUSTLAYER_EGRESS_TLS_CERT
  });
  const addresses = [];
  try {
    for (const { server, host: bindHost, port } of servers) addresses.push(await listen(server, bindHost, port));
  } catch (error) {
    await Promise.all(servers.map(({ server }) => new Promise(resolve => {
      if (!server.listening) return resolve();
      server.close(() => resolve());
    })));
    throw error;
  }
  for (let index = 0; index < servers.length; index++) {
    process.stdout.write(`Trust Layer probe endpoint listening: scheme=${servers[index].scheme} address=${addresses[index].address} port=${addresses[index].port}\n`);
  }

  let stopping = false;
  const stop = () => {
    if (stopping) return;
    stopping = true;
    const deadline = setTimeout(() => process.exit(1), 5000);
    deadline.unref();
    Promise.all(servers.map(({ server }) => new Promise(resolve => server.close(resolve))))
      .then(() => { clearTimeout(deadline); process.exit(0); }, () => process.exit(1));
  };
  process.once('SIGINT', stop);
  process.once('SIGTERM', stop);
}

if (process.argv[1] && fileURLToPath(import.meta.url) === path.resolve(process.argv[1])) {
  main().catch(error => {
    // Startup errors contain no request data; avoid printing key/certificate paths or contents.
    process.stderr.write(`Trust Layer probe endpoint startup failed: ${error.code || error.name || 'Error'}\n`);
    process.exitCode = 1;
  });
}
