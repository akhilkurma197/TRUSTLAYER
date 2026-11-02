import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { test } from 'node:test';
import { parseAuthorizedProbeUrls } from './helpers/external_egress_probe.js';
import { cleanupDockerContainers, readOnlyFileBindMount } from './helpers/docker_external_egress_resources.js';

const enabled = process.env.TRUSTLAYER_DOCKER_EXTERNAL_EGRESS === '1';

test('authorized external egress boundary probe in the production worker network profile', { skip: !enabled }, async () => {
  const urls = parseAuthorizedProbeUrls(process.env.TRUSTLAYER_EGRESS_HTTP_URL,
    process.env.TRUSTLAYER_EGRESS_HTTPS_URL);
  const isolatedNetwork = process.env.TRUSTLAYER_ISOLATED_NETWORK || 'trustlayer-isolated-net';
  const egressNetwork = process.env.TRUSTLAYER_EGRESS_NETWORK || 'trustlayer-egress-net';
  const suffix = randomUUID().replaceAll('-', '').slice(0, 16);
  const proxyName = `trustlayer-egress-audit-${suffix}`;
  const proxyAlias = `trustlayer-egress-audit-${suffix}`;
  const probeName = `trustlayer-worker-egress-audit-${suffix}`;
  const username = randomUUID();
  const password = randomUUID();
  const docker = (args, options = {}) => {
    try {
      return execFileSync('docker', ['--context', process.env.DOCKER_CONTEXT || 'desktop-linux', ...args],
        { encoding: 'utf8', timeout: 20000, maxBuffer: 1024 * 1024, ...options }).trim();
    } catch (error) {
      throw new Error(`Docker ${args[0] || 'operation'} failed; exit=${Number.isInteger(error.status) ? error.status : 'unavailable'}. Details are intentionally redacted.`);
    }
  };
  const inspectInternal = name => docker(['network', 'inspect', '--format={{.Internal}}', name]) === 'true';
  let probeCreated = false;
  let proxyCreated = false;
  let primaryFailure = null;
  try {
    assert.equal(inspectInternal(isolatedNetwork), true, 'worker network must be Docker-internal');
    assert.equal(inspectInternal(egressNetwork), false, 'proxy egress network must not be marked internal');

    docker(['run', '-d', '--name', proxyName, `--network=${isolatedNetwork}`, `--network-alias=${proxyAlias}`,
      '--user=pwuser', '--read-only', '--tmpfs', '/tmp:rw,noexec,nosuid,size=32m',
      '--tmpfs', '/output:rw,noexec,nosuid,size=16m,uid=1001,gid=1001,mode=0700', '--cap-drop=ALL',
      '--security-opt=no-new-privileges', '--pids-limit=32', '--memory=128m', '--cpus=0.25',
      '--env=TRUSTLAYER_DISABLE_DOH_FALLBACK=1',
      '--entrypoint', 'node', 'trustlayer-worker:latest', 'worker/egress_proxy_worker.js',
      `--username=${username}`, `--password=${password}`, '--correlationId=external-egress-audit', '--output=/output/egress.json']);
    proxyCreated = true;
    docker(['network', 'connect', egressNetwork, proxyName]);

    let ready = false;
    for (let attempt = 0; attempt < 30 && !ready; attempt++) {
      try {
        docker(['exec', proxyName, 'node', '-e',
          "const n=require('node:net').connect(3128,'127.0.0.1');n.on('connect',()=>{n.destroy();process.exit(0)});n.on('error',()=>process.exit(1))"]);
        ready = true;
      } catch { await new Promise(resolve => setTimeout(resolve, 100)); }
    }
    assert.equal(ready, true, 'authenticated proxy process must become ready before probing');

    const proxyAddress = `${proxyAlias}:3128`;
    const config = JSON.stringify({ ...urls, proxy: { host: proxyAddress.split(':')[0], port: 3128, username, password }, timeoutMs: 5000 });
    const helperPath = fileURLToPath(new URL('./helpers/external_egress_probe.js', import.meta.url));
    const helperMount = readOnlyFileBindMount(helperPath, '/home/pwuser/app/worker/external_egress_probe.mjs');
    docker(['create', '--name', probeName, `--network=${isolatedNetwork}`, '--user=pwuser', '--init', '--read-only',
      '--tmpfs', '/tmp:rw,noexec,nosuid,size=64m', '--tmpfs', '/dev/shm:rw,noexec,nosuid,size=64m',
      '--tmpfs', '/output:rw,noexec,nosuid,size=24m,uid=1001,gid=1001,mode=0700', '--cap-drop=ALL', '--cap-add=SYS_CHROOT',
      '--security-opt=seccomp=worker/chromium-seccomp.json', '--security-opt=no-new-privileges',
      '--pids-limit=128', '--memory=512m', '--cpus=1.0', '--env=HTTP_PROXY=', '--env=HTTPS_PROXY=',
      '--env=http_proxy=', '--env=https_proxy=', `--mount=${helperMount}`,
      '--entrypoint', 'node', 'trustlayer-worker:latest', '-e', 'setInterval(()=>{},1000)']);
    probeCreated = true;
    docker(['start', probeName]);
    const runProbeContainer = mode => JSON.parse(docker(['exec', '-i', probeName, 'node',
      '/home/pwuser/app/worker/external_egress_probe.mjs', mode], { input: config }));
    const outcomes = runProbeContainer('runProbeSet');
    const report = Object.fromEntries(Object.entries(outcomes).map(([key, value]) => [key, {
      verdict: value.verdict, markerId: value.markerId, status: value.status ?? null,
      errorCode: value.errorCode ?? null, errorName: value.errorName ?? null,
      dnsStatus: value.dnsStatus ?? null, dnsAddressCount: value.dnsAddressCount ?? null,
      dnsFamilies: value.dnsFamilies ?? [],
      tlsError: value.tlsError ?? false, tlsVerified: value.tlsVerified ?? null,
      durationMs: value.durationMs, markerAcknowledged: value.markerAcknowledged ?? false
    }]));
    console.log(`External egress probe outcomes (no URLs or credentials): ${JSON.stringify(report)}`);
    assert.ok(Object.keys(outcomes).length === 4);
    assert.ok(new Set(Object.values(outcomes).map(item => item.markerId)).size === 4,
      'each direct/proxy protocol request must use a unique marker');
    assert.ok(Object.values(outcomes).every(item => item.verdict !== undefined));
    assert.equal(outcomes.proxy_http.verdict, 'PASS', 'HTTP proxy control endpoint must acknowledge its marker');
    assert.equal(outcomes.proxy_https.verdict, 'PASS', 'HTTPS proxy control endpoint must acknowledge its marker with verified TLS');
    assert.notEqual(outcomes.direct_http.verdict, 'FAIL', 'successful direct HTTP is a proxy-bypass failure');
    assert.notEqual(outcomes.direct_https.verdict, 'FAIL', 'successful direct HTTPS is a proxy-bypass failure');
    console.log('Endpoint log correlation: NOT VERIFIED by this process; correlate each markerId with the authorized endpoint access logs and peer address.');

    await new Promise(resolve => setTimeout(resolve, 250));
    let proxyEvidence = null;
    for (let attempt = 0; attempt < 5 && !proxyEvidence; attempt++) {
      try {
        proxyEvidence = JSON.parse(docker(['exec', proxyName, 'node', '-e',
          "const f=require('node:fs');process.stdout.write(f.readFileSync('/output/egress.json','utf8'))"]));
      } catch { await new Promise(resolve => setTimeout(resolve, 100)); }
    }
    const proxyDns = proxyEvidence ? [...(proxyEvidence.allowedRequests || []), ...(proxyEvidence.blockedRequests || [])]
      .map(item => ({ method: item.method, status: item.status ?? null,
        resolvedAddressCount: Array.isArray(item.resolvedIps) ? item.resolvedIps.length : null,
        selectedAddressFamily: item.targetIp?.includes(':') ? 6 : item.targetIp ? 4 : null,
        blocked: Boolean(item.type) })) : [];
    console.log(`Proxy DNS/connection evidence (hostnames and IPs omitted): ${JSON.stringify(proxyDns)}`);
    docker(['stop', '--time=2', proxyName]);
    const unavailable = runProbeContainer('runProxyUnavailableSet');
    const unavailableReport = Object.fromEntries(Object.entries(unavailable).map(([key, value]) => [key, {
      verdict: value.verdict, markerId: value.markerId, status: value.status ?? null,
      errorCode: value.errorCode ?? null, errorName: value.errorName ?? null, durationMs: value.durationMs
    }]));
    console.log(`Proxy-unavailable outcomes (no URLs or credentials): ${JSON.stringify(unavailableReport)}`);
    assert.equal(unavailable.proxy_unavailable_http.verdict, 'PASS', 'dead proxy must refuse HTTP without direct fallback');
    assert.equal(unavailable.proxy_unavailable_https.verdict, 'PASS', 'dead proxy must refuse HTTPS without direct fallback');
  } catch (error) {
    primaryFailure = error;
  }
  const resources = [probeCreated ? probeName : null, proxyCreated ? proxyName : null].filter(Boolean);
  const cleanupFailures = cleanupDockerContainers(resources, name => docker(['rm', '-f', name]));
  if (primaryFailure && cleanupFailures.length) {
    throw new AggregateError([primaryFailure, new Error(`Cleanup failed for ${cleanupFailures.length} Docker container(s).`)],
      'External-egress test failed and Docker cleanup was incomplete.');
  }
  if (primaryFailure) throw primaryFailure;
  if (cleanupFailures.length) throw new Error(`External-egress test cleanup failed for ${cleanupFailures.length} Docker container(s).`);
});
