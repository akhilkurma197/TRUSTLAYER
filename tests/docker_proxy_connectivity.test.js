import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { randomUUID } from 'node:crypto';
import { test } from 'node:test';

const enabled = process.env.TRUSTLAYER_DOCKER_INTEGRATION === '1';

test('local-only worker sandbox and authenticated proxy checks (external egress not tested)', { skip: !enabled }, async () => {
  const name = `trustlayer-egress-test-${process.pid}-${Date.now()}`;
  const browserName = `trustlayer-browser-test-${process.pid}-${Date.now()}`;
  const quotaName = `trustlayer-output-quota-${process.pid}-${Date.now()}`;
  const failedJobName = `trustlayer-failed-job-${process.pid}-${Date.now()}`;
  const timeoutJobName = `trustlayer-timeout-job-${process.pid}-${Date.now()}`;
  const cancelJobName = `trustlayer-cancel-job-${process.pid}-${Date.now()}`;
  const repeatedBrowserName = `trustlayer-browser-repeat-${process.pid}-${Date.now()}`;
  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'trustlayer-proxy-test-'));
  const username = randomUUID();
  const password = randomUUID();
  const docker = args => execFileSync('docker', args, { encoding: 'utf8', timeout: 20000 }).trim();
  const dockerQuiet = args => execFileSync('docker', args, { encoding: 'utf8', timeout: 20000,
    stdio: ['ignore', 'pipe', 'ignore'] }).trim();
  const readOutput = (container, name, destination, maxBytes) => {
    const bytes = execFileSync('docker', ['exec', container, 'node', '-e',
      `process.stdout.write(require('node:fs').readFileSync('/output/${name}'))`],
    { encoding: null, timeout: 10000, maxBuffer: maxBytes + 1024 * 1024 });
    if (bytes.length > maxBytes) throw new Error('Worker output exceeded test transfer cap.');
    fs.writeFileSync(destination, bytes);
  };
  try {
    const isolatedNetwork = JSON.parse(docker(['network', 'inspect', '--format={{json .Internal}}', 'trustlayer-isolated-net']));
    assert.equal(isolatedNetwork, true, 'browser network must be Docker-internal');
    const quotaOutput = docker([
      'run', '--name', quotaName, '--network=none', '--read-only', '--user=pwuser',
      '--user=pwuser', '--tmpfs', '/output:rw,noexec,nosuid,size=1m,uid=1001,gid=1001,mode=0700', '--memory=32m',
      '--entrypoint', 'node', 'trustlayer-worker:latest', '-e',
      "const fs=require('node:fs');const b=Buffer.alloc(256*1024);let i=0;try{for(;i<20;i++)fs.writeFileSync('/output/temp-'+i,b);console.log('QUOTA_NOT_ENFORCED')}catch(e){console.log('WRITE_FAILURE='+e.code+' files='+i);if(e.code!=='ENOSPC')process.exitCode=2}"
    ]);
    assert.match(quotaOutput, /WRITE_FAILURE=ENOSPC/, 'tmpfs must stop oversized and accumulated temporary writes');
    const quotaState = docker(['inspect', '--format={{.State.ExitCode}}', quotaName]);
    assert.equal(quotaState, '0');
    docker(['rm', quotaName]);
    assert.throws(() => dockerQuiet(['inspect', quotaName]));
    docker([
      'run', '-d', '--name', name,
      '--network=trustlayer-isolated-net', '--network-alias=trustlayer-egress',
      '--user=pwuser', '--read-only', '--tmpfs', '/tmp:rw,noexec,nosuid,size=32m',
      '--tmpfs', '/output:rw,noexec,nosuid,size=16m,uid=1001,gid=1001,mode=0700',
      '--cap-drop=ALL', '--security-opt=no-new-privileges', '--memory=128m', '--cpus=0.25',
      '--entrypoint', 'node', 'trustlayer-worker:latest',
      'worker/egress_proxy_worker.js', `--username=${username}`, `--password=${password}`,
      '--output=/output/egress.json'
    ]);
    docker(['network', 'connect', 'trustlayer-egress-net', name]);
    await new Promise(resolve => setTimeout(resolve, 500));

    const checkProxy = `
      const http = require('node:http');
      const request = http.get({
        hostname: 'trustlayer-egress',
        port: 3128,
        path: 'http://127.0.0.1/',
        headers: { 'proxy-authorization': 'Basic ${Buffer.from(`${username}:${password}`).toString('base64')}' }
      }, response => {
        console.log('PROXY_HTTP_STATUS=' + response.statusCode);
        response.resume();
      });
      request.on('error', error => { console.error(error.message); process.exitCode = 2; });
    `;
    const output = docker([
      'run', '--rm', '--network=trustlayer-isolated-net',
      '--entrypoint', 'node', 'trustlayer-worker:latest', '-e', checkProxy
    ]);

    // Local-only check: the proxy must be reachable on the internal network
    // and reject loopback under the SSRF policy. Direct external egress is not
    // tested by this test.
    assert.match(output, /PROXY_HTTP_STATUS=403/);

    // Start the actual browser worker against a loopback target. The proxy
    // blocks it locally, so this exercises the container without contacting a
    // public website. Inspect the live Docker configuration, not worker claims.
    docker([
      'run', '-d', '--name', browserName,
      '--network=trustlayer-isolated-net',
      '--user=pwuser', '--init', '--read-only',
      '--tmpfs', '/tmp:rw,noexec,nosuid,size=64m',
      '--tmpfs', '/dev/shm:rw,noexec,nosuid,size=64m',
      '--tmpfs', '/output:rw,noexec,nosuid,size=24m,uid=1001,gid=1001,mode=0700',
      '--cap-drop=ALL', '--cap-add=SYS_CHROOT',
      '--security-opt=seccomp=worker/chromium-seccomp.json',
      '--security-opt=no-new-privileges',
      '--pids-limit=128', '--memory=512m', '--cpus=1.0',
      'trustlayer-worker:latest',
      '--url=http://127.0.0.1/private/alice?token=runtime-secret', '--jobId=runtime-audit',
      '--proxy=http://trustlayer-egress:3128',
      `--proxyUsername=${username}`, `--proxyPassword=${password}`,
      '--output=/output/runtime-result.json', '--screenshot=/output/runtime.png',
      '--initialScreenshot=/output/runtime-initial.png',
      '--captureDelayMs=0', '--timeout=20000', '--keepAlive=10000'
    ]);

    const hostConfig = JSON.parse(docker(['inspect', `--format={{json .HostConfig}}`, browserName]));
    const configuredUser = docker(['inspect', '--format={{.Config.User}}', browserName]);
    const networks = JSON.parse(docker(['inspect', '--format={{json .NetworkSettings.Networks}}', browserName]));
    assert.equal(configuredUser, 'pwuser');
    assert.equal(hostConfig.Privileged, false);
    assert.equal(hostConfig.ReadonlyRootfs, true);
    assert.ok(hostConfig.CapDrop.includes('ALL'));
    assert.deepEqual(hostConfig.CapAdd, ['CAP_SYS_CHROOT']);
    assert.equal(hostConfig.PidsLimit, 128);
    assert.equal(hostConfig.Memory, 512 * 1024 * 1024);
    assert.equal(hostConfig.NanoCpus, 1_000_000_000);
    assert.ok(hostConfig.SecurityOpt.some(value => value.startsWith('seccomp=')));
    assert.ok(hostConfig.SecurityOpt.some(value => value.startsWith('no-new-privileges')));
    assert.deepEqual(Object.keys(hostConfig.Tmpfs).sort(), ['/dev/shm', '/output', '/tmp']);
    assert.ok(Object.values(hostConfig.Tmpfs).every(value => /noexec/.test(value) && /nosuid/.test(value) && /size=\d+m/.test(value)));
    assert.match(hostConfig.Tmpfs['/output'], /size=24m/);
    assert.deepEqual(hostConfig.Binds || [], [], 'worker output must not use an unquotaed host bind mount');
    assert.equal(hostConfig.NetworkMode, 'trustlayer-isolated-net');
    assert.deepEqual(Object.keys(networks), ['trustlayer-isolated-net']);
    assert.ok(Number.parseInt(docker(['exec', browserName, 'node', '-p', 'process.getuid()']), 10) > 0);

    const filesystemCheck = JSON.parse(docker(['exec', browserName, 'node', '-e',
      "const f=require('node:fs');let root='unexpected';try{f.writeFileSync('/home/pwuser/app/.runtime-check','x')}catch(e){root=e.code}f.writeFileSync('/tmp/.runtime-check','x');f.unlinkSync('/tmp/.runtime-check');console.log(JSON.stringify({root}))"]));
    assert.equal(filesystemCheck.root, 'EROFS');

    const processStatus = docker(['exec', browserName, 'node', '-e',
      "const s=require('node:fs').readFileSync('/proc/self/status','utf8');console.log(JSON.stringify(Object.fromEntries(s.split('\\n').filter(x=>/^(NoNewPrivs|Seccomp|Cap(?:Inh|Prm|Eff|Bnd|Amb)):/.test(x)).map(x=>x.split(/:\\s+/)))))"]);
    const restrictedProcess = JSON.parse(processStatus);
    assert.equal(restrictedProcess.NoNewPrivs, '1');
    assert.equal(restrictedProcess.Seccomp, '2');
    for (const field of ['CapInh', 'CapPrm', 'CapEff', 'CapBnd', 'CapAmb']) {
      assert.equal(Number.parseInt(restrictedProcess[field], 16) & ~0x40000, 0,
        `${field} contains capabilities beyond SYS_CHROOT: ${JSON.stringify(restrictedProcess)}`);
    }

    const readyFile = path.join(tempDir, 'runtime-result.json.ready');
    for (let attempt = 0; attempt < 300 && !fs.existsSync(readyFile); attempt++) {
      try {
        const artifactState = docker(['exec', browserName, 'node', '-e',
          "const f=require('node:fs');console.log(f.existsSync('/output/runtime-result.json.ready')?'READY':(f.existsSync('/output/runtime-result.json')?'FAILED':'WAIT'))"]);
        if (artifactState === 'READY') readOutput(browserName, 'runtime-result.json.ready', readyFile, 2 * 1024 * 1024);
        else if (artifactState === 'FAILED') {
          const failureJson = execFileSync('docker', ['exec', browserName, 'node', '-e',
            "process.stdout.write(require('node:fs').readFileSync('/output/runtime-result.json'))"], { encoding: 'utf8', timeout: 10000, maxBuffer: 2 * 1024 * 1024 });
          const failure = JSON.parse(failureJson);
          fs.writeFileSync(path.join(tempDir, 'safe-failure.json'), JSON.stringify({
            status: failure.status,
            errorName: /^[A-Za-z][A-Za-z0-9]*$/.test(String(failure.error || '').split(':')[0])
              ? String(failure.error).split(':')[0] : 'WorkerError'
          }));
          break;
        }
      } catch {}
      if (fs.existsSync(readyFile)) {
        try { readOutput(browserName, 'runtime.png', path.join(tempDir, 'runtime.png'), 5 * 1024 * 1024); } catch {}
      } else {
        try { if (docker(['inspect', '--format={{.State.Running}}', browserName]) === 'false') break; } catch { break; }
      }
      await new Promise(resolve => setTimeout(resolve, 100));
    }
    if (!fs.existsSync(readyFile)) {
      let workerLogs = '';
      let workerState = '';
      let workerResult = '';
      try { workerLogs = docker(['logs', browserName]).slice(-16 * 1024); } catch (error) { workerLogs = String(error.stderr || error.message).slice(-16 * 1024); }
      try { workerState = docker(['inspect', '--format={{.State.Status}} exit={{.State.ExitCode}}', browserName]); } catch (error) { workerState = String(error.stderr || error.message).slice(-2048); }
      try { workerResult = fs.readFileSync(path.join(tempDir, 'safe-failure.json'), 'utf8'); } catch {}
      if (!workerResult) {
        try {
          readOutput(browserName, 'runtime-result.json', path.join(tempDir, 'runtime-result.json'), 2 * 1024 * 1024);
          const failure = JSON.parse(fs.readFileSync(path.join(tempDir, 'runtime-result.json'), 'utf8'));
          workerResult = JSON.stringify({ status: failure.status, errorName: String(failure.error || '').split(':')[0] });
        } catch {}
      }
      assert.fail(`sandboxed worker did not publish a rendered result; state=${workerState}; logs=${workerLogs.slice(-2048)}; result=${workerResult}`);
    }
    const runtimeResult = JSON.parse(fs.readFileSync(readyFile, 'utf8'));
    assert.equal(runtimeResult.browserDiagnostics.browser, 'Chromium');
    assert.equal(runtimeResult.browserDiagnostics.chromiumSandbox, true);
    assert.equal(runtimeResult.browserDiagnostics.chromiumSandboxVerification.status, 'VERIFIED');
    assert.equal(runtimeResult.isolationReport.chromiumSandboxVerification.status, 'VERIFIED');
    assert.ok(runtimeResult.isolationReport.chromiumSandboxVerification.rendererChecks.length > 0);
    assert.ok(runtimeResult.isolationReport.chromiumSandboxVerification.rendererChecks.every(check =>
      check.verified && check.processEvidenceFresh && check.processEvidenceStable && check.filtersAddedBeyondContainer &&
      check.namespacesIsolated && check.parentHasZygoteSandbox));
    assert.equal(runtimeResult.httpStatus, 403);
    assert.equal(runtimeResult.renderStatus, 'ACCESS_DENIED');
    assert.equal(runtimeResult.status, 'BLOCKED');
    const operationalTelemetry = JSON.stringify({
      blockedRequests: runtimeResult.blockedRequests,
      networkEvents: runtimeResult.networkEvents,
      redirectChain: runtimeResult.redirectChain,
      responseHeaders: runtimeResult.responseHeaders
    });
    assert.doesNotMatch(operationalTelemetry, /alice|runtime-secret/);
    assert.ok(runtimeResult.networkEvents.some(event => event.url === 'http://127.0.0.1/[path-redacted]'));
    const chromiumProcesses = JSON.parse(docker(['exec', browserName, 'node', '-e',
      "const fs=require('node:fs');const p=fs.readdirSync('/proc').filter(x=>/^\\d+$/.test(x));const c=p.map(pid=>{try{return fs.readFileSync('/proc/'+pid+'/cmdline','utf8').replace(/\\0/g,' ')}catch{return ''}}).filter(x=>/chrome|chromium/i.test(x));console.log(JSON.stringify(c))"]));
    assert.ok(chromiumProcesses.length > 0, 'a Chromium process should be running during the retained render window');
    assert.ok(chromiumProcesses.every(command => !command.includes('--no-sandbox')));

    // Query Chromium's own supported sandbox diagnostic in a separate
    // container with the worker's current security profile. An unavailable
    // diagnostic is recorded distinctly from an affirmative result.
    const sandboxProbe = JSON.parse(docker([
      'run', '--rm', '--network=trustlayer-isolated-net', '--user=pwuser', '--init', '--read-only',
      '--tmpfs', '/tmp:rw,noexec,nosuid,size=64m', '--tmpfs', '/dev/shm:rw,noexec,nosuid,size=64m',
      '--cap-drop=ALL', '--cap-add=SYS_CHROOT', '--security-opt=seccomp=worker/chromium-seccomp.json',
      '--security-opt=no-new-privileges', '--pids-limit=128', '--memory=512m', '--cpus=1.0',
      '--entrypoint', 'node', 'trustlayer-worker:latest', 'worker/chromium_sandbox_probe.js'
    ]));
    assert.equal(sandboxProbe.diagnosticStatus, 'VERIFIED', JSON.stringify(sandboxProbe.sandboxVerification));
    assert.ok(Number(sandboxProbe.uid) > 0, 'sandbox probe must run as non-root');
    assert.ok(sandboxProbe.sandboxVerification.evidenceCapturedAtMs > Date.now() - 10_000);
    assert.ok(sandboxProbe.sandboxVerification.rendererChecks.length > 0);
    assert.ok(sandboxProbe.sandboxVerification.rendererChecks.every(check =>
      check.verified && check.processEvidenceFresh && check.processEvidenceStable && check.filtersAddedBeyondContainer &&
      check.namespacesIsolated && check.parentHasZygoteSandbox));
    console.log(`Chromium sandbox verification: ${JSON.stringify({ status: sandboxProbe.diagnosticStatus,
      chromeSandboxDiagnostic: sandboxProbe.chromeSandboxDiagnostic, browserVersion: sandboxProbe.browserVersion,
      uid: sandboxProbe.uid, gid: sandboxProbe.gid, observedFlags: sandboxProbe.sandboxVerification.observedFlags,
      renderers: sandboxProbe.sandboxVerification.rendererChecks })}`);
    const screenshot = fs.readFileSync(path.join(tempDir, 'runtime.png'));
    assert.deepEqual([...screenshot.subarray(0, 8)], [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);
    assert.ok(screenshot.length > 1000);

    // A failed job writes a recognizable stale result only into its own tmpfs.
    docker(['run', '-d', '--name', failedJobName, '--network=none', '--read-only',
      '--user=pwuser', '--tmpfs', '/output:rw,noexec,nosuid,size=1m,uid=1001,gid=1001,mode=0700', '--entrypoint', 'node', 'trustlayer-worker:latest', '-e',
      "require('node:fs').writeFileSync('/output/result.json', JSON.stringify({jobId:'failed-old-job',sentinel:'stale'}));process.exit(17)"]);
    for (let attempt = 0; attempt < 20 && docker(['inspect', '--format={{.State.Running}}', failedJobName]) === 'true'; attempt++) {
      await new Promise(resolve => setTimeout(resolve, 50));
    }
    assert.equal(docker(['inspect', '--format={{.State.ExitCode}}', failedJobName]), '17');
    docker(['rm', failedJobName]);

    for (const [scenario, name] of [['timeout', timeoutJobName], ['cancel', cancelJobName]]) {
      docker(['run', '-d', '--name', name, '--network=none', '--read-only', '--user=pwuser',
        '--tmpfs', '/tmp:rw,noexec,nosuid,size=1m', '--pids-limit=8', '--memory=32m',
        '--entrypoint', 'node', 'trustlayer-worker:latest', '-e', 'setInterval(()=>{},1000)']);
      await new Promise(resolve => setTimeout(resolve, 150));
      assert.equal(docker(['inspect', '--format={{.State.Running}}', name]), 'true');
      docker(['rm', '-f', name]);
      assert.throws(() => dockerQuiet(['inspect', name]), `${scenario} container should be gone after termination`);
    }

    const repeatedOutputDir = path.join(tempDir, 'repeated-job');
    fs.mkdirSync(repeatedOutputDir);
    docker(['run', '-d', '--name', repeatedBrowserName,
      '--network=trustlayer-isolated-net', '--user=pwuser', '--init', '--read-only',
      '--tmpfs', '/tmp:rw,noexec,nosuid,size=64m', '--tmpfs', '/dev/shm:rw,noexec,nosuid,size=64m',
      '--tmpfs', '/output:rw,noexec,nosuid,size=24m,uid=1001,gid=1001,mode=0700', '--cap-drop=ALL', '--cap-add=SYS_CHROOT',
      '--security-opt=seccomp=worker/chromium-seccomp.json', '--security-opt=no-new-privileges',
      '--pids-limit=128', '--memory=512m', '--cpus=1.0', 'trustlayer-worker:latest',
      '--url=http://127.0.0.1/private/bob?token=runtime-secret-two', '--jobId=runtime-audit-two',
      '--proxy=http://trustlayer-egress:3128', `--proxyUsername=${username}`, `--proxyPassword=${password}`,
      '--output=/output/runtime-result.json', '--screenshot=/output/runtime.png',
      '--captureDelayMs=0', '--timeout=20000', '--keepAlive=0', '--handoffGrace=3000']);
    const repeatedReady = path.join(repeatedOutputDir, 'runtime-result.json.ready');
    for (let attempt = 0; attempt < 120 && !fs.existsSync(repeatedReady); attempt++) {
      try {
        const artifactState = docker(['exec', repeatedBrowserName, 'node', '-e',
          "const f=require('node:fs');console.log(f.existsSync('/output/runtime-result.json.ready')?'READY':'WAIT')"]);
        if (artifactState === 'READY') readOutput(repeatedBrowserName, 'runtime-result.json.ready', repeatedReady, 2 * 1024 * 1024);
      } catch {}
      if (fs.existsSync(repeatedReady)) {
        try { readOutput(repeatedBrowserName, 'runtime.png', path.join(repeatedOutputDir, 'runtime.png'), 5 * 1024 * 1024); } catch {}
      } else {
        try { if (docker(['inspect', '--format={{.State.Running}}', repeatedBrowserName]) === 'false') break; } catch { break; }
      }
      await new Promise(resolve => setTimeout(resolve, 100));
    }
    if (!fs.existsSync(repeatedReady)) {
      let repeatedState = '';
      let repeatedLogs = '';
      try { repeatedState = docker(['inspect', '--format={{.State.Status}} exit={{.State.ExitCode}}', repeatedBrowserName]); } catch {}
      try { repeatedLogs = docker(['logs', repeatedBrowserName]).slice(-2048); } catch {}
      assert.fail(`second local job did not publish a result; state=${repeatedState}; logs=${repeatedLogs}`);
    }
    const repeatedResult = JSON.parse(fs.readFileSync(repeatedReady, 'utf8'));
    assert.equal(repeatedResult.jobId, 'runtime-audit-two');
    assert.equal(repeatedResult.blockedRequests.some(item => JSON.stringify(item).includes('failed-old-job')), false);
    assert.equal(repeatedResult.networkEvents.some(item => JSON.stringify(item).includes('runtime-secret')), false);
    assert.ok(fs.existsSync(path.join(repeatedOutputDir, 'runtime.png')));
    assert.equal(fs.existsSync(path.join(repeatedOutputDir, 'result.json')), false);
    const repeatedHostConfig = JSON.parse(docker(['inspect', '--format={{json .HostConfig}}', repeatedBrowserName]));
    assert.deepEqual(repeatedHostConfig.Binds || [], []);
    assert.match(repeatedHostConfig.Tmpfs['/output'], /size=24m/);
  } finally {
    try { dockerQuiet(['stop', '--time', '2', name]); } catch {}
    try { dockerQuiet(['rm', '-f', name]); } catch {}
    try { dockerQuiet(['rm', '-f', browserName]); } catch {}
    try { dockerQuiet(['rm', '-f', quotaName]); } catch {}
    try { dockerQuiet(['rm', '-f', failedJobName]); } catch {}
    try { dockerQuiet(['rm', '-f', timeoutJobName]); } catch {}
    try { dockerQuiet(['rm', '-f', cancelJobName]); } catch {}
    try { dockerQuiet(['rm', '-f', repeatedBrowserName]); } catch {}
    fs.rmSync(tempDir, { recursive: true, force: true });
  }
});
