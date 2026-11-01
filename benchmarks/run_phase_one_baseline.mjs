import fs from 'node:fs';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { LiveJobController } from '../core/investigators/live_job_controller.js';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const runs = Math.min(50, Math.max(20, Number.parseInt(process.argv[2] || '20', 10)));
const scenarios = ['small', 'assets', 'delayed', 'forbidden', 'moderate', 'timeout'];
const start = () => Date.now();
const docker = (args, timeout = 120000) => execFileSync('docker', args, { cwd: root, encoding: 'utf8', timeout, windowsHide: true, maxBuffer: 20 * 1024 * 1024 }).trim();
new LiveJobController()._ensureDockerRuntime();

function runContainer(mode, rounds) {
  const startedAt = start();
  const hostStartedAt = Date.now();
  const raw = docker(['run', '--rm', '--network=none', '--user=pwuser', '--init', '--read-only',
    '--tmpfs', '/tmp:rw,noexec,nosuid,size=64m', '--tmpfs', '/dev/shm:rw,noexec,nosuid,size=64m',
    '--cap-drop=ALL', '--cap-add=SYS_CHROOT', '--security-opt=seccomp=worker/chromium-seccomp.json',
    '--security-opt=no-new-privileges', '--pids-limit=128', '--memory=512m', '--cpus=1.0',
    '--entrypoint', 'node', 'trustlayer-worker:latest', 'worker/browser_benchmark.js',
    `--mode=${mode}`, `--rounds=${rounds}`, `--containerStartedAt=${hostStartedAt}`], 120000);
  return { wallMs: Date.now() - startedAt, result: JSON.parse(raw) };
}

const coldSamples = Object.fromEntries(scenarios.map(name => [name, []]));
const coldContainerStartupMs = [];
let browserVersion = null;
for (let index = 0; index < runs; index++) {
  const measured = runContainer('cold', 1);
  coldContainerStartupMs.push(measured.result.containerToScriptMs);
  browserVersion = measured.result.browserVersion;
  for (const sample of measured.result.samples) coldSamples[sample.scenario].push({ ...sample, containerToScriptMs: measured.result.containerToScriptMs });
}
const warm = runContainer('warm', runs);
browserVersion = warm.result.browserVersion || browserVersion;

function percentile(values, pct) {
  const sorted = values.filter(Number.isFinite).sort((a, b) => a - b);
  return sorted.length ? sorted[Math.max(0, Math.ceil(pct * sorted.length) - 1)] : null;
}
function summarize(samples) {
  const fields = ['containerToScriptMs', 'browserLaunchMs', 'navigationMs', 'screenshotMs', 'totalMs', 'cleanupMs', 'rssMb'];
  return Object.fromEntries(fields.map(field => {
    const vals = samples.map(sample => sample[field]);
    return [field, { median: percentile(vals, 0.5), p95: percentile(vals, 0.95) }];
  }).concat([['timeouts', samples.filter(sample => sample.timedOut).length],
    ['screenshotFailures', samples.filter(sample => Boolean(sample.screenshotError)).length],
    ['httpStatuses', [...new Set(samples.map(sample => sample.status))]],
    ['sampleCount', samples.length]]));
}

const report = {
  generatedAt: new Date().toISOString(),
  scope: 'Local-only Playwright/Chromium benchmark in the Trust Layer worker image with Docker network=none. Browser requests are fulfilled by Playwright routes; no DNS or Internet access. Cold means a fresh browser process in each isolated container run; warm means 20 pages per scenario in a retained browser process. This is not an end-to-end proxy or production investigation benchmark.',
  runsPerScenario: runs,
  browserVersion,
  playwrightVersion: '1.64.1 (worker image package lock)',
  cold: Object.fromEntries(scenarios.map(name => [name, summarize(coldSamples[name])])),
  warm: Object.fromEntries(scenarios.map(name => [name, summarize(warm.result.samples
    .filter(sample => sample.scenario === name)
    .map(sample => ({ ...sample, containerToScriptMs: warm.result.containerToScriptMs })))])),
  containerWallMs: { coldMedianForSixScenarios: percentile(coldContainerStartupMs, 0.5), warmFor120Samples: warm.wallMs },
  coldContainerToWorkerMs: { median: percentile(coldContainerStartupMs, 0.5), p95: percentile(coldContainerStartupMs, 0.95) },
  warmContainerToWorkerMs: warm.result.containerToScriptMs,
  securityProfile: 'pwuser; read-only root; no network; no capabilities except SYS_CHROOT; Chromium sandbox requested; seccomp; no-new-privileges; 512 MiB; 1 CPU; PID limit 128',
  raw: { coldContainerStartupMs, coldSamples, warm: warm.result }
};
const out = path.join(root, 'docs', 'phase-one-benchmark-results.json');
fs.writeFileSync(out, `${JSON.stringify(report, null, 2)}\n`);
console.log(`Saved ${out}`);
console.log(JSON.stringify({ runs, browserVersion, coldContainerToWorkerMs: report.coldContainerToWorkerMs,
  scenarios: Object.fromEntries(scenarios.map(name => [name, { cold: report.cold[name], warm: report.warm[name] }])) }, null, 2));
