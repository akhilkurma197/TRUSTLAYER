import fs from 'node:fs';

function readProcess(pid) {
  try {
    const statusText = fs.readFileSync(`/proc/${pid}/status`, 'utf8');
    const commandLine = fs.readFileSync(`/proc/${pid}/cmdline`, 'utf8').replace(/\0/g, ' ').trim();
    const fields = Object.fromEntries(statusText.split('\n')
      .filter(line => /^(Uid|Gid|PPid|NoNewPrivs|Seccomp|Seccomp_filters|CapEff):\s/.test(line))
      .map(line => { const [key, ...values] = line.split(/:\s+/); return [key, values.join(' ')]; }));
    const namespaces = Object.fromEntries(['user', 'pid'].map(name => {
      try { return [name, fs.readlinkSync(`/proc/${pid}/ns/${name}`)]; }
      catch { return [name, null]; }
    }));
    return { pid: Number(pid), commandLine, fields, namespaces, observedAtMs: Date.now() };
  } catch {
    return null;
  }
}

function hasDisablingFlag(commandLine = '') {
  return /(?:^|\s)(?:--no-sandbox|--disable-seccomp-filter-sandbox|--single-process|--no-zygote)(?:\s|$)/.test(commandLine);
}

export function evaluateChromiumSandboxEvidence({ baseline, browserProcess, processes }) {
  const failures = [];
  const now = Date.now();
  const isFresh = process => Number.isSafeInteger(process?.observedAtMs) &&
    process.observedAtMs <= now && now - process.observedAtMs <= 10_000;
  const strictCount = value => {
    if (typeof value !== 'string' || !/^\d+$/.test(value)) return Number.NaN;
    const parsed = Number(value);
    return Number.isSafeInteger(parsed) ? parsed : Number.NaN;
  };
  const validNamespace = (value, name) => typeof value === 'string' &&
    new RegExp(`^${name}:\\[\\d+\\]$`).test(value);
  const baselineFilters = strictCount(baseline?.fields?.Seccomp_filters);
  if (!Number.isFinite(baselineFilters)) failures.push('KERNEL_SECCOMP_FILTER_COUNT_UNAVAILABLE');
  if (!baseline || !Number.isSafeInteger(baseline.pid) || baseline.pid <= 0 || !isFresh(baseline) ||
      baseline.fields?.Seccomp !== '2' || baseline.fields?.NoNewPrivs !== '1') {
    failures.push('WORKER_BASELINE_EVIDENCE_INVALID_OR_STALE');
  }
  if (!browserProcess) failures.push('BROWSER_PROCESS_NOT_FOUND');
  if (browserProcess && hasDisablingFlag(browserProcess.commandLine)) failures.push('BROWSER_SANDBOX_DISABLING_FLAG');

  const processList = Array.isArray(processes) ? processes : [];
  const pids = processList.map(process => process.pid);
  const processListValid = processList.length > 0 && pids.every(pid => Number.isSafeInteger(pid) && pid > 0) &&
    new Set(pids).size === pids.length;
  if (!processListValid) failures.push('PROCESS_SNAPSHOT_INVALID');
  const baselineInSnapshot = processList.find(process => process.pid === baseline?.pid);
  if (!baselineInSnapshot || !isFresh(baselineInSnapshot) ||
      baselineInSnapshot.commandLine !== baseline.commandLine ||
      baselineInSnapshot.fields.Seccomp !== baseline.fields?.Seccomp ||
      baselineInSnapshot.fields.NoNewPrivs !== baseline.fields?.NoNewPrivs ||
      baselineInSnapshot.fields.Seccomp_filters !== baseline.fields?.Seccomp_filters ||
      baselineInSnapshot.namespaces.user !== baseline.namespaces?.user ||
      baselineInSnapshot.namespaces.pid !== baseline.namespaces?.pid) {
    failures.push('WORKER_BASELINE_NOT_IN_CURRENT_PROCESS_SNAPSHOT');
  }
  if (browserProcess && (!isFresh(browserProcess) ||
      !processList.some(process => process.pid === browserProcess.pid && process.commandLine === browserProcess.commandLine))) {
    failures.push('BROWSER_PROCESS_EVIDENCE_INVALID_OR_STALE');
  }
  const byPid = new Map(processList.map(process => [process.pid, process]));
  const renderers = processList.filter(process => /(?:^|\s)--type=renderer(?:\s|$)/.test(process.commandLine));
  if (renderers.length === 0) failures.push('RENDERER_PROCESS_NOT_FOUND');

  const rendererChecks = renderers.map(renderer => {
    const parent = byPid.get(Number(renderer.fields.PPid));
    const rendererFilters = strictCount(renderer.fields?.Seccomp_filters);
    const filtersAddedBeyondContainer = Number.isFinite(baselineFilters) && Number.isFinite(rendererFilters) && rendererFilters > baselineFilters;
    const namespacesValid = validNamespace(browserProcess?.namespaces?.user, 'user') &&
      validNamespace(browserProcess?.namespaces?.pid, 'pid') &&
      validNamespace(renderer.namespaces?.user, 'user') && validNamespace(renderer.namespaces?.pid, 'pid');
    const namespacesIsolated = Boolean(namespacesValid &&
      renderer.namespaces.user !== browserProcess.namespaces.user &&
      renderer.namespaces.pid !== browserProcess.namespaces.pid);
    const parentIsRendererZygote = Boolean(parent && /(?:^|\s)--type=zygote(?:\s|$)/.test(parent.commandLine));
    const parentHasZygoteSandbox = parentIsRendererZygote && !/(?:^|\s)--no-zygote-sandbox(?:\s|$)/.test(parent.commandLine);
    const flagsAllowSandbox = !hasDisablingFlag(renderer.commandLine);
    const seccompEnabled = renderer.fields?.Seccomp === '2' && renderer.fields?.NoNewPrivs === '1' && filtersAddedBeyondContainer;
    const processEvidenceFresh = isFresh(renderer) && isFresh(parent) &&
      typeof renderer.fields?.PPid === 'string' && /^\d+$/.test(renderer.fields.PPid) && Number(renderer.fields.PPid) > 0;
    const checks = {
      pid: renderer.pid,
      parentPid: Number(renderer.fields.PPid) || null,
      seccompMode: renderer.fields.Seccomp || null,
      noNewPrivs: renderer.fields.NoNewPrivs || null,
      containerSeccompFilters: Number.isFinite(baselineFilters) ? baselineFilters : null,
      rendererSeccompFilters: Number.isFinite(rendererFilters) ? rendererFilters : null,
      filtersAddedBeyondContainer,
      namespacesIsolated,
      browserUserNamespace: browserProcess?.namespaces?.user || null,
      rendererUserNamespace: renderer.namespaces?.user || null,
      browserPidNamespace: browserProcess?.namespaces?.pid || null,
      rendererPidNamespace: renderer.namespaces?.pid || null,
      parentIsRendererZygote,
      parentHasZygoteSandbox,
      flagsAllowSandbox,
      processEvidenceFresh
    };
    const verified = namespacesIsolated && seccompEnabled && parentHasZygoteSandbox && flagsAllowSandbox && processEvidenceFresh;
    return { ...checks, verified };
  });

  if (rendererChecks.length === 0 || rendererChecks.some(check => !check.verified)) {
    failures.push('RENDERER_NAMESPACE_OR_SECCOMP_LAYER_NOT_VERIFIED');
  }
  return {
    status: failures.length === 0 ? 'VERIFIED' : 'UNVERIFIED',
    browserSandboxEnabled: failures.length === 0,
    evidenceCapturedAtMs: now,
    mechanism: 'renderer user+pid namespace isolation and additional Chromium seccomp filter beyond container baseline',
    failures,
    baselineSeccompFilters: Number.isFinite(baselineFilters) ? baselineFilters : null,
    observedFlags: processList.filter(process => /chrome|chromium/i.test(process.commandLine) &&
      (/(?:^|\s)--type=(?:zygote|renderer)(?:\s|$)/.test(process.commandLine) || process.pid === browserProcess?.pid))
      .map(process => ({ pid: process.pid,
        type: /(?:^|\s)--type=([^\s]+)/.exec(process.commandLine)?.[1] || 'browser',
        flags: process.commandLine.split(/\s+/).filter(arg => arg.startsWith('--') &&
          /^(?:--(?:no-zygote-sandbox|no-sandbox|disable-setuid-sandbox|disable-seccomp-filter-sandbox|single-process|no-zygote|type=))/.test(arg)) })),
    rendererChecks
  };
}

export async function verifyChromiumSandbox(browser, page) {
  try {
    // Force creation and execution of a local renderer before inspecting /proc.
    await page.setContent('<!doctype html><title>local sandbox check</title><p>fixture</p>', { waitUntil: 'load', timeout: 3000 });
    await page.evaluate(() => document.title);
    const baseline = readProcess(process.pid);
    const processes = fs.readdirSync('/proc').filter(name => /^\d+$/.test(name)).map(readProcess).filter(Boolean);
    if (!baseline || baseline.pid !== process.pid) {
      throw new Error('Worker process baseline could not be read from the current /proc snapshot');
    }
    const browserProcess = processes.find(process => /(?:^|\s)--remote-debugging-pipe(?:\s|$)/.test(process.commandLine) &&
      /chrome(?:-headless-shell)?(?:\s|$)/.test(process.commandLine) && !/(?:^|\s)--type=/.test(process.commandLine));
    const result = evaluateChromiumSandboxEvidence({ baseline, browserProcess, processes });
    const byPid = new Map(processes.map(process => [process.pid, process]));
    const checkedProcesses = [baseline, browserProcess, ...result.rendererChecks.flatMap(check => [
      byPid.get(check.pid), byPid.get(check.parentPid)
    ])].filter(Boolean);
    const processIds = [...new Set(checkedProcesses.map(process => process.pid))];
    const changedProcesses = processIds.filter(pid => {
      const before = checkedProcesses.find(process => process.pid === pid);
      const current = readProcess(pid);
      return !current || current.commandLine !== before.commandLine ||
        current.fields.PPid !== before.fields.PPid ||
        current.fields.Seccomp !== before.fields.Seccomp ||
        current.fields.Seccomp_filters !== before.fields.Seccomp_filters ||
        current.fields.NoNewPrivs !== before.fields.NoNewPrivs ||
        current.namespaces.user !== before.namespaces.user || current.namespaces.pid !== before.namespaces.pid;
    });
    if (changedProcesses.length) {
      result.failures.push('PROCESS_EVIDENCE_CHANGED_DURING_VERIFICATION');
      result.status = 'UNVERIFIED';
      result.browserSandboxEnabled = false;
      result.changedProcessPids = changedProcesses;
      for (const check of result.rendererChecks) {
        check.processEvidenceStable = !changedProcesses.includes(check.pid) && !changedProcesses.includes(check.parentPid);
        check.verified = false;
      }
    } else {
      for (const check of result.rendererChecks) check.processEvidenceStable = true;
    }
    return { ...result, chromiumVersion: browser.version(), playwrightSandboxRequested: true };
  } catch (error) {
    return {
      status: 'UNAVAILABLE', browserSandboxEnabled: false,
      mechanism: 'renderer user+pid namespace isolation and additional Chromium seccomp filter beyond container baseline',
      failures: ['SANDBOX_DIAGNOSTIC_ERROR'], diagnosticError: String(error.message).slice(0, 240),
      rendererChecks: []
    };
  }
}
