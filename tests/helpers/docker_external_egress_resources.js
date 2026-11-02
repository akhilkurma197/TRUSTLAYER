import path from 'node:path';

export function readOnlyFileBindMount(sourcePath, targetPath) {
  if (typeof sourcePath !== 'string' || sourcePath.includes(',') ||
      !(path.isAbsolute(sourcePath) || path.win32.isAbsolute(sourcePath))) {
    throw new Error('Probe helper bind source must be an absolute path without mount separators.');
  }
  if (typeof targetPath !== 'string' || !/^\/[A-Za-z0-9_./-]+$/.test(targetPath) || targetPath.includes('..')) {
    throw new Error('Probe helper bind target must be a normalized absolute container path.');
  }
  return `type=bind,source=${sourcePath},target=${targetPath},readonly`;
}

export function cleanupDockerContainers(containerNames, removeContainer) {
  const failures = [];
  for (const name of containerNames) {
    try { removeContainer(name); }
    catch { failures.push(name); }
  }
  return failures;
}
