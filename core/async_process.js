import { execFile } from 'node:child_process';

/** Execute a bounded argument-vector command without blocking the Node event loop. */
export function execFileAsync(file, args, options = {}) {
  return new Promise((resolve, reject) => {
    execFile(file, args, options, (error, stdout, stderr) => {
      if (error) {
        if (stderr !== undefined) error.stderr = stderr;
        reject(error);
        return;
      }
      resolve({ stdout, stderr });
    });
  });
}
