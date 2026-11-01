import test from 'node:test';
import assert from 'node:assert/strict';
import { execFileAsync } from '../core/async_process.js';

test('bounded child-process polling leaves the Node event loop responsive', async () => {
  let heartbeatObserved = false;
  const heartbeat = setTimeout(() => { heartbeatObserved = true; }, 5);
  try {
    const result = await execFileAsync(process.execPath, ['-e', 'setTimeout(() => process.stdout.write("ready"), 60)'], {
      encoding: 'utf8', timeout: 1000, windowsHide: true
    });
    assert.equal(result.stdout, 'ready');
    assert.equal(heartbeatObserved, true);
  } finally {
    clearTimeout(heartbeat);
  }
});

test('bounded child-process polling preserves its command timeout', async () => {
  await assert.rejects(
    execFileAsync(process.execPath, ['-e', 'setTimeout(() => {}, 1000)'], {
      encoding: 'utf8', timeout: 25, windowsHide: true
    }),
    error => error.code === 'ETIMEDOUT' || error.killed === true
  );
});
