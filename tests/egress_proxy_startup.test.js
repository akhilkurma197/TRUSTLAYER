import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import path from 'node:path';
import { test } from 'node:test';

test('egress proxy reports incomplete fixture configuration before exiting with code 2', () => {
  const username = 'diagnostic-user-secret';
  const password = 'diagnostic-password-secret';
  const child = spawnSync(process.execPath, [path.resolve('worker/egress_proxy_worker.js'),
    `--username=${username}`, `--password=${password}`, '--output=/tmp/egress-proxy-startup-test.json',
    '--test-fixture-host=trustlayer-fixture-12345678.test', '--test-fixture-address=172.20.0.2',
    '--test-fixture-port=8080'], {
    encoding: 'utf8', timeout: 5000, env: { ...process.env, NODE_ENV: 'test' }, windowsHide: true
  });

  assert.equal(child.error, undefined);
  assert.equal(child.status, 2);
  assert.match(child.stderr, /Egress proxy rejected incomplete or non-test fixture configuration\./);
  assert.equal(`${child.stdout}${child.stderr}`.includes(username), false);
  assert.equal(`${child.stdout}${child.stderr}`.includes(password), false);
});
