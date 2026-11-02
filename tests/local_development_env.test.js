import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { test } from 'node:test';
import { initializeLocalDevelopmentEnvironment, parseLocalEnv } from '../backend/local_development_env.js';

test('local environment parser supports basic assignments, exports, quotes, and comments', () => {
  assert.deepEqual(parseLocalEnv('PORT=3100\nexport SAMPLE="hello world"\nCOMMENT=value # note\nSINGLE=\'local value\''), {
    PORT: '3100', SAMPLE: 'hello world', COMMENT: 'value', SINGLE: 'local value'
  });
});

test('development token is generated once, persisted, and reused on later startups', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'trustlayer-env-'));
  const envFile = path.join(dir, '.env');
  let generatedCount = 0;
  const tokenFactory = () => { generatedCount++; return 'A'.repeat(43); };
  try {
    const firstEnv = {};
    const first = initializeLocalDevelopmentEnvironment({ env: firstEnv, envFile, tokenFactory });
    assert.equal(first.generatedToken, true);
    assert.equal(first.tokenSource, 'generated_local');
    assert.equal(firstEnv.TRUSTLAYER_API_TOKEN, 'A'.repeat(43));
    assert.equal(generatedCount, 1);

    const secondEnv = {};
    const second = initializeLocalDevelopmentEnvironment({ env: secondEnv, envFile, tokenFactory });
    assert.equal(second.generatedToken, false);
    assert.equal(second.tokenSource, 'env_file');
    assert.equal(secondEnv.TRUSTLAYER_API_TOKEN, firstEnv.TRUSTLAYER_API_TOKEN);
    assert.equal(generatedCount, 1, 'a later startup must not rotate the token');
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});

test('existing environment values take precedence and production neither loads nor creates local secrets', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'trustlayer-env-'));
  const envFile = path.join(dir, '.env');
  fs.writeFileSync(envFile, 'TRUSTLAYER_API_TOKEN=local-token-value-long-enough-0123456789\nCUSTOM=loaded');
  let generatedCount = 0;
  try {
    const overrideEnv = { TRUSTLAYER_API_TOKEN: 'external-environment-token-value-long-enough-0123456789' };
    const override = initializeLocalDevelopmentEnvironment({ env: overrideEnv, envFile,
      tokenFactory: () => { generatedCount++; return 'B'.repeat(43); } });
    assert.equal(overrideEnv.TRUSTLAYER_API_TOKEN, 'external-environment-token-value-long-enough-0123456789');
    assert.equal(overrideEnv.CUSTOM, 'loaded');
    assert.equal(override.generatedToken, false);
    assert.equal(override.tokenSource, 'process_environment');

    const productionEnv = { NODE_ENV: 'production' };
    const production = initializeLocalDevelopmentEnvironment({ env: productionEnv, envFile: path.join(dir, 'absent.env'),
      tokenFactory: () => { generatedCount++; return 'C'.repeat(43); } });
    assert.equal(production.loaded, false);
    assert.equal(production.tokenSource, 'missing');
    assert.equal(productionEnv.TRUSTLAYER_API_TOKEN, undefined);
    assert.equal(generatedCount, 0, 'production must never generate a development token');
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});

test('invalid generated token material is rejected rather than weakening API validation', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'trustlayer-env-'));
  try {
    assert.throws(() => initializeLocalDevelopmentEnvironment({ env: {}, envFile: path.join(dir, '.env'), tokenFactory: () => 'short' }),
      /did not produce a valid secret/);
    assert.equal(fs.existsSync(path.join(dir, '.env')), false);
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});
