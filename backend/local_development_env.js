import fs from 'node:fs';
import path from 'node:path';
import { randomBytes } from 'node:crypto';

function decodeEnvValue(raw) {
  const value = raw.trim();
  if (!value) return '';
  const quote = value[0];
  if (quote === '"' || quote === "'") {
    const end = value.lastIndexOf(quote);
    if (end <= 0) return null;
    const content = value.slice(1, end);
    return quote === '"' ? content.replace(/\\n/g, '\n').replace(/\\r/g, '\r').replace(/\\"/g, '"').replace(/\\\\/g, '\\') : content;
  }
  return value.replace(/\s+#.*$/, '').trim();
}

export function parseLocalEnv(source) {
  const values = {};
  for (const line of String(source).split(/\r?\n/)) {
    const match = /^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*?)\s*$/.exec(line);
    if (!match) continue;
    const value = decodeEnvValue(match[2]);
    if (value !== null) values[match[1]] = value;
  }
  return values;
}

function readEnvFile(envFile) {
  try { return parseLocalEnv(fs.readFileSync(envFile, 'utf8')); }
  catch (error) {
    if (error?.code === 'ENOENT') return {};
    throw new Error('Unable to read the local environment file.');
  }
}

function applyFileValues(env, values) {
  for (const [name, value] of Object.entries(values)) {
    if (env[name] === undefined) env[name] = value;
  }
}

/** Load a gitignored local .env and provision one stable token for non-production startup. */
export function initializeLocalDevelopmentEnvironment({
  env = process.env,
  envFile = path.resolve('.env'),
  tokenFactory = () => randomBytes(32).toString('base64url')
} = {}) {
  const processTokenConfigured = typeof env.TRUSTLAYER_API_TOKEN === 'string' && env.TRUSTLAYER_API_TOKEN.length > 0;
  if (env.NODE_ENV === 'production') return { loaded: false, generatedToken: false,
    tokenSource: processTokenConfigured ? 'process_environment' : 'missing' };

  const fileValues = readEnvFile(envFile);
  applyFileValues(env, fileValues);
  const tokenSource = processTokenConfigured ? 'process_environment'
    : fileValues.TRUSTLAYER_API_TOKEN ? 'env_file' : null;
  if (typeof env.TRUSTLAYER_API_TOKEN === 'string' && env.TRUSTLAYER_API_TOKEN.length > 0) {
    return { loaded: true, generatedToken: false, tokenSource };
  }

  const token = tokenFactory();
  if (typeof token !== 'string' || Buffer.byteLength(token) < 32 || Buffer.byteLength(token) > 1024 || /[\r\n]/.test(token)) {
    throw new Error('Local API token generation did not produce a valid secret.');
  }
  const existing = fs.existsSync(envFile) ? fs.readFileSync(envFile, 'utf8') : '';
  const separator = existing.length > 0 && !existing.endsWith('\n') ? '\n' : '';
  const tokenLine = `TRUSTLAYER_API_TOKEN=${token}\n`;
  try {
    if (fs.existsSync(envFile)) fs.appendFileSync(envFile, `${separator}${tokenLine}`, { encoding: 'utf8' });
    else fs.writeFileSync(envFile, tokenLine, { encoding: 'utf8', mode: 0o600, flag: 'wx' });
  } catch (error) {
    if (error?.code !== 'EEXIST') throw new Error('Unable to persist the local API token in .env.');
    const persisted = readEnvFile(envFile).TRUSTLAYER_API_TOKEN;
    if (!persisted) throw new Error('A concurrent local startup did not persist an API token.');
    env.TRUSTLAYER_API_TOKEN = persisted;
    return { loaded: true, generatedToken: false, tokenSource: 'env_file' };
  }
  env.TRUSTLAYER_API_TOKEN = token;
  return { loaded: true, generatedToken: true, tokenSource: 'generated_local' };
}
