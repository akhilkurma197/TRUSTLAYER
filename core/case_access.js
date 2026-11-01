import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';

const ACCESS_TOKEN_PATTERN = /^[A-Za-z0-9_-]{43}$/;
const VERIFIER_PATTERN = /^[a-f0-9]{64}$/;

export function createCaseAccessCredential() {
  const token = randomBytes(32).toString('base64url');
  return { token, verifier: hashCaseAccessCredential(token) };
}

export function hashCaseAccessCredential(token) {
  if (typeof token !== 'string' || !ACCESS_TOKEN_PATTERN.test(token)) {
    throw new TypeError('Invalid case access credential.');
  }
  return createHash('sha256').update(token, 'utf8').digest('hex');
}

export function verifyCaseAccessCredential(token, verifier) {
  if (typeof token !== 'string' || !ACCESS_TOKEN_PATTERN.test(token) ||
      typeof verifier !== 'string' || !VERIFIER_PATTERN.test(verifier)) return false;
  const actual = Buffer.from(hashCaseAccessCredential(token), 'hex');
  const expected = Buffer.from(verifier, 'hex');
  return timingSafeEqual(actual, expected);
}
