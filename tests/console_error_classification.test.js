import assert from 'node:assert/strict';
import test from 'node:test';
import { classifyConsoleError, isExpectedCaseCreationAuthChallenge, isExpectedUnsafeInteractiveRejection } from './helpers/console_error_classification.js';

const baseUrl = 'http://127.0.0.1:48123';
const authError = classifyConsoleError({
  text: 'Failed to load resource: the server responded with a status of 401 (Unauthorized)',
  sourceUrl: `${baseUrl}/investigation.html`, baseUrl, phase: 'case-creation'
});
const successfulChallenge = {
  unauthenticatedCaseCreation401Count: 1,
  authenticatedCaseCreation201Count: 1,
  authSession204Count: 1,
  allApplication401ResponseCount: 1,
  authSessionEstablished: true
};

test('only the completed unauthenticated case-creation challenge matches its browser console 401', () => {
  assert.deepEqual(authError, {
    messageCode: 'RESOURCE_HTTP_401', sourcePath: '/investigation.html', phase: 'case-creation'
  });
  assert.equal(isExpectedCaseCreationAuthChallenge(authError, successfulChallenge), true);
  assert.equal(isExpectedCaseCreationAuthChallenge({ ...authError, phase: 'cancellation' }, successfulChallenge), false);
  assert.equal(isExpectedCaseCreationAuthChallenge({ ...authError, messageCode: 'CONSOLE_ERROR' }, successfulChallenge), false);
  for (const field of ['unauthenticatedCaseCreation401Count', 'authenticatedCaseCreation201Count', 'authSession204Count', 'allApplication401ResponseCount']) {
    assert.equal(isExpectedCaseCreationAuthChallenge(authError, { ...successfulChallenge, [field]: 0 }), false, field);
  }
  assert.equal(isExpectedCaseCreationAuthChallenge(authError, { ...successfulChallenge, authSessionEstablished: false }), false);
});

test('console error diagnostics retain path and phase but never retain message or credential values', () => {
  const error = classifyConsoleError({ text: 'private-token Failed to load resource: 401',
    sourceUrl: `${baseUrl}/api/cases/TL-case?token=secret`, baseUrl, phase: 'interactive-actions' });
  assert.deepEqual(error, { messageCode: 'CONSOLE_ERROR', sourcePath: '/api/cases/TL-case', phase: 'interactive-actions' });
  assert.equal(JSON.stringify(error).includes('private-token'), false);
  assert.equal(JSON.stringify(error).includes('secret'), false);
});

test('only the confirmed unsafe-link policy rejection matches its interaction 409 console error', () => {
  const caseId = 'TL-test-case';
  const policyError = classifyConsoleError({
    text: 'Failed to load resource: the server responded with a status of 409 (Conflict)',
    sourceUrl: `${baseUrl}/api/cases/${caseId}/interactions?caseAccess=secret`, baseUrl,
    phase: 'interactive-actions'
  });
  assert.deepEqual(policyError, {
    messageCode: 'RESOURCE_HTTP_409', sourcePath: `/api/cases/${caseId}/interactions`, phase: 'interactive-actions'
  });
  const evidence = { caseId, phase: 'interactive-actions', responseStatus: 409, errorCode: 'TARGET_NOT_PERMITTED' };
  assert.equal(isExpectedUnsafeInteractiveRejection(policyError, evidence), true);
  assert.equal(isExpectedUnsafeInteractiveRejection(policyError, { ...evidence, errorCode: 'RATE_LIMITED' }), false);
  assert.equal(isExpectedUnsafeInteractiveRejection(policyError, { ...evidence, phase: 'cancellation' }), false);
  assert.equal(isExpectedUnsafeInteractiveRejection({ ...policyError, sourcePath: '/api/cases/other/interactions' }, evidence), false);
  assert.equal(JSON.stringify(policyError).includes('secret'), false);
});
