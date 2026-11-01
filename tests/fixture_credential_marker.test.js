import assert from 'node:assert/strict';
import test from 'node:test';
import { fixtureCredentialMarker, summarizeFixtureCredentialObservations } from './helpers/fixture_credential_marker.js';

test('fixture credential marker independently identifies each credential header without values', () => {
  assert.equal(fixtureCredentialMarker({}),
    'TRUSTLAYER_FIXTURE_CREDENTIALS cookie=false authorization=false proxyAuth=false');
  assert.equal(fixtureCredentialMarker({ cookie: 'secret-cookie' }),
    'TRUSTLAYER_FIXTURE_CREDENTIALS cookie=true authorization=false proxyAuth=false');
  assert.equal(fixtureCredentialMarker({ authorization: 'Bearer secret' }),
    'TRUSTLAYER_FIXTURE_CREDENTIALS cookie=false authorization=true proxyAuth=false');
  assert.equal(fixtureCredentialMarker({ 'proxy-authorization': 'Basic secret' }),
    'TRUSTLAYER_FIXTURE_CREDENTIALS cookie=false authorization=false proxyAuth=true');
  assert.equal(fixtureCredentialMarker({ cookie: 'a', authorization: 'b', 'proxy-authorization': 'c' }),
    'TRUSTLAYER_FIXTURE_CREDENTIALS cookie=true authorization=true proxyAuth=true');
});

test('fixture credential log summary identifies the failed header category without exposing values', () => {
  const summary = summarizeFixtureCredentialObservations([
    fixtureCredentialMarker({}),
    fixtureCredentialMarker({ 'proxy-authorization': 'private-proxy-token' })
  ].join('\n'));
  assert.deepEqual(summary, {
    observationCount: 2,
    received: { cookie: false, authorization: false, proxyAuth: true }
  });
  assert.equal(JSON.stringify(summary).includes('private-proxy-token'), false);
  assert.deepEqual(summarizeFixtureCredentialObservations('unrelated log line'), {
    observationCount: 0, received: { cookie: false, authorization: false, proxyAuth: false }
  });
});
