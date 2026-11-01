import fs from 'node:fs';
import { ControlledEgressProxy } from '../core/investigators/egress_proxy.js';
import { normalizeTestLocalFixturePolicy } from '../core/investigators/test_local_fixture.js';

function argsFromCli() {
  const values = {};
  for (const arg of process.argv.slice(2)) {
    if (!arg.startsWith('--')) continue;
    const split = arg.indexOf('=');
    if (split > 2) values[arg.slice(2, split)] = arg.slice(split + 1);
  }
  return values;
}

async function failStartup(message) {
  await new Promise(resolve => process.stderr.write(`${message}\n`, resolve));
  process.exit(2);
}

const args = argsFromCli();
if (!args.username || !args.password || !args.output) {
  await failStartup('Egress proxy requires username, password and output path.');
}

const correlationId = args.correlationId || 'UNAVAILABLE';
const fixtureArguments = ['test-fixture-host', 'test-fixture-address', 'test-fixture-port', 'test-fixture-network'];
const suppliedFixtureArguments = fixtureArguments.filter(name => args[name] !== undefined);
let testLocalFixturePolicy = null;
if (suppliedFixtureArguments.length > 0) {
  if (process.env.NODE_ENV !== 'test' || suppliedFixtureArguments.length !== fixtureArguments.length) {
    await failStartup('Egress proxy rejected incomplete or non-test fixture configuration.');
  }
  try {
    testLocalFixturePolicy = normalizeTestLocalFixturePolicy({
      hostname: args['test-fixture-host'], address: args['test-fixture-address'],
      port: Number(args['test-fixture-port']), networkName: args['test-fixture-network']
    });
  } catch {
    await failStartup('Egress proxy rejected invalid test fixture configuration.');
  }
}

const proxy = new ControlledEgressProxy({
  host: '0.0.0.0',
  port: 3128,
  requireAuth: true,
  username: args.username,
  password: args.password,
  testLocalFixturePolicy
});

try {
  await proxy.start();
  console.log('TRUST_LAYER_EGRESS_READY');
} catch (error) {
  console.error(`Egress proxy failed to start: ${error.message}`);
  process.exit(1);
}

let stopping = false;
function persistObservations() {
  try {
    const snapshot = JSON.stringify({
      correlationId,
      allowedRequests: proxy.allowedRequests.map(item => ({ ...item, correlationId })),
      blockedRequests: proxy.blockedRequests.map(item => ({ ...item, correlationId }))
    }, null, 2);
    const temporaryPath = `${args.output}.tmp`;
    fs.writeFileSync(temporaryPath, snapshot);
    fs.renameSync(temporaryPath, args.output);
  } catch (error) {
    console.error(`Failed to persist egress observations: ${error.message}`);
  }
}
const observationFlush = setInterval(persistObservations, 200);
async function stop() {
  if (stopping) return;
  stopping = true;
  clearInterval(observationFlush);
  persistObservations();
  await proxy.stop();
  process.exit(0);
}

process.on('SIGTERM', stop);
process.on('SIGINT', stop);
