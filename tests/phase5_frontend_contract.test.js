import test from 'node:test';
import { buildTypingControlFailureDiagnostic, logDiagnosticSafely } from './helpers/typing_control_failure_diagnostic.js';
import assert from 'node:assert/strict';
import fs from 'node:fs';

const consoleHtml = fs.readFileSync(new URL('../investigation.html', import.meta.url), 'utf8');
const homeHtml = fs.readFileSync(new URL('../index.html', import.meta.url), 'utf8');
const fixtureTest = fs.readFileSync(new URL('./docker_interactive_fixture.test.js', import.meta.url), 'utf8');
const typingDiagnosticHelper = fs.readFileSync(new URL('./helpers/typing_control_failure_diagnostic.js', import.meta.url), 'utf8');
const cardObserverHelper = fs.readFileSync(new URL('./helpers/interactive_card_observer.js', import.meta.url), 'utf8');
const browserWorker = fs.readFileSync(new URL('../worker/browser_worker.js', import.meta.url), 'utf8');
const investigationEngine = fs.readFileSync(new URL('../core/investigation_engine.js', import.meta.url), 'utf8');
const backendServer = fs.readFileSync(new URL('../backend/server.js', import.meta.url), 'utf8');

test('interactive browser panel uses existing case-authenticated APIs and bounded action controls', () => {
  assert.match(consoleHtml, /id="mode-c-interactive-optin"/);
  assert.match(consoleHtml, /interactive: interactive === true/);
  assert.match(consoleHtml, /new EventSource\(`\/api\/cases\/\$\{caseId\}\/events`\)/);
  for (const route of ['/interactions', '/interactive-artifacts/', '/cancel-live', '/evidence-report']) {
    assert.ok(consoleHtml.includes(route), `frontend should use protected route ${route}`);
  }
  assert.match(consoleHtml, /window\.trustLayerApiFetch\(`\/api\/cases\/\$\{schema\.id\}\/interactions`/);
  assert.doesNotMatch(consoleHtml, /created\.caseAccessToken/);
  assert.doesNotMatch(consoleHtml, /remote-debugging-port|--no-sandbox/i);
});

test('interactive type control exists uniquely and follows session readiness state', () => {
  assert.equal((consoleHtml.match(/id="interactive-type"/g) || []).length, 1,
    'the Playwright action selector must identify one real control');
  assert.match(consoleHtml, /<button[^>]*id="interactive-type"[^>]*>Type bounded text<\/button>/);
  assert.match(consoleHtml, /for \(const id of \['interactive-navigate', 'interactive-click', 'interactive-type', 'interactive-screenshot', 'interactive-cancel'\]\) document\.getElementById\(id\)\.disabled = !running/);
  assert.match(consoleHtml, /const running = session\.status === 'RUNNING'/);
  assert.match(consoleHtml, /document\.getElementById\('interactive-type'\)\?\.addEventListener\('click'/);
  assert.match(consoleHtml, /card\.style\.display = session\?\.enabled \? 'block' : 'none'/);
});

test('Docker typing failure reports schema details and value-redacted request shape', () => {
  assert.match(fixtureTest, /summarizeInteractionFailure\(typeResponse, \{ expectedFixtureSelector: '#note' \}\)/);
  assert.match(fixtureTest, /\.\.\.interactionFailure/);
  const helper = fs.readFileSync(new URL('./helpers/interactive_failure_summary.js', import.meta.url), 'utf8');
  assert.match(helper, /validationDetails/);
  assert.match(helper, /selectorLength/);
  assert.match(helper, /textLength/);
  assert.doesNotMatch(helper, /selector:\s*action\.selector|text:\s*action\.text/);
});

test('accepted interactive case renders a disabled STARTING card before the asynchronous SSE snapshot', () => {
  const initialSchemaAt = consoleHtml.indexOf('const initialSchema = inspectionMode');
  const initialRenderAt = consoleHtml.indexOf('renderInteractivePanel(initialSchema)', initialSchemaAt);
  const eventSourceAt = consoleHtml.indexOf('const evtSource = new EventSource', initialSchemaAt);
  assert.ok(initialSchemaAt >= 0 && initialRenderAt > initialSchemaAt && eventSourceAt > initialRenderAt,
    'the accepted case must render its startup card before the SSE stream is opened');
  assert.match(consoleHtml, /interactiveSession: \{ enabled: true, status: 'STARTING', events: \[\] \}/,
    'the initial panel must reflect server-accepted interactive mode without claiming readiness');
  assert.match(consoleHtml, /const running = session\.status === 'RUNNING'/,
    'STARTING must keep interaction controls disabled until backend readiness reaches RUNNING');
  assert.match(consoleHtml, /switchView\('overview'\);[\s\S]*?const res = await window\.trustLayerApiFetch\('\/api\/cases'/,
    'case creation must start while the overview view is active');
  assert.match(consoleHtml, /window\.activeCase = activeCase = \{ id: caseId, target: cleanTarget, schema: initialSchema \};[\s\S]*?renderInteractivePanel\(initialSchema\);[\s\S]*?const evtSource = new EventSource/,
    'accepted case state must render the card synchronously before SSE processing can update it');
});

test('Docker acceptance checks the card immediately after case creation, before slow cookie protocol reads', () => {
  const caseBodyRead = fixtureTest.indexOf('const first = await createResponse.json()');
  const cardWait = fixtureTest.indexOf("recordTimeline('interactive-card-wait-started')");
  const operatorCookieRead = fixtureTest.indexOf("uiContext.cookies(`${base}/api/`)", cardWait);
  const caseCookieRead = fixtureTest.indexOf("uiContext.cookies(`${base}/api/`)", operatorCookieRead + 1);
  const firstTypingResponse = fixtureTest.indexOf('assert.equal(typeResponse.status(), 200');
  assert.ok(caseBodyRead >= 0 && cardWait > caseBodyRead && operatorCookieRead > cardWait &&
    caseCookieRead > operatorCookieRead && firstTypingResponse < operatorCookieRead,
  'card assertion must happen after creation and cookie authorization assertions must follow the first action');
  assert.match(fixtureTest, /interactive-card-wait-rejected[\s\S]*?frontendReadStatus: frontendRead\.readStatus/,
    'card failure must include a bounded frontend snapshot attempt and its read status');
  assert.match(fixtureTest, /readInteractiveUiSnapshotBounded\(page, timeoutMs = 750\)/,
    'failure-only frontend sampling must remain bounded');
  assert.match(fixtureTest, /uiContext\.addInitScript\(installInteractiveCardObserver\)/,
    'card state changes must be observed independently of a later page evaluation');
  assert.match(fixtureTest, /uiCardObservations: interactiveCardObservations/,
    'card failure diagnostics must include the retained observer samples');
  assert.match(cardObserverHelper, /MutationObserver/);
  assert.match(cardObserverHelper, /cardDisplay: cardStyle\?\.display/);
  assert.match(cardObserverHelper, /overviewActive: view\?\.classList\.contains\('active'\)/);
  assert.doesNotMatch(cardObserverHelper, /caseAccessToken|operatorToken|cookie|authorization|targetUrl|caseId/i,
    'observer must not capture credentials or target data');
});

test('URL-only homepage result cannot label absence of indicators as a verified safe link', () => {
  assert.match(homeHtml, /URL_ONLY_NO_INDICATORS/);
  assert.match(homeHtml, /page safety is unverified/);
  assert.doesNotMatch(homeHtml, /Verified Safe Web Link/);
});

test('completed case keeps SSE open while its bounded interactive browser is active', () => {
  assert.match(consoleHtml, /function shouldCloseCaseEventStream\(schema\)/);
  assert.match(consoleHtml, /const browserStillActive = \['STARTING', 'RUNNING'\]\.includes\(schema\?\.interactiveSession\?\.status\)/);
  assert.match(consoleHtml, /return caseComplete && !browserStillActive/);
  assert.equal((consoleHtml.match(/shouldCloseCaseEventStream\(acceptedSchema\)/g) || []).length, 2,
    'accepted SSE snapshots and fetched schemas must use the lifecycle-aware stream close decision');
  assert.match(consoleHtml, /function mergeInteractiveCaseSchema\(current, incoming\)/,
    'asynchronous schema refreshes must be reconciled against the current interactive lifecycle');
  assert.match(consoleHtml, /function interactiveSchemaFromStreamMessage\(message\)/,
    'the confirmed readiness stage must consume its authoritative schema from SSE');
});

test('frontend closes its EventSource only after an accepted terminal case schema', () => {
  assert.match(consoleHtml, /function shouldCloseCaseEventStream\(schema\)\s*\{\s*const caseComplete = \['COMPLETED', 'INCOMPLETE', 'FAILED', 'BLOCKED'\]\.includes\(schema\?\.status\);\s*const browserStillActive = \['STARTING', 'RUNNING'\]\.includes\(schema\?\.interactiveSession\?\.status\);\s*return caseComplete && !browserStillActive;/);
  assert.match(consoleHtml, /const acceptedSchema = acceptCaseSchema\(schema\);\s*if \(!acceptedSchema\) return;\s*const done = shouldCloseCaseEventStream\(acceptedSchema\);[\s\S]{0,500}?evtSource\.close\(\);/,
    'EventSource close must follow acceptance of the authoritative terminal schema');
  assert.match(backendServer, /if \(icase\.schema\.interactiveSession\?\.enabled && icase\.schema\.interactiveSession\.status === 'RUNNING'\)\s*\{\s*icase\.schema\.interactiveSession\.status = 'CANCELLED';[\s\S]{0,800}?icase\.emit\('complete', icase\.schema\);/,
    'cancel-live must publish the terminal session state before the frontend closes its stream');
});

test('Docker fixture test performs the first browser action before bounded container diagnostics', () => {
  const firstTypingAction = fixtureTest.indexOf("label: 'typing interaction'");
  const containerInspection = fixtureTest.indexOf("['inspect', firstHandle.browserContainerName, firstHandle.egressContainerName], 10_000");
  assert.ok(firstTypingAction >= 0 && containerInspection > firstTypingAction,
    'slow Docker diagnostics must not consume the short worker interaction window before first action');
  const inputPreparation = fixtureTest.indexOf('prepareTypingActionInputs(uiPage');
  const readinessWait = fixtureTest.indexOf('const firstReady = await waitReady(base, operatorToken, first)');
  const controlsReady = fixtureTest.indexOf("recordTimeline('ui-interaction-controls-enabled')");
  const firstClick = fixtureTest.indexOf("const typeResponse = await clickForApiResponse");
  const typingInputsHelper = fs.readFileSync(new URL('./helpers/typing_action_inputs.js', import.meta.url), 'utf8');
  assert.ok(readinessWait >= 0 && controlsReady > readinessWait && inputPreparation > controlsReady && firstClick > inputPreparation,
    'typing fields must be set and verified after session readiness, immediately before the first action');
  assert.ok(typingInputsHelper.includes('await selectorInput.fill(expectedSelector, { timeout: 5_000 })'));
  assert.ok(typingInputsHelper.includes('await textInput.fill(text, { timeout: 5_000 })'));
  assert.ok(typingInputsHelper.includes('await selectorInput.inputValue({ timeout: 1_000 })'));
  assert.match(typingInputsHelper, /selectorMatchesExpectedFixture/);
  assert.match(fixtureTest, /page\.locator\('#view-overview'\)[\s\S]*?view\.locator\('#ov-interactive-browser-card'\)[\s\S]*?card\.locator\('#interactive-type'\)/,
    'the action locator must be scoped to the actual view and interactive card');
  assert.match(fixtureTest, /button\.scrollIntoViewIfNeeded\(\{ timeout: 1_000 \}\)/,
    'the action control must use Playwright scrolling before the click');
  assert.match(fixtureTest, /button\.click\(\{ timeout: 5_000 \}\)/);
  assert.doesNotMatch(fixtureTest, /button\.click\([^)]*force:\s*true/,
    'the browser interaction must preserve normal Playwright actionability checks');
  assert.match(fixtureTest, /wallElapsedMs: Math\.max\(0, Date\.now\(\) - testStartedWallAt\)/,
    'test diagnostics must retain wall and monotonic elapsed clocks separately');
  assert.match(fixtureTest, /sessionElapsedMsAtClick/,
    'the first-click timeline must include the supervisor session age');
  assert.match(consoleHtml, /\.app-workspace \{[^}]*overflow-y: auto/);
  assert.match(consoleHtml, /\.bottom-statusbar \{[^}]*flex-shrink: 0/);
  assert.match(browserWorker, /Math\.min\(keepAliveMs, MAX_SESSION_MS\)/);
  assert.match(browserWorker, /reason: endReason/);
  assert.match(browserWorker, /SESSION_LIMIT_REACHED/);
});

test('interactive termination records a bounded reason and refreshes the case UI', () => {
  assert.match(browserWorker, /emit\('interactive_session_ended',[\s\S]{0,160}reason: endReason/);
  assert.match(investigationEngine, /endedReason = reason/);
  assert.match(investigationEngine, /liveInspection\.runtimeSessionActive = false/);
  assert.match(investigationEngine, /stage: 'INTERACTIVE_SESSION_ENDED'/);
});

test('case refreshes do not restart screenshot requests unless the artifact revision changes', () => {
  assert.match(consoleHtml, /const screenshotRevision = schema\.liveInspection\?\.screenshotCaptured/);
  assert.match(consoleHtml, /shotImg\.dataset\.trustLayerArtifactUrl !== screenshotRequestUrl/);
  assert.match(consoleHtml, /shotImg\.src = screenshotRequestUrl/);
  assert.doesNotMatch(consoleHtml, /shotImg\.src = `\$\{screenshotUrl\}.*Date\.now\(\)/);
});

test('typing-control failures retain bounded last-known UI and browser lifecycle diagnostics', () => {
  const phaseMarker = fixtureTest.indexOf("workflowPhase = 'interaction-preflight'");
  const positionCall = fixtureTest.indexOf('prepareTypingControlForClick(uiPage,', phaseMarker);
  const failureDiagnostic = fixtureTest.indexOf("logDiagnosticSafely('trustlayer-typing-position-diagnostic'", positionCall);
  assert.ok(phaseMarker >= 0 && positionCall > phaseMarker && failureDiagnostic > positionCall,
    'control preparation must have its own phase and failure diagnostics');
  const diagnosticBlock = fixtureTest.slice(failureDiagnostic, fixtureTest.indexOf('throw error;', failureDiagnostic));
  for (const field of ['url:', 'pageClosed', 'browserConnected', 'browserLifecycle',
    'lastReadinessSample', 'elapsedMonotonicMs', 'elapsedWallMs', 'typingPreparationOperation']) {
    assert.ok(diagnosticBlock.includes(field), `failure diagnostics should include ${field}`);
  }
  assert.match(fixtureTest, /uiPage\.on\('crash'/, 'renderer crash events should be captured without page evaluation');
  assert.match(fixtureTest, /uiPage\.on\('framenavigated'/, 'main-frame navigation should be recorded without query data');
  assert.match(fixtureTest, /uiPage\.on\('dialog'/, 'outstanding JavaScript dialogs should be tracked');
  assert.match(fixtureTest, /withPlaywrightStepDeadline\(name, run, 1_000\)/,
    'locator operations without native timeouts must still be bounded');
  assert.match(fixtureTest, /documentReadyState: document\.readyState/,
    'last-known readiness evidence should include document readiness');
  assert.match(fixtureTest, /lastReadinessSample: lastReadinessSnapshot/,
    'the sampled readiness value must be explicitly passed to failure diagnostics');
  const prepareStart = fixtureTest.indexOf('async function prepareTypingControlForClick');
  const prepareEnd = fixtureTest.indexOf('\nfunction validateCaseEvents', prepareStart);
  const prepareBlock = fixtureTest.slice(prepareStart, prepareEnd);
  assert.match(prepareBlock, /const card = view\.locator\('#ov-interactive-browser-card'\)/);
  assert.match(prepareBlock, /step\('wait-for-card'/);
  assert.doesNotMatch(prepareBlock, /wait-for-view|view\.waitFor|viewVisible/,
    'the card visibility check already proves the parent view is rendered');
  assert.doesNotMatch(diagnosticBlock, /page\.evaluate|domSnapshot/,
    'failure diagnostics must not issue another page evaluation');
  assert.doesNotMatch(diagnosticBlock, /operatorToken|caseAccessToken|cookie|authorization/i,
    'positioning diagnostics must not contain credentials or authentication data');
  assert.match(fixtureTest, /ui-browser-close-finished[\s\S]{0,220}strategy/,
    'browser shutdown outcome should be measured independently from supervisor cleanup');
  assert.match(typingDiagnosticHelper, /freshPageEvaluation: 'NOT_ATTEMPTED_AFTER_FAILURE'/,
    'failure diagnostics must not issue another page evaluation');
  assert.match(fixtureTest, /uiBrowserServer\.process\(\) === uiBrowserProcess/,
    'the BrowserServer close event must be tied to the tracked child process');
  assert.match(fixtureTest, /uiBrowserProcess\.once\('exit'/,
    'the tracked child process exit should be recorded independently');
  const clickHelperStart = fixtureTest.indexOf('async function clickForApiResponse');
  const clickHelperEnd = fixtureTest.indexOf('\nasync function openEvents', clickHelperStart);
  const clickHelper = fixtureTest.slice(clickHelperStart, clickHelperEnd);
  const clickFailureDiagnostics = clickHelper.slice(clickHelper.indexOf('} catch (error) {'));
  assert.doesNotMatch(clickFailureDiagnostics, /await\s+(?:button\.|page\.)|\.evaluate\(/,
    'click failure diagnostics must not make more renderer calls');
  assert.match(clickFailureDiagnostics, /throw error;/,
    'click failure must rethrow the original Playwright exception');
  assert.doesNotMatch(fixtureTest, /readInteractiveUiSnapshot\(uiPage\)\.catch/,
    'startup failure diagnostics must use last-known state instead of another page read');
});

test('typing-control failure diagnostics use only last-known state and retain the actual error class', () => {
  const lastReadinessSample = { ready: true, activeViewId: 'view-overview', controlEnabled: true };
  const diagnostic = buildTypingControlFailureDiagnostic({
    error: Object.assign(new Error('sensitive text must not be logged'), { name: 'TimeoutError' }),
    operation: 'scroll-button', phase: 'interaction-preflight',
    url: 'http://127.0.0.1:3000/investigation.html?secret=hidden',
    elapsedMonotonicMs: 12_345, elapsedWallMs: 12_350,
    pageClosed: false, browserConnected: true, contextPageCount: 1,
    serverProcessExitCode: null, serverProcessSignalCode: null,
    browserLifecycle: [{ event: 'page-crashed', at: 123 }],
    activeDialog: { type: 'prompt', phase: 'interactive-actions', openedAt: Date.now() },
    lastReadinessSample
  });
  assert.equal(diagnostic.errorName, 'TimeoutError');
  assert.equal(diagnostic.operation, 'scroll-button');
  assert.equal(diagnostic.currentUrl, 'http://127.0.0.1:3000/investigation.html');
  assert.equal(JSON.stringify(diagnostic).includes('secret'), false);
  assert.equal(JSON.stringify(diagnostic).includes('sensitive text'), false);
  assert.equal(diagnostic.lastReadinessSample, lastReadinessSample);
  assert.equal(diagnostic.freshPageEvaluation, 'NOT_ATTEMPTED_AFTER_FAILURE');
  assert.equal(diagnostic.browser.activeDialog.type, 'prompt');
});

test('diagnostic construction and logging failures cannot replace the original error', () => {
  const original = new Error('original locator failure');
  let observed;
  try {
    try { throw original; }
    catch (error) {
      logDiagnosticSafely('diagnostic-test', () => { throw new Error('diagnostic builder failed'); }, () => {
        throw new Error('diagnostic logger failed');
      });
      throw error;
    }
  } catch (error) { observed = error; }
  assert.equal(observed, original);
  assert.match(observed.stack, /original locator failure/);
});

test('UI browser teardown has graceful, BrowserServer.kill, and process-exit fallbacks', () => {
  assert.match(fixtureTest, /chromium\.launchServer\(\{ headless: true \}\)/);
  assert.match(fixtureTest, /chromium\.connect\(uiBrowserServer\.wsEndpoint\(\)\)/);
  assert.match(fixtureTest, /closeBrowserBounded\(\{/);
  assert.match(fixtureTest, /gracefulTimeoutMs: 2_000/);
  assert.match(fixtureTest, /serverKillTimeoutMs: 1_500/);
  assert.match(fixtureTest, /processExitTimeoutMs: 1_500/);
  assert.match(fixtureTest, /killBrowserServer: \(\) => uiBrowserServer\.kill\(\)/);
  assert.match(fixtureTest, /process: uiBrowserProcess/);
  assert.match(fixtureTest, /settleTasksWithin\(\[\.\.\.dialogTasks\], 500\)/,
    'dialog handler draining after shutdown must also remain bounded');
});
