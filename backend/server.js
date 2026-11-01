/**
 * Trust Layer — Backend Investigation Server v2.5
 * REST & SSE APIs serving structured case schema telemetry.
 * Control Plane only: Does not perform arbitrary fetches or run browsers in-process.
 */

import express from 'express';
import fs from 'node:fs';
import { createServer } from 'node:http';
import { randomBytes, randomUUID, timingSafeEqual } from 'node:crypto';
import path from 'path';
import { fileURLToPath } from 'url';
import { InvestigationEngine, INSPECTION_MODE } from '../core/investigation_engine.js';
import { CASE_STATE } from '../core/case_schema.js';
import { validateEvidenceEvent } from '../core/evidence_event.js';
import { globalJobController } from '../core/investigators/live_job_controller.js';
import { validateInteractiveAction, MAX_INTERACTIVE_SCREENSHOTS, MAX_INTERACTIVE_VIEWPORT_FRAME_BYTES } from '../core/interactive_action.js';
import { redactSensitiveUrl } from '../core/investigators/url_redaction.js';
import { createCaseAccessCredential, verifyCaseAccessCredential } from '../core/case_access.js';
import { buildEvidenceReport } from '../core/evidence_report.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const rootDir = path.resolve(__dirname, '..');

const PORT = process.env.PORT || 3000;

function secureEqual(left, right) {
  if (typeof left !== 'string' || typeof right !== 'string') return false;
  const a = Buffer.from(left);
  const b = Buffer.from(right);
  return a.length === b.length && timingSafeEqual(a, b);
}

function parseCookies(header = '') {
  const cookies = new Map();
  for (const part of header.split(';')) {
    const separator = part.indexOf('=');
    if (separator <= 0) continue;
    const name = part.slice(0, separator).trim();
    if (/^[A-Za-z0-9_-]+$/.test(name)) cookies.set(name, part.slice(separator + 1).trim());
  }
  return cookies;
}

export function createApp({ apiToken = process.env.TRUSTLAYER_API_TOKEN, cases = new Map(), rateLimits = {},
  investigateCase = icase => InvestigationEngine.investigate(icase) } = {}) {
  if (typeof apiToken !== 'string' || Buffer.byteLength(apiToken) < 32 || Buffer.byteLength(apiToken) > 1024) {
    throw new Error('TRUSTLAYER_API_TOKEN must contain 32 to 1024 bytes of random secret material.');
  }
  const app = express();
  app.disable('x-powered-by');
  const sessions = new Map();
  const loginAttempts = new Map();
  const requestBuckets = new Map();
  const maxCases = 1000;
  const activeCaseLimit = 16;
  const sseClients = new Set();
  const sessionTtlMs = 8 * 60 * 60 * 1000;
  const sessionCookieName = 'trustlayer_session';
  const cookieSecure = process.env.NODE_ENV === 'production';
  const requestOrigin = (req) => process.env.TRUSTLAYER_PUBLIC_ORIGIN || `${req.protocol}://${req.get('host')}`;
  const originMatches = (req) => typeof req.get('origin') === 'string' && req.get('origin') === requestOrigin(req);

  function consumeLimit(map, key, { limit, windowMs }) {
    const now = Date.now();
    let bucket = map.get(key);
    if (!bucket || bucket.until <= now) bucket = { count: 0, until: now + windowMs };
    if (bucket.count >= limit) return false;
    bucket.count++;
    map.delete(key);
    map.set(key, bucket);
    while (map.size > 2048) map.delete(map.keys().next().value);
    return true;
  }

  function findCase(req, res) {
    const id = req.params.id;
    if (typeof id !== 'string' || !/^TL-\d{4}-\d{4}-\d{4}-[A-Z0-9]{3,12}$/.test(id)) return null;
    const icase = cases.get(id);
    if (!icase || !hasCaseAccess(req, id, icase)) return null;
    return icase;
  }

  function hasCaseAccess(req, id, icase) {
    if (!Number.isSafeInteger(icase?._caseAccessExpiresAt) || icase._caseAccessExpiresAt <= Date.now()) return false;
    const headerCredential = req.get('x-trustlayer-case-access');
    const cookieCredential = parseCookies(req.headers.cookie).get(`trustlayer_case_${id}`);
    const credential = headerCredential === undefined ? cookieCredential : headerCredential;
    return verifyCaseAccessCredential(credential, icase?._caseAccessVerifier);
  }

  app.use((req, res, next) => {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('Referrer-Policy', 'no-referrer');
    res.setHeader('Cache-Control', 'no-store');
    next();
  });

  app.post('/api/auth/session', express.json({ limit: '2kb' }), (req, res) => {
    const now = Date.now();
    for (const [ip, attempt] of loginAttempts) if (attempt.until <= now) loginAttempts.delete(ip);
    const ip = req.socket.remoteAddress || 'unknown';
    const attempt = loginAttempts.get(ip) || { count: 0, until: now + 60_000 };
    if (attempt.count >= 5) return res.status(429).json({ error: 'Authentication temporarily unavailable.' });
    attempt.count++;
    loginAttempts.set(ip, attempt);
    if (loginAttempts.size > 1024) loginAttempts.delete(loginAttempts.keys().next().value);
    if (req.get('origin') && !originMatches(req)) return res.status(403).json({ error: 'Origin rejected.' });
    if (!secureEqual(req.body?.token, apiToken)) return res.status(401).json({ error: 'Invalid API credentials.' });
    loginAttempts.delete(ip);
    for (const [id, session] of sessions) if (session.expiresAt <= now) sessions.delete(id);
    if (sessions.size >= 2048) return res.status(503).json({ error: 'Session capacity reached; retry later.' });
    const sessionId = randomBytes(32).toString('base64url');
    sessions.set(sessionId, { expiresAt: now + sessionTtlMs });
    res.setHeader('Set-Cookie', `${sessionCookieName}=${sessionId}; Path=/api; HttpOnly; SameSite=Strict; Max-Age=${Math.floor(sessionTtlMs / 1000)}${cookieSecure ? '; Secure' : ''}`);
    res.setHeader('Cache-Control', 'no-store');
    return res.status(204).end();
  });

  app.use('/api', (req, res, next) => {
    const authorization = req.get('authorization');
    if (authorization !== undefined) {
      const match = /^Bearer ([^\s]+)$/.exec(authorization);
      if (!match || !secureEqual(match[1], apiToken)) return res.status(401).json({ error: 'Authentication required.' });
      req.trustLayerAuth = 'bearer';
      return next();
    }
    const sessionId = parseCookies(req.headers.cookie).get(sessionCookieName);
    const session = sessionId && sessions.get(sessionId);
    if (session && session.expiresAt > Date.now()) {
      if (!['GET', 'HEAD', 'OPTIONS'].includes(req.method) && !originMatches(req)) {
        return res.status(403).json({ error: 'Origin rejected.' });
      }
      req.trustLayerAuth = 'session';
      return next();
    }
    if (sessionId) sessions.delete(sessionId);
    res.setHeader('WWW-Authenticate', 'Bearer realm="Trust Layer API"');
    return res.status(401).json({ error: 'Authentication required.' });
  });
  app.use('/api', express.json({ limit: '64kb' }));
  app.post('/api/auth/logout', (req, res) => {
    const sessionId = parseCookies(req.headers.cookie).get(sessionCookieName);
    if (sessionId) sessions.delete(sessionId);
    const expired = [`${sessionCookieName}=; Path=/api; HttpOnly; SameSite=Strict; Max-Age=0${cookieSecure ? '; Secure' : ''}`];
    for (const cookieName of parseCookies(req.headers.cookie).keys()) {
      if (/^trustlayer_case_TL-\d{4}-\d{4}-\d{4}-[A-Z0-9]{3,12}$/.test(cookieName)) {
        expired.push(`${cookieName}=; Path=/api; HttpOnly; SameSite=Strict; Max-Age=0${cookieSecure ? '; Secure' : ''}`);
      }
    }
    res.setHeader('Set-Cookie', expired);
    res.status(204).end();
  });

// 1. Landing page / main pre-investigation dashboard
app.get('/', (req, res) => {
  res.sendFile(path.join(rootDir, 'index.html'));
});

// 2. Investigation console routes
app.get('/investigate', (req, res) => {
  res.sendFile(path.join(rootDir, 'investigation.html'));
});

app.get('/console', (req, res) => {
  res.sendFile(path.join(rootDir, 'investigation.html'));
});

app.get('/investigation', (req, res) => {
  res.sendFile(path.join(rootDir, 'investigation.html'));
});

app.get('/investigation.html', (req, res) => {
  res.sendFile(path.join(rootDir, 'investigation.html'));
});

// Only explicitly referenced vendor assets are public. Serving the repository
// root would expose local source, audit documents, and screenshot files.
app.use('/vendor', express.static(path.join(rootDir, 'vendor'), { dotfiles: 'deny', index: false }));

// ── Case Management REST API ──────────────────────────────────────────────

/**
 * POST /api/cases
 * Create and execute a new forensic investigation case
 */
app.post('/api/cases', (req, res) => {
  const ip = req.socket.remoteAddress || 'unknown';
  if (!consumeLimit(requestBuckets, `create:${ip}`, { limit: rateLimits.createPerMinute || 20, windowMs: 60_000 })) {
    return res.status(429).json({ error: 'Investigation creation rate limit reached.' });
  }
  if (cases.size >= maxCases) return res.status(503).json({ error: 'Investigation capacity reached.' });
  let activeCases = 0;
  for (const item of cases.values()) if (!item.schema?.completedAt && ![CASE_STATE.COMPLETED, CASE_STATE.FAILED, CASE_STATE.INCOMPLETE, CASE_STATE.BLOCKED].includes(item.schema?.status)) activeCases++;
  if (activeCases >= activeCaseLimit) return res.status(429).json({ error: 'Investigation concurrency limit reached.' });
  const { target, targetType, expectedContext, inspectionMode, consentConfirmed, captureDelayMs, interactive } = req.body || {};
  if (!target || typeof target !== 'string' || Buffer.byteLength(target, 'utf8') > 4096 || target.trim().length === 0) {
    return res.status(400).json({ error: 'Field "target" is required.' });
  }
  if (targetType !== undefined && !['URL', 'QR', 'UPI'].includes(targetType)) return res.status(400).json({ error: 'Invalid target type.' });
  if (expectedContext !== undefined && (typeof expectedContext !== 'string' || expectedContext.length > 1000)) return res.status(400).json({ error: 'Invalid expected context.' });

  const cleanTarget = target.trim();
  const selectedMode = inspectionMode || INSPECTION_MODE.URL_ONLY;
  if (!Object.values(INSPECTION_MODE).includes(selectedMode)) return res.status(400).json({ error: 'Invalid inspection mode.' });
  if (selectedMode === INSPECTION_MODE.ISOLATED_LIVE && captureDelayMs !== undefined && ![0, 5000, 10000].includes(captureDelayMs)) {
    return res.status(400).json({ error: 'captureDelayMs must be 0, 5000, or 10000.' });
  }
  if (interactive !== undefined && typeof interactive !== 'boolean') return res.status(400).json({ error: 'interactive must be a boolean.' });
  if (interactive && selectedMode !== INSPECTION_MODE.ISOLATED_LIVE) return res.status(400).json({ error: 'Interactive sessions require isolated live inspection.' });
  if ([INSPECTION_MODE.MODE_B, INSPECTION_MODE.ISOLATED_LIVE].includes(selectedMode) && consentConfirmed !== true) {
    return res.status(400).json({ error: 'Explicit consent is required before active HTTP tracing or isolated live inspection.' });
  }
  const icase = InvestigationEngine.createCase(cleanTarget, targetType || 'URL', selectedMode);
  const caseAccess = createCaseAccessCredential();
  // Keep only a verifier on the in-memory case. The raw credential is returned
  // once to the authenticated creator and stored by browsers in an HttpOnly cookie.
  icase._caseAccessVerifier = caseAccess.verifier;
  icase._caseAccessExpiresAt = Date.now() + sessionTtlMs;
  icase.schema.captureDelayMs = selectedMode === INSPECTION_MODE.ISOLATED_LIVE ? (captureDelayMs ?? 10000) : 10000;
  icase.schema.screenshotCapture.captureDelayMs = icase.schema.captureDelayMs;
  if (selectedMode === INSPECTION_MODE.MODE_B) icase.schema.modeBConsentAt = Date.now();
  if (selectedMode === INSPECTION_MODE.ISOLATED_LIVE) icase.schema.modeCConsentAt = Date.now();
  if (interactive) {
    icase.schema.interactiveSession = { enabled: true, status: 'STARTING', startedAt: Date.now(), maxDurationMs: 120000,
      maxActions: 20, actionCount: 0, screenshotCount: 0, maxScreenshots: MAX_INTERACTIVE_SCREENSHOTS,
      currentUrl: redactSensitiveUrl(cleanTarget), events: [], limitations: ['Form submissions, downloads, permissions, popups, and sensitive controls are blocked.'] };
  }
  if (expectedContext) {
    icase.schema.expectedContext = expectedContext;
  }
  cases.set(icase.id, icase);
  res.setHeader('Set-Cookie', `trustlayer_case_${icase.id}=${caseAccess.token}; Path=/api; HttpOnly; SameSite=Strict; Max-Age=${Math.floor(sessionTtlMs / 1000)}${cookieSecure ? '; Secure' : ''}`);

  // SSE client set
  icase._sseClients = new Set();

  // Broadcast events to SSE subscribers
  icase.on('*', (msg) => {
    const payload = `data: ${JSON.stringify(msg)}\n\n`;
    for (const client of icase._sseClients) {
      try { client.write(payload); } catch {}
    }
  });

  if (interactive) {
    let sequence = 0;
    const knownEventIds = new Set();
    icase._publishInteractiveObservation = (observation = {}) => {
      if (icase.schema.interactiveSession?.events?.length >= 512) return;
      const actionEvent = String(observation.type || '').startsWith('action_');
      const event = {
        version: 1, investigationId: icase.id, eventId: randomUUID().replaceAll('-', ''), timestamp: Date.now(), sequence: ++sequence,
        type: observation.type === 'screenshot' ? 'screenshot' : (actionEvent ? 'user_action' : (observation.type === 'redirect' ? 'redirect' : (observation.type === 'dom_change' ? 'dom_change' : 'network_observation'))),
        source: actionEvent ? 'operator' : 'browser', collectionStatus: 'complete', limitations: [], freshness: 'live', kind: 'observed',
        ...(typeof observation.url === 'string' ? { url: (() => { try { const u = new URL(observation.url); return `${u.origin}${u.pathname}`; } catch { return undefined; } })() } : {}),
        evidenceRefs: Array.isArray(observation.evidenceRefs) ? observation.evidenceRefs : [], observation: String(observation.observation || observation.type || 'Browser observation').slice(0, 2048)
      };
      const validation = validateEvidenceEvent(event, { investigationId: icase.id, knownEvidenceIds: new Set(icase.schema.evidence.map(item => item.id)), expectedSequence: sequence, knownEventIds });
      if (!validation.valid) return;
      knownEventIds.add(event.eventId);
      icase.schema.interactiveSession.events.push(event);
      icase.emit('evidence_event', event);
    };
  }

  // Execute pipeline in background
  Promise.resolve().then(() => investigateCase(icase)).catch((err) => {
    icase.log('PIPELINE EXCEPTION: internal processing failure', 'error');
  });

  res.status(201).json({
    caseId: icase.id,
    caseAccessToken: caseAccess.token,
    target: icase.target,
    status: icase.status,
    currentStage: icase.currentStage,
    inspectionMode: icase.schema.inspectionMode,
    interactiveEnabled: icase.schema.interactiveSession?.enabled === true,
    createdAt: icase.schema.createdAt
  });
});

/**
 * POST /api/cases/:id/live-inspect
 * Explicitly trigger Mode C (Isolated Live Inspection) with user consent
 */
app.post('/api/cases/:id/live-inspect', (req, res) => {
  const ip = req.socket.remoteAddress || 'unknown';
  if (!consumeLimit(requestBuckets, `live:${ip}`, { limit: rateLimits.livePerMinute || 10, windowMs: 60_000 })) return res.status(429).json({ error: 'Live inspection rate limit reached.' });
  const icase = findCase(req, res);
  if (!icase) {
    return res.status(404).json({ error: 'Case not found' });
  }
  if (icase.schema.lifecycleState === 'running') return res.status(409).json({ error: 'Investigation is already running.' });

  const { consentConfirmed, captureDelayMs } = req.body || {};
  if (!consentConfirmed) {
    return res.status(400).json({ error: 'Explicit user consent is required to execute live inspection.' });
  }
  if (captureDelayMs !== undefined && ![0, 5000, 10000].includes(captureDelayMs)) {
    return res.status(400).json({ error: 'captureDelayMs must be 0, 5000, or 10000.' });
  }

  icase.schema.inspectionMode = INSPECTION_MODE.ISOLATED_LIVE;
  icase.schema.captureDelayMs = captureDelayMs ?? icase.schema.captureDelayMs ?? 10000;
  icase.schema.screenshotCapture = { status: 'STARTING', captureDelayMs: icase.schema.captureDelayMs,
    countdownStartedAt: null, countdownEndsAt: null, capturedAt: null };
  // A reinspection must leave the previous terminal state immediately so SSE/UI
  // consumers can show live progress instead of retaining stale INCOMPLETE.
  icase.schema.status = CASE_STATE.NORMALIZING;
  icase.schema.completedAt = null;
  icase._abortController = new AbortController();
  icase._abortSignal = icase._abortController.signal;
  icase.log('OPERATOR AUTHORIZED: Upgrading case to Mode C (Isolated Live Inspection)');
  icase.emit('stage', { stage: 'ISOLATED_LIVE_AUTHORIZED' });

  // Re-run pipeline with Mode C active
  Promise.resolve().then(() => investigateCase(icase)).catch((err) => {
    icase.log('LIVE INSPECTION EXCEPTION: internal processing failure', 'error');
  });

  res.json({
    caseId: icase.id,
    mode: INSPECTION_MODE.ISOLATED_LIVE,
    status: icase.status,
    message: 'Isolated Live Inspection started in background worker.'
  });
});

app.post('/api/cases/:id/interactions', async (req, res) => {
  const icase = findCase(req, res);
  if (!icase) return res.status(404).json({ error: 'Case not found' });
  if (!icase.schema.interactiveSession?.enabled || icase.schema.interactiveSession.status !== 'RUNNING') return res.status(409).json({ error: 'Interactive session is unavailable.' });
  const validation = validateInteractiveAction(req.body?.action);
  if (!validation.valid) {
    icase._publishInteractiveObservation?.({ type: 'action_rejected', observation: 'Investigator action rejected by the interaction schema.' });
    return res.status(400).json({ error: 'Invalid interaction action.', details: validation.errors });
  }
  if (req.body.action.type === 'screenshot' && icase.schema.interactiveSession.screenshotCount >= MAX_INTERACTIVE_SCREENSHOTS) return res.status(429).json({ error: 'Interactive screenshot limit reached.' });
  const pointerMove = req.body.action.type === 'pointer_move';
  if (!consumeLimit(requestBuckets, `interact:${req.socket.remoteAddress || 'unknown'}:${icase.id}`, {
    limit: pointerMove ? 120 : 30, windowMs: 60_000
  })) return res.status(429).json({ error: 'Interaction request rate limit reached.' });
  icase._publishInteractiveObservation?.({ type: 'action_accepted', observation: `Investigator ${req.body.action.type} action accepted for worker validation.` });
  const result = await globalJobController.interact(icase.id, req.body?.action);
  if (!result.ok) {
    icase._publishInteractiveObservation?.({ type: 'action_rejected', observation: 'Investigator action was rejected by the worker session or destination policy.' });
    return res.status(409).json({ error: result.error });
  }
  if (!pointerMove) icase.schema.interactiveSession.actionCount++;
  icase.schema.interactiveSession.currentUrl = result.url || icase.schema.interactiveSession.currentUrl;
  if (result.screenshotBase64) {
    try {
      const bytes = Buffer.from(result.screenshotBase64, 'base64');
      if (bytes.length < 1000 || bytes.length > 5 * 1024 * 1024 || bytes.readUInt32BE(16) > 1280 || bytes.readUInt32BE(20) > 800 || !bytes.subarray(0, 8).equals(Buffer.from([137,80,78,71,13,10,26,10]))) throw new Error('invalid image');
      const artifactId = randomUUID().replaceAll('-', '');
      const storageRoot = path.resolve(rootDir, 'data', 'screenshots');
      fs.mkdirSync(storageRoot, { recursive: true });
      const artifactPath = path.resolve(storageRoot, `${icase.id}-interactive-${artifactId}.png`);
      if (!artifactPath.startsWith(storageRoot + path.sep)) throw new Error('invalid path');
      fs.writeFileSync(artifactPath, bytes, { flag: 'wx', mode: 0o600 });
      if (!icase._interactiveArtifacts) icase._interactiveArtifacts = new Map();
      icase._interactiveArtifacts.set(artifactId, artifactPath);
      const evidence = icase.addEvidence('OBSERVED', 'screenshot', 'Interactive Browser Screenshot Captured', 'A bounded viewport screenshot was captured in the isolated worker.', { artifactId, bytes: bytes.length });
      icase.schema.interactiveSession.screenshotCount++;
      icase._publishInteractiveObservation?.({ type: 'screenshot', observation: 'Interactive screenshot captured; evidence reference recorded.', url: result.url, evidenceRefs: [evidence.id] });
      return res.json({ ok: true, action: result.action, url: result.url, artifactId, evidenceId: evidence.id });
    } catch { return res.status(502).json({ error: 'Screenshot artifact was rejected.' }); }
  }
  icase._publishInteractiveObservation?.({ type: `action_${result.action}`, observation: `Investigator ${result.action} action completed.`, url: result.url });
  res.json({ ok: true, action: result.action, url: result.url, ...(result.typed ? { typed: true } : {}) });
});

app.get('/api/cases/:id/interactive-viewport', async (req, res) => {
  const icase = findCase(req, res);
  if (!icase) return res.status(404).json({ error: 'Interactive viewport unavailable.' });
  if (!icase.schema.interactiveSession?.enabled || icase.schema.interactiveSession.status !== 'RUNNING' ||
      icase.schema.liveInspection?.runtimeSessionActive !== true) {
    return res.status(409).json({ error: 'Interactive viewport is unavailable.' });
  }
  if (!consumeLimit(requestBuckets, `viewport:${req.socket.remoteAddress || 'unknown'}:${icase.id}`, { limit: 2, windowMs: 1000 })) {
    return res.status(429).json({ error: 'Interactive viewport refresh is rate limited.' });
  }
  const frame = await globalJobController.captureViewport(icase.id);
  if (!frame?.ok || typeof frame.viewportBase64 !== 'string') return res.status(409).json({ error: 'Interactive viewport disconnected.' });
  try {
    const bytes = Buffer.from(frame.viewportBase64, 'base64');
    if (bytes.length < 256 || bytes.length > MAX_INTERACTIVE_VIEWPORT_FRAME_BYTES || bytes[0] !== 0xff || bytes[1] !== 0xd8 || bytes[2] !== 0xff) {
      return res.status(502).json({ error: 'Interactive viewport frame was rejected.' });
    }
    res.setHeader('Content-Type', 'image/jpeg');
    res.setHeader('Cache-Control', 'private, no-store');
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('Content-Length', String(bytes.length));
    return res.end(bytes);
  } catch { return res.status(502).json({ error: 'Interactive viewport frame was rejected.' }); }
});

app.get('/api/cases/:id/interactive-artifacts/:artifactId', (req, res) => {
  const icase = findCase(req, res);
  if (!icase) return res.status(404).json({ error: 'Artifact unavailable.' });
  const artifactId = req.params.artifactId;
  const artifactPath = /^[a-f0-9]{32}$/.test(artifactId) ? icase._interactiveArtifacts?.get(artifactId) : null;
  if (!artifactPath) return res.status(404).json({ error: 'Artifact unavailable.' });
  try {
    const root = fs.realpathSync(path.resolve(rootDir, 'data', 'screenshots'));
    const real = fs.realpathSync(artifactPath);
    const stat = fs.statSync(real);
    if (!real.startsWith(root + path.sep) || !stat.isFile() || stat.size > 5 * 1024 * 1024) return res.status(404).json({ error: 'Artifact unavailable.' });
    res.type('png').sendFile(real);
  } catch { res.status(404).json({ error: 'Artifact unavailable.' }); }
});

/**
 * POST /api/cases/:id/cancel-live
 * Abort active live inspection
 */
app.post('/api/cases/:id/cancel-live', (req, res) => {
  const icase = findCase(req, res);
  if (!icase) {
    return res.status(404).json({ error: 'Case not found' });
  }

  if (icase._abortController) {
    icase._abortController.abort();
  }
  if (icase.schema.interactiveSession?.enabled && icase.schema.interactiveSession.status === 'RUNNING') {
    icase.schema.interactiveSession.status = 'CANCELLED';
    icase.schema.interactiveSession.endedAt = Date.now();
  }
  const wasCompleted = icase.schema.status === CASE_STATE.COMPLETED;
  if (icase.schema.liveInspection) {
    icase.schema.liveInspection.runtimeSessionActive = false;
    icase.schema.liveInspection.runtimeSessionEndedAt = Date.now();
  }
  if (!wasCompleted) icase.schema.status = CASE_STATE.INCOMPLETE;
  if (!wasCompleted) icase.schema.lifecycleState = 'cancelled';
  icase.log(wasCompleted ? 'LIVE BROWSER SESSION STOPPED BY OPERATOR' : 'LIVE INSPECTION CANCELLED BY OPERATOR', 'warn');
  icase.emit('complete', icase.schema);

  res.json({ message: 'Live inspection cancelled', caseId: icase.id });
});

/**
 * GET /api/cases
 * List recent investigation cases
 */
app.get('/api/cases', (req, res) => {
  const list = [];
  const recent = [...cases.entries()].slice(-100).reverse();
  for (const [id, icase] of recent) {
    if (!hasCaseAccess(req, id, icase)) continue;
    list.push({
      id,
      target: icase.target,
      status: icase.status,
      currentStage: icase.currentStage,
      inspectionMode: icase.schema.inspectionMode || 'URL_ONLY',
      assessment: icase.assessment,
      evidenceCount: icase.evidence.length,
      createdAt: icase.schema.createdAt,
      completedAt: icase.schema.completedAt,
      isDemo: icase.isDemo
    });
  }
  res.json({ cases: list });
});

/**
 * GET /api/cases/:id
 * Retrieve complete structured case schema
 */
app.get('/api/cases/:id', (req, res) => {
  const icase = findCase(req, res);
  if (!icase) {
    return res.status(404).json({ error: 'Case not found' });
  }
  res.json(icase.schema);
});

app.get('/api/cases/:id/evidence-report', (req, res) => {
  const icase = findCase(req, res);
  if (!icase) return res.status(404).json({ error: 'Case not found' });
  return res.json(buildEvidenceReport(icase.schema));
});

/**
 * GET /api/cases/:id/events
 * SSE stream for real-time investigation telemetry
 */
app.get('/api/cases/:id/events', (req, res) => {
  const icase = findCase(req, res);
  if (!icase) {
    return res.status(404).json({ error: 'Case not found' });
  }

  if (!icase._sseClients) icase._sseClients = new Set();
  if (sseClients.size >= 128 || icase._sseClients.size >= 8) return res.status(429).json({ error: 'Event stream capacity reached.' });
  res.setHeader('X-Accel-Buffering', 'no');
  res.writeHead(200, {
    'Content-Type': 'text/event-stream',
    'Cache-Control': 'no-cache',
    'Connection': 'keep-alive'
  });
  icase._sseClients.add(res);
  sseClients.add(res);
  const heartbeat = setInterval(() => { try { if (!res.writableEnded) res.write(': keepalive\n\n'); } catch {} }, 20_000);
  heartbeat.unref?.();
  const closeTimer = setTimeout(() => res.end(), 30 * 60_000);
  closeTimer.unref?.();

  // Send current schema snapshot immediately
  res.write(`data: ${JSON.stringify({ event: 'snapshot', schema: icase.schema })}\n\n`);

  let streamClosed = false;
  const closeStream = () => {
    if (streamClosed) return;
    streamClosed = true;
    clearInterval(heartbeat);
    clearTimeout(closeTimer);
    icase._sseClients.delete(res);
    sseClients.delete(res);
  };
  res.once('close', closeStream);
  req.once('aborted', closeStream);
});

/**
 * POST /api/cases/:id/cancel
 */
app.post('/api/cases/:id/cancel', (req, res) => {
  const icase = findCase(req, res);
  if (!icase) {
    return res.status(404).json({ error: 'Case not found' });
  }

  if (icase._abortController) {
    icase._abortController.abort();
  }
  if (icase.schema.interactiveSession?.enabled && icase.schema.interactiveSession.status === 'RUNNING') {
    icase.schema.interactiveSession.status = 'CANCELLED';
    icase.schema.interactiveSession.endedAt = Date.now();
  }
  icase.schema.status = CASE_STATE.INCOMPLETE;
  icase.schema.lifecycleState = 'cancelled';
  icase.schema.completedAt = Date.now();
  icase.log('INVESTIGATION HALTED BY OPERATOR', 'warn');
  icase.emit('complete', icase.schema);

  res.json({ message: 'Investigation cancelled', caseId: icase.id });
});

// /console is an alias for the unified SPA — keeps legacy bookmarks working

/**
 * GET /api/cases/:id/screenshot
 * Stream validated webpage screenshot artifact
 */
app.get('/api/cases/:id/screenshot', (req, res) => {
  const caseId = req.params.id;

  // 1. Validate Case ID format to block path traversal attempts
  // 2. Enforce case access / existence check
  const icase = cases.get(caseId);
  if (!/^TL-\d{4}-\d{4}-\d{4}-[A-Z0-9]{3,12}$/.test(caseId) || !icase || !hasCaseAccess(req, caseId, icase)) {
    return res.status(404).json({ error: 'Screenshot unavailable.' });
  }

  if (req.query.type !== undefined && req.query.type !== 'initial') return res.status(404).json({ error: 'Screenshot unavailable.' });

  // 3. Resolve path strictly within approved storage root
  const storageRoot = path.resolve(rootDir, 'data', 'screenshots');
  const shotFileName = req.query.type === 'initial' ? `${caseId}-initial.png` : `${caseId}.png`;
  let shotPath = path.resolve(storageRoot, shotFileName);
  if (!shotPath.startsWith(storageRoot + path.sep)) {
    return res.status(403).json({ error: 'Access denied: Path traversal detected' });
  }

  // Fallback to primary screenshot if initial checkpoint doesn't exist
  if (!fs.existsSync(shotPath) && req.query.type === 'initial') {
    shotPath = path.resolve(storageRoot, `${caseId}.png`);
  }

  if (!fs.existsSync(shotPath)) {
    return res.status(404).json({
      error: 'Screenshot unavailable',
      reason: 'No screenshot artifact exists for this case (e.g. Mode A URL-only or failed navigation).'
    });
  }

  try {
    const realRoot = fs.realpathSync(storageRoot);
    const realShot = fs.realpathSync(shotPath);
    if (!realShot.startsWith(realRoot + path.sep)) return res.status(404).json({ error: 'Screenshot unavailable.' });
    const stat = fs.statSync(realShot);
    if (!stat.isFile() || stat.size > 5 * 1024 * 1024) return res.status(404).json({ error: 'Screenshot unavailable.' });
    const header = Buffer.alloc(8);
    const fd = fs.openSync(realShot, 'r');
    try { fs.readSync(fd, header, 0, 8, 0); }
    finally { fs.closeSync(fd); }

    const isPng = header[0] === 0x89 && header[1] === 0x50 && header[2] === 0x4e && header[3] === 0x47 &&
                  header[4] === 0x0d && header[5] === 0x0a && header[6] === 0x1a && header[7] === 0x0a;

    if (!isPng) {
      return res.status(415).json({ error: 'Invalid or corrupt screenshot artifact' });
    }

    res.setHeader('Content-Type', 'image/png');
    res.setHeader('Cache-Control', 'private, max-age=3600');
    const stream = fs.createReadStream(realShot);
    stream.on('error', () => { if (!res.headersSent) res.status(404).json({ error: 'Screenshot unavailable.' }); else res.destroy(); });
    stream.pipe(res);
  } catch {
    res.status(500).json({ error: 'Failed to stream screenshot artifact' });
  }
});

app.get('/console', (req, res) => {
  res.sendFile(path.join(rootDir, 'investigation.html'));
});

app.use('/api', (req, res) => res.status(404).json({ error: 'API endpoint not found.' }));
app.use((err, req, res, next) => {
  if (res.headersSent) return next(err);
  if (err?.type === 'entity.too.large') return res.status(413).json({ error: 'Request body exceeds the 64 KiB limit.' });
  if (err instanceof SyntaxError && err.status === 400) return res.status(400).json({ error: 'Malformed JSON request body.' });
  if (err?.type === 'entity.parse.failed') return res.status(400).json({ error: 'Malformed JSON request body.' });
  return res.status(500).json({ error: 'Request could not be completed.' });
});

  return app;
}

const isMainModule = process.argv[1] && path.resolve(process.argv[1]) === __filename;
if (isMainModule) {
  try {
    const app = createApp();
    const server = createServer({ maxHeaderSize: 16 * 1024, requestTimeout: 30_000, headersTimeout: 15_000 }, app);
    server.timeout = 30_000;
    server.listen(PORT, '0.0.0.0', () => {
      console.log('Trust Layer API server started.');
      console.log(`   Server listening at http://localhost:${PORT}`);
      console.log(`   Unified SPA:     http://localhost:${PORT}/`);
    });
  } catch {
    console.error('Trust Layer refused startup: configure TRUSTLAYER_API_TOKEN with 32 to 1024 random bytes.');
    process.exitCode = 1;
  }
}
