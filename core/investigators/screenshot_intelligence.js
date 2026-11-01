/**
 * Trust Layer — Screenshot Intelligence Extractor v1.0
 * Processes Playwright-captured viewport screenshot artifacts, performs local OCR,
 * detects visual & embedded deception patterns (fake software updates, credential traps,
 * social engineering lures, security test fixtures), cross-checks findings with DOM,
 * and produces evidence-linked forensic observations.
 */

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const PROJECT_ROOT = path.resolve(__dirname, '..', '..');

// Common Deception & Pretext Patterns
const PATTERNS = {
  CREDENTIAL_HARVESTING: [
    { pattern: /\b(?:enter\s+)?(?:username|user\s*id|customer\s*id|user\s*name)\b/i, label: 'Username Prompt', severity: 'HIGH', weight: 20 },
    { pattern: /\b(?:enter\s+)?(?:password|ipin|passcode|secret\s*pin)\b/i, label: 'Password / PIN Request', severity: 'HIGH', weight: 25 },
    { pattern: /\b(?:one-?time\s*password|otp|2fa|verification\s*code)\b/i, label: 'OTP / 2FA Token Request', severity: 'HIGH', weight: 20 },
    { pattern: /\b(?:credit|debit)\s*card\s*(?:number|details)?\b/i, label: 'Payment Card Details Request', severity: 'CRITICAL', weight: 30 },
    { pattern: /\b(?:card\s*cvv|cvc|security\s*code)\b/i, label: 'Card Security Code Request', severity: 'CRITICAL', weight: 30 },
    { pattern: /\b(?:log\s*in|sign\s*in|authenticate|verify\s*identity)\b/i, label: 'Authentication Action Call', severity: 'MEDIUM', weight: 10 }
  ],
  FAKE_SOFTWARE_UPDATE: [
    { pattern: /\b(?:media\s*player|flv(?:\s*hd)?|flash\s*player|codec)\b/i, label: 'Media Player / Codec Pretext', severity: 'HIGH', weight: 25 },
    { pattern: /\b(?:software\s*is\s*out-?of-?date|browser\s*is\s*out-?of-?date)\b/i, label: 'Outdated Software Warning Pretext', severity: 'HIGH', weight: 25 },
    { pattern: /\b(?:update\s*is\s*required|update\s*required|critical\s*update)\b/i, label: 'Mandatory Update Claim', severity: 'HIGH', weight: 20 },
    { pattern: /\b(?:please\s*install|install\s*to\s*continue|install\s*and\s*continue)\b/i, label: 'Deceptive Installation Call-To-Action', severity: 'HIGH', weight: 25 },
    { pattern: /\b(?:download\s*update|click\s*update|start\s*download)\b/i, label: 'Update Download Trigger', severity: 'HIGH', weight: 15 }
  ],
  SOCIAL_ENGINEERING: [
    { pattern: /\b(?:social\s*engineering|trick\s*you\s*into\s*clicking|trick\s*visitors)\b/i, label: 'Social Engineering Pattern Reference', severity: 'HIGH', weight: 20 },
    { pattern: /\b(?:account\s*(?:has\s*been\s*)?suspended|access\s*blocked|service\s*interruption)\b/i, label: 'Account Suspension Urgency Lure', severity: 'HIGH', weight: 20 },
    { pattern: /\b(?:urgent\s*security\s*alert|unusual\s*activity\s*detected|compromised\s*session)\b/i, label: 'Security Emergency Pretext', severity: 'HIGH', weight: 20 },
    { pattern: /\b(?:immediate\s*action\s*required|within\s*24\s*hours|prevent\s*deactivation)\b/i, label: 'Urgency Pressure Tactic', severity: 'MEDIUM', weight: 15 }
  ],
  SECURITY_TEST_FIXTURE: [
    { pattern: /\b(?:phishing\s*page\s*example|example\s*of\s*a\s*phishing\s*page)\b/i, label: 'Safe Browsing Phishing Demonstration Header', severity: 'INFO', isFixture: true },
    { pattern: /\b(?:social\s*engineering\s*content\s*example)\b/i, label: 'Safe Browsing Social Engineering Demonstration Header', severity: 'INFO', isFixture: true },
    { pattern: /\b(?:testsafebrowsing|google\s*safe\s*browsing\s*test|security\s*demonstration\s*fixture)\b/i, label: 'Security Research / Demonstration Pretext', severity: 'INFO', isFixture: true }
  ]
};

export class ScreenshotIntelligenceExtractor {
  /**
   * Validate that the file is an accessible PNG file within allowed directories.
   * Prevents arbitrary path traversal.
   * @param {string} screenshotPath 
   * @returns {{ valid: boolean, error?: string, resolvedPath?: string, fileSize?: number }}
   */
  static validateArtifact(screenshotPath) {
    if (!screenshotPath || typeof screenshotPath !== 'string') {
      return { valid: false, error: 'Screenshot path not specified or invalid.' };
    }

    const resolved = path.isAbsolute(screenshotPath)
      ? path.normalize(screenshotPath)
      : path.normalize(path.join(PROJECT_ROOT, screenshotPath));

    // Path Traversal Defense: Must reside within project root or screenshots dir
    const screenshotsDir = path.normalize(path.join(PROJECT_ROOT, 'data', 'screenshots'));
    const isWithin = (root) => {
      const relative = path.relative(root, resolved);
      return relative === '' || (!relative.startsWith(`..${path.sep}`) && relative !== '..' && !path.isAbsolute(relative));
    };
    const isWithinScreenshots = isWithin(screenshotsDir);
    const isWithinProject = isWithin(PROJECT_ROOT);

    if (!isWithinScreenshots && !isWithinProject) {
      return { valid: false, error: 'Access denied: Screenshot path resides outside authorized investigation directories.' };
    }

    if (!fs.existsSync(resolved)) {
      return { valid: false, error: `Screenshot file does not exist at path: ${resolved}` };
    }

    const stat = fs.statSync(resolved);
    // Enforce 10MB maximum image size limit
    if (stat.size > 10 * 1024 * 1024) {
      return { valid: false, error: `Screenshot exceeds maximum allowed size (10MB): ${stat.size} bytes` };
    }

    if (stat.size < 8) {
      return { valid: false, error: 'Screenshot file is too small or empty.' };
    }

    // Verify PNG magic header: 89 50 4E 47 0D 0A 1A 0A
    const fd = fs.openSync(resolved, 'r');
    const headerBuf = Buffer.alloc(8);
    fs.readSync(fd, headerBuf, 0, 8, 0);
    fs.closeSync(fd);

    const isPng = headerBuf[0] === 0x89 &&
                  headerBuf[1] === 0x50 && // P
                  headerBuf[2] === 0x4E && // N
                  headerBuf[3] === 0x47 && // G
                  headerBuf[4] === 0x0D &&
                  headerBuf[5] === 0x0A &&
                  headerBuf[6] === 0x1A &&
                  headerBuf[7] === 0x0A;

    if (!isPng) {
      return { valid: false, error: 'Invalid image format: File does not contain a valid PNG magic header.' };
    }

    return { valid: true, resolvedPath: resolved, fileSize: stat.size };
  }

  /**
   * Run OCR on the screenshot using local tesseract.js with safety timeout.
   * @param {string} filePath 
   * @param {number} timeoutMs 
   * @returns {Promise<{ status: string, text: string, confidence: number, blocks: Array, error?: string }>}
   */
  static async performOcr(filePath, timeoutMs = 20000, dependencies = {}) {
    let worker = null;
    let timedOut = false;
    let recognitionStarted = false;
    let timer = null;
    const safeTimeout = Number.isFinite(timeoutMs) ? Math.max(1, timeoutMs) : 20000;

    try {
      const readImage = dependencies.readImage || (file => fs.promises.readFile(file));
      const createWorker = dependencies.createWorker || (async () => {
        const tesseract = await import('tesseract.js');
        return tesseract.createWorker('eng');
      });

      // Tesseract.js 7 reads string paths asynchronously inside worker.recognize().
      // If timeout cleanup runs during that read, terminate() nulls its internal
      // worker before recognize() reaches send(), producing postMessage-on-null.
      // Read the bounded, validated local artifact first and pass bytes instead.
      const operation = (async () => {
        try {
          const image = await readImage(filePath);
          if (timedOut) throw new Error(`OCR processing timed out after ${safeTimeout}ms`);
          worker = await createWorker();
          if (timedOut) throw new Error(`OCR processing timed out after ${safeTimeout}ms`);
          recognitionStarted = true;
          const ret = await worker.recognize(image, {}, { blocks: true });
          const text = ret.data?.text || '';
          const confidence = typeof ret.data?.confidence === 'number' ? ret.data.confidence : 0;
          const blocks = (ret.data?.blocks || []).map((b, idx) => ({
            id: `block_${idx + 1}`,
            text: (b.text || '').trim(),
            confidence: b.confidence ?? confidence,
            bbox: b.bbox || null
          })).filter(b => b.text.length > 0);

          return {
            status: 'SUCCESS',
            text,
            confidence,
            blocks,
            error: null
          };
        } finally {
          if (worker) {
            const ownedWorker = worker;
            worker = null;
            await ownedWorker.terminate();
          }
        }
      })();
      // Attach both handlers immediately. A timeout can win while worker creation is
      // pending; in that case the operation observes timedOut after creation and
      // performs its own cleanup without starting recognition.
      const timeout = new Promise(resolve => {
        timer = setTimeout(() => {
          timedOut = true;
          // Recognition dispatch is already queued when this branch is reachable.
          // Tesseract documents terminate() as the worker cleanup operation.
          if (worker && recognitionStarted) {
            const timedOutWorker = worker;
            worker = null;
            try {
              Promise.resolve(timedOutWorker.terminate()).catch(() => {});
            } catch {
              // The OCR result remains unavailable; no result is promoted on cleanup failure.
            }
          }
          resolve({ error: new Error(`OCR processing timed out after ${safeTimeout}ms`) });
        }, safeTimeout);
      });
      const settledOperation = operation.then(
        value => ({ value }),
        error => ({ error })
      );

      const outcome = await Promise.race([settledOperation, timeout]);
      if (outcome.error) throw outcome.error;
      return outcome.value;
    } catch (err) {
      return {
        status: 'UNAVAILABLE',
        text: '',
        confidence: 0,
        blocks: [],
        error: err.message || 'OCR processing failed'
      };
    } finally {
      if (timer) clearTimeout(timer);
    }
  }

  /**
   * Analyzes a screenshot artifact, extracts text, cross-references with DOM evidence,
   * detects deception clues and returns structured evidence findings.
   * @param {object} params
   * @param {string} params.screenshotPath
   * @param {string} [params.caseId]
   * @param {string} [params.url]
   * @param {string} [params.targetHostname]
   * @param {object} [params.domExtraction] DOM extraction from PageStructureExtractor
   * @param {object} [params.options]
   * @returns {Promise<object>}
   */
  static async analyze({
    screenshotPath,
    caseId = 'UNKNOWN',
    url = '',
    targetHostname = '',
    domExtraction = null,
    options = {}
  }) {
    const timestamp = Date.now();

    // 1. Artifact Validation
    const validation = this.validateArtifact(screenshotPath);
    if (!validation.valid) {
      return {
        status: 'UNAVAILABLE',
        caseId,
        url,
        timestamp,
        screenshotPath: screenshotPath || null,
        fileSize: 0,
        ocrConfidence: 0,
        extractedText: '',
        error: validation.error,
        findings: [],
        indicators: {
          hasCredentialsPrompt: false,
          hasFakeSoftwareUpdate: false,
          hasSocialEngineeringLure: false,
          isSecurityTestFixture: false,
          hasEmbeddedImageTextOnly: false
        },
        domCorrelation: {
          matchedInDomCount: 0,
          embeddedImageOnlyCount: 0
        },
        summary: `Screenshot analysis unavailable: ${validation.error}`
      };
    }

    // 2. Perform OCR
    const ocrResult = await this.performOcr(validation.resolvedPath, options.timeoutMs || 20000);
    if (ocrResult.status !== 'SUCCESS') {
      return {
        status: 'UNAVAILABLE',
        caseId,
        url,
        timestamp,
        screenshotPath: validation.resolvedPath,
        fileSize: validation.fileSize,
        ocrConfidence: 0,
        extractedText: '',
        error: ocrResult.error,
        findings: [],
        indicators: {
          hasCredentialsPrompt: false,
          hasFakeSoftwareUpdate: false,
          hasSocialEngineeringLure: false,
          isSecurityTestFixture: false,
          hasEmbeddedImageTextOnly: false
        },
        domCorrelation: {
          matchedInDomCount: 0,
          embeddedImageOnlyCount: 0
        },
        summary: `Screenshot OCR could not be completed: ${ocrResult.error}`
      };
    }

    const rawOcrText = ocrResult.text || '';
    // Normalize common OCR glyph confusions while keeping the observed text otherwise intact.
    const cleanOcrText = rawOcrText.replace(/\r\n/g, '\n').replace(/\busemame\b/gi, 'Username').trim();

    // 3. Build DOM Normalized Context for Cross-Layer Comparison
    const domHeadings = (domExtraction?.headings || []).map(h => h.toLowerCase());
    const domTitle = (domExtraction?.title || '').toLowerCase();
    const domButtons = (domExtraction?.buttons || []).map(b => b.toLowerCase());
    const domForms = domExtraction?.forms || [];
    const domInputs = [];
    for (const f of domForms) {
      for (const inp of (f.inputs || [])) {
        if (inp.name) domInputs.push(inp.name.toLowerCase());
        if (inp.placeholder) domInputs.push(inp.placeholder.toLowerCase());
      }
    }
    const domFullText = `${domTitle} ${domHeadings.join(' ')} ${domButtons.join(' ')} ${domInputs.join(' ')}`.toLowerCase();

    // Helper: checks if a phrase is present in DOM text
    const isTextInDom = (textSnippet) => {
      if (!domExtraction || !textSnippet) return false;
      const snippetLower = textSnippet.toLowerCase().trim();
      if (snippetLower.length < 3) return false;
      return domFullText.includes(snippetLower) ||
             domHeadings.some(h => h.includes(snippetLower) || snippetLower.includes(h)) ||
             domButtons.some(b => b.includes(snippetLower) || snippetLower.includes(b));
    };

    // 4. Clue & Pattern Detection across Categories
    const findings = [];
    const seenClues = new Set();
    let findingCounter = 1;

    let hasCredentialsPrompt = false;
    let hasFakeSoftwareUpdate = false;
    let hasSocialEngineeringLure = false;
    let isSecurityTestFixture = false;
    let embeddedImageOnlyCount = 0;
    let matchedInDomCount = 0;

    const ocrLines = cleanOcrText.split('\n').map(l => l.trim()).filter(l => l.length > 0);

    for (const [category, ruleList] of Object.entries(PATTERNS)) {
      for (const rule of ruleList) {
        const match = cleanOcrText.match(rule.pattern);
        if (match) {
          const matchedSnippet = match[0].trim();
          const clueKey = `${category}:${rule.label.toLowerCase()}`;
          if (seenClues.has(clueKey)) continue;
          seenClues.add(clueKey);

          // Locate line containing this match for precise text snippet
          const matchingLine = ocrLines.find(l => rule.pattern.test(l)) || matchedSnippet;

          // Locate block containing this match
          let matchedBlock = null;
          for (const b of ocrResult.blocks) {
            if (rule.pattern.test(b.text)) {
              matchedBlock = b;
              break;
            }
          }

          const inDom = isTextInDom(matchedSnippet) || isTextInDom(matchingLine);
          if (inDom) {
            matchedInDomCount++;
          } else {
            embeddedImageOnlyCount++;
          }

          // Provenance: If it appears in screenshot but NOT in DOM, it is embedded inside an image/canvas/dialog
          const provenance = inDom ? 'CONFIRMED_CROSS_LAYER' : 'SCREENSHOT_IMAGE_EMBEDDED';

          if (rule.isFixture) {
            isSecurityTestFixture = true;
          }
          if (category === 'CREDENTIAL_HARVESTING') hasCredentialsPrompt = true;
          if (category === 'FAKE_SOFTWARE_UPDATE') hasFakeSoftwareUpdate = true;
          if (category === 'SOCIAL_ENGINEERING') hasSocialEngineeringLure = true;

          const evidenceId = `SS-EVID-${String(findingCounter++).padStart(3, '0')}`;

          findings.push({
            id: evidenceId,
            category,
            severity: rule.severity,
            label: rule.label,
            textSnippet: matchingLine,
            matchedKeyword: matchedSnippet,
            confidence: matchedBlock?.confidence ?? ocrResult.confidence,
            bbox: matchedBlock?.bbox || null,
            source: provenance,
            inDom,
            isTestFixture: rule.isFixture || false,
            weight: rule.weight || 10,
            interpretation: inDom
              ? `Clue "${matchedSnippet}" confirmed across both rendered viewport screenshot and DOM layer.`
              : `Clue "${matchedSnippet}" detected visually inside an image or overlay in the screenshot, but is absent from standard DOM text elements.`
          });
        }
      }
    }

    // 5. Anti-Correlation Capping for Page Risk Weight
    let totalRiskScore = 0;
    for (const f of findings) {
      if (!f.isTestFixture) {
        totalRiskScore += f.weight;
      }
    }
    // Cap visual deception score at 100
    const normalizedRiskScore = Math.min(totalRiskScore, 100);

    // 6. Summary Generation
    let summary = '';
    if (isSecurityTestFixture) {
      summary = 'Screenshot intelligence identified deliberate security test fixture indicators (e.g. Google Safe Browsing test harness). Observed deceptive content is part of a security test environment.';
    } else if (hasFakeSoftwareUpdate && hasCredentialsPrompt) {
      summary = `High-risk visual deception: Screenshot contains fake software update lure combined with credential harvesting prompts. (${embeddedImageOnlyCount} clue(s) embedded in images).`;
    } else if (hasFakeSoftwareUpdate) {
      summary = `Deceptive lure detected: Screenshot contains fake software update / installation dialogs (${embeddedImageOnlyCount} clue(s) embedded directly in images).`;
    } else if (hasCredentialsPrompt) {
      summary = 'Authentication trap: Screenshot displays interactive credential input prompts.';
    } else if (findings.length > 0) {
      summary = `Extracted ${findings.length} visual clue(s) from rendered screenshot.`;
    } else {
      summary = 'No deceptive visual patterns or credential traps detected in viewport screenshot.';
    }

    return {
      status: 'SUCCESS',
      caseId,
      url,
      timestamp,
      screenshotPath: validation.resolvedPath,
      fileSize: validation.fileSize,
      ocrConfidence: ocrResult.confidence,
      extractedText: cleanOcrText,
      findings,
      indicators: {
        hasCredentialsPrompt,
        hasFakeSoftwareUpdate,
        hasSocialEngineeringLure,
        isSecurityTestFixture,
        hasEmbeddedImageTextOnly: embeddedImageOnlyCount > 0
      },
      domCorrelation: {
        matchedInDomCount,
        embeddedImageOnlyCount
      },
      visualRiskScore: normalizedRiskScore,
      summary
    };
  }
}
