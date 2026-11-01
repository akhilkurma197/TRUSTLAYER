import test from 'node:test';
import assert from 'node:assert/strict';
import { ScreenshotIntelligenceExtractor } from '../core/investigators/screenshot_intelligence.js';

const tick = () => new Promise(resolve => setImmediate(resolve));

test('OCR timeout during Tesseract initialization does not start recognition and terminates the late worker', async () => {
  let resolveWorker;
  let recognitionCalls = 0;
  let terminationCalls = 0;
  const workerPromise = new Promise(resolve => { resolveWorker = resolve; });

  const result = await ScreenshotIntelligenceExtractor.performOcr('local-fixture.png', 5, {
    readImage: async () => Buffer.from('bounded-local-image'),
    createWorker: () => workerPromise
  });

  assert.equal(result.status, 'UNAVAILABLE');
  assert.match(result.error, /timed out/i);
  resolveWorker({
    async recognize() { recognitionCalls += 1; return { data: {} }; },
    async terminate() { terminationCalls += 1; }
  });
  await tick();

  assert.equal(recognitionCalls, 0);
  assert.equal(terminationCalls, 1);
});

test('OCR timeout after recognition dispatch terminates the worker and returns unavailable evidence', async () => {
  let receivedImage;
  let terminationCalls = 0;
  const result = await ScreenshotIntelligenceExtractor.performOcr('local-fixture.png', 5, {
    readImage: async () => Buffer.from('bounded-local-image'),
    createWorker: async () => ({
      recognize(image) {
        receivedImage = image;
        return new Promise(() => {});
      },
      async terminate() { terminationCalls += 1; }
    })
  });

  assert.equal(result.status, 'UNAVAILABLE');
  assert.match(result.error, /timed out/i);
  assert.ok(Buffer.isBuffer(receivedImage), 'Tesseract receives preloaded bytes, avoiding async path reads after worker startup');
  assert.equal(terminationCalls, 1);
  assert.equal(result.text, '');
  assert.deepEqual(result.blocks, []);
});

test('OCR recognition failure terminates its worker and remains unavailable rather than benign', async () => {
  let terminationCalls = 0;
  const result = await ScreenshotIntelligenceExtractor.performOcr('local-fixture.png', 100, {
    readImage: async () => Buffer.from('bounded-local-image'),
    createWorker: async () => ({
      async recognize() { throw new Error('local worker failed'); },
      async terminate() { terminationCalls += 1; }
    })
  });

  assert.equal(result.status, 'UNAVAILABLE');
  assert.equal(result.error, 'local worker failed');
  assert.equal(result.text, '');
  assert.equal(terminationCalls, 1);
});
