import assert from 'node:assert/strict';
import { test } from 'node:test';
import { appendBounded, isBoundedPng, serializeBoundedJson } from '../worker/resource_limits.js';

test('worker telemetry has a hard record ceiling', () => {
  const records = [];
  appendBounded(records, { id: 1 }, 2);
  appendBounded(records, { id: 2 }, 2);
  appendBounded(records, { id: 3 }, 2);
  assert.deepEqual(records, [{ id: 1 }, { id: 2 }]);
});

test('PNG validation enforces signature, viewport dimensions, and byte ceiling', () => {
  const png = Buffer.alloc(1000);
  Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]).copy(png);
  png.writeUInt32BE(1280, 16);
  png.writeUInt32BE(800, 20);
  assert.equal(isBoundedPng(png), true);
  png.writeUInt32BE(1281, 16);
  assert.equal(isBoundedPng(png), false);
  png.writeUInt32BE(1280, 16);
  assert.equal(isBoundedPng(Buffer.concat([png, Buffer.alloc(5 * 1024 * 1024)])), false);
});

test('serialized worker output fails closed above its byte ceiling', () => {
  assert.equal(serializeBoundedJson({ ok: true }, 20), '{"ok":true}');
  assert.throws(() => serializeBoundedJson({ data: 'x'.repeat(32) }, 20), /output limit/);
});
