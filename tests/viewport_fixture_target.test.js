import assert from 'node:assert/strict';
import test from 'node:test';
import { viewportFixtureCssPosition } from './helpers/viewport_fixture_target.js';

test('fixture viewport target coordinates scale from worker pixels to the displayed image box', () => {
  const assertPoint = (actual, expected) => {
    assert.ok(Math.abs(actual.x - expected.x) < 1e-9);
    assert.ok(Math.abs(actual.y - expected.y) < 1e-9);
  };
  assertPoint(viewportFixtureCssPosition({ width: 960, height: 600 }, { x: 80, y: 110 }), { x: 60, y: 82.5 });
  assertPoint(viewportFixtureCssPosition({ width: 640, height: 400 }, { x: 80, y: 110 }), { x: 40, y: 55 });
  assertPoint(viewportFixtureCssPosition({ width: 960, height: 600 }, { x: 80, y: 175 }), { x: 60, y: 131.25 });
});

test('fixture viewport target coordinate mapping rejects invalid or out-of-viewport points', () => {
  assert.throws(() => viewportFixtureCssPosition({ width: 0, height: 600 }, { x: 1, y: 1 }), TypeError);
  assert.throws(() => viewportFixtureCssPosition({ width: 960, height: 600 }, { x: 1281, y: 1 }), TypeError);
});
