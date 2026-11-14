'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { UsedProofs } = require('../src/usedProofs');

test('add/has round-trip and duplicate detection', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'used-proofs-'));
  const file = path.join(dir, 'used.json');
  const store = new UsedProofs(file).load();
  assert.equal(store.has('ref-1'), false);
  assert.equal(store.add('ref-1'), true);
  assert.equal(store.has('ref-1'), true);
  assert.equal(store.add('ref-1'), false); // duplicate -> replay
  assert.equal(store.size(), 1);
});

test('references survive a reload from disk', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'used-proofs-'));
  const file = path.join(dir, 'used.json');
  const a = new UsedProofs(file).load();
  a.add('ref-a');
  a.add('ref-b');
  const b = new UsedProofs(file).load();
  assert.equal(b.has('ref-a'), true);
  assert.equal(b.has('ref-b'), true);
  assert.equal(b.has('ref-c'), false);
});
