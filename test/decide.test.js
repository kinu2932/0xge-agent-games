'use strict';

// Decision-engine tests — BOOTSTRAP MODE (no signal mapping configured).
// Every otherwise-valid task must REJECT rather than guess an APPROVE.

const test = require('node:test');
const assert = require('node:assert/strict');
const { decide, DEFAULT_VK_HASH } = require('../src/decide');
const { UsedProofs } = require('../src/usedProofs');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const RECIPIENT = '0x2AfDAcAF2856acB2BE7B85653DA236FC78d15fF2';
const OTHER = '0x0000000000000000000000000000000000000001';

function baseTask(overrides = {}) {
  const now = Date.now();
  const task = {
    taskId: 'task-001',
    timestamp: now,
    signature: '0xdeadbeef',
    condition: {
      threshold: '1000',
      recipient: RECIPIENT,
      action: 'approve',
      expiresAt: now + 3600_000,
      vkHash: DEFAULT_VK_HASH,
      circuit: 'groth16',
      curve: 'bn128',
    },
    payment: { amount: '1000', recipient: RECIPIENT, action: 'approve' },
    proof: {
      proof: { protocol: 'groth16', pi_a: ['1', '2', '1'], pi_b: [['3', '4'], ['5', '6'], ['1', '0']], pi_c: ['7', '8', '1'] },
      publicSignals: Array(13).fill('0'),
      reference: 'proof-ref-001',
    },
  };
  return deepMerge(task, overrides);
}

function deepMerge(target, source) {
  for (const [k, v] of Object.entries(source)) {
    if (v !== null && typeof v === 'object' && !Array.isArray(v) && target[k] && typeof target[k] === 'object') {
      deepMerge(target[k], v);
    } else {
      target[k] = v;
    }
  }
  return target;
}

function ctx() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'used-proofs-'));
  return {
    vkHash: DEFAULT_VK_HASH,
    timestampSkewMs: 300000,
    usedProofs: new UsedProofs(path.join(dir, 'used.json')).load(),
  };
}

test('bootstrap mode: otherwise-valid task REJECTs (mapping not configured)', async () => {
  const r = await decide(baseTask(), ctx());
  assert.equal(r.decision, 'REJECT');
  assert.match(r.reason, /mapping not configured/);
  assert.equal(r.checks.find((c) => c.name === 'publicSignals').pass, false);
});

test('VK substitution is rejected', async () => {
  const r = await decide(baseTask({ condition: { vkHash: '0x0000000000000000000000000000000000000000000000000000000000000000' } }), ctx());
  assert.equal(r.decision, 'REJECT');
  assert.equal(r.checks.find((c) => c.name === 'vk').pass, false);
});

test('threshold mismatch is rejected (payment != condition)', async () => {
  const r = await decide(baseTask({ payment: { amount: '1001' } }), ctx());
  assert.equal(r.decision, 'REJECT');
  assert.equal(r.checks.find((c) => c.name === 'consistency').pass, false);
});

test('amount overflow is rejected (payment above threshold)', async () => {
  const r = await decide(baseTask({ payment: { amount: '999999999999' } }), ctx());
  assert.equal(r.decision, 'REJECT');
  assert.equal(r.checks.find((c) => c.name === 'consistency').pass, false);
});

test('recipient mismatch is rejected', async () => {
  const r = await decide(baseTask({ payment: { recipient: OTHER } }), ctx());
  assert.equal(r.decision, 'REJECT');
  assert.equal(r.checks.find((c) => c.name === 'consistency').pass, false);
});

test('expired condition is rejected', async () => {
  const r = await decide(baseTask({ condition: { expiresAt: Date.now() - 1000 } }), ctx());
  assert.equal(r.decision, 'REJECT');
  assert.equal(r.checks.find((c) => c.name === 'timestamp').pass, false);
});

test('stale task timestamp is rejected', async () => {
  const r = await decide(baseTask({ timestamp: Date.now() - 3600_000 }), ctx());
  assert.equal(r.decision, 'REJECT');
  assert.equal(r.checks.find((c) => c.name === 'timestamp').pass, false);
});

test('wrong public-signal count is rejected', async () => {
  const task = baseTask();
  task.proof.publicSignals = Array(5).fill('0');
  const r = await decide(task, ctx());
  assert.equal(r.decision, 'REJECT');
  assert.equal(r.checks.find((c) => c.name === 'publicSignals').pass, false);
});

test('missing fields are rejected', async () => {
  const task = baseTask();
  delete task.condition;
  const r = await decide(task, ctx());
  assert.equal(r.decision, 'REJECT');
  assert.equal(r.checks.find((c) => c.name === 'shape').pass, false);
});

test('non-object envelope is rejected', async () => {
  const r = await decide('not-an-object', ctx());
  assert.equal(r.decision, 'REJECT');
  assert.equal(r.checks.find((c) => c.name === 'shape').pass, false);
});

test('wrong circuit is rejected', async () => {
  const r = await decide(baseTask({ condition: { circuit: 'plonk' } }), ctx());
  assert.equal(r.decision, 'REJECT');
  assert.equal(r.checks.find((c) => c.name === 'circuit').pass, false);
});
