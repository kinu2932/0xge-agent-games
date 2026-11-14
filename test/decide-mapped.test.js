'use strict';

// Decision-engine tests — CONFIGURED signal mapping.
// The mapping lives in a TEMP file pointed to by GATEKEEPER_SIGNALS_PATH,
// so this file never mutates the real circuits/gatekeeper.signals.json and
// can run in parallel with the bootstrap-mode suites.
//
// A real Groth16 proof cannot be fabricated here (the circuit's witness
// inputs are unknown until the first practice task), so the "invalid proof"
// case asserts the engine reaches the proof check and fails closed there.

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const RECIPIENT = '0x2AfDAcAF2856acB2BE7B85653DA236FC78d15fF2';
const RECIPIENT_DECIMAL = BigInt(RECIPIENT).toString();

const mappingFile = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'signals-')), 'gatekeeper.signals.json');
fs.writeFileSync(mappingFile, JSON.stringify({
  configured: true,
  vkHash: '0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0',
  fields: {
    threshold: 0,
    recipient: { index: 1, encoding: 'address' },
    action: { index: 2, encoding: 'code' },
  },
  codes: { action: { 1: 'approve', 0: 'reject' } },
  inputs: {},
  note: 'TEST-ONLY mapping.',
}, null, 2));
process.env.GATEKEEPER_SIGNALS_PATH = mappingFile;

const { decide, DEFAULT_VK_HASH } = require('../src/decide');
const { UsedProofs } = require('../src/usedProofs');

function baseTask() {
  const now = Date.now();
  const signals = Array(13).fill('0');
  signals[0] = '1000'; // threshold
  signals[1] = RECIPIENT_DECIMAL; // recipient as field element
  signals[2] = '1'; // action code: 1 = approve
  return {
    taskId: 'task-mapped-001',
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
      publicSignals: signals,
      reference: 'proof-ref-mapped-001',
    },
  };
}

function ctx() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'used-proofs-'));
  return {
    vkHash: DEFAULT_VK_HASH,
    timestampSkewMs: 300000,
    usedProofs: new UsedProofs(path.join(dir, 'used.json')).load(),
  };
}

test('configured mapping: public-signal values are decoded and checked', async () => {
  // The fake proof cannot verify, so the engine must reach the proof check
  // and reject there — proving steps 1-6 passed with the mapping.
  const r = await decide(baseTask(), ctx());
  assert.equal(r.decision, 'REJECT');
  const byName = Object.fromEntries(r.checks.map((c) => [c.name, c]));
  assert.equal(byName.shape.pass, true);
  assert.equal(byName.timestamp.pass, true);
  assert.equal(byName.vk.pass, true);
  assert.equal(byName.circuit.pass, true);
  assert.equal(byName.consistency.pass, true);
  assert.equal(byName.publicSignals.pass, true);
  assert.equal(byName.proof.pass, false);
});

test('configured mapping: threshold mismatch in public signals is rejected', async () => {
  const task = baseTask();
  task.proof.publicSignals[0] = '999';
  const r = await decide(task, ctx());
  assert.equal(r.decision, 'REJECT');
  assert.equal(r.checks.find((c) => c.name === 'publicSignals').pass, false);
});

test('configured mapping: recipient mismatch in public signals is rejected', async () => {
  const task = baseTask();
  task.proof.publicSignals[1] = BigInt('0x0000000000000000000000000000000000000001').toString();
  const r = await decide(task, ctx());
  assert.equal(r.decision, 'REJECT');
  assert.equal(r.checks.find((c) => c.name === 'publicSignals').pass, false);
});
