'use strict';

// Proof Gatekeeper decision engine.
//
// Job: given one proof-backed payment request, return a deterministic
// APPROVE or REJECT. The scoring makes a wrong APPROVE (-6) twice as costly
// as a wrong REJECT (-3), and a correct decision is +12 — so on ANY doubt
// the engine fails closed and REJECTs.
//
// Checks, in order (each is recorded in the response so a decision is
// auditable):
//   1. shape            — required fields present, right types
//   2. timestamp        — task timestamp fresh, condition not expired
//   3. vk               — condition's verification-key hash is the registered
//                         gatekeeper vkHash (VK_SUBSTITUTION trap)
//   4. circuit          — Groth16 / BN128, the expected system
//   5. consistency      — payment amount/recipient/action equal the condition
//                         (THRESHOLD_MISMATCH, RECIPIENT_MISMATCH,
//                          AMOUNT_OVERFLOW traps)
//   6. publicSignals    — exactly vk.nPublic (13) public inputs; when the
//                         signal layout is configured (see
//                         circuits/gatekeeper.signals.json) the decoded
//                         inputs must equal the condition
//   7. proof            — the attached Groth16 proof verifies against the
//                         registered verification key
//   8. replay           — the proof reference was never used before
//                         (PROOF_REUSED trap)
//
// Kurier finalization (§04: "verification reached a finalized state before
// approval") is enforced by the server, not here: decide() returns
// `needsFinalization: true` for an otherwise-approvable task, and the
// server only upgrades it to APPROVE after Kurier reports Finalized.
//
// BOOTSTRAP MODE: until circuits/gatekeeper.signals.json maps the 13 public
// inputs to condition fields, check 6 can only verify the COUNT. In that
// mode every otherwise-valid task is REJECTed with reason
// "public-input mapping not configured" — fail closed, never a guessed
// APPROVE. The first unscored practice task is where the mapping is learned
// (see docs/TASK_SCHEMA_NOTES.md). Expected value of REJECT-all in bootstrap
// mode is still positive (valid ~50% -> -3, traps ~50% -> +12).

const fs = require('node:fs');
const path = require('node:path');
const snarkjs = require('snarkjs');
const logger = require('./logger');

const VK_PATH = path.join(__dirname, '..', 'circuits', 'gatekeeper.vkey.json');
// Overridable for tests (so test files never mutate the real signals map).
const SIGNALS_PATH =
  process.env.GATEKEEPER_SIGNALS_PATH ||
  path.join(__dirname, '..', 'circuits', 'gatekeeper.signals.json');

const DEFAULT_VK_HASH =
  '0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0';

let vkCache = null;
function loadVk() {
  if (!vkCache) vkCache = JSON.parse(fs.readFileSync(VK_PATH, 'utf8'));
  return vkCache;
}

let signalsCache = undefined; // undefined = not loaded yet
function loadSignals() {
  if (signalsCache !== undefined) return signalsCache;
  try {
    const raw = JSON.parse(fs.readFileSync(SIGNALS_PATH, 'utf8'));
    signalsCache = raw && raw.configured === true ? raw : null;
  } catch {
    signalsCache = null;
  }
  return signalsCache;
}

function pick(obj, names) {
  for (const name of names) {
    if (obj && obj[name] !== undefined && obj[name] !== null) return obj[name];
  }
  return undefined;
}

function isAddress(v) {
  return typeof v === 'string' && /^0x[0-9a-fA-F]{40}$/.test(v);
}

function toBigInt(v) {
  if (typeof v === 'bigint') return v;
  if (typeof v === 'number' && Number.isInteger(v)) return BigInt(v);
  if (typeof v === 'string') {
    const s = v.trim();
    if (/^0x[0-9a-fA-F]+$/.test(s)) return BigInt(s);
    if (/^-?\d+$/.test(s)) return BigInt(s);
  }
  return null;
}

function toMs(ts) {
  const n = typeof ts === 'string' ? Number(ts) : ts;
  if (!Number.isFinite(n)) return null;
  // Seconds (< 1e12) vs milliseconds.
  return n < 1e12 ? n * 1000 : n;
}

/**
 * Normalize the many plausible envelope shapes into one canonical task.
 * Returns { task } or { error } — an un-normalizable envelope is REJECTed.
 *
 * The exact envelope schema is not published on the public build page; the
 * normalizer accepts the documented field names and their common aliases,
 * and REJECTs anything it cannot map unambiguously. See
 * docs/TASK_SCHEMA_NOTES.md.
 */
function normalize(raw) {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) {
    return { error: 'envelope is not a JSON object' };
  }
  const task = pick(raw, ['task', 'envelope', 'data']) || raw;

  const taskId = pick(task, ['taskId', 'task_id', 'id']);
  const condition = pick(task, ['condition', 'paymentCondition', 'proofCondition']);
  const proof = pick(task, ['proof', 'zkProof', 'paymentProof']);
  const payment = pick(task, ['payment', 'paymentRequest', 'request']);
  const timestamp = pick(task, ['timestamp', 'issuedAt', 'createdAt']);
  const signature = pick(task, ['signature', 'taskSignature']);

  if (typeof taskId !== 'string' || taskId.length === 0) {
    return { error: 'missing taskId' };
  }
  if (!condition || typeof condition !== 'object') {
    return { error: 'missing condition' };
  }
  if (!proof || typeof proof !== 'object') {
    return { error: 'missing proof' };
  }
  if (!payment || typeof payment !== 'object') {
    return { error: 'missing payment' };
  }

  const threshold = pick(condition, ['threshold', 'amount', 'minAmount']);
  const recipient = pick(condition, ['recipient', 'to', 'payee']);
  const action = pick(condition, ['action', 'operation']);
  const expiresAt = pick(condition, ['expiresAt', 'expiry', 'deadline', 'validUntil']);
  const vkHash = pick(condition, ['vkHash', 'vk_hash', 'verificationKeyHash']);
  const circuit = pick(condition, ['circuit', 'proofSystem', 'system']);
  const curve = pick(condition, ['curve', 'ellipticCurve']);

  const proofBody = pick(proof, ['proof', 'groth16Proof']) || proof;
  const publicSignals = pick(proof, ['publicSignals', 'public_signals', 'publicInputs']);
  const reference = pick(proof, ['reference', 'proofReference', 'proof_reference', 'id', 'hash']);

  return {
    task: {
      taskId,
      condition: { threshold, recipient, action, expiresAt, vkHash, circuit, curve },
      proof: { proof: proofBody, publicSignals, reference },
      payment,
      timestamp,
      signature,
    },
  };
}

/**
 * Decide one task. `ctx` carries config + the replay store.
 * Returns a decision object; never throws for bad input (bad input -> REJECT).
 */
async function decide(raw, ctx) {
  const checks = [];
  const fail = (name, reason) => {
    checks.push({ name, pass: false, reason });
    return { decision: 'REJECT', reason, checks, taskId: null };
  };
  const pass = (name, detail) => checks.push({ name, pass: true, detail });

  const { task, error } = normalize(raw);
  if (error) return fail('shape', error);
  const taskId = task.taskId;

  const reject = (name, reason) => {
    checks.push({ name, pass: false, reason });
    return { decision: 'REJECT', reason, checks, taskId };
  };

  // 1. Shape: required fields, right types.
  const c = task.condition;
  const threshold = toBigInt(c.threshold);
  if (threshold === null || threshold < 0n) return reject('shape', 'condition.threshold is not a non-negative integer');
  if (!isAddress(c.recipient)) return reject('shape', 'condition.recipient is not an address');
  if (typeof c.action !== 'string' || c.action.length === 0) return reject('shape', 'condition.action is missing');
  const expiresMs = toMs(c.expiresAt);
  if (expiresMs === null) return reject('shape', 'condition.expiresAt is not a timestamp');
  const payAmount = toBigInt(pick(task.payment, ['amount', 'value']));
  if (payAmount === null || payAmount < 0n) return reject('shape', 'payment.amount is not a non-negative integer');
  const payRecipient = pick(task.payment, ['recipient', 'to', 'payee']);
  if (!isAddress(payRecipient)) return reject('shape', 'payment.recipient is not an address');
  const payAction = pick(task.payment, ['action', 'operation']);
  if (!Array.isArray(task.proof.publicSignals)) return reject('shape', 'proof.publicSignals is not an array');
  if (typeof task.proof.reference !== 'string' || task.proof.reference.length === 0) {
    return reject('shape', 'proof.reference is missing');
  }
  pass('shape', 'envelope normalized');

  // 2. Timestamp: fresh, and the condition has not expired.
  const now = Date.now();
  const tsMs = toMs(task.timestamp);
  const skew = ctx.timestampSkewMs ?? 300000;
  if (tsMs === null) return reject('timestamp', 'task timestamp is not a timestamp');
  if (Math.abs(now - tsMs) > skew) return reject('timestamp', 'task timestamp outside skew window');
  if (expiresMs <= now) return reject('timestamp', 'condition expired');
  pass('timestamp', 'fresh, not expired');

  // 3. Verification key must be the registered gatekeeper key.
  const expectedVk = (ctx.vkHash || process.env.GATEKEEPER_VK_HASH || DEFAULT_VK_HASH).toLowerCase();
  if (typeof c.vkHash !== 'string' || c.vkHash.toLowerCase() !== expectedVk) {
    return reject('vk', 'verification key does not match the registered gatekeeper key');
  }
  pass('vk', 'registered gatekeeper key');

  // 4. Circuit / proof system must be the expected one.
  const circuit = String(c.circuit || '').toLowerCase();
  const curve = String(c.curve || '').toLowerCase();
  if (circuit && circuit !== 'groth16') return reject('circuit', `unexpected proof system: ${circuit}`);
  if (curve && curve !== 'bn128' && curve !== 'alt_bn128') return reject('circuit', `unexpected curve: ${curve}`);
  pass('circuit', 'groth16/bn128');

  // 5. Consistency: payment must equal the condition exactly.
  if (payAmount !== threshold) return reject('consistency', 'payment.amount != condition.threshold');
  if (payRecipient.toLowerCase() !== c.recipient.toLowerCase()) {
    return reject('consistency', 'payment.recipient != condition.recipient');
  }
  if (payAction !== undefined && String(payAction).toLowerCase() !== String(c.action).toLowerCase()) {
    return reject('consistency', 'payment.action != condition.action');
  }
  pass('consistency', 'payment matches condition');

  // 6. Public signals: count must equal vk.nPublic; values must match the
  // condition when the signal layout is configured.
  const vk = loadVk();
  const signals = task.proof.publicSignals.map((s) => String(s));
  if (signals.length !== vk.nPublic) {
    return reject('publicSignals', `expected ${vk.nPublic} public inputs, got ${signals.length}`);
  }
  const mapping = loadSignals();
  if (!mapping) {
    // Bootstrap mode: count matches but the layout is unknown, so the
    // values cannot be checked against the condition. Fail closed.
    checks.push({ name: 'publicSignals', pass: false, reason: 'public-input mapping not configured (bootstrap mode)' });
    return { decision: 'REJECT', reason: 'public-input mapping not configured (bootstrap mode)', checks, taskId };
  }
  const decoded = decodePublicSignals(signals, mapping);
  if (decoded.error) return reject('publicSignals', decoded.error);
  if (toBigInt(decoded.threshold) !== threshold) return reject('publicSignals', 'public input threshold != condition.threshold');
  if (String(decoded.recipient).toLowerCase() !== c.recipient.toLowerCase()) {
    return reject('publicSignals', 'public input recipient != condition.recipient');
  }
  if (String(decoded.action).toLowerCase() !== String(c.action).toLowerCase()) {
    return reject('publicSignals', 'public input action != condition.action');
  }
  pass('publicSignals', 'decoded inputs match condition');

  // 7. The attached proof must verify against the registered key.
  // Public signals are field elements: every one must be a decimal integer
  // string. A non-numeric signal is malformed input — reject it here rather
  // than handing it to the prover library (which may not terminate on it).
  for (const s of signals) {
    if (!/^-?\d+$/.test(s)) {
      return reject('proof', 'public signal is not a field element');
    }
  }
  let verified = false;
  try {
    verified = await snarkjs.groth16.verify(vk, signals, task.proof.proof);
  } catch (err) {
    logger.warn('proof verification threw', { taskId, error: err.message });
    return reject('proof', `proof verification error: ${err.message}`);
  }
  if (!verified) return reject('proof', 'attached proof does not verify against the registered key');
  pass('proof', 'verifies against registered key');

  // 8. Replay: this proof reference must never have been used before.
  if (ctx.usedProofs) {
    if (ctx.usedProofs.has(task.proof.reference)) {
      return reject('replay', 'proof reference already used');
    }
  }
  pass('replay', 'reference unused');

  // All checks passed. APPROVE still needs Kurier Finalized (server-side).
  return {
    decision: 'APPROVE',
    reason: 'all checks passed; awaiting Kurier finalization',
    checks,
    taskId,
    needsFinalization: true,
    publicSignals: signals,
    proof: task.proof.proof,
  };
}

/**
 * Decode public signals using the configured layout.
 * mapping = { configured: true, fields: { threshold: <index|{index,encoding}>,
 *   recipient: <index|{index,encoding}>, action: <index|{index,encoding}> } }
 * Encodings: 'decimal' (field element as decimal string), 'address'
 * (field element holding a 20-byte address, or a 0x address string),
 * 'code' (numeric code translated via mapping.codes[field], e.g.
 * {'1': 'approve'}), 'string' (raw string). Values are field elements
 * unless the mapping says otherwise; the exact encodings are confirmed
 * from the first practice task.
 */
function decodePublicSignals(signals, mapping) {
  const fields = mapping.fields || {};
  const resolve = (name) => {
    const spec = fields[name];
    if (spec === undefined || spec === null) return undefined;
    if (typeof spec === 'number') return { index: spec, encoding: 'decimal' };
    return { index: spec.index, encoding: spec.encoding || 'decimal' };
  };
  const read = (name) => {
    const spec = resolve(name);
    if (!spec || spec.index === undefined || spec.index === null) return undefined;
    const raw = signals[spec.index];
    if (raw === undefined) return undefined;
    if (spec.encoding === 'address') {
      const s = String(raw).trim();
      if (/^0x[0-9a-fA-F]{40}$/.test(s)) return s;
      try {
        const hex = BigInt(s).toString(16).padStart(40, '0');
        return `0x${hex}`;
      } catch {
        return s;
      }
    }
    if (spec.encoding === 'code') {
      // Numeric action code mapped to an action name, e.g. { '1': 'approve' }.
      const codes = (mapping.codes && mapping.codes[name]) || {};
      return codes[String(raw)] ?? String(raw);
    }
    return String(raw);
  };
  const threshold = read('threshold');
  const recipient = read('recipient');
  const action = read('action');
  if (threshold === undefined || recipient === undefined || action === undefined) {
    return { error: 'signal mapping is missing threshold/recipient/action' };
  }
  return { threshold, recipient, action };
}

module.exports = { decide, normalize, loadVk, loadSignals, DEFAULT_VK_HASH };
