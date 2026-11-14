'use strict';

// Local Groth16 proof generation with snarkjs.
//
// The agent's response includes a proof generated locally from the
// downloaded gatekeeper circuit artifacts (circuits/gatekeeper.wasm +
// gatekeeper_final.zkey). The witness inputs are built from the task by
// buildInputs(), whose mapping lives in circuits/gatekeeper.signals.json.
//
// If the signal mapping is not configured, generate() refuses with a clear
// NOT_CONFIGURED error — it never fabricates a proof, and the server
// answers with proofStatus "not_configured" instead of a fake proof.

const fs = require('node:fs');
const path = require('node:path');
const snarkjs = require('snarkjs');
const logger = require('./logger');

const WASM_PATH = path.join(__dirname, '..', 'circuits', 'gatekeeper.wasm');
const ZKEY_PATH = path.join(__dirname, '..', 'circuits', 'gatekeeper_final.zkey');
// Overridable for tests (so test files never mutate the real signals map).
const SIGNALS_PATH =
  process.env.GATEKEEPER_SIGNALS_PATH ||
  path.join(__dirname, '..', 'circuits', 'gatekeeper.signals.json');

function loadSignals() {
  try {
    const raw = JSON.parse(fs.readFileSync(SIGNALS_PATH, 'utf8'));
    return raw && raw.configured === true ? raw : null;
  } catch {
    return null;
  }
}

/**
 * Build the witness input object for the gatekeeper circuit.
 * The mapping documents which task field feeds which circuit signal.
 * Throws NOT_CONFIGURED when the mapping is absent.
 */
function buildInputs(task) {
  const mapping = loadSignals();
  if (!mapping || !mapping.inputs) {
    const err = new Error('gatekeeper signal mapping not configured (circuits/gatekeeper.signals.json)');
    err.code = 'NOT_CONFIGURED';
    throw err;
  }
  const inputs = {};
  for (const [signal, source] of Object.entries(mapping.inputs)) {
    // source is a dotted path into the normalized task, e.g. "condition.threshold".
    const value = source.split('.').reduce((o, k) => (o ? o[k] : undefined), task);
    if (value === undefined) {
      const err = new Error(`signal ${signal}: missing task field ${source}`);
      err.code = 'MISSING_INPUT';
      throw err;
    }
    inputs[signal] = String(value);
  }
  return inputs;
}

/**
 * Generate a Groth16 proof for a task. Returns { proof, publicSignals }.
 * Throws NOT_CONFIGURED / MISSING_INPUT / PROVE_FAILED — never a fake proof.
 */
async function generate(task, { timeoutMs = 30000 } = {}) {
  const inputs = buildInputs(task);
  const job = snarkjs.groth16.fullProve(inputs, WASM_PATH, ZKEY_PATH);
  const timeout = new Promise((_, reject) => {
    setTimeout(() => {
      const err = new Error('proof generation timed out');
      err.code = 'PROVE_TIMEOUT';
      reject(err);
    }, timeoutMs).unref();
  });
  try {
    const { proof, publicSignals } = await Promise.race([job, timeout]);
    logger.info('proof generated', { taskId: task.taskId, publicSignals: publicSignals.length });
    return { proof, publicSignals };
  } catch (err) {
    if (err.code === 'NOT_CONFIGURED' || err.code === 'MISSING_INPUT' || err.code === 'PROVE_TIMEOUT') throw err;
    const wrapped = new Error(`proof generation failed: ${err.message}`);
    wrapped.code = 'PROVE_FAILED';
    throw wrapped;
  }
}

module.exports = { buildInputs, generate };
