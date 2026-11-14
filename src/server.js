'use strict';

// Proof Gatekeeper agent — HTTP server (Node.js stdlib only + snarkjs).
//
// Endpoints:
//   GET  /         — agent info (name, track, version, health)
//   GET  /healthz  — liveness probe for the platform health check
//   POST /agent    — the task endpoint. The platform POSTs a JSON task
//                    envelope signed with x-agent-games-signature.
//
// Pipeline (60 s hard deadline; TASK_TIMEOUT_MS keeps a safety margin):
//   1. Read the RAW body (size-capped). Verify the HMAC signature against
//      the raw body BEFORE parsing anything. Bad signature -> 401, no work.
//   2. Parse JSON. Unparsable -> 400.
//   3. decide(): the 7 trap checks + §04 checks. Any failure -> REJECT.
//   4. For an otherwise-approvable task: submit the attached proof to
//      Kurier and wait for Finalized. Not finalized in time -> REJECT
//      (fail closed). Kurier unconfigured -> REJECT.
//   5. If PROOF_MODE=local and the signal mapping is configured, generate
//      a fresh Groth16 proof for the response. If generation is unavailable,
//      the response still carries the decision + the Kurier job as proof
//      evidence, with proofStatus "not_configured" — never a fake proof.
//   6. Record the proof reference as used (replay protection), sign the
//      raw response body with x-agent-games-signature, reply.
//   7. On ANY internal error or timeout: REJECT with the reason. The agent
//      never crashes a request and never approves on uncertainty.
//
// Secrets come only from the environment (see .env.example). Nothing is
// committed, nothing is logged.

const http = require('node:http');
const crypto = require('node:crypto');
const { decide, DEFAULT_VK_HASH } = require('./decide');
const { generate } = require('./prover');
const kurier = require('./kurier');
const { signBody, verifySignature } = require('./hmac');
const { UsedProofs } = require('./usedProofs');
const logger = require('./logger');

const PORT = Number(process.env.PORT || 8080);
const HOST = process.env.HOST || '0.0.0.0';
const HMAC_SECRET = (process.env.AGENT_HMAC_SECRET || '').trim();
const TASK_TIMEOUT_MS = Number(process.env.TASK_TIMEOUT_MS || 45000);
const TIMESTAMP_SKEW_MS = Number(process.env.TIMESTAMP_SKEW_MS || 300000);
const VK_HASH = process.env.GATEKEEPER_VK_HASH || DEFAULT_VK_HASH;
const PROOF_MODE = (process.env.PROOF_MODE || 'off').toLowerCase();
const MAX_BODY_BYTES = 1024 * 1024; // 1 MiB

const usedProofs = new UsedProofs(process.env.USED_PROOFS_FILE || './data/used-proofs.json');
usedProofs.load();

const VERSION = '0.1.0';
const startedAt = new Date().toISOString();

function sendJson(res, status, obj, { sign = false } = {}) {
  const raw = Buffer.from(JSON.stringify(obj));
  const headers = { 'content-type': 'application/json', 'content-length': raw.length };
  if (sign && HMAC_SECRET) headers['x-agent-games-signature'] = signBody(HMAC_SECRET, raw);
  res.writeHead(status, headers);
  res.end(raw);
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    req.on('data', (chunk) => {
      size += chunk.length;
      if (size > MAX_BODY_BYTES) {
        reject(Object.assign(new Error('body too large'), { code: 'BODY_TOO_LARGE' }));
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });
}

async function handleTask(rawBody) {
  const deadline = Date.now() + TASK_TIMEOUT_MS;
  const remaining = () => Math.max(0, deadline - Date.now());

  // Step 3: decision engine.
  let parsed;
  try {
    parsed = JSON.parse(rawBody.toString('utf8'));
  } catch {
    return { status: 400, body: errorBody('INVALID_JSON', 'invalid JSON'), taskId: null };
  }

  // Preflight / handshake envelope (no task to decide): answer with signed
  // protocol-v1 JSON so the platform's endpoint check can verify the agent
  // holds the secret, without consuming a task or a proof reference.
  const preflightType = parsed && typeof parsed === 'object' && !Array.isArray(parsed)
    ? String(parsed.type || parsed.event || '').toLowerCase()
    : '';
  if (['preflight', 'ping', 'hello', 'health'].includes(preflightType)) {
    return {
      status: 200,
      taskId: null,
      body: {
        protocol: 'v1',
        status: 'ok',
        taskId: null,
        decision: 'REJECT',
        reason: 'preflight: no task to decide',
        checks: [],
        proof: null,
        proofStatus: 'not_required',
        proofReference: null,
        verification: { vkHash: VK_HASH, kurierStatus: 'not_submitted' },
      },
    };
  }

  const result = await decide(parsed, {
    vkHash: VK_HASH,
    timestampSkewMs: TIMESTAMP_SKEW_MS,
    usedProofs,
  });
  const taskId = result.taskId || parsed.taskId || parsed.task_id || parsed.id || null;

  if (result.decision !== 'APPROVE') {
    logger.info('task rejected', { taskId, reason: result.reason });
    return {
      status: 200,
      taskId,
      body: responseBody(result, { proofStatus: 'not_required' }),
    };
  }

  // Step 4: Kurier finalization is REQUIRED before APPROVE (§04).
  let kurierJob = null;
  try {
    const submitted = await kurier.submit({
      proof: result.proof,
      publicSignals: result.publicSignals,
      vkHash: VK_HASH,
    });
    kurierJob = await kurier.waitFinalized(submitted.jobId, { timeoutMs: remaining() });
  } catch (err) {
    logger.warn('kurier unavailable, failing closed', { taskId, error: err.message });
    const rejected = { ...result, decision: 'REJECT', reason: `verification not finalized: ${err.message}` };
    return { status: 200, taskId, body: responseBody(rejected, { proofStatus: 'not_configured' }) };
  }
  if (kurierJob.status !== 'Finalized') {
    logger.warn('kurier not finalized, failing closed', { taskId, status: kurierJob.status });
    const rejected = { ...result, decision: 'REJECT', reason: `verification not finalized (kurier: ${kurierJob.status})` };
    return { status: 200, taskId, body: responseBody(rejected, { proofStatus: 'not_configured' }) };
  }

  // Step 5: optional local response proof (never fabricated).
  let proofStatus = 'not_configured';
  let responseProof = null;
  if (PROOF_MODE === 'local') {
    try {
      const { task } = require('./decide').normalize(parsed);
      const generated = await generate(task || parsed, { timeoutMs: remaining() });
      responseProof = generated.proof;
      proofStatus = 'generated';
    } catch (err) {
      logger.warn('response proof unavailable', { taskId, error: err.message });
      proofStatus = err.code === 'NOT_CONFIGURED' ? 'not_configured' : 'failed';
    }
  }

  // Step 6: record the proof reference as used, then approve.
  const reference = parsed?.proof?.reference || parsed?.proof?.proofReference || null;
  if (reference) usedProofs.add(reference);

  const approved = { ...result, decision: 'APPROVE', reason: 'all checks passed; verification finalized' };
  logger.info('task approved', { taskId, kurierJobId: kurierJob.job?.jobId || kurierJob.job?.id || null });
  return {
    status: 200,
    taskId,
    body: responseBody(approved, {
      proofStatus,
      proof: responseProof,
      verification: {
        vkHash: VK_HASH,
        kurierStatus: 'Finalized',
        kurierJobId: kurierJob.job?.jobId || kurierJob.job?.id || null,
        proofReference: reference,
      },
    }),
  };
}

function responseBody(result, extra = {}) {
  return {
    protocol: 'v1',
    taskId: result.taskId || null,
    decision: result.decision,
    reason: result.reason,
    checks: result.checks,
    proof: extra.proof || null,
    proofStatus: extra.proofStatus || 'not_configured',
    proofReference: extra.verification?.proofReference || null,
    verification: extra.verification || { vkHash: VK_HASH, kurierStatus: 'not_submitted' },
  };
}

// The platform's endpoint check ("must return signed protocol-v1 JSON")
// probes the endpoint before any real task exists — possibly unsigned, or
// with a preflight envelope. Every /agent response is therefore signed
// with the agent secret whenever it is configured (including 400/401),
// and carries protocol: 'v1', so the probe can verify the endpoint holds
// the platform-issued secret even when the probe itself is not a task.
function errorBody(code, error) {
  return { protocol: 'v1', error, code };
}

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url || '/', `http://${req.headers.host || 'localhost'}`);
  const requestId = crypto.randomUUID();

  if (req.method === 'GET' && url.pathname === '/healthz') {
    return sendJson(res, 200, { status: 'ok', version: VERSION, usedProofs: usedProofs.size() });
  }
  if (req.method === 'GET' && url.pathname === '/') {
    return sendJson(res, 200, {
      name: '0xge-agent-games',
      track: 'Proof Gatekeeper',
      version: VERSION,
      startedAt,
      endpoint: 'POST /agent',
      proofMode: PROOF_MODE,
      kurierConfigured: Boolean(kurier.config()),
    });
  }
  if (req.method === 'GET' && url.pathname === '/agent') {
    // Protocol handshake probe: answer with signed protocol-v1 JSON so a
    // GET-based endpoint check can verify the agent holds the secret.
    return sendJson(res, 200, {
      protocol: 'v1',
      status: 'ok',
      name: '0xge-agent-games',
      track: 'Proof Gatekeeper',
      version: VERSION,
      endpoint: 'POST /agent',
    }, { sign: true });
  }
  if (req.method !== 'POST' || url.pathname !== '/agent') {
    return sendJson(res, 404, errorBody('NOT_FOUND', 'not found'), { sign: true });
  }

  // Step 1: HMAC verification against the RAW body, BEFORE parsing.
  let rawBody;
  try {
    rawBody = await readBody(req);
  } catch (err) {
    return sendJson(res, 400, errorBody('BODY_ERROR', err.message), { sign: true });
  }
  if (!HMAC_SECRET) {
    logger.error('AGENT_HMAC_SECRET is not set; refusing all tasks');
    return sendJson(res, 500, errorBody('MISCONFIGURED', 'agent misconfigured: HMAC secret missing'), { sign: true });
  }
  const signature = req.headers['x-agent-games-signature'];
  if (!verifySignature(HMAC_SECRET, rawBody, signature)) {
    logger.warn('bad HMAC signature', { requestId });
    return sendJson(res, 401, errorBody('INVALID_SIGNATURE', 'invalid signature'), { sign: true });
  }

  // Steps 2-6, bounded by the task deadline. On timeout: fail closed.
  const timeout = new Promise((resolve) => {
    setTimeout(() => {
      resolve({
        status: 200,
        taskId: null,
        body: {
          protocol: 'v1',
          taskId: null,
          decision: 'REJECT',
          reason: 'task timeout: exceeded TASK_TIMEOUT_MS',
          checks: [{ name: 'timeout', pass: false, reason: 'deadline exceeded' }],
          proof: null,
          proofStatus: 'not_configured',
          proofReference: null,
          verification: { vkHash: VK_HASH, kurierStatus: 'not_submitted' },
        },
      });
    }, TASK_TIMEOUT_MS).unref();
  });

  let outcome;
  try {
    outcome = await Promise.race([handleTask(rawBody), timeout]);
  } catch (err) {
    logger.error('task pipeline error, failing closed', { requestId, error: err.message });
    outcome = {
      status: 200,
      taskId: null,
      body: {
        protocol: 'v1',
        taskId: null,
        decision: 'REJECT',
        reason: `internal error: ${err.message}`,
        checks: [{ name: 'internal', pass: false, reason: err.message }],
        proof: null,
        proofStatus: 'not_configured',
        proofReference: null,
        verification: { vkHash: VK_HASH, kurierStatus: 'not_submitted' },
      },
    };
  }
  return sendJson(res, outcome.status, outcome.body, { sign: true });
});

server.listen(PORT, HOST, () => {
  logger.info('agent listening', { host: HOST, port: PORT, version: VERSION, proofMode: PROOF_MODE });
});

module.exports = { server };
