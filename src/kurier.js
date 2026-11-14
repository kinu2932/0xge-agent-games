'use strict';

// Kurier client (zkVerify proof verification, REST).
//
// Flow: submit a proof with its vk hash -> poll the job until it reaches
// Finalized. The agent only APPROVEs after Finalized (§04).
//
// The Kurier base URL and API key come from the environment (see
// .env.example). They are NOT defaulted: the exact REST paths live in the
// Kurier docs linked from https://agentgames.zkverify.io/build, and this
// module refuses to guess them. If either is unset, submit() throws
// NOT_CONFIGURED and the server fails closed (REJECT).
//
// Expected job states (per /build §03): Submitted -> IncludedInBlock ->
// Finalized. Any terminal failure state is treated as "not finalized".

const logger = require('./logger');

const POLL_INTERVAL_MS = 2000;

function config() {
  const apiKey = process.env.KURIER_API_KEY || '';
  const baseUrl = (process.env.KURIER_BASE_URL || '').replace(/\/+$/, '');
  if (!apiKey || !baseUrl) return null;
  return { apiKey, baseUrl };
}

async function postJson(url, apiKey, body) {
  const res = await fetch(url, {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      authorization: `Bearer ${apiKey}`,
      'x-api-key': apiKey,
    },
    body: JSON.stringify(body),
  });
  const text = await res.text();
  let json = null;
  try {
    json = JSON.parse(text);
  } catch {
    // Non-JSON error body.
  }
  if (!res.ok) {
    const err = new Error(`kurier POST ${res.status}: ${text.slice(0, 200)}`);
    err.code = 'KURIER_HTTP';
    err.status = res.status;
    throw err;
  }
  return json;
}

async function getJson(url, apiKey) {
  const res = await fetch(url, {
    headers: { authorization: `Bearer ${apiKey}`, 'x-api-key': apiKey },
  });
  const text = await res.text();
  if (!res.ok) {
    const err = new Error(`kurier GET ${res.status}: ${text.slice(0, 200)}`);
    err.code = 'KURIER_HTTP';
    err.status = res.status;
    throw err;
  }
  try {
    return JSON.parse(text);
  } catch {
    return { raw: text };
  }
}

/**
 * Submit a proof for verification. Returns { jobId }.
 * Throws NOT_CONFIGURED when Kurier is not set up.
 */
async function submit({ proof, publicSignals, vkHash }) {
  const cfg = config();
  if (!cfg) {
    const err = new Error('Kurier not configured (KURIER_API_KEY / KURIER_BASE_URL missing)');
    err.code = 'NOT_CONFIGURED';
    throw err;
  }
  const data = await postJson(`${cfg.baseUrl}/api/v1/verify`, cfg.apiKey, {
    proof,
    publicSignals,
    vkHash,
    proofType: 'groth16',
  });
  const jobId = data.jobId || data.job_id || data.id;
  if (!jobId) throw new Error(`kurier submit: no job id in response ${JSON.stringify(data).slice(0, 200)}`);
  logger.info('kurier job submitted', { jobId });
  return { jobId };
}

/**
 * Poll a job until Finalized (or a terminal failure / timeout).
 * Returns { status: 'Finalized' | 'Failed' | 'Timeout', job }.
 */
async function waitFinalized(jobId, { timeoutMs = 30000 } = {}) {
  const cfg = config();
  if (!cfg) {
    const err = new Error('Kurier not configured (KURIER_API_KEY / KURIER_BASE_URL missing)');
    err.code = 'NOT_CONFIGURED';
    throw err;
  }
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    const job = await getJson(`${cfg.baseUrl}/api/v1/jobs/${encodeURIComponent(jobId)}`, cfg.apiKey);
    const status = String(job.status || job.state || '').toLowerCase();
    if (status === 'finalized' || status === 'finalised') return { status: 'Finalized', job };
    if (['failed', 'error', 'rejected', 'invalid'].includes(status)) {
      return { status: 'Failed', job };
    }
    if (Date.now() >= deadline) return { status: 'Timeout', job };
    await new Promise((r) => setTimeout(r, POLL_INTERVAL_MS));
  }
}

module.exports = { config, submit, waitFinalized };
