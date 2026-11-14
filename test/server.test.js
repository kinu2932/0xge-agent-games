'use strict';

// Server smoke tests: HMAC gate, JSON handling, health endpoints, and the
// fail-closed task path. Kurier is not configured in tests, so an
// otherwise-approvable task must REJECT (bootstrap mode rejects earlier).

const test = require('node:test');
const assert = require('node:assert/strict');

process.env.PORT = '0'; // ephemeral port
process.env.HOST = '127.0.0.1';
process.env.AGENT_HMAC_SECRET = 'test-hmac-secret-do-not-use-in-production';
process.env.PROOF_MODE = 'off';
delete process.env.KURIER_API_KEY;
delete process.env.KURIER_BASE_URL;

const { signBody } = require('../src/hmac');
const { server } = require('../src/server');

const SECRET = process.env.AGENT_HMAC_SECRET;

let base;
test.before(async () => {
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const { port } = server.address();
  base = `http://127.0.0.1:${port}`;
});
test.after(async () => {
  await new Promise((resolve) => server.close(resolve));
});

test('GET / returns agent info', async () => {
  const res = await fetch(`${base}/`);
  assert.equal(res.status, 200);
  const json = await res.json();
  assert.equal(json.track, 'Proof Gatekeeper');
  assert.equal(json.endpoint, 'POST /agent');
});

test('GET /healthz returns ok', async () => {
  const res = await fetch(`${base}/healthz`);
  assert.equal(res.status, 200);
  assert.equal((await res.json()).status, 'ok');
});

test('POST /agent without a signature is 401', async () => {
  const res = await fetch(`${base}/agent`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ taskId: 'x' }),
  });
  assert.equal(res.status, 401);
});

test('POST /agent with a bad signature is 401', async () => {
  const body = JSON.stringify({ taskId: 'x' });
  const res = await fetch(`${base}/agent`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', 'x-agent-games-signature': 'sha256=00'.repeat(32) },
    body,
  });
  assert.equal(res.status, 401);
});

test('POST /agent without a signature is 401 but signed (protocol-v1)', async () => {
  const body = JSON.stringify({ taskId: 'x' });
  const res = await fetch(`${base}/agent`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body,
  });
  assert.equal(res.status, 401);
  const header = res.headers.get('x-agent-games-signature');
  assert.ok(header && header.startsWith('sha256='));
  const responseRaw = Buffer.from(await res.arrayBuffer());
  const { verifySignature } = require('../src/hmac');
  assert.equal(verifySignature(SECRET, responseRaw, header), true);
  const json = JSON.parse(responseRaw.toString('utf8'));
  assert.equal(json.protocol, 'v1');
});

test('POST /agent with a valid signature but bad JSON is 400 and signed', async () => {
  const raw = Buffer.from('{not json');
  const res = await fetch(`${base}/agent`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', 'x-agent-games-signature': signBody(SECRET, raw) },
    body: raw,
  });
  assert.equal(res.status, 400);
  const header = res.headers.get('x-agent-games-signature');
  assert.ok(header && header.startsWith('sha256='));
  const responseRaw = Buffer.from(await res.arrayBuffer());
  const { verifySignature } = require('../src/hmac');
  assert.equal(verifySignature(SECRET, responseRaw, header), true);
  assert.equal(JSON.parse(responseRaw.toString('utf8')).protocol, 'v1');
});

test('POST /agent preflight envelope returns signed protocol-v1 ok', async () => {
  const raw = Buffer.from(JSON.stringify({ type: 'preflight', timestamp: Date.now() }));
  const res = await fetch(`${base}/agent`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', 'x-agent-games-signature': signBody(SECRET, raw) },
    body: raw,
  });
  assert.equal(res.status, 200);
  const header = res.headers.get('x-agent-games-signature');
  assert.ok(header && header.startsWith('sha256='));
  const responseRaw = Buffer.from(await res.arrayBuffer());
  const { verifySignature } = require('../src/hmac');
  assert.equal(verifySignature(SECRET, responseRaw, header), true);
  const json = JSON.parse(responseRaw.toString('utf8'));
  assert.equal(json.protocol, 'v1');
  assert.equal(json.status, 'ok');
});

test('GET /agent returns signed protocol-v1 info', async () => {
  const res = await fetch(`${base}/agent`);
  assert.equal(res.status, 200);
  const header = res.headers.get('x-agent-games-signature');
  assert.ok(header && header.startsWith('sha256='));
  const responseRaw = Buffer.from(await res.arrayBuffer());
  const { verifySignature } = require('../src/hmac');
  assert.equal(verifySignature(SECRET, responseRaw, header), true);
  const json = JSON.parse(responseRaw.toString('utf8'));
  assert.equal(json.protocol, 'v1');
  assert.equal(json.status, 'ok');
});

test('POST /agent with a valid task is signed and fail-closed (REJECT)', async () => {
  const now = Date.now();
  const task = {
    taskId: 'smoke-001',
    timestamp: now,
    signature: '0xdeadbeef',
    condition: {
      threshold: '1000',
      recipient: '0x2AfDAcAF2856acB2BE7B85653DA236FC78d15fF2',
      action: 'approve',
      expiresAt: now + 3600_000,
      vkHash: '0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0',
      circuit: 'groth16',
      curve: 'bn128',
    },
    payment: { amount: '1000', recipient: '0x2AfDAcAF2856acB2BE7B85653DA236FC78d15fF2', action: 'approve' },
    proof: {
      proof: { protocol: 'groth16', pi_a: ['1', '2', '1'], pi_b: [['3', '4'], ['5', '6'], ['1', '0']], pi_c: ['7', '8', '1'] },
      publicSignals: Array(13).fill('0'),
      reference: 'proof-ref-smoke-001',
    },
  };
  const raw = Buffer.from(JSON.stringify(task));
  const res = await fetch(`${base}/agent`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', 'x-agent-games-signature': signBody(SECRET, raw) },
    body: raw,
  });
  assert.equal(res.status, 200);
  const header = res.headers.get('x-agent-games-signature');
  assert.ok(header && header.startsWith('sha256='));
  const responseRaw = Buffer.from(await res.arrayBuffer());
  // The response signature must verify against the raw response body.
  const { verifySignature } = require('../src/hmac');
  assert.equal(verifySignature(SECRET, responseRaw, header), true);
  const json = JSON.parse(responseRaw.toString('utf8'));
  assert.equal(json.protocol, 'v1');
  assert.equal(json.taskId, 'smoke-001');
  assert.equal(json.decision, 'REJECT'); // bootstrap mode: mapping not configured
  assert.match(json.reason, /mapping not configured/);
});
