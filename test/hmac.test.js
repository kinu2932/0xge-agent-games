'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { signBody, verifySignature } = require('../src/hmac');

const SECRET = 'test-hmac-secret-do-not-use-in-production';
const BODY = Buffer.from(JSON.stringify({ taskId: 't1', decision: 'REJECT' }));

test('sign then verify round-trips', () => {
  const header = signBody(SECRET, BODY);
  assert.ok(header.startsWith('sha256='));
  assert.equal(verifySignature(SECRET, BODY, header), true);
});

test('raw hex header is accepted', () => {
  const header = signBody(SECRET, BODY).replace('sha256=', '');
  assert.equal(verifySignature(SECRET, BODY, header), true);
});

test('tampered body fails verification', () => {
  const header = signBody(SECRET, BODY);
  const tampered = Buffer.from(JSON.stringify({ taskId: 't1', decision: 'APPROVE' }));
  assert.equal(verifySignature(SECRET, tampered, header), false);
});

test('wrong secret fails verification', () => {
  const header = signBody(SECRET, BODY);
  assert.equal(verifySignature('another-secret', BODY, header), false);
});

test('missing / malformed headers fail verification', () => {
  assert.equal(verifySignature(SECRET, BODY, ''), false);
  assert.equal(verifySignature(SECRET, BODY, undefined), false);
  assert.equal(verifySignature(SECRET, BODY, 'not-a-signature'), false);
  assert.equal(verifySignature(SECRET, BODY, 'sha256=zz'), false);
});

test('empty secret refuses everything', () => {
  const header = signBody(SECRET, BODY);
  assert.equal(verifySignature('', BODY, header), false);
});

test('64-hex secret verifies in both string and hex-decoded forms', () => {
  // The platform issues a 64-hex-char secret; the docs do not say whether
  // it HMACs with the hex string or the decoded bytes. Both must verify.
  const hexSecret = '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';
  const headerString = signBody(hexSecret, BODY);
  assert.equal(verifySignature(hexSecret, BODY, headerString), true);
  const headerDecoded = signBody(Buffer.from(hexSecret, 'hex'), BODY);
  assert.equal(verifySignature(hexSecret, BODY, headerDecoded), true);
  // ...but a different hex secret still fails.
  const other = 'fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210';
  assert.equal(verifySignature(hexSecret, BODY, signBody(other, BODY)), false);
});
