'use strict';

// HMAC-SHA256 helpers for the x-agent-games-signature header.
// The platform signs the RAW request body; we sign the RAW response body.
// Verification uses a timing-safe comparison.
//
// Signature format: the platform docs do not publish the exact wire format,
// so we accept the common shapes and reject everything else:
//   "sha256=<hex>" | "<hex>" | "<base64>"
// If the dashboard's Rotate Secret page shows a different format, update
// parseSignature() there and add a test — never loosen verification to
// "accept anything".

const crypto = require('node:crypto');

function parseSignature(header) {
  if (typeof header !== 'string' || header.length === 0) return null;
  let hex = header.trim();
  if (hex.toLowerCase().startsWith('sha256=')) hex = hex.slice('sha256='.length);
  // Hex (64 chars = 32 bytes).
  if (/^[0-9a-fA-F]{64}$/.test(hex)) return Buffer.from(hex, 'hex');
  // Base64 (44 chars with padding = 32 bytes).
  if (/^[A-Za-z0-9+/]{43}=$/.test(hex)) return Buffer.from(hex, 'base64');
  return null;
}

function computeHmac(secret, rawBody) {
  return crypto.createHmac('sha256', secret).update(rawBody).digest();
}

// The platform issues the secret as 64 hex chars (32 bytes). The docs do
// not say whether it HMACs with the hex STRING or the hex-DECODED bytes,
// so verification accepts both forms of the same secret. Accepting both
// does not weaken anything: both keys derive from the same secret value.
function secretForms(secret) {
  const forms = [secret];
  if (typeof secret === 'string' && /^[0-9a-fA-F]{64}$/.test(secret.trim())) {
    forms.push(Buffer.from(secret.trim(), 'hex'));
  }
  return forms;
}

/**
 * Verify an incoming x-agent-games-signature header against the raw body.
 * Returns true only on an exact timing-safe match.
 */
function verifySignature(secret, rawBody, header) {
  if (!secret || !Buffer.isBuffer(rawBody) || rawBody.length === 0) return false;
  const given = parseSignature(header);
  if (!given) return false;
  return secretForms(secret).some((form) => {
    const expected = computeHmac(form, rawBody);
    return given.length === expected.length && crypto.timingSafeEqual(given, expected);
  });
}

/**
 * Sign an outgoing raw response body. Returns the header value to send.
 */
function signBody(secret, rawBody) {
  const digest = computeHmac(secret, rawBody).toString('hex');
  return `sha256=${digest}`;
}

module.exports = { computeHmac, parseSignature, signBody, verifySignature };
