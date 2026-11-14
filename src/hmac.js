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

/**
 * Verify an incoming x-agent-games-signature header against the raw body.
 * Returns true only on an exact timing-safe match.
 */
function verifySignature(secret, rawBody, header) {
  if (!secret || !Buffer.isBuffer(rawBody) || rawBody.length === 0) return false;
  const expected = computeHmac(secret, rawBody);
  const given = parseSignature(header);
  if (!given || given.length !== expected.length) return false;
  return crypto.timingSafeEqual(given, expected);
}

/**
 * Sign an outgoing raw response body. Returns the header value to send.
 */
function signBody(secret, rawBody) {
  const digest = computeHmac(secret, rawBody).toString('hex');
  return `sha256=${digest}`;
}

module.exports = { computeHmac, parseSignature, signBody, verifySignature };
