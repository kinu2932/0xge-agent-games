'use strict';

// Structured JSON logging to stdout. One line per event, no secrets.
// Never log the HMAC secret, API keys, or full task envelopes (they may
// contain proofs); log ids, decisions, and check outcomes only.

const LEVELS = { debug: 10, info: 20, warn: 30, error: 40 };
const levelName = (process.env.LOG_LEVEL || 'info').toLowerCase();
const threshold = LEVELS[levelName] ?? LEVELS.info;

function log(level, msg, fields = {}) {
  if ((LEVELS[level] ?? 20) < threshold) return;
  const line = {
    ts: new Date().toISOString(),
    level,
    msg,
    ...fields,
  };
  process.stdout.write(JSON.stringify(line) + '\n');
}

module.exports = {
  debug: (msg, fields) => log('debug', msg, fields),
  info: (msg, fields) => log('info', msg, fields),
  warn: (msg, fields) => log('warn', msg, fields),
  error: (msg, fields) => log('error', msg, fields),
};
