'use strict';

// Replay protection for proof references (PROOF_REUSED trap).
// A proof reference that has already been used for another task must never
// approve a second payment. The set is persisted to a JSON file so a
// restart does not forget what was already spent.
//
// The file holds only proof-reference hashes/ids — no secrets, no task data.

const fs = require('node:fs');
const path = require('node:path');
const logger = require('./logger');

class UsedProofs {
  constructor(filePath) {
    this.filePath = filePath;
    this.seen = new Set();
    this.loaded = false;
  }

  load() {
    try {
      if (fs.existsSync(this.filePath)) {
        const raw = JSON.parse(fs.readFileSync(this.filePath, 'utf8'));
        if (Array.isArray(raw)) for (const ref of raw) this.seen.add(String(ref));
      }
    } catch (err) {
      logger.warn('used-proofs load failed, starting empty', { error: err.message });
    }
    this.loaded = true;
    return this;
  }

  has(ref) {
    return this.seen.has(String(ref));
  }

  /**
   * Atomically record a reference. Returns false if it was already present
   * (caller must treat that as PROOF_REUSED and reject).
   */
  add(ref) {
    const key = String(ref);
    if (this.seen.has(key)) return false;
    this.seen.add(key);
    this.save();
    return true;
  }

  save() {
    try {
      fs.mkdirSync(path.dirname(this.filePath), { recursive: true });
      const tmp = `${this.filePath}.tmp`;
      fs.writeFileSync(tmp, JSON.stringify([...this.seen], null, 2));
      fs.renameSync(tmp, this.filePath);
    } catch (err) {
      logger.error('used-proofs save failed', { error: err.message });
    }
  }

  size() {
    return this.seen.size;
  }
}

module.exports = { UsedProofs };
