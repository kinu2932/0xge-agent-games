'use strict';

// Helper: pretty-print a task envelope (from a file, or piped on stdin) so
// the operator can map its fields and public signals into
// circuits/gatekeeper.signals.json after the first practice task.
//
// Usage:
//   npm run inspect-task -- test/fixtures/valid-task.json
//   cat task.json | npm run inspect-task
//
// The tool prints structure only — it never sends anything anywhere.

const fs = require('node:fs');

async function main() {
  let raw = '';
  if (process.argv[2]) {
    raw = fs.readFileSync(process.argv[2], 'utf8');
  } else {
    raw = await new Promise((resolve) => {
      let data = '';
      process.stdin.on('data', (c) => { data += c; });
      process.stdin.on('end', () => resolve(data));
    });
  }
  const task = JSON.parse(raw);
  const walk = (obj, prefix = '') => {
    if (obj === null || typeof obj !== 'object') {
      console.log(`${prefix} = ${JSON.stringify(obj)} (${typeof obj})`);
      return;
    }
    for (const [k, v] of Object.entries(obj)) {
      if (v !== null && typeof v === 'object') {
        if (Array.isArray(v)) {
          console.log(`${prefix}${k}[] (len ${v.length})`);
          v.forEach((item, i) => {
            if (item !== null && typeof item === 'object') walk(item, `${prefix}${k}[${i}].`);
            else console.log(`${prefix}${k}[${i}] = ${JSON.stringify(item)}`);
          });
        } else {
          walk(v, `${prefix}${k}.`);
        }
      } else {
        console.log(`${prefix}${k} = ${JSON.stringify(v)} (${typeof v})`);
      }
    }
  };
  console.log('--- task envelope structure ---');
  walk(task);
  console.log('--- notes ---');
  console.log('Map each publicSignals index to its meaning (threshold / recipient /');
  console.log('action / ...) in circuits/gatekeeper.signals.json, then set configured=true.');
}

main().catch((err) => {
  console.error(err.message);
  process.exit(1);
});
