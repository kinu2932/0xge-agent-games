#!/usr/bin/env bash
# Re-download the gatekeeper circuit artifacts from the official Agent Games
# site and verify them against the recorded SHA-256 hashes.
set -euo pipefail
cd "$(dirname "$0")/../circuits"

BASE="https://agentgames.zkverify.io/circuits"
WASM_SHA="be00aefe3c8ba910951a242f50e55937bf82a0375ad4b69c2ef10629ab92764f"
ZKEY_SHA="adfe95a439a7063a82a4967ef026d2dd6857a4d02c63b3caf63dac02e01af80d"

curl -sL --max-time 120 -o gatekeeper.wasm "$BASE/gatekeeper.wasm"
curl -sL --max-time 120 -o gatekeeper_final.zkey "$BASE/gatekeeper_final.zkey"

echo "$WASM_SHA  gatekeeper.wasm" | sha256sum -c -
echo "$ZKEY_SHA  gatekeeper_final.zkey" | sha256sum -c -

if command -v node >/dev/null && [ -f ../node_modules/snarkjs/build/main.cjs ]; then
  node -e "
const snarkjs = require('snarkjs');
(async () => {
  const vk = await snarkjs.zKey.exportVerificationKey('gatekeeper_final.zkey');
  require('fs').writeFileSync('gatekeeper.vkey.json', JSON.stringify(vk, null, 2));
  console.log('VK:', vk.protocol, vk.curve, 'nPublic =', vk.nPublic);
})();"
fi
echo "OK: circuits verified."
