# Gatekeeper circuit artifacts — Proof Gatekeeper (Agent Games, zkVerify)

Provenance: downloaded from the official Agent Games site. Re-download and
verify at any time with `npm run download-circuits` (or
`bash scripts/download-circuits.sh`).

| Artifact | URL | Size | SHA-256 |
|---|---|---|---|
| `gatekeeper.wasm` | https://agentgames.zkverify.io/circuits/gatekeeper.wasm | 1,755,820 bytes | `be00aefe3c8ba910951a242f50e55937bf82a0375ad4b69c2ef10629ab92764f` |
| `gatekeeper_final.zkey` | https://agentgames.zkverify.io/circuits/gatekeeper_final.zkey | 309,750 bytes | `adfe95a439a7063a82a4967ef026d2dd6857a4d02c63b3caf63dac02e01af80d` |
| `gatekeeper.vkey.json` | exported locally via `snarkjs.zKey.exportVerificationKey` | 5,502 bytes | — |

Circuit facts (verified 2026-11-15 from the downloaded artifacts):

- Protocol: **Groth16**, curve: **BN128**
- Public inputs: **13** (`vk.nPublic = 13`, `IC` length 14)
- Registered verification-key hash (zkVerify mainnet, from
  `https://agentgames.zkverify.io/api/circuit-info`):
  `0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0`
- The Steal the VFY circuit (`vfy-policy`) is NOT included here — this repo
  enters Proof Gatekeeper only.

## Signal layout — TODO (bootstrap mode)

`gatekeeper.signals.json` maps the 13 public inputs to condition fields
(threshold / recipient / action / ...). The public docs do not publish the
layout, so it is filled in from the first practice task — see
`docs/TASK_SCHEMA_NOTES.md`. Until it is configured the agent verifies
everything cryptographic and REJECTs otherwise-valid tasks rather than
guessing an APPROVE.
