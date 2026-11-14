# 0xge-agent-games — Proof Gatekeeper agent for Agent Games (zkVerify)

Participant **0xge** (X [@gole391](https://x.com/gole391), BSC wallet
`0x2AfDAcAF2856acB2BE7B85653DA236FC78d15fF2`).

Track: **Proof Gatekeeper only** — the agent receives proof-backed payment
requests, verifies them, and returns a deterministic `APPROVE` / `REJECT`
with proof evidence. Season 01: 21 Oct – 21 Nov 2026, 8 daily rounds
(13–20 Nov, 17:30–3:30 WIB), 8 tasks per agent per round, cumulative score.
Prize: 100,000 VFY for this track (1st 50,000 / 2nd 30,000 / 3rd 20,000).

## Scoring (why the agent fails closed)

| Outcome | Points |
|---|---|
| Correct decision (APPROVE or REJECT) | +12 |
| Wrong APPROVE | −6 |
| Wrong REJECT | −3 |
| Timeout | −2 |
| Missing / invalid proof | −2 |
| Reliability bonus | +0 … +5 |

A wrong APPROVE costs twice a wrong REJECT — so on **any** doubt the agent
REJECTs. It never approves on uncertainty, never fabricates a proof, and
never approves before Kurier reports the verification **Finalized**.

## How it works

```
platform POST /agent  ──HMAC(x-agent-games-signature, raw body)──▶ server.js
   1. verify HMAC against the RAW body, before parsing (401 otherwise)
   2. decide() — the 7 trap checks + §04 checks (src/decide.js):
      shape, timestamp/expiry, vkHash == registered gatekeeper key,
      groth16/bn128, payment == condition, public-signal count + values,
      attached proof verifies (snarkjs), proof reference never reused
   3. APPROVE candidates: submit the proof to Kurier, wait for Finalized
   4. optional local Groth16 response proof (PROOF_MODE=local, needs the
      signal mapping — see below)
   5. record the proof reference as used, sign the response, reply
   6. any error / timeout → REJECT
```

## Quick start

```bash
npm install
cp .env.example .env   # fill in AGENT_HMAC_SECRET (dashboard → Rotate Secret)
npm test               # node --test, no network needed
npm start              # listens on $PORT (default 8080)
```

Circuit artifacts are already in `circuits/` (verified downloads, see
`circuits/README.md`). Re-download any time: `npm run download-circuits`.

## Environment

| Variable | Required | Notes |
|---|---|---|
| `AGENT_HMAC_SECRET` | yes | Platform-generated, dashboard → Rotate Secret. Never a placeholder. |
| `KURIER_API_KEY` / `KURIER_BASE_URL` | yes for APPROVE | From the Kurier dashboard (linked from the build page). Unset → fail closed. |
| `GATEKEEPER_VK_HASH` | no | Defaults to the registered key `0x6b79c6…77b0`. |
| `PROOF_MODE` | no | `off` (default) or `local`. Local needs the signal mapping. |
| `TASK_TIMEOUT_MS` | no | Default 45000 (platform hard deadline is 60000). |
| `PORT` / `HOST` | no | Default 8080 / 0.0.0.0. |

## Registration checklist (do this on agentgames.zkverify.io)

1. Repo URL (this repo, **public**, personal account):
   `https://github.com/kinu2932/0xge-agent-games`
2. Deploy the endpoint somewhere public with HTTPS — see `deploy/DEPLOY.md`
   (fly.io free tier; the form's own example is `my-agent.fly.dev/agent`).
3. Paste the endpoint URL into **Register a new agent** → Agent Endpoint,
   tick **Proof Gatekeeper only**, submit.
4. Copy the HMAC secret from the dashboard (Rotate Secret) into the deploy
   env as `AGENT_HMAC_SECRET`, plus `KURIER_API_KEY` / `KURIER_BASE_URL`.
5. Run the **signed preflight** from the dashboard, then at least **1
   practice task** (unscored) — this is where the exact task schema and the
   13 public-signal layout are confirmed (see `docs/TASK_SCHEMA_NOTES.md`).
6. Fill in `circuits/gatekeeper.signals.json`, set `configured: true`,
   redeploy, run practice again.

## Current status — bootstrap mode

The scaffold is complete and tested (see `npm test`), but two things can
only come from the logged-in dashboard / first practice task:

- the exact task-envelope + response field names, and
- the gatekeeper circuit's 13-public-input layout.

Until those land, the agent verifies everything cryptographic and REJECTs
otherwise-valid tasks instead of guessing. That is deliberate: REJECT-all
still scores positive in expectation, APPROVE-on-a-guess does not.

## Files

```
src/server.js       HTTP server: HMAC gate, deadline, Kurier, signed replies
src/decide.js       the decision engine (7 traps + §04 checks, fail-closed)
src/prover.js       local Groth16 proof generation (snarkjs)
src/kurier.js       Kurier REST client (submit + poll to Finalized)
src/hmac.js         timing-safe HMAC-SHA256 verify/sign
src/usedProofs.js   replay protection (proof references, persisted)
src/logger.js       structured JSON logs (no secrets)
circuits/           gatekeeper.wasm + gatekeeper_final.zkey + vkey + signals map
test/               node:test suites + synthetic fixtures
scripts/            download-circuits.sh, inspect-task.js
deploy/             fly.toml + DEPLOY.md (free-tier deploy guide)
docs/               TASK_SCHEMA_NOTES.md (what's TBD and how to resolve it)
```
