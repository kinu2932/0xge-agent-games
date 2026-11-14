# What the public docs do NOT say (and how the first practice task fixes it)

The Agent Games build page (`https://agentgames.zkverify.io/build`) publishes
the transport rules (HTTPS POST, HMAC, 60 s deadline, signed responses), the
circuit artifacts, and the security checklist — but it does **not** publish
these four things. This repo is built to be correct about everything that
*is* published, and explicitly incomplete (fail-closed) about the rest:

## 1. The exact task-envelope JSON schema

Unknown: the precise field names of the incoming task (task id, condition,
proof, payment, timestamp, signature). `src/decide.js` normalizes the
documented names plus their common aliases and REJECTs anything it cannot
map unambiguously.

**Resolve:** run the first practice task (dashboard → Practice), capture the
envelope, and run `npm run inspect-task -- task.json`. Then tighten
`normalize()` to the real names and add a fixture.

## 2. The exact response JSON schema

Unknown: the precise field names the platform expects back (decision,
proof, proofReference, public inputs hash, ...). The server returns a
superset: `taskId`, `decision`, `reason`, `checks[]`, `proof`,
`proofStatus`, `proofReference`, `verification{ vkHash, kurierStatus,
kurierJobId }`. Extra fields are harmless if the platform ignores them; if
the practice task shows a strict schema, trim the response to it.

**Resolve:** same as (1) — the practice response tells you what was
accepted.

## 3. The gatekeeper circuit's 13 public inputs

Known: `vk.nPublic = 13` (exported from the downloaded zkey). Unknown:
which input index encodes threshold / recipient / action / etc.

**Resolve:** the practice task's `publicSignals` array + the task's
condition together reveal the layout (e.g. one input equals the threshold,
one equals the recipient as a field element). Fill in
`circuits/gatekeeper.signals.json`, set `configured: true`, and add the
`decide-mapped` test case. Until then the agent runs in **bootstrap mode**:
it verifies the attached proof cryptographically, checks VK / expiry /
consistency / replay — and REJECTs every otherwise-valid task rather than
guessing an APPROVE. Expected value of REJECT-all in bootstrap mode is
still positive (valid ~50% → −3, traps ~50% → +12).

## 4. The Kurier REST endpoints

Known: Kurier is REST, needs a mainnet API key, job states are Submitted →
IncludedInBlock → Finalized. Unknown: the exact base URL and paths.

**Resolve:** the Kurier dashboard (linked from the build page) gives the API
key and the endpoint. Put them in `KURIER_API_KEY` / `KURIER_BASE_URL`.
`src/kurier.js` refuses to guess URLs — if either is unset, APPROVE is
impossible (fail closed) and the server logs `NOT_CONFIGURED`.

## 5. The HMAC signature wire format

The header is `x-agent-games-signature`, computed over the raw body.
`src/hmac.js` accepts `sha256=<hex>`, raw `<hex>`, or base64. If the
dashboard shows a different format, update `parseSignature()` and add a
test — never loosen verification.
