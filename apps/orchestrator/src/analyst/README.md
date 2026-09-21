# Worker 3 Analyst

All implementation and test files for this stream live here. No shared types,
entrypoint, Commander, Shield, package manifests, lockfiles, or Wrangler settings
are changed. No new dependencies are required for the implementation.

## Local tests

From apps/orchestrator, with Node 24. Run:

```sh
node --import ./src/analyst/test-loader.mjs --test ./src/analyst/analyst.test.mjs
```

The loader resolves existing extensionless TypeScript imports for Node's built-in
type stripping. It is test-only; do not import it from the Worker. Tests use the
real Commander validator and signature extraction with a scripted mock model.
They do not call Cloudflare, deploy rules, or prove model quality.

The Analyst suite contains 33 tests. Additional regression coverage includes
two-pass decoding parity, malformed fields, overlapping regex repetitions,
duplicate tool reads, oversized object responses, invalid loop options, empty
incidents, and diagnostic trace retention on provider failure.
The fabricated CVE lookup was removed; a regression test confirms search_cve is
not advertised or dispatched. See ../SHIELD_TESTING.md for the combined 48-test
Shield and Analyst command and required upstream configuration.

## Contract

runAnalyst(env, brief) keeps the existing IncidentBrief -> MitigationPlan interface.
It uses env.AI when invoked by the Commander. Missing AI, provider failures,
deadline exhaustion, or exhausted attempts throw for the existing Commander
fallback. No synthetic fallback is presented as model output.

The model selects one structured JSON tool action per turn: inspect_incident,
read_history, read_campaign, or propose. This is an application-managed tool
protocol over text generation, not native function calling or the Agents SDK.
History and campaign tools read only the supplied brief, not live storage.
Proposals are schema checked, checked against a conservative regex subset, and
passed to the existing Commander validator. Rejection feedback goes back to the
model. A passing proposal returns immediately; deployment remains with Commander.

investigate() accepts an injected model client and returns a local trace suitable
for tests or a future dashboard adapter. runAnalyst() returns only the shared plan;
the trace is not yet connected to the shared WebSocket feed.
Failed model calls, deadlines, and exhausted attempts carry the accumulated trace
in AnalystError for local diagnostics. Commander still receives a normal Error;
no shared logging or feed integration is added.

Maximum six model turns, with an 8.5-second overall waiting budget, below the
Commander's existing 10-second timeout. Timers are cleared. A timed-out remote
inference may continue at the provider: env.AI's current structural interface has
no cancellation API. No further tools or deployment are executed after timeout.

The adapter uses @cf/meta/llama-3.3-70b-instruct-fp8-fast. Its messages/response
shape follows https://developers.cloudflare.com/workers-ai/models/llama-3.3-70b-instruct-fp8-fast/.
Live model access and latency have not been tested.

## Integration limitations

- The regex subset intentionally rejects groups, alternation, character classes,
  wildcards and backreferences before executing the shared validator. Passing
  checks is not a general proof of regex safety or absence of false positives.
  Quantified tokens are restricted further to whitespace between literal letters
  or digits, avoiding overlapping word/digit runs and leading repetition.
- URL and body are decoded separately with the Commander's two-pass behavior.
  Read tools return their full result only once per investigation to limit context
  duplication. Object-form model responses have the same size limit as text.
- Only block actions and observe/log plans are emitted. Challenge and rate_limit
  need coordinated enforcement semantics before support can be added.
- The shared validator tests detector-extracted signature snippets. Endpoint-scoped
  rules may fail this contract even when they match the full request. Coordinate
  changes to validation and enforcement input with Members 1 and 2.
- The Analyst also requires a pattern to match actual incident evidence. For
  unknown attacks with no signature samples, it validates against full evidence.
  This does not fix the upstream gate that may prevent unknown incidents arriving.
- High-stage IP blocking, KV propagation, and public API protection remain outside
  this stream. An observe plan does not guarantee Commander will abstain from its
  own high-stage IP block.
- Prompt instructions mark traffic as untrusted evidence. The tool allowlist and
  schema checks restrict authority, but do not prove prompt-injection resistance.
- Live multi-turn latency may exceed the current budget. Agree a background
  orchestration design or budget change before promising a live demo time.

Next integration check: feed a real IncidentBrief to a live model, confirm its
source is workers-ai without degraded fallback, then verify Worker 1 actually
enforces the approved pattern while a benign same-IP request still passes.
