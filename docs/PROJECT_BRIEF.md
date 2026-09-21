# Project Brief: "Red vs. Blue" Autonomous Zero-Day Patching Engine

> **Audience:** engineers (and LLM coding agents) picking this project up cold. It is written so that reading it
> top to bottom is enough to resume work without asking anyone anything. For a non-technical explanation, read
> the root [README](../README.md) instead.
>
> **Snapshot date:** 2026-09-19. **Branch:** `main`, HEAD `6a87a05` ("Implementation changes"), pushed to
> `origin/main` (`github.com/ayeshkadike/htn`). One untracked file: `apps/dashboard/package-lock.json` (should be committed).
> **Status in one line:** the full local demo works end to end (attack → detect → AI/fallback rule → edge block → live
> dashboard), verified in a real browser; it has **not** been deployed to Cloudflare or run against live Workers AI.

---

## 1. What we are trying to achieve

A web application has a vulnerability nobody has patched yet (a *zero-day*). Attackers exploit it now; a human
developer needs hours or days to ship a fix. This project shows a system that closes that gap **autonomously, in
seconds, without touching the vulnerable application**:

1. All traffic enters through an **edge proxy** (the *Shield*), which forwards it to the real app.
2. Traffic that *looks* hostile is copied onto a queue. A stateful **Commander** tracks each attacker, scores them,
   and decides when a pattern of behaviour is an incident.
3. On an incident, an **Analyst** (an LLM with a constrained toolset, plus a deterministic fallback) proposes a
   mitigation: usually a regex signature for the attack, or an IP block.
4. The Commander **validates** the proposal (it must catch the attack, must *not* catch legitimate traffic) and only
   then publishes it to KV, where the Shield reads it. The next attack request is answered `403` at the edge.
5. A **live dashboard** (the *War Room*) streams all of this so a human can watch and, if needed, override.

The name "Red vs. Blue" is the security-exercise framing: Red = the attacker (our Red Team console fires exploits),
Blue = the defender (this engine). The project was built for a hackathon (Hack the North); the deliverable is a
**convincing, reliable live demo** of the loop above, not a production WAF. Several design choices below trade
completeness for demo reliability, and each says so.

Success criteria for the demo: (a) benign traffic passes; (b) a real SQL injection visibly *succeeds* against the
unprotected origin; (c) the system opens an incident and deploys a rule with no human input; (d) the same attack is
then blocked at the edge; (e) the dashboard shows every step live; (f) a rule that would hurt legitimate users is
visibly *refused*.

---

## 2. System map

```
                 ┌────────────────────────── Cloudflare Worker "red-vs-blue-engine" (apps/orchestrator) ─────────────────────────┐
                 │                                                                                                             │
 Browser/curl ──►│  index.ts ── /commander/* ──► commander/api.ts (operator REST + WebSocket)                                   │
 (Red Team       │      │                                                                                                      │
  console →      │      └── everything else ──► shield.ts  (THE SHIELD)                                                        │
  :8787)         │            1. block_ip_<ip> in KV? ──────────────► 403                                                       │
                 │            2. waf:patterns rules match? ─────────► 403                                                       │
                 │            3. classify(); suspicious? ──► ANALYSIS_QUEUE.send(event)                                         │
                 │            4. proxy to DEMO_UPSTREAM ───────────► Vulnerable origin (apps/target, :3001)                     │
                 │                                                                                                             │
                 │  queue() ─► commander/queue-consumer.ts ─► IncidentCommander DO  (ONE PER IP)                                │
                 │                                                score/decay/stage, burst window, incidents                   │
                 │                                                   │  ├─► CampaignTracker DO (ONE GLOBAL): fingerprints,   │
                 │                                                   │  │     pattern-rule set, WebSocket feed               │
                 │                                                   │  ├─► analyst-client ─► analyst/ (LLM) ─or─ fallback   │
                 │                                                   │  ├─► validateRule() guardrail                          │
                 │                                                   │  └─► KV writes (block_ip_*, waf:patterns) + D1 ledger │
                 └─────────────────────────────────────────────────────────────────────────────────────────────────────────────┘
        Dashboard (apps/dashboard, Next.js :3000) ◄── WebSocket + REST from :8787;  POST /api/red-team ──► :8787 (server-side)
```

Ports: **3000** dashboard, **3001** vulnerable target, **8787** orchestrator (`wrangler dev`).

### Repository layout

```
apps/
  target/            Express + in-memory SQLite, deliberately vulnerable (index.js)
  orchestrator/      Cloudflare Worker: Shield + Commander + Analyst
    src/index.ts                 entry: routes /commander/* first, else Shield; exports DOs; queue handler
    src/types.ts                 THE integration contract (Env, SuspiciousEvent, IncidentBrief, MitigationPlan, FeedEvent…)
    src/shield.ts                edge enforcement + reverse proxy
    src/commander/               policy, fingerprint, incident-commander (DO), campaign-tracker (DO), mitigation,
                                 fallback-plan, analyst-client, queue-consumer, scheduler, ledger (D1), api
    src/analyst/                 LLM tool loop (loop.ts), adapter (index.ts), tests, README
    migrations/0001_init.sql     D1 schema
    wrangler.toml                bindings + tuning vars
    .dev.vars                    LOCAL ONLY, gitignored: DEMO_UPSTREAM (+ optional ANALYST_MODE)
  dashboard/         Next.js 15 (App Router) War Room
    src/lib/{types,state,useWarRoom,format}.ts   wire types, reducer, WebSocket hook, helpers
    src/components/                              StatsBar, LiveLog, MitigationFeed, RedTeamConsole, dashboard.module.css
    src/app/{page,layout}.tsx, globals.css       composition + theme
    src/app/api/red-team/route.ts                server-side attack/reset proxy
docs/PROJECT_BRIEF.md   this file
```

The orchestrator source is annotated with `OWNER: Member 1/2/3`. Member 1 = Shield, Member 2 = Commander,
Member 3 = Analyst. `types.ts` is the boundary between them: **change it only by agreement**.

---

## 3. Component deep-dive and the reasoning behind each decision

### 3.1 The vulnerable target (`apps/target/index.js`)

- Express 4 + `sqlite3` with an **in-memory** DB seeded with one `admin` user. `POST /login` builds its SQL by string
  interpolation: `SELECT * FROM users WHERE username = '${u}' AND password = '${p}'`.
- **Why real SQLite, not a mock that pretends:** the demo's credibility hinges on the injection *actually working*.
  `admin' OR 1=1 -- ` genuinely returns the admin row and a token. Anyone can see the exploit succeed before the
  defence kicks in, and the test suite even executes the same query shape against Node's built-in SQLite.
- Also has `GET /files?file=` (path-traversal mock), `GET /search?q=` (reflected XSS) and a login HTML form at `/`.
  Only `/login` is used by the demo/console; the others exist to show multi-class detection.
- **Caution:** `app.listen(3001)` binds *all* interfaces, so the intentionally vulnerable app is reachable from the
  LAN. Binding to `127.0.0.1` would be a one-line hardening (not done; see §8).
- SQL precedence trap worth knowing: `' OR '1'='1` in *username only* does **not** log in, because `AND` binds
  tighter than `OR` (`… OR ('1'='1' AND password='x')`). The payloads we use terminate with `--` so the password
  clause is commented out.

### 3.2 The Shield (`src/shield.ts`) — edge interception and enforcement

Request path, in this order (order matters for cost and safety):

1. **Validate `DEMO_UPSTREAM`.** Must be http(s), no embedded credentials. Missing/invalid → `503` with a clear
   message. *No third-party fallback:* an earlier version proxied to a public site; it was removed so the Shield can
   never forward traffic somewhere uncontrolled. Upstream pathname and search are **assigned as fields** (not
   resolved as a relative URL) so a request path beginning `//evil.com/` cannot change the host. Redirects use
   `redirect: 'manual'` so we never forward the caller's credentials to a redirect target.
2. **Per-IP block:** KV key `block_ip_<ip>` (a JSON `EdgeBlock`). Present with `action:"block"` → `403`. Unparseable
   value → `403` too (fail closed).
3. **Pattern rules:** read `waf:patterns` (one JSON document), evaluate only `action:"block"` rules against
   `decodedUrl + "\n" + decodedBody`. Blocking rules are evaluated *independently* of earlier log/challenge rules so a
   log rule can never mask a block rule (regression-tested).
4. **Classify** with the *same* `classify()` the Commander uses (single source of truth; an earlier keyword list
   diverged from the Commander and was replaced). Anything not `unknown` is pushed onto `ANALYSIS_QUEUE`. The
   queue send is **awaited** (acceptance only; analysis happens in the consumer).
5. **Proxy** the original request to the origin and return its response verbatim.

Decisions: two-pass percent-decoding of URL and body (`decodeEvidence`) defeats double-encoding bypasses; the same
logic is mirrored in the Analyst and Commander (parity is regression-tested). The Shield only ever enforces
`block`. `challenge` and `log` are **not** enforced at the edge (see §8).

### 3.3 The queue and consumer (`commander/queue-consumer.ts`)

Shield → Queue → Commander decouples the hot path from analysis. Consumer decisions:
- **Group by IP**, fan out in parallel across IPs, but keep one IP's events **sequential** (scoring an attack chain
  out of order gives wrong answers).
- **Ack/retry per message**, never per batch (throwing would re-score nine good messages).
- **Poison messages** (unparseable, or failing 3 attempts) are audited (`queue_poison`) and acked, never retried
  forever. Retry backoff is exponential, capped at 60s. `wrangler.toml` also names a dead-letter queue
  (`suspicious-traffic-dlq`); it must exist before deploying.
- `max_batch_timeout = 2` means a burst is analysed ~2s after the last request. That is the "wait a couple of
  seconds" in the demo script.
- **Exactly-once effect** on an at-least-once transport: `eventId` (queue message id) is stored per IP; a redelivery
  is ignored (`duplicate: true`) so a retry cannot inflate a threat score.

### 3.4 The Commander (`commander/incident-commander.ts`, `policy.ts`) — one Durable Object per IP

Why a Durable Object per IP: it gives strongly consistent, serialised state per attacker with no external database
on the hot path. Read-modify-write sequences are wrapped in a `serialize()` promise chain because DO storage awaits
can interleave.

Scoring (pure functions in `policy.ts`, unit-testable, deliberately separate from the DO):
- Each event contributes `severity × confidence × repeatMultiplier` (multiplier `1 + 0.25·priorIncidents`, capped at 2).
- The score **decays exponentially** (half-life 10 min) so IPs un-block themselves and the system never accumulates
  permanent blocks.
- Stages by score: `observe` < 30 ≤ `monitor` < 60 ≤ `challenge` < 85 ≤ `block`.
- **Analysis triggers** (any one): a *burst* (≥3 suspicious events in 60 s; repeat offenders need 2), *escalation* to
  a higher stage while an incident is already open, or a *new attack class* from the same IP (multi-vector probing).
  Cooldown 20 s between analyses; incident closes after 120 s idle. A human `pardon` suppresses enforcement.
- A DO has one alarm; `scheduler.ts` multiplexes several jobs (`gc`, `close_incident`, `expire_mitigation`, `decay`)
  onto it with a time-sorted key range.
- When stage is `block`, the Commander **also** writes an IP block even if it deployed a pattern rule ("stage is
  block: also blocked ::1 at the edge"). This is intentional defence in depth but has collateral impact (§8).
- Feed publishing: `ingest` events are pushed to the dashboard only if `stage !== observe` or analysis triggered.
  Benign/unclassified traffic never reaches the feed.

Classification (`fingerprint.ts`): regex detector table per class (`sqli`, `xss`, `path_traversal`, `rce`, `ssrf`,
`nosqli`, `log4shell`, `scanner`) with base severity; confidence = `1 − 0.45^indicators` capped at 0.97 (1 indicator =
0.55, 2 ≈ 0.80, 3 ≈ 0.91). The same module builds a **fingerprint** (FNV-1a over the attack's *shape* with literals
stripped) used for cross-IP correlation, and extracts "signature samples" used later to prove a rule is not a no-op.

### 3.5 The Campaign Tracker (`commander/campaign-tracker.ts`) — one global Durable Object

`IncidentCommander` sees one IP at a time, which is precisely the blind spot of a botnet (100 IPs × 1 request each never
trips a per-IP burst). Every classified event is reported here by fingerprint; when ≥3 distinct IPs share one
fingerprint within 10 minutes the campaign is `distributed`, a `campaign` feed event is broadcast, and the right
mitigation becomes "block the technique, not the address". It also owns two things *because it is a singleton and
therefore serialised*:
- the **published pattern-rule set** (one KV document, no lost updates), and
- the **WebSocket feed** (Hibernation API, so an idle dashboard costs nothing). It stores a replay buffer of
  `publish()`ed events (retention 100) served at `GET /commander/feed`. **Note:** `mitigation` and `campaign`
  broadcasts are *not* stored in that buffer (see §5.3 for how the dashboard compensates).

### 3.6 The Analyst (`src/analyst/`) — LLM diagnosis and rule synthesis

- Contract: `runAnalyst(env, brief: IncidentBrief) → MitigationPlan`. The Analyst **never deploys**; it only proposes.
  Deployment authority stays with the Commander. Any failure throws and the Commander falls back.
- Model: `@cf/meta/llama-3.3-70b-instruct-fp8-fast` via the `AI` binding. Tool use is an **application-managed JSON
  protocol over text generation** (not native function calling, not the Agents SDK). Tools: `inspect_incident`,
  `read_history`, `read_campaign` (these read only the supplied brief, not live storage) and `propose`.
- Budget: max 6 turns and an 8.5 s wall clock, safely under the Commander's 10 s timeout.
- Prompts treat all traffic as **untrusted evidence, never instructions** (prompt-injection posture). This narrows
  authority via a tool allowlist and schema checks; it is not a proof of injection resistance.
- Proposed regexes must pass a **conservative subset check** before even reaching the shared validator: flat literals,
  escaped punctuation, no groups/alternation/character classes/wildcards/backreferences; only `\s+`/`\s*` may repeat,
  at most twice, between literals. This kills ReDoS-shaped output by construction. Rejections are fed back to the
  model for revision.
- The fabricated CVE-lookup tool that existed earlier was **removed** (it advertised a capability that did not exist).
- Live model access and latency have **never been tested** (no Cloudflare login was available in dev). Local tests
  use a scripted mock model.

### 3.7 Fallback plan (`commander/fallback-plan.ts`) and `ANALYST_MODE`

If the Analyst errors, times out, or `ANALYST_MODE=fallback`, the Commander uses deterministic per-class signatures.
It emits a `pattern_rule` only when a signature exists **and** (confidence ≥ 0.7 **or** the campaign is distributed);
otherwise an IP block. `wrangler dev` with the `[ai]` binding but no `wrangler login` fails with "Not logged in", which
lands here, so the demo still works offline. Consequences you will hit:
- The SQLi signature is `union…select | or 1=1 | sleep()/pg_sleep()/benchmark() | information_schema | xp_cmdshell`.
  A payload the classifier flags but this signature does not match (e.g. `' OR '1'='1' -- `) is **correctly refused**
  by the validator as a no-op rule and downgraded to an IP block (`source: commander-fallback+downgraded`).
- `ANALYST_MODE` accepts `auto` (default) or `fallback`. (`types.ts` comments mention `ai`/`heuristic`, which the code
  does not implement; only `fallback` is special-cased in `analyst-client.ts`.)

### 3.8 The validation guardrail (`mitigation.ts: validateRule`) — the headline safety feature

An AI-written firewall rule is a liability unless checked. Before any pattern is published it must:
compile; not be a catch-all (`.*`, `[\s\S]+`, empty); not contain nested quantifiers (catastrophic backtracking:
otherwise an attacker could DoS *our* WAF); have `g`/`y` flags stripped (stateful `lastIndex`); **match at least one
payload from the incident** (else it is a no-op); and **match none of a 14-item benign corpus** (e.g. a comment
containing `--`, a search for "union jack flag", a query mentioning "SELECT your favourite plan"). On failure the
Commander records a `rule_rejected` audit row explaining why and **degrades to blocking the single IP**: reduced
coverage, never a self-inflicted outage. The corpus is small; growing it is the cheapest quality win available.

### 3.9 Mitigation storage, TTLs, ledger

- KV keys: `block_ip_<ip>` (JSON `EdgeBlock`, written with `expirationTtl` so it self-expires even if every DO is
  evicted) and `waf:patterns` (JSON array of `PatternRule`). TTL clamped to 60 s–24 h; suggested TTL by class
  (log4shell/rce 1 h, sqli/ssrf 30 min, path traversal 15 min, xss 10 min, scanner 5 min) × repeat multiplier.
- D1 (`INCIDENT_DB`, optional, every write **fail-soft**): tables `incidents`, `mitigations`, `audit_log`. Audit kinds:
  `incident_opened/closed`, `analysis_requested/returned`, `rule_deployed/rejected/revoked`, `campaign_detected`,
  `operator_pardon`, `queue_poison`, `event_ingested`. Rationale: "the AI proposed `.*` and we vetoed it" is only
  provable if written down. Run `npm run db:init` once locally to create the tables.
- **Propagation caveat:** `block_ip_*` is read uncached (instant), but pattern rules are read with a **60 s edge cache
  (`cacheTtl: 60`)** and KV is eventually consistent, so in production a fresh *pattern* rule may take up to a minute
  or more to bite. Local `wrangler dev` hides this. Verify on a deployed Worker before promising timings.

### 3.10 Operator API (`commander/api.ts`)

Everything under `/commander/*` is handled *before* the Shield (which therefore never sees it). Routes: `health`,
`state/<ip>`, `pardon/<ip>?minutes=`, `reset/<ip>`, `campaigns`, `rules`, `incidents`, `audit`, `stats`, `feed`,
`stream` (WebSocket), `simulate` (inject events; `?direct=1` bypasses the queue and returns the scoring result
synchronously, which is the best way to drive tests). CORS is `*`. If `COMMANDER_API_KEY` is set, routes require
`X-Commander-Key` (or `?key=`); unset means open (fine for local, **not** for deployment). **Gotcha:** path segments are
*not* percent-decoded, and DO names come from the raw segment, so IPv6 must be sent raw (`/commander/reset/::1`);
`%3A%3A1` silently addresses a different, empty object.

### 3.11 Data contracts to keep in sync

`apps/orchestrator/src/types.ts` is authoritative. The dashboard **duplicates** the needed subset in
`apps/dashboard/src/lib/types.ts` on purpose (importing would drag `@cloudflare/workers-types` into a browser
bundle). If `FeedEvent`, `IngestResult`, `DeployedMitigation`, `CampaignSummary` or `PatternRule` change, update both.
`FeedEvent` = `hello | ingest | campaign | mitigation`.

---

## 4. The dashboard (`apps/dashboard`) and why it looks/behaves this way

- **Stack:** Next.js 15 App Router, React 19, TypeScript strict. **No Tailwind**: a stated aesthetic requirement was a
  premium dark glassmorphism look in hand-written CSS Modules (`dashboard.module.css`; theme tokens in `globals.css`).
  Scaffolded by hand rather than `create-next-app` (no interactive prompts, no unwanted boilerplate); `npm run build`
  and `tsc --noEmit` are clean.
- **State:** one `useReducer` (`lib/state.ts`) is the whole model. Reducer is pure and idempotent: every feed event is
  de-duplicated by a deterministic id so the same event arriving via WebSocket *and* REST replay is counted once.
- **Three-source merge for mitigations.** A single mitigation reaches the browser up to three ways, each with different
  fields: a `mitigation` WebSocket event (pattern rules only; lacks attack class/reason), the `ingest` result that
  deployed it (carries `mitigation` and Commander `reasons`; the *only* way `block_ip` mitigations arrive), and
  `GET /commander/rules` (carries `attackClass` and the Analyst's `reason`). `upsertMitigation` merges by id into one
  card. `GET /commander/incidents` supplies the human-readable diagnosis when D1 is initialised.
- **Resilience:** WebSocket reconnect with exponential backoff (cap 5 s), 20 s `ping`/`pong` keepalive, and on every
  (re)connect it re-fetches `GET /commander/feed` + rules to backfill gaps. A page refresh does **not** blank the room.
  An offline banner explains how to start the orchestrator; the page reconnects by itself.
- **Live Log** follows the tail like a terminal unless the user scrolled up. **Stats:** Attacks detected (classified,
  accepted events), Incidents (distinct incident ids), Mitigations live (unexpired), Blocked at edge, Threat score
  (latest event's score + stage).
- **Red Team console + `/api/red-team`.** Extra to the original plan, added so the whole demo is runnable from the UI.
  Attacks are sent **from the Next.js server, not the browser** because the Shield's own `403` has no CORS headers: a
  browser `fetch` would throw an opaque "Failed to fetch", making "blocked at the edge" indistinguishable from
  "orchestrator is down". Actions: `benign`, `attack`, `burst` (3 sequential attacks), `reset` (calls
  `/commander/reset/<ip>` for each known IP; falls back to `::1`, `127.0.0.1`, `unknown`).
- **"Blocked at edge" counts only 403s the console itself observed.** The Shield does not publish an event when it
  blocks (adding one on the hot path was out of scope and would require touching Shield tests), so the WebSocket
  cannot supply that number. The stat's hint text says so.
- **Config:** `NEXT_PUBLIC_ORCHESTRATOR_URL` (default `http://localhost:8787`; used by browser and as server default),
  `ORCHESTRATOR_URL` (server-only override for `/api/red-team`). `NEXT_PUBLIC_*` is inlined at build: restart after changing.
- **Why the attack payload is `admin' OR 1=1 -- ` (not the plan's `' OR '1'='1`):** the plan's payload classifies as
  `unknown` (0.20) and never enters the pipeline. `admin' OR 1=1 -- ` still bypasses the login, trips two indicators
  (0.80 confidence) and matches the deterministic SQLi signature, so it yields a real regex rule even without AI.

---

## 4a. Demo-hardening changes (2026-09-19, review these)

A second pass turned the loop from a scripted walkthrough into a genuine adversarial demo and removed the
placeholder UI. All of it works with **no Cloudflare login** (the deterministic paths run when Workers AI is absent).

**Blue (defence):**
- **Rule synthesis from observed evidence** (`commander/fallback-plan.ts`). The deterministic path no longer just
  reaches for a fixed per-class signature; it *derives* a rule from the literal that actually tripped the detector,
  generalising only whitespace (`\s*`), digit runs (`\d+`) and word boundaries (`\b`). So a mutation the engine has
  never seen (`OR 2=2` after only ever seeing `OR 1=1`) is still caught. Every candidate still passes `validateRule`
  before deployment; the class signature is now the *fallback's* fallback, and an IP block the last resort.
- **Distributed-campaign enforcement** (`policy.ts`, `incident-commander.ts`). A distributed campaign is now itself an
  analysis trigger, and its plan enforces (`block`) even though each botnet address individually only reached
  `challenge` on its single request. Previously a botnet was detected and then waved through.
- **Real reasoning surfaced** (`types.ts: AnalystReport`/`AnalystStep`, `analyst-client.ts`, `analyst/index.ts`). Both
  the LLM tool loop and the deterministic synthesiser emit a step-by-step trace (inspect → synthesise → validate),
  carried on the `ingest` feed event. The dashboard renders this verbatim instead of a canned animation.
- **Shield reports its own blocks** (`shield.ts` emits an `edge_block` feed event via `ctx.waitUntil`, off the hot
  path). The dashboard's "Blocked at edge" count is now real, not console-observed. Grew the benign corpus 14 → 22.
- **Real reset** (`campaign-tracker.ts: resetAll`, wired into `/commander/reset`). Reset now also clears published
  rules, campaign state and the feed replay buffer, so a page reload after a reset no longer resurrects the last run.

**Red (attack):**
- **Autonomous attacker with an offline fallback** (`commander/red-agent.ts`). Mutates its payload against the
  defence's last verdict; falls back to a hand-written SQLite mutation ladder when Workers AI is unavailable (the old
  version threw a raw stack trace into the UI). Correct SQLite comment syntax; `#` payloads that 500 the origin are gone.
- **Botnet simulation** (`shield.ts` honours `x-demo-source-ip` only when `DEMO_ALLOW_SOURCE_SPOOF=true`; new
  `/api/red-team` `botnet` action). Lets one laptop simulate a distributed campaign.

**Dashboard truthfulness.** Removed the mock intercepted-payload, the fake "vector embeddings"/"99.4% block
rate"/"12ms" placeholders, and the typewriter. The Payload Analyzer now shows the real request, real classifier
confidence and indicators, and the real reasoning trace; the header shows the real last-analysis latency; the
analyzer follows the newest incident instead of freezing on the first, and clears on reset.

**Tests.** `commander/synthesizer.test.mjs` (8 tests) covers generalisation, benign-corpus safety, the campaign
trigger and the degrade-to-IP-block path. Suite is **57 pass** (was 49); both typechecks and the dashboard build clean.

**New config:** `apps/orchestrator/.dev.vars.example` (tracked) documents `DEMO_UPSTREAM` and the demo-only
`DEMO_ALLOW_SOURCE_SPOOF`. Copy it to `.dev.vars` before `npm run dev`.

---

## 5. Changes made to pre-existing orchestrator code (review these)

All three are small, in `6a87a05`, and were needed for the demo to be truthful:

1. `commander/fingerprint.ts` — `classify()` now scans `pathname + search` (`requestTarget()`), **not the host**.
   Previously the SSRF detector (`localhost:\d{2,5}`) matched the Worker's own host in local dev, so *every* request
   (including benign logins) was scored as SSRF and consumed a slot in the 3-request burst window. Loopback SSRF in the
   query string is still detected. Regression test added.
2. `commander/campaign-tracker.ts` — `webSocketClose` now maps reserved close codes **1005, 1006, 1015** to 1000.
   Closing/reloading a dashboard tab produced `Invalid WebSocket close code: 1006` (an uncaught error) each time.
3. `shield.test.mjs` — one added test for (1).

Nothing else in the Shield/Commander/Analyst was modified; `wrangler.toml` and `types.ts` are untouched.

---

## 6. Running, testing, configuring

Prereq: Node ≥ 20 (dev/verification on 22.23; the repo docs cite Node 24 for the test runner).

```bash
# 1) target
cd apps/target && npm install && npm start                       # :3001
# 2) orchestrator
cd apps/orchestrator && npm install && npm run db:init && npm run dev   # :8787  (db:init once)
# 3) dashboard
cd apps/dashboard && npm install && npm run dev                  # :3000
```

Tests (from `apps/orchestrator`): `node --import ./src/analyst/test-loader.mjs --test ./src/analyst/analyst.test.mjs ./src/shield.test.mjs`
→ **49 pass** (33 Analyst, 16 Shield/classifier). They mock KV, queue, upstream and the model; no network, no
Cloudflare credentials. `npm run typecheck` (orchestrator) and `npm run typecheck` / `npm run build` (dashboard) are clean.

Config: `apps/orchestrator/.dev.vars` (gitignored) sets `DEMO_UPSTREAM="http://localhost:3001"` and can set
`ANALYST_MODE="fallback"`. `wrangler.toml [vars]`: `BURST_THRESHOLD=3`, `BURST_WINDOW_MS=60000`,
`SCORE_HALF_LIFE_MS=600000`, `INCIDENT_IDLE_TIMEOUT_MS=120000`, `CAMPAIGN_MIN_IPS=3`, `ANALYST_MODE=auto`. Wrangler
merges `.dev.vars` over `[vars]`. Resource ids in `wrangler.toml` are placeholders (`<YOUR_KV_NAMESPACE_ID>`,
`<YOUR_D1_DATABASE_ID>`); local dev simulates KV/Queues/DOs/D1. **The `[ai]` binding is remote-only:** it needs
`wrangler login` and incurs Cloudflare charges even in local dev. Vectorize is commented out (no local emulation).

Demo script: **Benign login** (401 from origin) → **Burst ×3** (origin breached ×3; ~2 s later a rule card appears) →
**SQLi attack** (`403` at the edge) → **Reset demo**. Full-state reset: stop the orchestrator, delete
`apps/orchestrator/.wrangler`, `npm run db:init`, restart.

### Verification performed (2026-09-19)
Full stack driven by headless Chromium (Playwright): idle → benign → burst → rule card with validation trail → blocked →
page reload (hydration) → reset → traffic flows; orchestrator killed and restarted (banner, auto-reconnect); 3-IP
distributed campaign via `/commander/simulate?direct=1` (campaign row + stat); 390 px and 820 px widths (no horizontal
scroll); zero browser console errors and zero orchestrator errors in the final runs.

---

## 7. Local-demo behaviours that will surprise you

- **Everything is one IP.** Locally the caller is `::1` (IPv6 loopback; sometimes `127.0.0.1` or `unknown`). Once the
  Commander blocks it, *benign traffic is blocked too* until **Reset demo**. This is a demo artefact, not a bug.
- **One attack is not enough.** The first two attack events are only scored (the score can already reach `block`, but
  analysis is triggered by the burst rule); the *third* opens the incident and deploys the mitigation.
- Analysis appears ~2 s after the burst (queue batch timeout).
- Without a Cloudflare login the log shows `analyst … via commander-fallback (degraded: Error: Not logged in.)`.

---

## 8. Known limitations and open work (prioritised suggestions)

1. **Deploy and verify on real Cloudflare.** Create KV, D1 (apply migration remotely), both queues incl.
   `suspicious-traffic-dlq`; set `DEMO_UPSTREAM` to a *publicly reachable* origin (a laptop `localhost` is unreachable
   from a deployed Worker); set `COMMANDER_API_KEY`. Re-measure rule propagation (see §3.9).
2. **Exercise live Workers AI end to end.** Confirm `source: workers-ai` (no degraded reason), check the 6-turn/8.5 s
   budget against real latency, and confirm the Shield enforces the AI's pattern while a benign same-IP request passes.
3. **Emit a `block` feed event from the Shield** (via `ctx.waitUntil`, off the hot path) so the dashboard can show true
   edge-block counts instead of console-observed ones. Requires updating `shield.test.mjs` mocks.
4. **Surface the Analyst trace in the feed** (`investigate()` already returns a trace; `runAnalyst()` drops it). A
   "watch the AI think" panel is likely the strongest demo upgrade.
5. **Enforce `challenge` / `rate_limit` / `log` at the edge.** Today the Commander can stage an IP as `challenge` but
   the Shield only acts on `block`; the Analyst deliberately emits only `block`/`log`.
6. **Reduce IP-block collateral.** Behind NAT or a shared proxy, "also block the IP at stage block" can block innocent
   users. Options: block only on distributed/persistent evidence, shorter TTLs, or prefer pattern rules.
7. **Grow the benign corpus** and add property/fuzz tests for `validateRule`; it is the safety net under the AI.
8. **Harden the target:** bind to `127.0.0.1`; it is deliberately insecure.
9. **Dashboard:** it does not send `COMMANDER_API_KEY`; add support if you enable the key. Only `/login` is used by the
   console; add XSS/path-traversal buttons to show multi-class detection. Commit `apps/dashboard/package-lock.json`.
10. **Docs drift:** `wrangler.toml` comments, `types.ts` (`ANALYST_MODE` values) and `SHIELD_TESTING.md` mention Node 24 /
    `heuristic`/`ai` modes that do not match the code; reconcile when convenient.

---

## 9. Glossary

**Zero-day** vulnerability with no available patch. **WAF** web application firewall. **Shield / Commander / Analyst**
the three stages of the engine (Member 1/2/3). **Incident** a burst/escalation the Commander decided merits analysis.
**Campaign** one attack fingerprint seen from ≥3 IPs. **Fingerprint** hash of an attack's shape with literals removed.
**Mitigation** an IP block or pattern rule deployed to the edge. **Pardon/Reset** operator overrides. **Stage**
`observe → monitor → challenge → block`. **Durable Object (DO)** single-threaded stateful Cloudflare object.
**Hibernation API** lets a DO keep WebSockets open while evicted from memory. **DLQ** dead-letter queue.

## 10. Where to start (checklist for a new contributor or agent)

1. Read §1–§3, then `apps/orchestrator/src/types.ts` (the contract) and `src/commander/incident-commander.ts`
   (`ingestInner` and `runIncident` are the heart of the system).
2. Run the three services and click through the demo (§6); read the log lines the Commander prints.
3. Run the 49 tests and `npm run typecheck` in `apps/orchestrator`.
4. Pick from §8. Items 2 and 4 have the highest demo value; item 1 is required before any real deployment.
5. When touching `types.ts` or feed shapes, update `apps/dashboard/src/lib/types.ts` in the same change.
