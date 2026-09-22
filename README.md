# Immunis

*Red vs. Blue: a website that grows its own antibodies.*

We built this at Hack the North around one question: when someone finds a hole in your site that you don't know about
yet, how long does it stay open? Usually the answer is hours or days, because a person has to understand the bug,
write a fix, test it and ship it. Immunis tries to shrink that window to a few seconds by putting a smart layer *in
front of* the vulnerable app, so the app itself never has to change.

It's a hackathon project, not a product. It works end to end on a laptop, and we're upfront below about what we
haven't proven.

## The idea

Your immune system doesn't wait for a doctor to design a cure. It notices something that doesn't belong, works out
what it looks like, and builds a defence, while trying not to attack your own healthy cells. We wanted the same loop
for a web app:

1. **Notice** suspicious requests as they arrive.
2. **Remember** who's been doing what, and decide when a pattern is a real attack rather than a fluke.
3. **Diagnose** it. An AI reads the evidence and proposes a blocking rule.
4. **Check the rule** before it goes live. It has to catch the attack and must *not* catch normal traffic.
5. **Deploy** it in front of the app, instantly.
6. **Show everything** on a live dashboard, so nothing happens off-screen.

The example vulnerability is a classic SQL injection on a login form. Type `admin' OR 1=1 --` as the username and the
database is tricked into treating the login as valid. No password needed.

## The pieces

| Piece | What it does |
|---|---|
| **Target** (`apps/target`) | A tiny Express + SQLite site with a login that is *deliberately* vulnerable. Run it only on your own machine. |
| **Shield** | The checkpoint every request passes through before it reaches the Target. Honest traffic goes through, blocked attackers get a `403`, and anything suspicious is quietly reported. |
| **Commander** | Keeps a file on each suspicious visitor with a threat score that fades over time. It waits for a pattern (three suspicious requests inside a minute) before acting, because blocking on the first odd request would lock out innocent people. |
| **Analyst** | An LLM (Llama 3.3 on Cloudflare Workers AI) that's only called once the Commander declares an incident. It *proposes* a rule. If the model isn't available, a deterministic fallback with pre-written patterns takes over. |
| **Safety check** | Lives in the Commander. Every proposed rule is tested against the real attack and against a set of harmless requests. A "block everything" rule fails immediately and is refused, and the refusal is logged. |
| **War Room** (`apps/dashboard`) | The live Next.js dashboard, with buttons for firing test attacks. |

The Shield, Commander and Analyst all live in one Cloudflare Worker (`apps/orchestrator`).

```
 visitor ──► SHIELD ──── honest traffic ────► TARGET (vulnerable app)
               │
               │ suspicious: copy goes to a queue
               ▼
           COMMANDER ── attack confirmed ──► ANALYST ──► SAFETY CHECK
               │                                             │ safe
               │ broadcasts live                             ▼
               ▼                                   Shield now blocks it
           WAR ROOM
```

## Running it

Everything runs locally. You don't need a Cloudflare account or an API key.

**You'll need** Node.js and npm. Next 15 wants Node 18.18 or newer; 20+ is the safer bet.

There are three programs, so open three terminals. Leave each one running.

**1. Target** (port 3001)

```powershell
cd apps/target
npm install
npm start
```

You should see `[Origin] Vulnerable target running on http://localhost:3001`.

**2. Orchestrator: Shield + Commander + Analyst** (port 8787)

```powershell
cd apps/orchestrator
npm install
Copy-Item .dev.vars.example .dev.vars    # macOS/Linux: cp .dev.vars.example .dev.vars
npm run db:init
npm run dev
```

Wait for `Ready on http://localhost:8787`. Skip the `.dev.vars` step and every request comes back `503`, because the
Shield doesn't know where to forward traffic. The `install`, `.dev.vars` and `db:init` steps are first-run only.

**3. Dashboard** (port 3000)

```powershell
cd apps/dashboard
npm install
npm run dev
```

Then open <http://localhost:3000>. A green **LIVE** badge in the top right means it's talking to the orchestrator. Start
order doesn't matter much: if the dashboard comes up first it shows an amber warning and connects by itself once the
orchestrator is running.

**About the AI.** Without a Cloudflare login, the Analyst just falls back to its built-in rules, and you'll see
"degraded: Not logged in" in the reasoning on the mitigation card. That's expected. To skip the attempt entirely,
uncomment `ANALYST_MODE="fallback"` in `apps/orchestrator/.dev.vars` and restart the orchestrator.

## The demo

Use the Red Team Console at the top of the dashboard. (There's also a talk-track for presenting this in
[DEMO_WALKTHROUGH.md](DEMO_WALKTHROUGH.md).)

1. **Benign login**: a wrong password. The Target says `401`, the Shield stays quiet. Honest users aren't bothered.
2. **Burst ×3**: the SQL injection three times. Nothing is defending yet, so you'll see red `200 BREACHED` lines. The flaw is real.
3. **Wait a couple of seconds.** The Commander sees the pattern, calls the Analyst, and the Blue Team reasoning panel
   walks through its thinking: the rule it wrote from the payload it actually saw, and the safety check results. A
   card appears under Active Mitigations with a countdown.
4. **SQLi attack** again: instant `403 BLOCKED`. The Target never sees it.
5. **Reset demo** clears everything so you can go again.

Two extras:

- **Botnet ×4** sends the same exploit from four "different" addresses, one request each. No single address looks busy
  enough to act on, but the campaign tracker notices the same attack *shape* everywhere and blocks the technique
  instead of any one address. A fifth, brand-new attacker is stopped on the first try.
- **Unleash AI** turns the attacker into an agent that mutates its payload after each block, while the defence writes
  new rules in response. Both sides have offline fallbacks, so it runs without a Cloudflare login.

Two things that look like bugs but aren't. Blocks expire on purpose, so nobody is punished forever. And after the
attack your own "benign" login may get blocked too, because on one machine the attacker and the honest customer share
an IP. Hit **Reset demo**.

## When something goes wrong

- **Port already in use (3000, 3001 or 8787):** an old copy is still running. On Windows, `netstat -ano | findstr :3000`
  finds the process ID, and `taskkill /PID <id> /F` stops it. If workerd is left over, kill it too.
- **Dashboard says it can't reach the orchestrator:** window 2 isn't running or crashed. Start it again.
- **Everything returns 503:** you skipped `.dev.vars`.
- **Everything's blocked, even the benign login:** see above, then **Reset demo**.
- **`npm install` fails in `apps/target` on `sqlite3`:** that package compiles native code on some setups. On Windows
  you may need the Visual Studio Build Tools, or try a Node LTS version that has a prebuilt binary.
- **Want a fully clean slate:** stop the orchestrator, delete `apps/orchestrator/.wrangler`, run `npm run db:init`,
  and start it again.

## What this is and isn't

The goal was a convincing live demo of one loop: an attack succeeds, the system responds without a human, and the
same attack is stopped at the door. Honest traffic is never touched, every decision is visible, and the AI is on a
leash. It can only *propose* rules, and independent code decides whether they go live.

What we haven't done:

- It hasn't been deployed to Cloudflare's network, so real-world latency is unmeasured.
- The live LLM path hasn't been tested end to end. The fallback has. The AI's tools and safeguards are unit-tested.
- Detection is pattern-based: SQL injection plus a handful of other common families (XSS, path traversal, command
  injection). It's not a general detect-anything system.
- The Shield's only enforcement action today is blocking. "Challenge this visitor" is planned, not built.
- It isn't a substitute for actually fixing the vulnerability. It buys the developers time to do that.

## For developers

The full engineering write-up is in [docs/PROJECT_BRIEF.md](docs/PROJECT_BRIEF.md): architecture, design decisions,
what's verified, known pitfalls and a to-do list.

| Task | Command |
|---|---|
| Orchestrator tests | `cd apps/orchestrator && node --import ./src/analyst/test-loader.mjs --test ./src/analyst/analyst.test.mjs ./src/shield.test.mjs` |
| Typecheck | `npm run typecheck` in `apps/orchestrator` or `apps/dashboard` |
| Dashboard production build | `cd apps/dashboard && npm run build` |

The shared data contract between the pieces is `apps/orchestrator/src/types.ts`, so change it deliberately. Local
config lives in `apps/orchestrator/.dev.vars` (git-ignored).

Built with Cloudflare Workers, Durable Objects, KV, Queues, D1 and Workers AI; Express and SQLite for the target;
Next.js 15 and React 19 for the dashboard. MIT licensed, see [LICENSE](LICENSE).
