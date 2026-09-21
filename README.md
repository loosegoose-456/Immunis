# Red vs. Blue: a security system that patches itself

**In one sentence:** this project is a demonstration of a website defence that notices an attack, works out how to
stop it, and switches that protection on within seconds, with no human doing anything.

You do not need to be a programmer to understand it, and this page is written for that reader. If you *are* a
developer who wants to contribute, jump to [For developers](#for-developers) at the bottom.

---

## Contents

1. [The problem in plain English](#1-the-problem-in-plain-english)
2. [The idea: an immune system for a website](#2-the-idea-an-immune-system-for-a-website)
3. [Meet the cast](#3-meet-the-cast)
4. [What happens during the demo, step by step](#4-what-happens-during-the-demo-step-by-step)
5. [How to run it on your computer](#5-how-to-run-it-on-your-computer)
6. [How to read the dashboard](#6-how-to-read-the-dashboard)
7. [Stopping everything](#7-stopping-everything)
8. [Troubleshooting](#8-troubleshooting)
9. [What this project aims for (and what it does not claim)](#9-what-this-project-aims-for-and-what-it-does-not-claim)
10. [Questions people ask](#10-questions-people-ask)
11. [Glossary](#11-glossary)
12. [For developers](#for-developers)

---

## 1. The problem in plain English

Every website is built from software, and software has mistakes in it. Some mistakes are *security* mistakes: a
hidden door that lets an attacker do something they should not, like logging in as an administrator without a password.

When the website's owner does not yet know about a mistake, it is called a **zero-day**: the owners have had *zero
days* to fix it. Attackers who find one can use it immediately. Fixing it properly means a developer must understand
the flaw, change the code, test it and release it. That takes **hours or days**, and during that time the door is open.

The example used in this project is a classic one, called **SQL injection**. A login page asks for a username and
password and then asks its database a question, roughly:

> "Is there a user called *(what the visitor typed)* with the password *(what the visitor typed)*?"

If the page pastes the visitor's words straight into that question without checking them, a cunning visitor can type
something that *changes the question itself*. For example, typing `admin' OR 1=1 --` turns it into:

> "Is there a user called *admin*, **or is 1 equal to 1** (always true)? *(ignore the rest)*"

The answer is always "yes", and the attacker is let in as the administrator. No password needed.

## 2. The idea: an immune system for a website

Your body does not wait for a doctor to design a cure before reacting to a new germ. Your immune system notices
something that does not belong, works out what it looks like, and produces defences within days, without asking
you. It also has to be careful not to attack your own healthy cells.

This project tries the same thing for a website:

1. **Notice** suspicious visitors.
2. **Remember** what each one has been doing and decide when it has become a real attack.
3. **Diagnose** the attack, with an AI helping, and write a defensive rule.
4. **Check the rule is safe** so it does not block honest customers.
5. **Deploy** the rule instantly, in front of the website.
6. **Show a human everything** on a live screen, so nothing happens in the dark.

The important trick: **the vulnerable website is never modified.** The protection sits *in front of it*, like a
security guard standing at the door of a building with a broken lock. You do not have to fix the lock first.

## 3. Meet the cast

The project has six parts. Think of a shop with a faulty back door.

| Part | What it is | Everyday analogy |
|---|---|---|
| **The Target** | A small fake website with a login page that is *deliberately* vulnerable. | The shop with the faulty lock. |
| **The Shield** | A checkpoint that every visitor passes through *before* reaching the target. It waves honest visitors through, refuses known attackers, and quietly reports anyone suspicious. | The bouncer at the door. |
| **The Commander** | A record-keeper that keeps a file on every visitor who looked suspicious, gives them a "threat score" that fades over time if they behave, and decides when a pattern of behaviour has become an attack. | The security chief with a notebook. |
| **The Analyst** | An AI that is called in only when the Commander declares an attack. It studies what happened and proposes a rule, such as "block any request containing this attack pattern". If the AI is unavailable, a simpler built-in fallback with pre-written patterns takes over. | The detective who writes the "wanted" poster. |
| **The Safety Check** | Built into the Commander. Before *any* rule goes live it is tested: does it catch the real attack, and does it wrongly catch normal, honest traffic? If it fails, the rule is refused and the Commander falls back to a cautious option (blocking just that one visitor). | A lawyer who reads the poster before it goes up, so no innocent person's photo is on it. |
| **The War Room** | A live web page showing all of the above as it happens, with buttons to fire test attacks yourself. | The security monitor wall. |

### How they connect

```
   Visitor (or you, clicking a button)
        │
        ▼
   ┌──────────┐   honest traffic     ┌──────────────┐
   │  SHIELD  │ ───────────────────► │    TARGET    │   (the vulnerable shop)
   │ (bouncer)│                      └──────────────┘
   └──────────┘
        │ "this looks suspicious": a copy goes to ...
        ▼
   ┌──────────────┐  attack confirmed  ┌──────────┐   proposes a rule   ┌───────────────┐
   │  COMMANDER   │ ─────────────────► │ ANALYST  │ ──────────────────► │  SAFETY CHECK │
   │ (notebook)   │                    │  (AI)    │                     │ (is it safe?) │
   └──────────────┘                    └──────────┘                     └───────┬───────┘
        │                                                                       │ safe: switch it on
        │ everything is broadcast live                                          ▼
        ▼                                                          the SHIELD now blocks the attack
   ┌──────────────┐
   │   WAR ROOM   │   (the dashboard you look at)
   └──────────────┘
```

## 4. What happens during the demo, step by step

The dashboard has a **Red Team Console** (top of the screen). "Red team" is security-speak for the people playing
the attacker, and "blue team" for the defenders. The centre panel — the **Payload Analyzer** — shows the real
intercepted request and the Blue Team's real reasoning as it decides what to do. Here is the story you will act out:

1. **Click "Benign login".** This pretends to be an ordinary customer typing a wrong password. The Target says "wrong
   password" (a `401`). The Shield lets it through, and nothing suspicious is recorded. *This proves the defence does
   not bother honest people.*
2. **Click "Burst ×3".** This sends the SQL-injection attack **three times**. Nothing is defending yet, so all three
   **succeed**: the Target hands over the administrator's access token. In the console you see red "200 BREACHED"
   lines. *This is the moment that shows the flaw is real.*
3. **Wait two or three seconds.** Behind the scenes, the Shield has been reporting each attack. On the third, the
   Commander decides "this is an attack" and calls the Analyst. Watch the **Blue Team reasoning** panel: it reads the
   evidence, *synthesises a rule from the payload it actually saw*, checks that rule against the real attack and
   against a corpus of honest traffic, and only then deploys it. A card appears in **Active Mitigations** with the new
   rule and a countdown.
4. **Click "SQLi attack" once more.** This time the Shield answers instantly with a **`403 Forbidden`**. The Target
   never even sees the request. The "Blocked at edge" counter goes up. *That is the whole point: the system defended
   itself, with no human, and the website's code never changed.*
5. **Click "Reset demo"** to wipe the slate so you can run it again.

Two extra demos on the same console:

- **"Botnet ×4"** sprays the *same* exploit from four different addresses, one request each. No single address looks
  busy enough to act on, so this is the blind spot of per-address defence. A separate component notices the same
  attack *shape* on several addresses at once, raises a **distributed campaign**, and blocks the *technique* rather
  than any one address — so a fifth, never-before-seen attacker is stopped on its first try, while honest traffic
  from that same address still passes.
- **"Unleash AI"** turns the attacker itself into an autonomous agent that *mutates* its payload in response to what
  the defence did to its last attempt, round after round. Watch the two AIs fight: Red changes its exploit, Blue
  adapts its rule. (Both AIs fall back to built-in behaviour when there is no Cloudflare login, so this works offline.)

> **Why three attacks, not one?** The Commander is deliberately cautious. One odd request could be a mistake or a
> coincidence, so it waits for a *pattern* (three suspicious requests within a minute) before taking action.
> Blocking on the first hint would risk locking out innocent people.
>
> **Why is my benign login blocked after the attack?** On a single computer, the "attacker" and the "honest
> customer" are the same machine (same address), so once the attacker's address is blocked, honest requests from it
> are too. In real life they would be different people. Click **Reset demo** to clear it.

## 5. How to run it on your computer

This runs entirely on your own machine. You do **not** need a Cloudflare account, an API key, or a server.
(The instructions below are for a Mac. Windows and Linux notes are at the end of this section.)

### 5.1 One-time setup

**a) Install Node.js.** This is the engine that runs the project's software.

- Go to <https://nodejs.org>, download the **LTS** version and install it like any other app. (If you use Homebrew,
  `brew install node` also works.)
- Check it worked: open the **Terminal** app (press `Command + Space`, type `Terminal`, press Enter) and type:
  ```
  node -v
  ```
  You should see a version number like `v22.x.x`. Version **20 or newer** is needed.

**b) Get the project.** If you have not already:
```
git clone https://github.com/ayeshkadike/htn.git
cd htn
```

### 5.2 Start the three programs

The project is three programs that talk to each other, so you need **three Terminal windows or tabs** open at once
(in VS Code, use the **+** button in its Terminal panel; in the Mac Terminal, press `Command + T` for a new tab).
Each one must **stay open and running**. Think of each as a machine that has to stay switched on.

In each window, first move into the project folder (`cd` means "change directory"). Adjust the path to wherever you
put the project.

**Window 1: the vulnerable Target** (runs at port 3001)
```
cd apps/target
npm install        # first time only: downloads what it needs
npm start
```
You should see: `[Origin] Vulnerable target running on http://localhost:3001`

**Window 2: the Shield + Commander + Analyst** (runs at port 8787)
```
cd apps/orchestrator
npm install                 # first time only
cp .dev.vars.example .dev.vars   # first time only: local config (which origin to protect)
npm run db:init             # first time only: creates the local incident notebook
npm run dev
```
Wait until you see `Ready on http://localhost:8787`. If you skip the `.dev.vars` copy, every
request comes back as `503` because the Shield has no origin to forward to.

**Window 3: the War Room dashboard** (runs at port 3000)
```
cd apps/dashboard
npm install        # first time only
npm run dev
```
You should see `Ready` and `http://localhost:3000`.

### 5.3 Open the dashboard

Open your web browser and go to **<http://localhost:3000>**.

In the top right there should be a green **LIVE** badge. That means the dashboard is connected to the Commander. You
are ready to play the demo from [section 4](#4-what-happens-during-the-demo-step-by-step).

> **The order does not matter much.** If you open the dashboard before the orchestrator is running, it shows an amber
> "can't reach the orchestrator" message and connects by itself the moment the orchestrator starts.

### 5.4 About the AI (optional)

The Analyst can use a real AI model hosted by Cloudflare. That needs a free Cloudflare login and can incur small
usage charges. **You do not need it.** Without it, the project automatically uses its built-in fallback rules, and the
demo works the same way on screen. You will see *"degraded: Not logged in"* in the reasoning shown on the mitigation card, which is
expected and harmless.

If you would rather skip the AI attempt entirely, open `apps/orchestrator/.dev.vars`, remove the `#` at the start of
the `ANALYST_MODE="fallback"` line and restart Window 2.

### 5.5 Windows and Linux

- **Windows:** install Node.js from nodejs.org, then use *PowerShell* or *Windows Terminal* in place of Terminal. The
  `npm` commands are identical. Use `Ctrl + C` to stop things. The `lsof` commands in sections 7 and 8 are Mac/Linux
  only; on Windows, find what is using a port with `netstat -ano | findstr :3000` and stop it with `taskkill /PID <number> /F`.
- **Linux:** install Node.js with your package manager or from nodejs.org; the commands are identical.

## 6. How to read the dashboard

**Header.** The pill at the top right says **LIVE** (green, connected), **CONNECTING** (amber) or **OFFLINE** (red).

**The five number cards**

| Card | What it counts |
|---|---|
| **Attacks detected** | Requests the system recognised as hostile and reported to the Commander. |
| **Incidents** | Times the Commander decided a pattern of behaviour was serious enough to investigate. |
| **Mitigations live** | Defences currently switched on and not yet expired. |
| **Blocked at edge** | Requests the Shield refused, **as observed by the Red Team Console**. (The Shield does not currently announce its refusals to the dashboard, so this counts only the ones you triggered from the console's buttons.) |
| **Threat score** | How dangerous the latest visitor looks. It climbs with each attack and fades slowly if they stop. The coloured tag shows the response level: *observe → monitor → challenge → block*. |

**Live Log (left).** A scrolling record, like a hacker-movie terminal. Each attack line shows the visitor's address,
the type of attack (e.g. **SQLI**), how confident the system is, the threat score, and the response level. The
**ANALYST ENGAGED** tag marks the moment the AI (or fallback) was called in. Green lines are defences being deployed
or blocking an attack; red lines are attacks that got through.

**Red Team Console (top right).** Your three attack buttons and **Reset demo**, plus the last few results:
`401 REJECTED` (normal), `200 BREACHED` (the attack worked), `403 BLOCKED` (the defence worked).

**Mitigation Feed (bottom right).** One card per defence deployed. It shows the type of attack it targets, whether it
is a **WAF pattern rule** (a rule that recognises an attack's shape) or an **IP block** (refuse this visitor), the
rule itself, a countdown until it expires (defences are temporary on purpose), and the Commander's reasoning,
including the Safety Check result such as *"clean against 14 benign samples"*.

## 7. Stopping everything

In each Terminal window, press **`Control + C`**. On a Mac, that is the **`control`** key, *not* `command`
(`Command + C` is "copy" and does nothing here). Closing the window also works. To confirm everything has stopped, in
any Terminal run:
```
lsof -i tcp:3000 -i tcp:3001 -i tcp:8787
```
No output means everything is off.

## 8. Troubleshooting

| What you see | What it means and what to do |
|---|---|
| `command not found: node` or `npm` | Node.js is not installed (or Terminal needs restarting after installing). See 5.1. |
| **OFFLINE** / amber "can't reach the orchestrator" | Window 2 is not running or has crashed. Start it (`npm run dev` in `apps/orchestrator`). The page reconnects by itself. |
| `port 3000 / 3001 / 8787 is already in use` | An old copy is still running. Run `lsof -ti tcp:3000 \| xargs kill` (change the number to match), and `pkill -f workerd`. |
| Everything is blocked, even "Benign login" | The single-computer effect described in section 4. Click **Reset demo**. |
| `npm install` fails in `apps/target` mentioning `sqlite3` or `gyp` | That package sometimes needs Apple's developer tools. Run `xcode-select --install`, then try again. |
| The mitigation card shows **IP block** instead of a regex rule | Normal in some cases; the Safety Check refuses rules that would not actually catch the attack and falls back to blocking the address. |
| You want a completely clean slate | Stop Window 2, delete the folder `apps/orchestrator/.wrangler`, run `npm run db:init` again, then start it again. |

## 9. What this project aims for (and what it does not claim)

**The goal.** To show, convincingly and live, that a vulnerability can be contained **automatically and quickly** by
a layer sitting in front of an application, buying the human developers time to make a real fix. A good demonstration
has these properties, and this one is built to show all of them:

- Honest traffic is **never disturbed**.
- The flaw is **real and visible**: you watch the attack succeed against the unprotected site first.
- The defence appears **without human input**, within seconds.
- The same attack is then **stopped at the door**, before it reaches the website.
- Everything is **transparent**: nothing happens off-screen, and every decision is explained.
- The AI is **kept on a leash**: it can only *propose*. Independent code checks every proposal, and unsafe ones are
  refused (this is what the Safety Check does).

**What it honestly is not.**

- It is a **hackathon demonstration**, not a finished commercial security product. It is not a substitute for actually
  fixing the vulnerability.
- It has been run **on one computer**. It has not yet been deployed to Cloudflare's global network, so real-world
  speed and timing there are still unmeasured.
- The **live AI model has not yet been tested end to end** (the built-in fallback has). The AI's tools and safeguards
  are built and unit-tested, but not proven against the real model.
- It currently recognises **SQL injection and several other common attack families** by pattern (cross-site
  scripting, path traversal, command injection and so on). It is not a general "detect anything" system.
- Some responses (such as "challenge this visitor with a puzzle") are planned but **not yet enforced**; today the
  Shield's only enforcement action is to block.
- The target website is **intentionally insecure**. Only run it on your own computer, on a trusted network.

## 10. Questions people ask

**Is the attack real? Could it harm my computer?** The attack is real *against the fake shop* that is part of this
project: the login page truly is vulnerable, and it is only a small in-memory demo database with one fake account that
disappears when you stop the program. It does not touch your files, and you are not attacking anything belonging to
anyone else. Just do not put the Target on a public network.

**Why does the defence take a couple of seconds and not happen instantly?** The Shield reports suspicious requests into
a queue and gets on with its job (so it never slows honest visitors down). The Commander picks reports up in small
batches, roughly every two seconds.

**Why does a defence expire?** On purpose. A block that lasts forever risks punishing someone who later behaves
(or whose network address now belongs to someone else). Threat scores also fade over time, so the system forgives.

**What stops the AI from writing a dangerous rule, like "block everything"?** Two layers. First, the AI is only allowed
to write very simple, restricted patterns. Second, the Commander runs every proposed rule through the Safety Check:
it must match the real attack and must *not* match a set of normal, harmless requests. A "block everything" rule fails
immediately and is refused, and the refusal is recorded.

**What if lots of different computers attack at once?** The Commander normally tracks visitors one by one. A separate
component looks for the *same attack shape* appearing from many different addresses (a "distributed campaign") and
raises a **campaign** alert, because at that point blocking addresses is pointless and blocking the technique is right.

**Where do I look if I want to change something?** See the next section.

## 11. Glossary

| Term | Meaning |
|---|---|
| **Zero-day** | A security flaw the owner has not had any time to fix. |
| **SQL injection** | Typing database commands into a form so the site's own database obeys the attacker. |
| **Edge** | The front door of a network: the place traffic is checked before it reaches the real website. |
| **WAF** | *Web Application Firewall*: software that filters web traffic using rules. |
| **Rule / pattern** | A description of what an attack looks like, used to spot and refuse it. |
| **Regex** | *Regular expression*: a compact way to describe a text pattern. The rules here are regexes. |
| **Mitigation** | Any defensive action taken: a pattern rule or an address block. |
| **Incident** | A cluster of suspicious behaviour the Commander decided is worth investigating. |
| **Campaign** | The same attack shape seen from several different addresses at once. |
| **IP address** | The numeric address of a computer on a network; locally it appears as `::1` (your own machine). |
| **TTL** | *Time to live*: how long a defence stays switched on before it expires. |
| **Red team / blue team** | Attackers / defenders in a security exercise. |
| **Queue** | A waiting line for messages, so one part can hand work to another without waiting for it. |

---

## For developers

The full engineering brief covers the architecture, every design decision and why it was made, what has been verified
and what has not, known pitfalls, and a prioritised to-do list:

**→ [`docs/PROJECT_BRIEF.md`](docs/PROJECT_BRIEF.md)**

**Quick reference**

```
apps/target        Express + SQLite, deliberately vulnerable            :3001
apps/orchestrator  Cloudflare Worker: Shield + Commander + Analyst      :8787   (wrangler dev)
apps/dashboard     Next.js 15 War Room (hand-written CSS, no Tailwind) :3000
```

| Task | Command (from the app's folder) |
|---|---|
| Run the target | `cd apps/target && npm start` |
| Run the orchestrator | `cd apps/orchestrator && npm run dev` (once: `npm run db:init`) |
| Run the dashboard | `cd apps/dashboard && npm run dev` |
| Orchestrator tests (49) | `cd apps/orchestrator && node --import ./src/analyst/test-loader.mjs --test ./src/analyst/analyst.test.mjs ./src/shield.test.mjs` |
| Typecheck | `npm run typecheck` in `apps/orchestrator` or `apps/dashboard` |
| Dashboard production build | `cd apps/dashboard && npm run build` |

Local configuration lives in `apps/orchestrator/.dev.vars` (git-ignored; sets `DEMO_UPSTREAM` to the target).

**Who built which piece.** The code is annotated by owner: *Member 1* built the Shield, *Member 2* the Commander,
*Member 3* the Analyst. The shared data contract between them is `apps/orchestrator/src/types.ts`; change it only by
agreement.

**Built on:** Cloudflare Workers, Durable Objects, KV, Queues, D1 and Workers AI (Llama 3.3 70B); Express and SQLite
for the target; Next.js 15 and React 19 for the dashboard.

Released under the MIT License (see `LICENSE`).
