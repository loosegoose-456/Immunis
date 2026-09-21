# 🎭 Red vs. Blue: The Live Demo Script

This is your foolproof, step-by-step script for presenting to the judges. It is designed to fit within a 3-minute pitch while maximizing the "wow" factor by showing two autonomous AI agents battling in real-time.

---

### Step 0: The Setup (Before Judges Arrive)
Ensure your environment is running smoothly:
1. **Target**: `cd apps/target && npm start` (Running on 3001)
2. **Orchestrator**: `cd apps/orchestrator && npm run dev` (Running on 8787)
3. **Dashboard**: `cd apps/dashboard && npm run dev` (Running on 3000)
4. Open the War Room Dashboard in your browser (`http://localhost:3000`).
5. Open the Red Team Simulator menu and click **Reset Demo** to clear the database and memory.

---

### Step 1: The Hook (0:00 - 0:30)
*Introduce the problem: WAFs are static and attackers are dynamic.*

**🗣️ What you say:**
> "Traditional Web Application Firewalls rely on static, manually written regex rules. But modern attackers are constantly evolving. If an attacker discovers a crack, a static WAF can't adapt in real-time. We built an autonomous Blue Team AI that monitors traffic, detects zero-days, and synthesizes its own WAF rules on the fly."

**🖱️ What you do:**
- Point to the live feed in the dashboard.
- Show how the traffic flows (Target Origin on the right, Cloudflare Edge on the left).

---

### Step 2: The Baseline (0:30 - 1:00)
*Show normal traffic vs. a standard attack.*

**🗣️ What you say:**
> "Here is our Red Team Simulator. Let's send some normal login traffic."
**🖱️ What you do:** Click **Benign Login**. 
*(The feed shows a 401 Rejected—normal behavior for wrong credentials).*

**🗣️ What you say:**
> "Now, let's try a standard SQL injection."
**🖱️ What you do:** Click **SQLi Attack**.
*(The feed shows `200 BREACHED`.)*

**🗣️ What you say:**
> "It got right through. The edge didn't know about this payload yet. But our Commander AI is constantly analyzing the telemetry. If we send a burst of attacks, it will realize we are under an active threat."

---

### Step 3: Waking the Blue Agent (1:00 - 1:45)
*Demonstrate the Blue Agent's mitigation pipeline.*

**🖱️ What you do:** Click **Burst ×3**.
*(Wait a few seconds. Watch the right side of the screen.)*

**🗣️ What you say:**
> "Look at the feed! The Commander noticed the burst and opened an incident. It extracted the payloads, scored them, and handed the evidence to our Analyst AI (Llama 3.3). The AI analyzed the attack vector and just synthesized a brand new regular expression to neutralize the threat. It then automatically deployed this rule to our Cloudflare KV."

**🖱️ What you do:** Click **SQLi Attack** again.
*(The feed instantly shows `403 BLOCKED`.)*

**🗣️ What you say:**
> "And now, that exact same attack is blocked instantly at the edge. No human intervention required."

---

### Step 4: Unleashing the Red Agent (1:45 - 2:45)
*The grand finale: Watch the Red Agent try to bypass the new rule.*

**🗣️ What you say:**
> "But what happens when the attacker is also an AI? A static WAF would be bypassed the second the attacker mutates their payload. Let's turn on our Autonomous Attacker—an LLM designed to bypass firewalls."

**🖱️ What you do:** Click **Unleash AI (Auto-Attack)**.

**🗣️ What you say:**
> "Watch its thought process. It realizes its standard payload was blocked. It says, *'I must obfuscate this to evade detection'* and mutates the payload using hex encoding or comments."

*(Let the loop run. Point to the UI showing the AI's internal thoughts and the mutated payloads).*

**🗣️ What you say:**
> "It threw the mutated payload. It successfully breached the firewall! But our Blue Agent immediately wakes up, analyzes the *new* breach, and deploys another rule to block it. When the Red Agent tries again... it's blocked again. This is a live, evolutionary arms race happening completely autonomously."

---

### Step 5: The Closer (2:45 - 3:00)
**🗣️ What you say:**
> "We aren't just building a static defense. We've built a dynamic immune system for the web that evolves just as fast as the attackers do. Thank you."
