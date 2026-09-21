/**
 * The Commander's degraded mode. OWNER: Member 2.
 *
 * When the Analyst is unavailable — model rate-limited, not authenticated, returning
 * prose instead of JSON, or simply not merged yet — the Commander still has to act.
 * A security system that stops defending because its LLM hiccuped is not a security
 * system, so the escalation path is:
 *
 *     Analyst (LLM)  ->  synthesize from observed evidence  ->  class signature  ->  IP block
 *
 * The middle step matters more than it looks. A fixed table of per-class signatures can
 * only ever catch the payloads someone thought of in advance, so an attacker beats it by
 * changing one character (`OR 1=1` -> `OR 2=2`). Deriving the rule from the literal that
 * actually tripped the detector means the deterministic path adapts to a mutation it has
 * never seen, which is the difference between a demo and a defence.
 *
 * Every pattern here still goes through `validateRule` before deployment; nothing in this
 * file has the authority to publish.
 */

import type { AnalystStep, AttackClass, IncidentBrief, MitigationPlan } from '../types';
import { suggestedTtlSeconds } from './policy';
import { extractSignatureSamples } from './fingerprint';
import { validateRule } from './mitigation';

/** Last-resort signatures, used only when nothing can be synthesized from evidence. */
const CLASS_SIGNATURES: Record<AttackClass, { pattern: string; flags: string } | null> = {
	sqli: {
		pattern: String.raw`(?:\bunion\b[\s\S]{0,40}?\bselect\b|\bor\b\s+1\s*=\s*1|\b(?:sleep|pg_sleep|benchmark)\s*\(|\binformation_schema\b|\bxp_cmdshell\b)`,
		flags: 'i',
	},
	xss: {
		pattern: String.raw`(?:<\s*script[\s>]|\bon(?:error|load|toggle)\s*=|javascript\s*:|document\s*\.\s*cookie)`,
		flags: 'i',
	},
	path_traversal: {
		pattern: String.raw`(?:(?:\.\.[\/\\]){2,}|%2e%2e(?:%2f|%5c)|\/etc\/(?:passwd|shadow)|\/proc\/self\/environ)`,
		flags: 'i',
	},
	rce: {
		pattern: String.raw`(?:[;&|]\s*(?:cat|ls|whoami|curl|wget|chmod)\s|\$\([^)]{1,60}\)|\/dev\/tcp\/|\bnc\s+-[a-z]*e\b)`,
		flags: 'i',
	},
	ssrf: {
		pattern: String.raw`(?:169\.254\.169\.254|metadata\.google\.internal|\b(?:file|gopher|dict):\/\/)`,
		flags: 'i',
	},
	nosqli: {
		pattern: String.raw`["']?\$(?:ne|gt|gte|lt|lte|where|regex|expr)["']?\s*[:=]`,
		flags: 'i',
	},
	log4shell: {
		pattern: String.raw`\$\{\s*jndi\s*:\s*(?:ldap|ldaps|rmi|dns|iiop)`,
		flags: 'i',
	},
	scanner: {
		pattern: String.raw`\b(?:sqlmap|nikto|nmap|masscan|acunetix|nessus|dirbuster|gobuster|wpscan|nuclei)\b`,
		flags: 'i',
	},
	// No trustworthy signature exists for traffic we could not classify. Blocking the
	// single address is the honest response; inventing a pattern is how you take a site down.
	unknown: null,
};

export function signatureFor(attackClass: AttackClass): { pattern: string; flags: string } | null {
	return CLASS_SIGNATURES[attackClass];
}

const REGEX_META = /[.*+?^${}()|[\]\\/]/g;

/**
 * Turn one observed attack literal into a rule that generalizes over the boring parts.
 *
 * `' OR 2=2 --` becomes `'\s*OR\s*\d+\s*=\s*\d+\s*-\s*-`, which also catches
 * `'OR 7 = 7--` and `' or 1=1 --`. Three deliberate generalizations, and nothing else:
 *
 *   - whitespace between tokens -> `\s*`  (spacing is free for an attacker to change)
 *   - runs of digits            -> `\d+`  (the number in a tautology is arbitrary)
 *   - word-char edges           -> `\b`   (so `or` does not fire inside `colour`)
 *
 * Everything else is escaped to a literal. There are no groups, no alternation and no
 * nested quantifiers — every `\s*` sits between two required literals, so there is
 * nothing for a backtracking engine to explode on. It is still validated like any
 * other proposal, and a pattern this derives can and does get rejected.
 */
export function generalizeLiteral(sample: string): string | null {
	const trimmed = sample.trim();
	if (trimmed.length < 3) return null;

	// Tokens: a run of letters, a run of digits, or one punctuation character.
	// Whitespace only separates tokens; the `\s*` joins below make it optional anyway.
	const tokens: string[] = [];
	for (let i = 0; i < trimmed.length; ) {
		const ch = trimmed[i];
		if (/\s/.test(ch)) {
			i++;
			continue;
		}
		if (/[a-z_]/i.test(ch)) {
			let run = '';
			while (i < trimmed.length && /[a-z_]/i.test(trimmed[i])) run += trimmed[i++];
			tokens.push(run);
			continue;
		}
		if (/\d/.test(ch)) {
			while (i < trimmed.length && /\d/.test(trimmed[i])) i++;
			tokens.push(String.raw`\d+`);
			continue;
		}
		tokens.push(ch.replace(REGEX_META, '\\$&'));
		i++;
	}
	if (tokens.length < 2) return null;

	let out = tokens.join(String.raw`\s*`);
	// Anchor only where the literal itself starts or ends on a word character.
	if (/^[a-z_]/i.test(trimmed)) out = String.raw`\b` + out;
	if (/[a-z0-9_]$/i.test(trimmed)) out += String.raw`\b`;
	return out.length >= 4 ? out : null;
}

/**
 * Build candidate rules from the evidence, best first.
 *
 * "Best" means most specific: a literal carrying both a quote and an operator is far
 * less likely to appear in honest traffic than a bare `--`, so it is tried first and
 * the weak ones are only reached if the strong ones somehow fail validation.
 */
export function candidatePatterns(brief: IncidentBrief): string[] {
	const samples = brief.events.flatMap((event) => extractSignatureSamples(event, 4));
	const scored = [...new Set(samples)]
		.map((sample) => ({ sample, score: sample.length + (/['"`]/.test(sample) ? 40 : 0) + (/[=<>()]/.test(sample) ? 20 : 0) }))
		.sort((a, b) => b.score - a.score);

	const patterns: string[] = [];
	for (const { sample } of scored) {
		const pattern = generalizeLiteral(sample);
		if (pattern && !patterns.includes(pattern)) patterns.push(pattern);
	}
	return patterns.slice(0, 6);
}

/**
 * Deterministic plan from the classifier and the observed payloads alone.
 * No network, no model, always available — and it records its working, so the dashboard
 * can show what it tried instead of a canned animation.
 */
export function fallbackPlan(brief: IncidentBrief, proofSamples: string[] = []): { plan: MitigationPlan; steps: AnalystStep[] } {
	const { classification } = brief;
	const ttlSeconds = suggestedTtlSeconds(classification.attackClass, brief.priorIncidents);
	const steps: AnalystStep[] = [];
	let step = 0;

	// A distributed campaign blocks the *technique*, so it enforces even though each
	// individual address only reached `challenge` on its single request. Otherwise the
	// botnet is detected and then waved through — the exact failure campaign detection
	// exists to prevent.
	const action: 'block' | 'challenge' = brief.stage === 'challenge' && !brief.campaign?.distributed ? 'challenge' : 'block';

	const evidenceCount = brief.events.length;
	steps.push({
		step: ++step,
		tool: 'inspect_incident',
		ok: true,
		summary: `${evidenceCount} request(s) from ${brief.ip} classified ${classification.attackClass} at confidence ${classification.confidence.toFixed(2)} (${classification.indicators.join(', ') || 'no named indicator'})`,
	});

	if (brief.campaign?.distributed) {
		steps.push({
			step: ++step,
			tool: 'read_campaign',
			ok: true,
			summary: `fingerprint ${brief.campaign.fingerprint} is live on ${brief.campaign.ipCount} addresses — blocking the technique, not the address`,
		});
	}

	// --- 1. Synthesize a rule from what we actually saw. ---
	const candidates = candidatePatterns(brief);
	if (candidates.length) {
		steps.push({ step: ++step, tool: 'synthesize', ok: true, summary: `derived ${candidates.length} candidate pattern(s) from the observed payloads` });
	}

	for (const pattern of candidates) {
		const validation = validateRule(pattern, 'i', proofSamples);
		if (validation.ok) {
			steps.push({ step: ++step, tool: 'validate', ok: true, summary: `/${pattern}/i accepted — ${validation.reasons.join('; ')}` });
			return {
				plan: {
					kind: 'pattern_rule',
					action,
					pattern,
					flags: 'i',
					ttlSeconds,
					attackClass: classification.attackClass,
					confidence: classification.confidence,
					source: 'commander-synthesizer',
					diagnosis:
						`${evidenceCount} request(s) from ${brief.ip} match a ${classification.attackClass} pattern ` +
						`(${classification.indicators.join(', ') || 'no named indicator'}). ` +
						(brief.campaign?.distributed
							? `The same fingerprint is live on ${brief.campaign.ipCount} addresses, so this deploys a payload rule rather than an IP block. `
							: '') +
						`Rule synthesized from the observed payload and checked against the benign corpus.`,
				},
				steps,
			};
		}
		steps.push({ step: ++step, tool: 'validate', ok: false, summary: `/${pattern}/i rejected — ${validation.reasons.join('; ')}` });
	}

	// --- 2. Fall back to the hand-verified signature for the class. ---
	const signature = CLASS_SIGNATURES[classification.attackClass];
	const preferSignature = Boolean(signature) && (brief.campaign?.distributed || classification.confidence >= 0.7);
	if (preferSignature && signature) {
		const validation = validateRule(signature.pattern, signature.flags, proofSamples);
		if (validation.ok) {
			steps.push({ step: ++step, tool: 'validate', ok: true, summary: `fell back to the ${classification.attackClass} class signature — ${validation.reasons.join('; ')}` });
			return {
				plan: {
					kind: 'pattern_rule',
					action,
					pattern: signature.pattern,
					flags: signature.flags,
					ttlSeconds,
					attackClass: classification.attackClass,
					confidence: classification.confidence,
					source: 'commander-fallback',
					diagnosis:
						`${evidenceCount} request(s) from ${brief.ip} match a ${classification.attackClass} pattern ` +
						`(${classification.indicators.join(', ') || 'no named indicator'}). ` +
						`No rule could be synthesized from the payload, so the standing ${classification.attackClass} signature was deployed.`,
				},
				steps,
			};
		}
		steps.push({ step: ++step, tool: 'validate', ok: false, summary: `class signature rejected — ${validation.reasons.join('; ')}` });
	}

	// --- 3. Nothing safe to publish: block the one address. ---
	// (Manually disabled for the demo, degrading to observe instead of block_ip)
	steps.push({ step: ++step, tool: 'propose', ok: true, summary: `no safe pattern available — degrading to observe on ${brief.ip} for ${ttlSeconds}s` });
	return {
		plan: {
			kind: 'observe',
			action: 'block', // keeping action as 'block' ensures it logs as a failed block attempt
			ttlSeconds,
			attackClass: classification.attackClass,
			confidence: classification.confidence,
			source: 'commander-fallback',
			diagnosis:
				`${brief.ip} sent ${evidenceCount} suspicious request(s) (threat score ${brief.threatScore.toFixed(1)}, stage ${brief.stage}). ` +
				`Classified ${classification.attackClass}; no payload signature passed validation. IP blocks are disabled for this demo, so degrading to observe for ${ttlSeconds}s.`,
		},
		steps,
	};
}
