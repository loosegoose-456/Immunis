/**
 * Rule validation and deployment to the edge. OWNER: Member 2.
 *
 * The Analyst proposes; the Commander disposes. An LLM asked for a regex will
 * occasionally hand back `.*` — which, deployed to KV, takes the whole site offline in
 * under a second. So nothing reaches RULES_KV without passing `validateRule`, and every
 * deployment records what it wrote so it can be revoked precisely.
 *
 * KV LAYOUT (the contract Member 1 reads on the hot path):
 *   block_ip_<ip>  -> JSON EdgeBlock. Truthy string, so a plain `if (await kv.get(...))`
 *                     check still works. Carries an expirationTtl.
 *   waf:patterns   -> JSON PatternRule[]. One key holding the whole active rule set, so
 *                     the hot path is a single KV read (use `{ cacheTtl: 60 }`).
 *
 * Per-IP blocks are written by the per-IP IncidentCommander. The pattern rule set is
 * a single shared document, so only CampaignTracker (a singleton DO, therefore
 * serialized) is allowed to publish it — that is what keeps concurrent
 * read-modify-write from losing rules.
 */

import type { AttackClass, DeployedMitigation, Env, MitigationAction, MitigationPlan, ValidationResult } from '../types';

export interface EdgeBlock {
	action: MitigationAction;
	ruleId: string;
	incidentId: string;
	attackClass: AttackClass;
	reason: string;
	deployedAt: number;
	expiresAt: number;
	source: string;
}

export interface PatternRule {
	id: string;
	pattern: string;
	flags: string;
	action: MitigationAction;
	attackClass: AttackClass;
	reason: string;
	deployedAt: number;
	expiresAt: number;
	source: string;
	/** IPs observed using this pattern, for the dashboard. */
	ips: string[];
}

export const IP_BLOCK_PREFIX = 'block_ip_';
export const PATTERN_RULES_KEY = 'waf:patterns';
/** Member 1 should cap how much of a request body it tests against rules. */
export const MAX_MATCH_INPUT = 16_384;

/**
 * Real traffic a rule must never match. This is the safety net under the AI: a
 * generated regex is tested against these before it is allowed near the edge.
 */
export const BENIGN_CORPUS: string[] = [
	'GET /index.html HTTP/1.1',
	'/api/v1/users?page=2&per_page=50',
	'name=alice&email=alice%40example.com',
	'/static/css/app.4f21c9.css',
	'search=blue+running+shoes+size+10',
	'{"id":42,"status":"ok","items":[{"sku":"AB-12","qty":2}]}',
	'/products/1234/reviews',
	'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0 Safari/537.36',
	'/health',
	'POST /checkout {"address":"221B Baker Street, London","coupon":"SUMMER-2024"}',
	'comment=I loved this product! Would buy again -- 5 stars',
	'/blog/2024/03/how-we-scaled-our-database',
	'query=SELECT your favourite plan from the pricing page',
	'/api/search?q=union+jack+flag',
	// Apostrophes and dashes in ordinary prose. A synthesized rule anchored on a quote
	// next to punctuation looks precise and is not: real customers write like this.
	"comment=it's -- honestly -- the best thing we've bought",
	"name=O'Brien&city=Coeur+d'Alene",
	"search=rock+'n'+roll+vinyl",
	"feedback=don't stop -- keep the updates coming",
	// Numeric comparisons and equals signs that a tautology rule must not swallow.
	'filter=price=100&compare=size=10',
	'utm_source=newsletter&utm_campaign=spring-2024&ref=partner',
	'/api/orders?status=open&limit=25&offset=50',
	"note=Ana's order #1234 -- shipped 2 of 2 items",
];

/**
 * Patterns that are technically valid but operationally suicidal.
 * The empty-string and benign-corpus checks below would catch these anyway; this test
 * exists so the rejection reason says *why* instead of listing 14 false positives.
 */
const CATCH_ALL_SHAPES = /^\(?(?:\?:)?(?:\.|\[\\s\\S\]|\[\\S\\s\]|\[\^\\n\])(?:[*+]|\{\d*,\d*\})\)?$/;

function isCatchAll(pattern: string): boolean {
	const core = pattern.replace(/^\^+/, '').replace(/\$+$/, '').trim();
	return core === '' || CATCH_ALL_SHAPES.test(core);
}

/**
 * Nested quantifier — the classic catastrophic-backtracking shape: `(a+)+`, `([a-z]*)*`.
 * A group whose body already contains `*` or `+` and which is itself quantified can take
 * exponential time on a crafted input, so an attacker could turn our own WAF rule into
 * the denial of service.
 */
const NESTED_QUANTIFIER = /\([^()]*[+*][^()]*\)\s*[*+]/;

export function stripUnsafeFlags(flags: string | undefined): string {
	// `g` and `y` make a RegExp stateful via lastIndex — a shared rule object with `g`
	// silently alternates between matching and not matching. Drop them.
	return [...new Set((flags ?? '').split(''))].filter((f) => 'imsu'.includes(f)).join('');
}

/**
 * Decide whether a proposed rule is safe to deploy.
 *
 * `proofSamples` are the actual attack strings from the incident. A rule that matches
 * none of them is useless even if it is safe, so we reject that too.
 */
export function validateRule(pattern: string | undefined, flags: string | undefined, proofSamples: string[] = []): ValidationResult {
	const reasons: string[] = [];
	const falsePositives: string[] = [];

	if (!pattern || typeof pattern !== 'string') {
		return { ok: false, reasons: ['no pattern supplied'], falsePositives };
	}
	const trimmed = pattern.trim();
	if (trimmed.length < 4) return { ok: false, reasons: [`pattern too short (${trimmed.length} chars) — would over-match`], falsePositives };
	if (trimmed.length > 400) return { ok: false, reasons: [`pattern too long (${trimmed.length} chars) — refusing to compile`], falsePositives };
	if (isCatchAll(trimmed)) return { ok: false, reasons: ['pattern is a catch-all and would block all traffic'], falsePositives };
	if (NESTED_QUANTIFIER.test(trimmed)) {
		return { ok: false, reasons: ['nested quantifier detected — catastrophic backtracking risk (ReDoS)'], falsePositives };
	}

	let re: RegExp;
	try {
		re = new RegExp(trimmed, stripUnsafeFlags(flags));
	} catch (error) {
		return { ok: false, reasons: [`pattern does not compile: ${(error as Error).message}`], falsePositives };
	}

	if (re.test('')) return { ok: false, reasons: ['pattern matches the empty string and would block every request'], falsePositives };

	for (const sample of BENIGN_CORPUS) {
		if (re.test(sample)) falsePositives.push(sample);
	}
	if (falsePositives.length) {
		reasons.push(`matches ${falsePositives.length} known-benign request(s) — rejected to protect real users`);
		return { ok: false, reasons, falsePositives };
	}

	if (proofSamples.length) {
		const matched = proofSamples.some((sample) => re.test(sample.slice(0, MAX_MATCH_INPUT)));
		if (!matched) {
			reasons.push('pattern does not match any payload from this incident — would be a no-op rule');
			return { ok: false, reasons, falsePositives };
		}
		reasons.push(`matches ${proofSamples.filter((s) => re.test(s.slice(0, MAX_MATCH_INPUT))).length}/${proofSamples.length} incident payloads`);
	}

	reasons.push(`clean against ${BENIGN_CORPUS.length} benign samples`);
	return { ok: true, reasons, falsePositives };
}

/** Test a request against the active rule set. Shared with Member 1's hot path. */
export function matchPatternRules(rules: PatternRule[], input: string, now = Date.now()): PatternRule | undefined {
	const haystack = input.slice(0, MAX_MATCH_INPUT);
	for (const rule of rules) {
		if (rule.expiresAt <= now) continue;
		try {
			if (new RegExp(rule.pattern, stripUnsafeFlags(rule.flags)).test(haystack)) return rule;
		} catch {
			// A rule that no longer compiles is skipped rather than allowed to throw at the edge.
		}
	}
	return undefined;
}

export function newRuleId(prefix: string): string {
	return `${prefix}_${Date.now().toString(36)}_${Math.random().toString(36).slice(2, 8)}`;
}

/** Write an IP block to the edge. Called by the per-IP IncidentCommander. */
export async function deployIpBlock(
	env: Env,
	args: { ip: string; incidentId: string; plan: MitigationPlan; reason: string },
): Promise<DeployedMitigation> {
	const now = Date.now();
	const ttl = clampTtl(args.plan.ttlSeconds);
	const ruleId = newRuleId('blk');
	const key = `${IP_BLOCK_PREFIX}${args.ip}`;

	const block: EdgeBlock = {
		action: args.plan.action,
		ruleId,
		incidentId: args.incidentId,
		attackClass: args.plan.attackClass,
		reason: args.reason,
		deployedAt: now,
		expiresAt: now + ttl * 1000,
		source: args.plan.source,
	};

	// expirationTtl is the backstop: even if every Durable Object is evicted and no
	// alarm ever fires, the block self-expires at the edge.
	await env.RULES_KV.put(key, JSON.stringify(block), { expirationTtl: ttl });

	return {
		id: ruleId,
		incidentId: args.incidentId,
		ip: args.ip,
		kind: 'block_ip',
		action: args.plan.action,
		deployedAt: now,
		expiresAt: block.expiresAt,
		source: args.plan.source,
		keys: [key],
	};
}

export async function revokeMitigation(env: Env, mitigation: DeployedMitigation): Promise<void> {
	await Promise.all(mitigation.keys.map((key) => env.RULES_KV.delete(key)));
}

export async function readPatternRules(env: Env, cacheTtl = 0): Promise<PatternRule[]> {
	const raw =
		cacheTtl > 0
			? await env.RULES_KV.get(PATTERN_RULES_KEY, { type: 'text', cacheTtl })
			: await env.RULES_KV.get(PATTERN_RULES_KEY, 'text');
	if (!raw) return [];
	try {
		const parsed = JSON.parse(raw);
		return Array.isArray(parsed) ? (parsed as PatternRule[]) : [];
	} catch {
		return [];
	}
}

/**
 * Replace the published rule set, dropping anything expired.
 *
 * Only CampaignTracker calls this. Being a singleton DO, its calls are serialized, so
 * this read-modify-write cannot interleave with itself.
 */
export async function publishPatternRules(env: Env, rules: PatternRule[]): Promise<PatternRule[]> {
	const now = Date.now();
	const live = rules.filter((rule) => rule.expiresAt > now).slice(0, 64);
	if (!live.length) {
		await env.RULES_KV.delete(PATTERN_RULES_KEY);
		return [];
	}
	const longestTtl = Math.ceil((Math.max(...live.map((r) => r.expiresAt)) - now) / 1000);
	await env.RULES_KV.put(PATTERN_RULES_KEY, JSON.stringify(live), { expirationTtl: Math.max(60, longestTtl) });
	return live;
}

/** KV requires expirationTtl >= 60s; cap at a day so nothing is blocked forever by accident. */
export function clampTtl(seconds: number | undefined): number {
	const value = Number.isFinite(seconds) ? Number(seconds) : 300;
	return Math.min(24 * 3600, Math.max(60, Math.round(value)));
}
