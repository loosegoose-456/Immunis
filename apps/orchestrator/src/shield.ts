import type { EdgeBlockEvent, Env } from './types';
import { classify } from './commander/fingerprint';
import { readPatternRules, matchPatternRules, type EdgeBlock } from './commander/mitigation';

// Mirror the two-pass normalization used by the Analyst.
function decodeEvidence(input: string): string {
	let value = input;
	for (let pass = 0; pass < 2; pass++) {
		try {
			const next = decodeURIComponent(value.replace(/\+/g, ' '));
			if (next === value) break;
			value = next;
		} catch {
			break;
		}
	}
	return value;
}

const SIMULATED_IP = /^[0-9a-fA-F:.]{1,45}$/;

/**
 * Who sent this request.
 *
 * Cloudflare sets `cf-connecting-ip` itself and overwrites anything the client supplied,
 * which is exactly what you want in production and exactly what makes a one-machine demo
 * impossible: every simulated attacker collapses into a single address, so the campaign
 * logic can never fire. `DEMO_ALLOW_SOURCE_SPOOF` opts into trusting an explicit demo
 * header. It is off unless configured, and it must stay off anywhere real.
 */
function sourceIp(request: Request, env: Env): string {
	if (env.DEMO_ALLOW_SOURCE_SPOOF === 'true') {
		const simulated = request.headers.get('x-demo-source-ip');
		if (simulated && SIMULATED_IP.test(simulated)) return simulated;
	}
	return request.headers.get('cf-connecting-ip') || 'unknown';
}

/** Path + query: the attacker-controlled part of the URL. */
function requestTarget(rawUrl: string): string {
	try {
		const parsed = new URL(rawUrl);
		return parsed.pathname + parsed.search;
	} catch {
		return rawUrl;
	}
}

/**
 * Tell the dashboard we refused something.
 *
 * Deliberately off the hot path via `waitUntil`: the caller already has their 403 and
 * nothing here may delay it. Without this the dashboard can only count the blocks the
 * Red Team console happened to observe itself, which is not the same number.
 */
function reportBlock(env: Env, ctx: ExecutionContext | undefined, data: EdgeBlockEvent): void {
	if (!env.CAMPAIGN_TRACKER) return;
	const publish = (async () => {
		try {
			const tracker = env.CAMPAIGN_TRACKER.get(env.CAMPAIGN_TRACKER.idFromName('global'));
			await tracker.publish({ type: 'edge_block', at: Date.now(), data });
		} catch {
			// Telemetry only. An unreachable tracker must never affect enforcement.
		}
	})();
	if (ctx?.waitUntil) ctx.waitUntil(publish);
}

export async function handleShieldRequest(
	request: Request,
	env: Env,
	fetchOrigin: typeof fetch = fetch,
	ctx?: ExecutionContext,
): Promise<Response> {
	const ip = sourceIp(request, env);
	const url = new URL(request.url);
	let proxyUrl: URL;
	try {
		if (!env.DEMO_UPSTREAM) throw new Error('missing upstream');
		proxyUrl = new URL(env.DEMO_UPSTREAM);
		if (!['http:', 'https:'].includes(proxyUrl.protocol) || proxyUrl.username || proxyUrl.password) throw new Error('invalid upstream');
		// Assign fields instead of resolving an attacker-controlled relative URL.
		proxyUrl.pathname = url.pathname;
		proxyUrl.search = url.search;
		proxyUrl.hash = '';
	} catch {
		return new Response('DEMO_UPSTREAM must be configured as an HTTP(S) target.', { status: 503 });
	}
	const payload = await request.clone().text();
	const target = requestTarget(request.url);

	// Safely decode evidence
	const decodedUrl = decodeEvidence(request.url);
	const decodedPayload = decodeEvidence(payload);

	// 1. Check if IP is already blocked in KV
	const ipBlockRaw = await env.RULES_KV.get(`block_ip_${ip}`);
	if (ipBlockRaw) {
		let block: EdgeBlock | undefined;
		try {
			block = JSON.parse(ipBlockRaw) as EdgeBlock;
		} catch {
			// Unparseable value: fail closed.
			reportBlock(env, ctx, { ip, method: request.method, target, reason: 'ip_block' });
			return new Response('403 Forbidden: Exploit neutralized by Edge Agent.', { status: 403 });
		}
		if (block.action === 'block') {
			reportBlock(env, ctx, { ip, method: request.method, target, reason: 'ip_block', ruleId: block.ruleId, attackClass: block.attackClass });
			return new Response('403 Forbidden: Exploit neutralized by Edge Agent.', { status: 403 });
		}
	}

	// 2. Test against Pattern Rules
	const rules = await readPatternRules(env, 0); // KV Cache disabled for instant demo feedback
	const matchInput = decodedUrl + '\n' + decodedPayload;
	const hit = matchPatternRules(rules.filter(rule => rule.action === 'block'), matchInput);

	if (hit && hit.action === 'block') {
		reportBlock(env, ctx, { ip, method: request.method, target, reason: 'pattern_rule', ruleId: hit.id, pattern: hit.pattern, attackClass: hit.attackClass });
		return new Response('403 Forbidden: Pattern exploit neutralized by Edge Agent.', { status: 403 });
	}

	// 3. Use the same attack classification as Commander.
	const event = {
		ip, url: request.url, method: request.method, payload,
		timestamp: Date.now(), userAgent: request.headers.get('user-agent') ?? '',
	};
	const isSuspicious = classify(event).attackClass !== 'unknown';

	if (isSuspicious) {
		// Await queue acceptance; analysis itself runs in the queue consumer.
		await env.ANALYSIS_QUEUE.send(event);
	}

	// 4. Proxy normal response to Demo Application
	const proxyRequest = new Request(proxyUrl, request);
	proxyRequest.headers.set('Host', proxyUrl.host);

	// Preserve redirects as responses rather than forwarding credentials to a new origin.
	return fetchOrigin(new Request(proxyRequest, { redirect: 'manual' }));
}
