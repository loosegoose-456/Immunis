/**
 * ==========================================================================
 * MEMBER 2: OPERATOR API — everything under /commander/*
 * ==========================================================================
 *
 * An autonomous system that can't be inspected or overridden is not one you'd deploy.
 * This exposes the Commander's state, its audit trail, a human off-switch, and a live
 * WebSocket feed for the dashboard.
 *
 * Mounted by src/index.ts ahead of Member 1's fetch handler. Member 1's path is
 * untouched: these routes return before their code runs.
 */

import type { Env, SuspiciousEvent } from '../types';
import { sanitizeEvent } from './policy';
import { listAudit, listIncidents, summaryStats } from './ledger';
import { readPatternRules } from './mitigation';
import { generateAttackPayload, type AttackHistory } from './red-agent';

export const COMMANDER_PREFIX = '/commander';

function json(body: unknown, status = 200): Response {
	return new Response(JSON.stringify(body, null, 2), {
		status,
		headers: {
			'content-type': 'application/json; charset=utf-8',
			// The dashboard may be served from anywhere during the demo.
			'access-control-allow-origin': '*',
			'access-control-allow-headers': 'content-type, x-commander-key',
			'access-control-allow-methods': 'GET, POST, OPTIONS',
		},
	});
}

function tracker(env: Env) {
	return env.CAMPAIGN_TRACKER.get(env.CAMPAIGN_TRACKER.idFromName('global'));
}

function commanderFor(env: Env, ip: string) {
	return env.INCIDENT_COMMANDER.get(env.INCIDENT_COMMANDER.idFromName(ip));
}

/**
 * Shared-secret guard. If COMMANDER_API_KEY is unset the routes are open, which is what
 * you want for `wrangler dev`; set it as a secret before deploying anywhere public.
 */
function authorized(request: Request, env: Env): boolean {
	if (!env.COMMANDER_API_KEY) return true;
	const provided = request.headers.get('x-commander-key') ?? new URL(request.url).searchParams.get('key');
	return provided === env.COMMANDER_API_KEY;
}

/** Returns null when the path isn't ours, so the caller falls through to Member 1. */
export async function handleCommanderRequest(request: Request, env: Env): Promise<Response | null> {
	const url = new URL(request.url);
	if (url.pathname !== COMMANDER_PREFIX && !url.pathname.startsWith(`${COMMANDER_PREFIX}/`)) return null;

	if (request.method === 'OPTIONS') return json({ ok: true });
	if (!authorized(request, env)) return json({ error: 'unauthorized', hint: 'send X-Commander-Key' }, 401);

	const segments = url.pathname.slice(COMMANDER_PREFIX.length).split('/').filter(Boolean);
	const route = segments[0] ?? 'health';

	try {
		switch (route) {
			case 'health':
				return json({
					ok: true,
					role: 'incident-commander',
					now: Date.now(),
					bindings: {
						rulesKv: Boolean(env.RULES_KV),
						queue: Boolean(env.ANALYSIS_QUEUE),
						incidentCommander: Boolean(env.INCIDENT_COMMANDER),
						campaignTracker: Boolean(env.CAMPAIGN_TRACKER),
						d1: Boolean(env.INCIDENT_DB),
						ai: Boolean(env.AI),
						vectorize: Boolean(env.ATTACK_VECTORS),
					},
					analystMode: env.ANALYST_MODE ?? 'auto',
				});

			// GET /commander/state/<ip> — everything the Commander knows about one address.
			case 'state': {
				const ip = segments[1];
				if (!ip) return json({ error: 'usage: /commander/state/<ip>' }, 400);
				return json(await commanderFor(env, ip).snapshot());
			}

			// POST /commander/pardon/<ip>?minutes=30 — the human off-switch.
			case 'pardon': {
				const ip = segments[1];
				if (!ip) return json({ error: 'usage: POST /commander/pardon/<ip>' }, 400);
				const minutes = Number.parseInt(url.searchParams.get('minutes') ?? '30', 10);
				return json(await commanderFor(env, ip).pardon(Number.isFinite(minutes) ? minutes : 30));
			}

			// POST /commander/reset/<ip> — clean slate, for re-running the demo.
			// Also wipes the global tracker (rules, campaigns, feed replay) so a page
			// reload after a reset does not repopulate the room from the previous run.
			case 'reset': {
				const ip = segments[1];
				if (!ip) return json({ error: 'usage: POST /commander/reset/<ip>' }, 400);
				const [commander, tracker_] = await Promise.all([commanderFor(env, ip).reset(), tracker(env).resetAll()]);
				return json({ ...commander, tracker: tracker_ });
			}

			case 'campaigns':
				return json({ campaigns: await tracker(env).campaigns() });

			// GET /commander/rules — what is live at the edge right now.
			case 'rules': {
				const [patterns, tracked] = await Promise.all([readPatternRules(env), tracker(env).rules()]);
				return json({ publishedToKv: patterns, trackedInDurableObject: tracked });
			}

			case 'incidents':
				return json({ incidents: await listIncidents(env, Number.parseInt(url.searchParams.get('limit') ?? '25', 10)) });

			case 'audit':
				return json({ audit: await listAudit(env, Number.parseInt(url.searchParams.get('limit') ?? '50', 10)) });

			case 'stats':
				return json({ ...(await summaryStats(env)), campaigns: (await tracker(env).campaigns()).length });

			case 'feed':
				return json({ feed: await tracker(env).recentFeed(Number.parseInt(url.searchParams.get('limit') ?? '50', 10)) });

			// GET /commander/stream — WebSocket live feed, handed to the tracker DO.
			case 'stream':
				return tracker(env).fetch(request);

			// POST /commander/simulate — drive the pipeline without real attack traffic.
			case 'simulate':
				return simulate(request, env, url);

			// POST /commander/red-agent — autonomous Red attacker's next move.
			// Never fails for lack of a login: falls back to a scripted mutation ladder.
			case 'red-agent': {
				if (request.method !== 'POST') return json({ error: 'POST required' }, 405);
				let body: { history?: AttackHistory[] };
				try {
					body = await request.json();
				} catch {
					return json({ error: 'invalid JSON body' }, 400);
				}
				return json(await generateAttackPayload(env, Array.isArray(body.history) ? body.history : []));
			}

			default:
				return json({ error: `unknown route ${route}`, routes: ROUTES }, 404);
		}
	} catch (error) {
		console.error(`[commander-api] ${route} failed:`, error);
		return json({ error: (error as Error).message, route }, 500);
	}
}

const ROUTES = [
	'GET  /commander/health',
	'GET  /commander/state/<ip>',
	'POST /commander/pardon/<ip>?minutes=30',
	'POST /commander/reset/<ip>',
	'GET  /commander/campaigns',
	'GET  /commander/rules',
	'GET  /commander/incidents?limit=25',
	'GET  /commander/audit?limit=50',
	'GET  /commander/stats',
	'GET  /commander/feed?limit=50',
	'GET  /commander/stream   (websocket)',
	'POST /commander/simulate  body: {ip,url,method,payload} | {events:[...]}  ?direct=1 to skip the queue',
	'POST /commander/red-agent body: { history: [{ payload, result }] }',
];

/**
 * Inject events for demos and tests.
 *
 * By default they go through ANALYSIS_QUEUE, exercising the real path end to end
 * (Member 1 -> queue -> consumer -> DO). `?direct=1` calls the Durable Object straight
 * away instead, which returns the scoring decision synchronously — much better for a
 * live demo, where waiting on a batch timeout is dead air.
 */
async function simulate(request: Request, env: Env, url: URL): Promise<Response> {
	if (request.method !== 'POST') return json({ error: 'POST required', example: { ip: '203.0.113.7', url: '/login?id=1 OR 1=1--', payload: '' } }, 405);

	let body: unknown;
	try {
		body = await request.json();
	} catch {
		return json({ error: 'invalid JSON body' }, 400);
	}

	const raw = body as { events?: unknown[] } & Record<string, unknown>;
	const candidates = Array.isArray(raw.events) ? raw.events : [body];

	const events: SuspiciousEvent[] = [];
	for (const [index, candidate] of candidates.entries()) {
		const event = sanitizeEvent(candidate, `sim_${Date.now().toString(36)}_${index}`);
		if (!event) return json({ error: `event ${index} is missing a valid "ip"` }, 400);
		events.push(event);
	}

	if (url.searchParams.get('direct') === '1') {
		const results = [];
		for (const event of events) {
			results.push(await commanderFor(env, event.ip).ingest(event));
		}
		return json({ mode: 'direct', count: results.length, results });
	}

	await env.ANALYSIS_QUEUE.sendBatch(events.map((event) => ({ body: event })));
	return json({ mode: 'queued', count: events.length, note: 'poll /commander/state/<ip> once the batch drains' });
}
