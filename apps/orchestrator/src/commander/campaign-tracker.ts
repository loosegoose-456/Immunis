/**
 * ==========================================================================
 * MEMBER 2: CAMPAIGN TRACKER — a single global Durable Object.
 * ==========================================================================
 *
 * IncidentCommander sees one IP at a time, which is exactly the blind spot a botnet
 * exploits: a hundred addresses sending one request each never trips a per-IP burst
 * rule. This object is the other half of the brain. Every classified event is reported
 * here keyed by *fingerprint* — the shape of the attack, with literals stripped — so
 * the same exploit from a hundred IPs collapses into one campaign.
 *
 * Once a fingerprint is live on enough distinct addresses, the right answer stops being
 * "block the IP" and becomes "block the technique". Rotating IPs is cheap for the
 * attacker; rewriting the payload is not.
 *
 * It owns two further things because it is a singleton and therefore serialized:
 *   - the published pattern rule set in KV (one shared document, no lost updates)
 *   - the WebSocket feed the dashboard subscribes to
 */

import { DurableObject } from 'cloudflare:workers';

import type { AttackClass, CampaignSignal, CampaignSummary, Env, FeedEvent } from '../types';
import { publishPatternRules, type PatternRule } from './mitigation';
import { loadPolicy } from './policy';
import { audit } from './ledger';

const PREFIX_FINGERPRINT = 'fp:';
const PREFIX_FEED = 'feed:';
const KEY_RULES = 'rules';

const SWEEP_INTERVAL_MS = 60_000;
const FEED_RETENTION = 100;
const MAX_IPS_PER_CAMPAIGN = 200;

interface CampaignState {
	fingerprint: string;
	attackClass: AttackClass;
	pathTemplate: string;
	sampleIndicator: string;
	/** ip -> last seen. A map, so a chatty IP counts once toward the distinct-IP threshold. */
	ips: Record<string, number>;
	eventCount: number;
	firstSeen: number;
	lastSeen: number;
	distributed: boolean;
	announcedAt?: number;
}

function padTime(ms: number): string {
	return Math.max(0, Math.floor(ms)).toString().padStart(16, '0');
}

function toSummary(state: CampaignState): CampaignSummary {
	const ips = Object.keys(state.ips);
	return {
		fingerprint: state.fingerprint,
		attackClass: state.attackClass,
		ipCount: ips.length,
		eventCount: state.eventCount,
		firstSeen: state.firstSeen,
		lastSeen: state.lastSeen,
		ips: ips.slice(0, 50),
		distributed: state.distributed,
	};
}

export class CampaignTracker extends DurableObject<Env> {
	private tail: Promise<unknown> = Promise.resolve();

	/** Same reasoning as IncidentCommander: protect read-modify-write across awaits. */
	private serialize<T>(operation: () => Promise<T>): Promise<T> {
		const run = this.tail.then(operation, operation);
		this.tail = run.catch(() => undefined);
		return run;
	}

	// =======================================================================
	// Correlation
	// =======================================================================

	/** Record one classified event. Returns the campaign it belongs to, if any. */
	async report(signal: CampaignSignal): Promise<CampaignSummary | null> {
		return this.serialize(async () => {
			const config = loadPolicy(this.env);
			const now = signal.ts || Date.now();
			const key = `${PREFIX_FINGERPRINT}${signal.fingerprint}`;

			const state: CampaignState = (await this.ctx.storage.get<CampaignState>(key)) ?? {
				fingerprint: signal.fingerprint,
				attackClass: signal.attackClass,
				pathTemplate: signal.pathTemplate,
				sampleIndicator: signal.sampleIndicator,
				ips: {},
				eventCount: 0,
				firstSeen: now,
				lastSeen: now,
				distributed: false,
			};

			// Age out addresses that have gone quiet, so "12 IPs" means 12 IPs *now*.
			const cutoff = now - config.campaignWindowMs;
			for (const [ip, seenAt] of Object.entries(state.ips)) {
				if (seenAt < cutoff) delete state.ips[ip];
			}

			if (Object.keys(state.ips).length < MAX_IPS_PER_CAMPAIGN || state.ips[signal.ip]) {
				state.ips[signal.ip] = now;
			}
			state.eventCount += 1;
			state.lastSeen = now;

			const distinctIps = Object.keys(state.ips).length;
			const crossedThreshold = !state.distributed && distinctIps >= config.campaignMinIps;
			if (crossedThreshold) {
				state.distributed = true;
				state.announcedAt = now;
			}

			await this.ctx.storage.put(key, state);
			await this.ensureSweep();

			const summary = toSummary(state);

			if (crossedThreshold) {
				// This is the moment the system stops chasing addresses and starts
				// blocking the technique. Worth announcing loudly.
				console.log(`[campaign] distributed attack detected: ${signal.attackClass} on ${distinctIps} IPs (fingerprint ${signal.fingerprint})`);
				await audit(this.env, 'campaign_detected', signal.ip, {
					fingerprint: signal.fingerprint,
					attackClass: signal.attackClass,
					ipCount: distinctIps,
					pathTemplate: signal.pathTemplate,
				});
				await this.broadcast({ type: 'campaign', at: now, data: summary });
			}

			return summary;
		});
	}

	async campaigns(): Promise<CampaignSummary[]> {
		const stored = await this.ctx.storage.list<CampaignState>({ prefix: PREFIX_FINGERPRINT });
		return [...stored.values()].sort((a, b) => b.lastSeen - a.lastSeen).map(toSummary);
	}

	// =======================================================================
	// Pattern rule set (single-writer, because this object is a singleton)
	// =======================================================================

	async addPatternRule(rule: PatternRule): Promise<PatternRule[]> {
		return this.serialize(async () => {
			const now = Date.now();
			const existing = (await this.ctx.storage.get<PatternRule[]>(KEY_RULES)) ?? [];

			// Same pattern already live: extend it and merge the IP list rather than
			// stacking duplicate rules that all have to be evaluated on the hot path.
			const duplicate = existing.find((r) => r.pattern === rule.pattern && r.flags === rule.flags && r.expiresAt > now);
			const next = duplicate
				? existing.map((r) =>
						r === duplicate
							? {
									...r,
									// Never let a merge quietly weaken an existing `block` back to `challenge`.
									action: r.action === 'block' || rule.action === 'block' ? ('block' as const) : rule.action,
									expiresAt: Math.max(r.expiresAt, rule.expiresAt),
									ips: [...new Set([...r.ips, ...rule.ips])].slice(0, 50),
								}
							: r,
					)
				: [...existing.filter((r) => r.expiresAt > now), rule];

			await this.ctx.storage.put(KEY_RULES, next);
			const published = await publishPatternRules(this.env, next);
			await this.ensureSweep();
			await this.broadcast({
				type: 'mitigation',
				at: now,
				data: {
					id: rule.id,
					incidentId: '',
					ip: rule.ips[0] ?? '',
					kind: 'pattern_rule',
					action: rule.action,
					pattern: rule.pattern,
					flags: rule.flags,
					deployedAt: rule.deployedAt,
					expiresAt: rule.expiresAt,
					source: rule.source,
					keys: [],
				},
			});
			return published;
		});
	}

	async removePatternRule(ruleId: string): Promise<PatternRule[]> {
		return this.serialize(async () => {
			const existing = (await this.ctx.storage.get<PatternRule[]>(KEY_RULES)) ?? [];
			const next = existing.filter((rule) => rule.id !== ruleId);
			await this.ctx.storage.put(KEY_RULES, next);
			return publishPatternRules(this.env, next);
		});
	}

	async rules(): Promise<PatternRule[]> {
		const now = Date.now();
		const stored = (await this.ctx.storage.get<PatternRule[]>(KEY_RULES)) ?? [];
		return stored.filter((rule) => rule.expiresAt > now);
	}

	/**
	 * Wipe everything this object owns: published rules, campaign correlation and the
	 * feed replay buffer.
	 *
	 * Resetting the per-IP Commanders alone is not enough to re-run the demo, because
	 * the replay buffer lives here — clear only the browser and the next page load
	 * repopulates the room with the previous run's events.
	 */
	async resetAll(): Promise<{ ok: true; clearedRules: number; clearedCampaigns: number; clearedFeed: number }> {
		return this.serialize(async () => {
			const rules = (await this.ctx.storage.get<PatternRule[]>(KEY_RULES)) ?? [];
			const campaigns = await this.ctx.storage.list({ prefix: PREFIX_FINGERPRINT });
			const feed = await this.ctx.storage.list({ prefix: PREFIX_FEED });

			await this.ctx.storage.delete([...campaigns.keys(), ...feed.keys()]);
			await this.ctx.storage.put(KEY_RULES, []);
			await publishPatternRules(this.env, []);
			await this.ctx.storage.deleteAlarm();

			return { ok: true as const, clearedRules: rules.length, clearedCampaigns: campaigns.size, clearedFeed: feed.size };
		});
	}

	// =======================================================================
	// Live feed
	// =======================================================================

	/** Append to the replay buffer and push to every connected dashboard. */
	async publish(event: FeedEvent): Promise<void> {
		await this.ctx.storage.put(`${PREFIX_FEED}${padTime(event.at)}:${Math.random().toString(36).slice(2, 6)}`, event);
		await this.broadcast(event);
	}

	async recentFeed(limit = 50): Promise<FeedEvent[]> {
		const stored = await this.ctx.storage.list<FeedEvent>({ prefix: PREFIX_FEED, reverse: true, limit: Math.min(FEED_RETENTION, limit) });
		return [...stored.values()].reverse();
	}

	private async broadcast(event: FeedEvent): Promise<void> {
		const payload = JSON.stringify(event);
		for (const socket of this.ctx.getWebSockets()) {
			try {
				socket.send(payload);
			} catch {
				// A dead socket must not break the ingest path that triggered this.
			}
		}
	}

	/**
	 * WebSocket upgrade for the dashboard.
	 * Uses the hibernation API: connections survive the object being evicted from memory,
	 * so an idle dashboard costs nothing to keep open.
	 */
	override async fetch(request: Request): Promise<Response> {
		if (request.headers.get('Upgrade')?.toLowerCase() !== 'websocket') {
			return new Response('expected a WebSocket upgrade', { status: 426 });
		}

		const pair = new WebSocketPair();
		const client = pair[0];
		const server = pair[1];
		this.ctx.acceptWebSocket(server);

		const hello: FeedEvent = { type: 'hello', at: Date.now(), data: { campaigns: await this.campaigns() } };
		try {
			server.send(JSON.stringify(hello));
		} catch {
			// Client vanished mid-handshake.
		}

		return new Response(null, { status: 101, webSocket: client });
	}

	override async webSocketMessage(ws: WebSocket, message: string | ArrayBuffer): Promise<void> {
		if (typeof message === 'string' && message === 'ping') ws.send('pong');
	}

	override async webSocketClose(ws: WebSocket, code: number, reason: string): Promise<void> {
		// 1005 ("no status received"), 1006 ("abnormal closure", e.g. a tab closed or reloaded) and
		// 1015 (TLS failure) are reserved: they are only ever reported, never sent, and passing
		// them back to close() throws.
		ws.close(code === 1005 || code === 1006 || code === 1015 ? 1000 : code, reason);
	}

	// =======================================================================
	// Background sweep
	// =======================================================================

	private async ensureSweep(): Promise<void> {
		const current = await this.ctx.storage.getAlarm();
		if (current === null) await this.ctx.storage.setAlarm(Date.now() + SWEEP_INTERVAL_MS);
	}

	async alarm(): Promise<void> {
		const now = Date.now();
		const config = loadPolicy(this.env);

		// Retire expired rules and republish the set so the edge stops evaluating them.
		const rules = (await this.ctx.storage.get<PatternRule[]>(KEY_RULES)) ?? [];
		const live = rules.filter((rule) => rule.expiresAt > now);
		if (live.length !== rules.length) {
			await this.ctx.storage.put(KEY_RULES, live);
			await publishPatternRules(this.env, live);
			console.log(`[campaign] retired ${rules.length - live.length} expired pattern rule(s)`);
		}

		// Forget campaigns that have gone quiet, so a fingerprint can be re-detected later.
		const campaigns = await this.ctx.storage.list<CampaignState>({ prefix: PREFIX_FINGERPRINT });
		const stale = [...campaigns.entries()].filter(([, state]) => now - state.lastSeen > config.campaignWindowMs * 2).map(([key]) => key);
		if (stale.length) await this.ctx.storage.delete(stale);

		// Trim the feed replay buffer.
		const feed = await this.ctx.storage.list({ prefix: PREFIX_FEED, reverse: true });
		const overflow = [...feed.keys()].slice(FEED_RETENTION);
		if (overflow.length) await this.ctx.storage.delete(overflow);

		// Keep sweeping while there is anything left to sweep.
		if (live.length || campaigns.size > stale.length) {
			await this.ctx.storage.setAlarm(now + SWEEP_INTERVAL_MS);
		}
	}
}
