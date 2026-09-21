/**
 * ==========================================================================
 * MEMBER 2: THE COMMANDER — one Durable Object per source IP.
 * ==========================================================================
 *
 * This is the stateful brain. Cloudflare guarantees exactly one instance of this object
 * exists globally for a given IP, so it can hold a coherent picture of that attacker
 * without any locking or external database: what they have tried, how dangerous they
 * are right now, what we deployed against them, and when to take it back down.
 *
 * Lifecycle of an event:
 *   queue consumer -> ingest() -> classify -> score -> decide
 *                              -> [if warranted] open incident -> ask the Analyst
 *                              -> validate the proposed rule -> deploy to the edge
 *                              -> schedule its expiry
 *
 * Alarms then run the background half: decaying the threat score, closing idle
 * incidents, expiring mitigations, and garbage-collecting old events. That is what
 * makes this an agent rather than a request handler — it keeps working after the
 * request that woke it has gone.
 */

import { DurableObject } from 'cloudflare:workers';

import type {
	AnalystReport,
	CampaignSummary,
	CommanderSnapshot,
	DeployedMitigation,
	Env,
	IncidentBrief,
	IncidentRecord,
	IngestResult,
	IpProfile,
	MitigationPlan,
	RequestEvidence,
	Stage,
	SuspiciousEvent,
	ValidationResult,
} from '../types';
import { classify } from './fingerprint';
import { decide, emptyProfile, loadPolicy, decayScore, stageForScore, stageRank, type PolicyConfig } from './policy';
import { AlarmScheduler, type Job } from './scheduler';
import { requestPlan } from './analyst-client';
import { deployIpBlock, revokeMitigation, validateRule, clampTtl, type PatternRule } from './mitigation';
import { audit, recordIncident, recordMitigation, markMitigationRevoked } from './ledger';

const KEY_PROFILE = 'profile';
const KEY_OPEN_INCIDENT = 'incident:open';
const PREFIX_EVENT = 'evt:';
const PREFIX_DEDUPE = 'dedupe:';
const PREFIX_INCIDENT = 'incident:rec:';
const PREFIX_MITIGATION = 'mitigation:';

const GC_INTERVAL_MS = 5 * 60_000;
const DECAY_INTERVAL_MS = 60_000;
const DEDUPE_RETENTION_MS = 10 * 60_000;
/** Keep a bit of history past the scoring window so snapshots and briefs are useful. */
const EVENT_RETENTION_MULTIPLIER = 6;

function padTime(ms: number): string {
	return Math.max(0, Math.floor(ms)).toString().padStart(16, '0');
}

/**
 * The request as the dashboard should show it: path and body only.
 * The host is ours, not evidence, and showing it invites the reader to misread our own
 * origin as part of the attack. Percent-decode target and body so the panel shows the
 * payload the way the classifier sees it (`admin' OR 1=1 -- `, not `admin%27+OR...`).
 */
function decodeForDisplay(input: string): string {
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

function describeEvidence(event: SuspiciousEvent): RequestEvidence {
	let target = event.url;
	try {
		const parsed = new URL(event.url);
		target = parsed.pathname + parsed.search;
	} catch {
		// Relative or malformed: show it as received.
	}
	return {
		method: event.method,
		target: decodeForDisplay(target).slice(0, 512),
		payload: decodeForDisplay(event.payload).slice(0, 2048),
		userAgent: event.userAgent?.slice(0, 256),
	};
}

export class IncidentCommander extends DurableObject<Env> {
	private readonly scheduler: AlarmScheduler;
	/** Guards the expensive analyst path against a burst triggering it many times over. */
	private analysisInFlight = false;
	/** Serializes ingest() so concurrent calls can't lose a profile update. */
	private tail: Promise<unknown> = Promise.resolve();

	constructor(ctx: DurableObjectState, env: Env) {
		super(ctx, env);
		this.scheduler = new AlarmScheduler(ctx.storage);
	}

	/**
	 * Durable Object input gates protect individual storage operations, not a whole
	 * read-modify-write sequence. ingest() reads the profile, computes, then writes it,
	 * so two concurrent calls could interleave and drop an update. Chaining them is
	 * cheap insurance and keeps the scoring arithmetic exact.
	 */
	private serialize<T>(operation: () => Promise<T>): Promise<T> {
		const run = this.tail.then(operation, operation);
		this.tail = run.catch(() => undefined);
		return run;
	}

	// =======================================================================
	// RPC surface
	// =======================================================================

	/** Called by the queue consumer, once per suspicious request. */
	async ingest(event: SuspiciousEvent): Promise<IngestResult> {
		return this.serialize(() => this.ingestInner(event));
	}

	async snapshot(): Promise<CommanderSnapshot> {
		const config = loadPolicy(this.env);
		const now = Date.now();
		const stored = await this.ctx.storage.get<IpProfile>(KEY_PROFILE);
		const profile = stored ?? emptyProfile('unknown', now);

		// Report the live decayed score, not the stale stored one.
		const score = decayScore(profile.score, now - profile.scoredAt, config.scoreHalfLifeMs);
		const windowEvents = await this.ctx.storage.list<SuspiciousEvent>({
			prefix: PREFIX_EVENT,
			start: `${PREFIX_EVENT}${padTime(now - config.burstWindowMs)}`,
		});
		const incidents = await this.ctx.storage.list<IncidentRecord>({ prefix: PREFIX_INCIDENT, reverse: true, limit: 10 });
		const mitigations = await this.ctx.storage.list<DeployedMitigation>({ prefix: PREFIX_MITIGATION });
		const jobs = await this.scheduler.pending();

		return {
			profile: { ...profile, score, stage: stageForScore(score, config) },
			openIncident: await this.ctx.storage.get<IncidentRecord>(KEY_OPEN_INCIDENT),
			recentIncidents: [...incidents.values()],
			activeMitigations: [...mitigations.values()].filter((m) => m.expiresAt > now),
			windowEventCount: windowEvents.size,
			nextAlarmAt: await this.ctx.storage.getAlarm(),
			scheduledJobs: jobs.map((job) => ({ kind: job.kind, dueAt: job.dueAt })),
		};
	}

	/**
	 * Operator override: lift enforcement and suppress re-escalation for a while.
	 * Real security tools need a human off-switch, and it has to be faster than a deploy.
	 */
	async pardon(minutes = 30): Promise<{ ip: string; pardonedUntil: number; revoked: number }> {
		return this.serialize(async () => {
			const now = Date.now();
			const profile = (await this.ctx.storage.get<IpProfile>(KEY_PROFILE)) ?? emptyProfile('unknown', now);
			const revoked = await this.revokeAll('operator pardon');

			profile.pardonedUntil = now + Math.max(1, minutes) * 60_000;
			profile.score = 0;
			profile.scoredAt = now;
			profile.stage = 'observe';
			await this.ctx.storage.put(KEY_PROFILE, profile);
			await audit(this.env, 'operator_pardon', profile.ip, { minutes, revoked });

			return { ip: profile.ip, pardonedUntil: profile.pardonedUntil, revoked };
		});
	}

	/** Wipe this IP's state. Used to re-run the demo from a clean slate. */
	async reset(): Promise<{ ok: true }> {
		return this.serialize(async () => {
			await this.revokeAll('reset');
			await this.ctx.storage.deleteAll();
			await this.ctx.storage.deleteAlarm();
			return { ok: true } as const;
		});
	}

	// =======================================================================
	// Ingest pipeline
	// =======================================================================

	private async ingestInner(event: SuspiciousEvent): Promise<IngestResult> {
		const now = Date.now();
		const config = loadPolicy(this.env);
		const classification = classify(event);

		// --- Exactly-once. Queues deliver at-least-once, so a retried message must not
		// --- be scored twice; otherwise a transient error inflates an IP's threat score.
		const dedupeKey = `${PREFIX_DEDUPE}${event.eventId}`;
		if (event.eventId && (await this.ctx.storage.get(dedupeKey))) {
			const profile = (await this.ctx.storage.get<IpProfile>(KEY_PROFILE)) ?? emptyProfile(event.ip, now);
			return {
				ip: event.ip,
				accepted: false,
				duplicate: true,
				score: profile.score,
				stage: profile.stage,
				classification,
				triggeredAnalysis: false,
				reasons: ['duplicate delivery ignored'],
			};
		}

		const profile = (await this.ctx.storage.get<IpProfile>(KEY_PROFILE)) ?? emptyProfile(event.ip, now);
		const openIncident = await this.ctx.storage.get<IncidentRecord>(KEY_OPEN_INCIDENT);

		// Store the event under a time-sorted key so the sliding window is a range scan
		// rather than a read of the entire history.
		const eventKey = `${PREFIX_EVENT}${padTime(now)}:${Math.random().toString(36).slice(2, 8)}`;
		await this.ctx.storage.put(eventKey, event);
		if (event.eventId) await this.ctx.storage.put(dedupeKey, now);

		const windowEvents = await this.ctx.storage.list<SuspiciousEvent>({
			prefix: PREFIX_EVENT,
			start: `${PREFIX_EVENT}${padTime(now - config.burstWindowMs)}`,
		});

		// Correlate before deciding. A botnet gives each address a single request, so the
		// only signal that this event matters may be that 40 other addresses sent the
		// same shape — and `decide()` cannot weigh that unless it is asked first.
		const campaign = await this.reportToCampaignTracker(event, classification, now);

		const decision = decide({
			profile,
			classification,
			windowEventCount: windowEvents.size,
			now,
			config,
			incidentOpen: Boolean(openIncident),
			campaignDistributed: campaign?.distributed,
		});

		profile.ip = event.ip;
		profile.lastSeen = now;
		profile.score = decision.score;
		profile.scoredAt = now;
		profile.stage = decision.stage;
		profile.totalEvents += 1;
		profile.lastFingerprint = classification.fingerprint;
		if (event.country) profile.country = event.country;
		if (classification.attackClass !== 'unknown' && !profile.classesSeen.includes(classification.attackClass)) {
			profile.classesSeen.push(classification.attackClass);
		}
		await this.ctx.storage.put(KEY_PROFILE, profile);

		// Background work, scheduled rather than done inline.
		await this.scheduler.scheduleIn('gc', GC_INTERVAL_MS);
		await this.scheduler.scheduleIn('decay', DECAY_INTERVAL_MS);

		const result: IngestResult = {
			ip: event.ip,
			accepted: true,
			duplicate: false,
			score: decision.score,
			stage: decision.stage,
			classification,
			triggeredAnalysis: false,
			reasons: decision.reasons,
			evidence: describeEvidence(event),
		};

		if (decision.triggerAnalysis) {
			const outcome = await this.runIncident({
				event,
				classification,
				profile,
				decision: { stage: decision.stage, score: decision.score, escalated: decision.escalated },
				openIncident,
				campaign,
				config,
				now,
			});
			result.triggeredAnalysis = outcome.triggered;
			result.incidentId = outcome.incidentId;
			result.mitigation = outcome.mitigation;
			result.reasons = [...result.reasons, ...outcome.reasons];
			result.analyst = outcome.analyst;
		}

		await this.publishToFeed(result);
		return result;
	}

	/**
	 * Open or extend an incident, ask the Analyst what to do, check the answer, and
	 * deploy it. Everything that makes this system autonomous happens in here.
	 */
	private async runIncident(args: {
		event: SuspiciousEvent;
		classification: ReturnType<typeof classify>;
		profile: IpProfile;
		decision: { stage: Stage; score: number; escalated: boolean };
		openIncident?: IncidentRecord;
		campaign?: CampaignSummary;
		config: PolicyConfig;
		now: number;
	}): Promise<{ triggered: boolean; incidentId?: string; mitigation?: DeployedMitigation; reasons: string[]; analyst?: AnalystReport }> {
		const { event, classification, profile, decision, campaign, config, now } = args;
		const reasons: string[] = [];

		let incident: IncidentRecord =
			args.openIncident ??
			({
				id: `inc_${now.toString(36)}_${Math.random().toString(36).slice(2, 7)}`,
				ip: event.ip,
				openedAt: now,
				lastEventAt: now,
				eventCount: 0,
				peakScore: 0,
				stage: decision.stage,
				classesSeen: [],
				fingerprint: classification.fingerprint,
				status: 'open',
				analysisCount: 0,
			} satisfies IncidentRecord);

		const isNew = !args.openIncident;
		incident.lastEventAt = now;
		incident.eventCount += 1;
		incident.peakScore = Math.max(incident.peakScore, decision.score);
		incident.stage = stageRank(decision.stage) > stageRank(incident.stage) ? decision.stage : incident.stage;
		incident.fingerprint = classification.fingerprint;
		if (classification.attackClass !== 'unknown' && !incident.classesSeen.includes(classification.attackClass)) {
			incident.classesSeen.push(classification.attackClass);
		}

		if (isNew) {
			reasons.push(`opened incident ${incident.id}`);
			await audit(this.env, 'incident_opened', event.ip, { incidentId: incident.id, stage: decision.stage, score: decision.score });
		}

		// Always close the incident eventually, even if analysis is skipped below.
		await this.ctx.storage.put(KEY_OPEN_INCIDENT, incident);
		await this.scheduler.scheduleIn('close_incident', config.incidentIdleTimeoutMs, undefined, { dedupe: false });

		// --- Rate-limit the expensive path ---
		const newClass = classification.attackClass !== 'unknown' && incident.classesSeen[incident.classesSeen.length - 1] === classification.attackClass && incident.classesSeen.length > 1;
		const cooledDown = !incident.lastAnalysisAt || now - incident.lastAnalysisAt >= config.analysisCooldownMs;
		if (this.analysisInFlight) {
			reasons.push('analysis already running for this IP');
			return { triggered: false, incidentId: incident.id, reasons };
		}
		// A stage escalation bypasses the cooldown: the earlier plan was sized for a weaker
		// threat, and waiting out the timer would leave a `block`-stage IP unblocked.
		if (!cooledDown && !newClass && !decision.escalated) {
			reasons.push(`analysis on cooldown (${Math.round((config.analysisCooldownMs - (now - incident.lastAnalysisAt!)) / 1000)}s left)`);
			return { triggered: false, incidentId: incident.id, reasons };
		}
		// Below `challenge` we watch and record but do not enforce. Graduated response
		// keeps a single noisy scanner from getting a blanket rule deployed against it.
		if (stageRank(decision.stage) < stageRank('challenge')) {
			reasons.push(`stage ${decision.stage}: observing, no enforcement yet`);
			await this.ctx.storage.put(KEY_OPEN_INCIDENT, incident);
			return { triggered: false, incidentId: incident.id, reasons };
		}

		this.analysisInFlight = true;
		try {
			incident.status = 'analyzing';
			incident.analysisCount += 1;
			incident.lastAnalysisAt = now;
			await this.ctx.storage.put(KEY_OPEN_INCIDENT, incident);

			const brief = await this.buildBrief(incident, profile, classification, decision, campaign);
			await audit(this.env, 'analysis_requested', event.ip, { incidentId: incident.id, eventCount: brief.eventCount });

			const outcome = await requestPlan(this.env, brief);
			reasons.push(
				`analyst responded in ${outcome.latencyMs}ms via ${outcome.plan.source}` + (outcome.degradedReason ? ` (degraded: ${outcome.degradedReason})` : ''),
			);
			await audit(this.env, 'analysis_returned', event.ip, {
				incidentId: incident.id,
				source: outcome.plan.source,
				kind: outcome.plan.kind,
				latencyMs: outcome.latencyMs,
				degradedReason: outcome.degradedReason,
			});

			const applied = await this.applyPlan(incident, outcome.plan, outcome.proofSamples, campaign);
			reasons.push(...applied.reasons);

			// The validator's verdict is part of the Analyst's story: "it proposed this,
			// we checked it against the benign corpus, here is what happened".
			const analyst: AnalystReport = { ...outcome.report, validation: applied.validation };
			if (applied.plan.source !== outcome.plan.source) analyst.source = applied.plan.source;

			// IP blocks have been manually disabled for the demo.
			// Normally, we would deploy a block_ip_<ip> here if decision.stage === 'block'.

			incident.plan = applied.plan;
			incident.validation = applied.validation;
			incident.status = applied.mitigation ? 'mitigated' : 'open';
			incident.summary = applied.plan.diagnosis;
			await this.ctx.storage.put(KEY_OPEN_INCIDENT, incident);
			await recordIncident(this.env, incident);

			return { triggered: true, incidentId: incident.id, mitigation: applied.mitigation, reasons, analyst };
		} catch (error) {
			// An incident that fails to analyse must not take down the queue consumer.
			console.error('[commander] incident handling failed:', (error as Error).message);
			reasons.push(`incident handling error: ${(error as Error).message}`);
			return { triggered: false, incidentId: incident.id, reasons };
		} finally {
			this.analysisInFlight = false;
		}
	}

	/**
	 * Validate the Analyst's plan and push it to the edge.
	 *
	 * This is the guardrail. A pattern rule is only deployed if it compiles, matches
	 * payloads from this incident, and matches nothing in the benign corpus. If it
	 * fails, we log exactly why and fall back to blocking the single IP — degraded,
	 * but never a self-inflicted outage.
	 */
	private async applyPlan(
		incident: IncidentRecord,
		plan: MitigationPlan,
		proofSamples: string[],
		campaign?: CampaignSummary,
	): Promise<{ plan: MitigationPlan; mitigation?: DeployedMitigation; validation: ValidationResult; reasons: string[] }> {
		const reasons: string[] = [];
		let effectivePlan = plan;
		let validation: ValidationResult = { ok: true, reasons: ['no pattern to validate'], falsePositives: [] };

		if (plan.kind === 'pattern_rule') {
			validation = validateRule(plan.pattern, plan.flags, proofSamples);
			if (validation.ok) {
				reasons.push(`rule validated: ${validation.reasons.join('; ')}`);
				const published = await this.publishPatternRule(incident, plan, campaign);
				if (published) {
					await recordMitigation(this.env, published, plan.diagnosis, validation);
					await audit(this.env, 'rule_deployed', incident.ip, {
						incidentId: incident.id,
						kind: 'pattern_rule',
						pattern: plan.pattern,
						source: plan.source,
					});
					await this.trackMitigation(published);
					return { plan, mitigation: published, validation, reasons };
				}
				reasons.push('campaign tracker unavailable; falling back to IP block');
			} else {
				// The headline safety behaviour: we refuse the rule and say why.
				reasons.push(`REJECTED proposed rule: ${validation.reasons.join('; ')}`);
				await audit(this.env, 'rule_rejected', incident.ip, {
					incidentId: incident.id,
					pattern: plan.pattern,
					source: plan.source,
					reasons: validation.reasons,
					falsePositives: validation.falsePositives.slice(0, 3),
				});
			}
			// Degrade to observe instead of IP block (manually disabled by user)
			effectivePlan = { ...plan, kind: 'observe', pattern: undefined, flags: undefined, source: `${plan.source}+downgraded` };
		}

		if (effectivePlan.kind === 'observe') {
			reasons.push('plan is observe-only; nothing deployed');
			return { plan: effectivePlan, validation, reasons };
		}

		const mitigation = await deployIpBlock(this.env, {
			ip: incident.ip,
			incidentId: incident.id,
			plan: effectivePlan,
			reason: effectivePlan.diagnosis.slice(0, 300),
		});
		await recordMitigation(this.env, mitigation, effectivePlan.diagnosis, validation);
		await audit(this.env, 'rule_deployed', incident.ip, {
			incidentId: incident.id,
			kind: 'block_ip',
			ttlSeconds: clampTtl(effectivePlan.ttlSeconds),
			source: effectivePlan.source,
		});
		await this.trackMitigation(mitigation);
		reasons.push(`deployed ${effectivePlan.action} on ${incident.ip} for ${clampTtl(effectivePlan.ttlSeconds)}s`);

		return { plan: effectivePlan, mitigation, validation, reasons };
	}

	/** Pattern rules are one shared document, so only the singleton tracker may write them. */
	private async publishPatternRule(incident: IncidentRecord, plan: MitigationPlan, campaign?: CampaignSummary): Promise<DeployedMitigation | undefined> {
		try {
			const tracker = this.env.CAMPAIGN_TRACKER.get(this.env.CAMPAIGN_TRACKER.idFromName('global'));
			const rule: PatternRule = {
				id: `pat_${Date.now().toString(36)}_${Math.random().toString(36).slice(2, 8)}`,
				pattern: plan.pattern!,
				flags: plan.flags ?? 'i',
				action: plan.action,
				attackClass: plan.attackClass,
				reason: plan.diagnosis.slice(0, 300),
				deployedAt: Date.now(),
				expiresAt: Date.now() + clampTtl(plan.ttlSeconds) * 1000,
				source: plan.source,
				ips: campaign?.ips.slice(0, 20) ?? [incident.ip],
			};
			await tracker.addPatternRule(rule);
			return {
				id: rule.id,
				incidentId: incident.id,
				ip: incident.ip,
				kind: 'pattern_rule',
				action: rule.action,
				pattern: rule.pattern,
				flags: rule.flags,
				deployedAt: rule.deployedAt,
				expiresAt: rule.expiresAt,
				source: rule.source,
				// The key is owned by the tracker; revocation goes through it, not KV directly.
				keys: [],
			};
		} catch (error) {
			console.error('[commander] pattern rule publish failed:', (error as Error).message);
			return undefined;
		}
	}

	private async trackMitigation(mitigation: DeployedMitigation): Promise<void> {
		await this.ctx.storage.put(`${PREFIX_MITIGATION}${mitigation.id}`, mitigation);
		// Schedule the take-down. KV's expirationTtl is the backstop; this alarm is what
		// lets us also de-escalate the IP's stage and record the rollback.
		await this.scheduler.schedule('expire_mitigation', mitigation.expiresAt, { mitigationId: mitigation.id }, { id: mitigation.id });
	}

	private async buildBrief(
		incident: IncidentRecord,
		profile: IpProfile,
		classification: ReturnType<typeof classify>,
		decision: { stage: Stage; score: number },
		campaign?: CampaignSummary,
	): Promise<IncidentBrief> {
		const stored = await this.ctx.storage.list<SuspiciousEvent>({ prefix: PREFIX_EVENT, reverse: true, limit: 10 });
		// list(reverse) gives newest first; the Analyst reads better oldest-first.
		const events = [...stored.values()].reverse();

		return {
			incidentId: incident.id,
			ip: incident.ip,
			openedAt: incident.openedAt,
			// The number of requests we can actually show, not the number of events that
			// happened to trigger analysis — otherwise a 3-request burst reports "1 request".
			eventCount: Math.max(events.length, incident.eventCount),
			events,
			classification,
			classesSeen: incident.classesSeen,
			threatScore: decision.score,
			stage: decision.stage,
			priorIncidents: profile.totalIncidents,
			campaign,
		};
	}

	// =======================================================================
	// Cross-IP correlation + live feed
	// =======================================================================

	private async reportToCampaignTracker(
		event: SuspiciousEvent,
		classification: ReturnType<typeof classify>,
		now: number,
	): Promise<CampaignSummary | undefined> {
		if (classification.attackClass === 'unknown') return undefined;
		try {
			const tracker = this.env.CAMPAIGN_TRACKER.get(this.env.CAMPAIGN_TRACKER.idFromName('global'));
			const summary = await tracker.report({
				ip: event.ip,
				fingerprint: classification.fingerprint,
				attackClass: classification.attackClass,
				severity: classification.severity,
				pathTemplate: classification.pathTemplate,
				sampleIndicator: classification.indicators[0] ?? '',
				ts: now,
			});
			return summary ?? undefined;
		} catch (error) {
			// Correlation is an enhancement. Losing it must not stop us defending this IP.
			console.error('[commander] campaign report failed:', (error as Error).message);
			return undefined;
		}
	}

	private async publishToFeed(result: IngestResult): Promise<void> {
		if (result.stage === 'observe' && !result.triggeredAnalysis) return;
		try {
			const tracker = this.env.CAMPAIGN_TRACKER.get(this.env.CAMPAIGN_TRACKER.idFromName('global'));
			await tracker.publish({ type: 'ingest', at: Date.now(), data: result });
		} catch {
			// Dashboard-only. Never fatal.
		}
	}

	// =======================================================================
	// Background work (alarms)
	// =======================================================================

	async alarm(): Promise<void> {
		const now = Date.now();
		const due = await this.scheduler.claimDue(now);

		for (const job of due) {
			try {
				await this.runJob(job, now);
			} catch (error) {
				console.error(`[commander] job ${job.kind} failed:`, (error as Error).message);
			}
		}
		// Re-point the single alarm at whatever is next.
		await this.scheduler.sync();
	}

	private async runJob(job: Job, now: number): Promise<void> {
		switch (job.kind) {
			case 'gc':
				return this.collectGarbage(now);
			case 'close_incident':
				return this.closeIncidentIfIdle(now);
			case 'expire_mitigation':
				return this.expireMitigation((job.payload as { mitigationId?: string } | undefined)?.mitigationId);
			case 'decay':
				return this.decayTick(now);
		}
	}

	/** Drop events and dedupe markers we no longer need, keeping DO storage bounded. */
	private async collectGarbage(now: number): Promise<void> {
		const config = loadPolicy(this.env);
		const eventCutoff = now - config.burstWindowMs * EVENT_RETENTION_MULTIPLIER;

		const staleEvents = await this.ctx.storage.list({ prefix: PREFIX_EVENT, end: `${PREFIX_EVENT}${padTime(eventCutoff)}` });
		if (staleEvents.size) await this.ctx.storage.delete([...staleEvents.keys()]);

		const dedupeMarkers = await this.ctx.storage.list<number>({ prefix: PREFIX_DEDUPE, limit: 1000 });
		const expired = [...dedupeMarkers.entries()].filter(([, ts]) => now - ts > DEDUPE_RETENTION_MS).map(([key]) => key);
		if (expired.length) await this.ctx.storage.delete(expired);

		// Keep collecting only while there is still state worth collecting.
		const profile = await this.ctx.storage.get<IpProfile>(KEY_PROFILE);
		if (profile && profile.score > 0) await this.scheduler.scheduleIn('gc', GC_INTERVAL_MS);
	}

	private async closeIncidentIfIdle(now: number): Promise<void> {
		const config = loadPolicy(this.env);
		const incident = await this.ctx.storage.get<IncidentRecord>(KEY_OPEN_INCIDENT);
		if (!incident) return;

		if (now - incident.lastEventAt < config.incidentIdleTimeoutMs) {
			// Still active — check again when it could next go idle.
			await this.scheduler.schedule('close_incident', incident.lastEventAt + config.incidentIdleTimeoutMs, undefined, { dedupe: false });
			return;
		}

		incident.closedAt = now;
		incident.status = 'closed';
		await this.ctx.storage.put(`${PREFIX_INCIDENT}${padTime(incident.openedAt)}:${incident.id}`, incident);
		await this.ctx.storage.delete(KEY_OPEN_INCIDENT);

		// Only now does this count as a *prior* incident — which is what makes the next
		// one escalate faster. This is the Commander's long-term memory of an attacker.
		const profile = await this.ctx.storage.get<IpProfile>(KEY_PROFILE);
		if (profile) {
			profile.totalIncidents += 1;
			await this.ctx.storage.put(KEY_PROFILE, profile);
		}

		await recordIncident(this.env, incident);
		await audit(this.env, 'incident_closed', incident.ip, {
			incidentId: incident.id,
			eventCount: incident.eventCount,
			peakScore: incident.peakScore,
			durationMs: now - incident.openedAt,
		});
	}

	/**
	 * Take a mitigation back down when its clock runs out.
	 * Self-healing is the point: an attack that stops is forgiven automatically, so the
	 * block list does not grow forever and a shared NAT address is not blackholed for good.
	 */
	private async expireMitigation(mitigationId?: string): Promise<void> {
		if (!mitigationId) return;
		const key = `${PREFIX_MITIGATION}${mitigationId}`;
		const mitigation = await this.ctx.storage.get<DeployedMitigation>(key);
		if (!mitigation) return;

		if (mitigation.keys.length) await revokeMitigation(this.env, mitigation);
		await this.ctx.storage.delete(key);
		await markMitigationRevoked(this.env, mitigation.id, 'ttl expired');
		await audit(this.env, 'rule_revoked', mitigation.ip, { mitigationId: mitigation.id, kind: mitigation.kind, reason: 'ttl expired' });
	}

	/**
	 * Decay the threat score on a timer, and de-escalate when it drops far enough.
	 * Without this the score would only ever move when new traffic arrived, and an IP
	 * that went quiet would stay at its peak stage forever.
	 */
	private async decayTick(now: number): Promise<void> {
		const config = loadPolicy(this.env);
		const profile = await this.ctx.storage.get<IpProfile>(KEY_PROFILE);
		if (!profile || profile.score <= 0) return;

		const score = decayScore(profile.score, now - profile.scoredAt, config.scoreHalfLifeMs);
		const stage = stageForScore(score, config);
		const deEscalated = stageRank(stage) < stageRank(profile.stage);

		profile.score = score;
		profile.scoredAt = now;
		profile.stage = stage;
		await this.ctx.storage.put(KEY_PROFILE, profile);

		// Once an IP falls back below the enforcement threshold, lift what we deployed
		// early rather than waiting out the full TTL.
		if (deEscalated && stageRank(stage) < stageRank('challenge')) {
			const revoked = await this.revokeAll('threat score decayed below enforcement threshold');
			if (revoked) {
				await audit(this.env, 'rule_revoked', profile.ip, { revoked, reason: 'score decayed', score });
			}
		}

		if (score > 0) await this.scheduler.scheduleIn('decay', DECAY_INTERVAL_MS);
	}

	private async revokeAll(reason: string): Promise<number> {
		const mitigations = await this.ctx.storage.list<DeployedMitigation>({ prefix: PREFIX_MITIGATION });
		if (!mitigations.size) return 0;

		for (const mitigation of mitigations.values()) {
			if (mitigation.keys.length) await revokeMitigation(this.env, mitigation);
			if (mitigation.kind === 'pattern_rule') {
				try {
					const tracker = this.env.CAMPAIGN_TRACKER.get(this.env.CAMPAIGN_TRACKER.idFromName('global'));
					await tracker.removePatternRule(mitigation.id);
				} catch {
					// Tracker unavailable; the rule's own expiresAt still retires it.
				}
			}
			await markMitigationRevoked(this.env, mitigation.id, reason);
		}
		await this.ctx.storage.delete([...mitigations.keys()]);
		await this.scheduler.cancel('expire_mitigation');
		return mitigations.size;
	}
}
