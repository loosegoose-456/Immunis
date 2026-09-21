/**
 * Threat scoring and the escalation ladder. OWNER: Member 2.
 *
 * The Commander's judgement lives here, deliberately separated from the Durable Object
 * so it is pure, synchronous and unit-testable. Two ideas drive it:
 *
 *   - Score decays. An IP that attacked ten minutes ago and stopped is less dangerous
 *     than one attacking now, so the score has a half-life. This is what lets the system
 *     un-block on its own instead of accumulating blocks forever.
 *   - The Commander remembers. A repeat offender escalates on fewer events than a
 *     first-timer, because we already know what they are.
 */

import type { AttackClass, Classification, Env, IpProfile, Stage, SuspiciousEvent } from '../types';

export interface PolicyConfig {
	/** Suspicious events inside the window needed to open an incident. */
	burstThreshold: number;
	burstWindowMs: number;
	/** Time for a threat score to fall by half with no new activity. */
	scoreHalfLifeMs: number;
	/** Close an incident after this much silence. */
	incidentIdleTimeoutMs: number;
	/** Don't re-run the Analyst more often than this for one incident. */
	analysisCooldownMs: number;
	/** Distinct IPs on one fingerprint before we call it a distributed campaign. */
	campaignMinIps: number;
	campaignWindowMs: number;
	/** Score at which each stage begins. */
	thresholds: Record<Exclude<Stage, 'observe'>, number>;
}

export const DEFAULT_POLICY: PolicyConfig = {
	burstThreshold: 3,
	burstWindowMs: 60_000,
	scoreHalfLifeMs: 10 * 60_000,
	incidentIdleTimeoutMs: 120_000,
	analysisCooldownMs: 20_000,
	campaignMinIps: 3,
	campaignWindowMs: 10 * 60_000,
	thresholds: { monitor: 30, challenge: 60, block: 85 },
};

function intVar(raw: string | undefined, fallback: number): number {
	const parsed = Number.parseInt(raw ?? '', 10);
	return Number.isFinite(parsed) && parsed > 0 ? parsed : fallback;
}

export function loadPolicy(env: Env): PolicyConfig {
	return {
		...DEFAULT_POLICY,
		burstThreshold: intVar(env.BURST_THRESHOLD, DEFAULT_POLICY.burstThreshold),
		burstWindowMs: intVar(env.BURST_WINDOW_MS, DEFAULT_POLICY.burstWindowMs),
		scoreHalfLifeMs: intVar(env.SCORE_HALF_LIFE_MS, DEFAULT_POLICY.scoreHalfLifeMs),
		incidentIdleTimeoutMs: intVar(env.INCIDENT_IDLE_TIMEOUT_MS, DEFAULT_POLICY.incidentIdleTimeoutMs),
		campaignMinIps: intVar(env.CAMPAIGN_MIN_IPS, DEFAULT_POLICY.campaignMinIps),
	};
}

/** Exponential decay toward zero. Pure function of elapsed time. */
export function decayScore(score: number, elapsedMs: number, halfLifeMs: number): number {
	if (score <= 0 || elapsedMs <= 0) return Math.max(0, score);
	const decayed = score * Math.pow(0.5, elapsedMs / halfLifeMs);
	// Snap tiny residues to zero so an IP can actually return to a clean slate.
	return decayed < 0.5 ? 0 : Math.round(decayed * 100) / 100;
}

export function stageForScore(score: number, config: PolicyConfig): Stage {
	if (score >= config.thresholds.block) return 'block';
	if (score >= config.thresholds.challenge) return 'challenge';
	if (score >= config.thresholds.monitor) return 'monitor';
	return 'observe';
}

const STAGE_RANK: Record<Stage, number> = { observe: 0, monitor: 1, challenge: 2, block: 3 };

export function stageRank(stage: Stage): number {
	return STAGE_RANK[stage];
}

/** Repeat offenders escalate faster — capped so it can't run away. */
export function repeatMultiplier(priorIncidents: number): number {
	return Math.min(2, 1 + priorIncidents * 0.25);
}

/** A single event's contribution to the score, before decay. */
export function eventWeight(classification: Classification, priorIncidents: number): number {
	const base = classification.severity * classification.confidence;
	return Math.round(base * repeatMultiplier(priorIncidents) * 100) / 100;
}

export interface Decision {
	/** Score after decaying the old one and adding this event. */
	score: number;
	stage: Stage;
	previousStage: Stage;
	escalated: boolean;
	/** Open an incident and call the Analyst. */
	triggerAnalysis: boolean;
	reasons: string[];
}

/**
 * The core judgement call, made once per ingested event.
 *
 * Analysis fires on any of four signals, because attacks do not all look the same:
 *   - a burst: 3 suspicious requests in 1 minute, the project's documented trigger (volume),
 *   - crossing into a higher enforcement stage once an incident is already open (intensity),
 *   - a second distinct attack class from one IP (breadth — someone is probing for
 *     whatever sticks, which is worse than someone spraying one payload),
 *   - this event belonging to a *distributed campaign* (coordination).
 *
 * That last signal is the whole reason CampaignTracker exists. A botnet giving each
 * address a single request never trips a per-IP burst, so without it the one attack
 * shape we most want to stop is the one that never gets analysed.
 */
export function decide(input: {
	profile: IpProfile;
	classification: Classification;
	windowEventCount: number;
	now: number;
	config: PolicyConfig;
	incidentOpen: boolean;
	/** The global tracker has seen this fingerprint on enough distinct addresses. */
	campaignDistributed?: boolean;
}): Decision {
	const { profile, classification, windowEventCount, now, config, incidentOpen, campaignDistributed } = input;
	const reasons: string[] = [];

	const decayed = decayScore(profile.score, now - profile.scoredAt, config.scoreHalfLifeMs);
	if (profile.score > 0 && decayed < profile.score) {
		reasons.push(`decayed ${profile.score.toFixed(1)} -> ${decayed.toFixed(1)} over ${Math.round((now - profile.scoredAt) / 1000)}s`);
	}

	const weight = eventWeight(classification, profile.totalIncidents);
	const score = Math.min(200, Math.round((decayed + weight) * 100) / 100);
	reasons.push(
		`+${weight.toFixed(1)} from ${classification.attackClass} (severity ${classification.severity}, confidence ${classification.confidence.toFixed(2)})`,
	);
	if (profile.totalIncidents > 0) {
		reasons.push(`repeat offender x${repeatMultiplier(profile.totalIncidents).toFixed(2)} (${profile.totalIncidents} prior incidents)`);
	}

	const previousStage = profile.stage;
	let stage = stageForScore(score, config);

	// An operator pardon holds the IP at observe until it expires — human override wins.
	if (profile.pardonedUntil && profile.pardonedUntil > now) {
		reasons.push(`pardoned until ${new Date(profile.pardonedUntil).toISOString()}, enforcement suppressed`);
		stage = 'observe';
	}

	const escalated = stageRank(stage) > stageRank(previousStage);
	if (escalated) reasons.push(`escalated ${previousStage} -> ${stage}`);

	// Repeat offenders need one fewer event to trip the burst rule.
	const effectiveBurst = Math.max(2, config.burstThreshold - (profile.totalIncidents > 0 ? 1 : 0));
	const burst = windowEventCount >= effectiveBurst;
	if (burst) reasons.push(`burst: ${windowEventCount} events in ${Math.round(config.burstWindowMs / 1000)}s (threshold ${effectiveBurst})`);

	const newClass =
		classification.attackClass !== 'unknown' &&
		!profile.classesSeen.includes(classification.attackClass) &&
		profile.classesSeen.length > 0;
	if (newClass) reasons.push(`multi-vector: new attack class ${classification.attackClass} after ${profile.classesSeen.join(', ')}`);

	if (campaignDistributed) {
		reasons.push('part of a distributed campaign: the same fingerprint is live on several addresses');
	}

	const suppressed = stage === 'observe' && Boolean(profile.pardonedUntil && profile.pardonedUntil > now);
	const triggerAnalysis = !suppressed && (burst || newClass || Boolean(campaignDistributed) || (incidentOpen && escalated));

	return { score, stage, previousStage, escalated, triggerAnalysis, reasons };
}

export function emptyProfile(ip: string, now: number): IpProfile {
	return {
		ip,
		firstSeen: now,
		lastSeen: now,
		score: 0,
		scoredAt: now,
		stage: 'observe',
		totalEvents: 0,
		totalIncidents: 0,
		classesSeen: [],
	};
}

/** Enforcement TTL grows with how dangerous the class is and how often we've seen this IP. */
export function suggestedTtlSeconds(attackClass: AttackClass, priorIncidents: number): number {
	const base: Record<AttackClass, number> = {
		log4shell: 3600,
		rce: 3600,
		sqli: 1800,
		ssrf: 1800,
		path_traversal: 900,
		nosqli: 900,
		xss: 600,
		scanner: 300,
		unknown: 300,
	};
	return Math.min(24 * 3600, Math.round(base[attackClass] * repeatMultiplier(priorIncidents)));
}

/** Payload cap per stored event. DO values top out at 128KB; we stay far under. */
export const MAX_PAYLOAD_CHARS = 4096;

export function sanitizeEvent(raw: unknown, fallbackId: string): SuspiciousEvent | null {
	if (!raw || typeof raw !== 'object') return null;
	const candidate = raw as Record<string, unknown>;
	const ip = typeof candidate.ip === 'string' && candidate.ip.trim() ? candidate.ip.trim().slice(0, 64) : null;
	if (!ip) return null;

	const timestamp = typeof candidate.timestamp === 'number' && Number.isFinite(candidate.timestamp) ? candidate.timestamp : Date.now();
	const headers =
		candidate.headers && typeof candidate.headers === 'object'
			? Object.fromEntries(
					Object.entries(candidate.headers as Record<string, unknown>)
						.filter(([, v]) => typeof v === 'string')
						.slice(0, 24)
						.map(([k, v]) => [k.toLowerCase(), String(v).slice(0, 512)]),
				)
			: undefined;

	return {
		ip,
		url: typeof candidate.url === 'string' ? candidate.url.slice(0, 2048) : '/',
		method: typeof candidate.method === 'string' ? candidate.method.slice(0, 16).toUpperCase() : 'GET',
		payload: typeof candidate.payload === 'string' ? candidate.payload.slice(0, MAX_PAYLOAD_CHARS) : '',
		timestamp,
		userAgent: typeof candidate.userAgent === 'string' ? candidate.userAgent.slice(0, 512) : undefined,
		country: typeof candidate.country === 'string' ? candidate.country.slice(0, 8) : undefined,
		asn: typeof candidate.asn === 'number' ? candidate.asn : undefined,
		headers,
		eventId: typeof candidate.eventId === 'string' && candidate.eventId ? candidate.eventId.slice(0, 128) : fallbackId,
	};
}
