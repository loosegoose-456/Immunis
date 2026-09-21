/**
 * Shared contracts for the Red vs. Blue engine.
 *
 * OWNER: Member 2 (The Commander). This file is the integration boundary between
 * all three members — change it only by agreement, since Member 1 produces
 * `SuspiciousEvent` and Member 3 consumes `IncidentBrief` / produces `MitigationPlan`.
 */

import type { IncidentCommander } from './commander/incident-commander';
import type { CampaignTracker } from './commander/campaign-tracker';

export interface Env {
	/** Rules read by Member 1 on the hot path. Written only by Member 2's mitigation module. */
	RULES_KV: KVNamespace;
	/** Member 1 -> Member 2 transport. */
	ANALYSIS_QUEUE: Queue<SuspiciousEvent>;
	/** One Durable Object per source IP. */
	INCIDENT_COMMANDER: DurableObjectNamespace<IncidentCommander>;
	/** Singleton Durable Object that correlates incidents across IPs. */
	CAMPAIGN_TRACKER: DurableObjectNamespace<CampaignTracker>;

	/** Append-only incident ledger. Optional: every write is fail-soft. */
	INCIDENT_DB?: D1Database;
	/** Member 3: similarity search over known attack signatures. */
	ATTACK_VECTORS?: VectorizeIndex;
	/** Member 3: Workers AI. Kept structural so we don't pin a types version. */
	AI?: { run(model: string, input: Record<string, unknown>): Promise<unknown> };

	/** If set, `/commander/*` routes require `X-Commander-Key`. Unset = open (local dev). */
	COMMANDER_API_KEY?: string;
	/**
	 * "auto" (default) tries the Workers AI Analyst and falls back on any failure.
	 * "fallback" skips the model entirely and uses the deterministic synthesizer.
	 * Those are the only two values the code implements.
	 */
	ANALYST_MODE?: string;
	/**
	 * Demo affordance: when "true", the Shield trusts an `x-demo-source-ip` header so the
	 * Red Team console can simulate a botnet from one machine. Cloudflare overwrites
	 * `cf-connecting-ip`, so without this a deployed demo collapses every simulated
	 * attacker into one address. Turn it off for anything that is not a demo.
	 */
	DEMO_ALLOW_SOURCE_SPOOF?: string;

	// Policy tuning, all optional (see commander/policy.ts for defaults).
	BURST_THRESHOLD?: string;
	BURST_WINDOW_MS?: string;
	SCORE_HALF_LIFE_MS?: string;
	INCIDENT_IDLE_TIMEOUT_MS?: string;
	CAMPAIGN_MIN_IPS?: string;
	DEMO_UPSTREAM?: string;
}

// ---------------------------------------------------------------------------
// Member 1 -> Member 2
// ---------------------------------------------------------------------------

/** What The Shield pushes onto ANALYSIS_QUEUE. Only `ip` is strictly required. */
export interface SuspiciousEvent {
	ip: string;
	url: string;
	method: string;
	payload: string;
	timestamp: number;
	/** Optional enrichment. Supply these if you can — they sharpen classification. */
	userAgent?: string;
	country?: string;
	asn?: number;
	headers?: Record<string, string>;
	/** Stable id used for exactly-once ingestion. Defaults to the queue message id. */
	eventId?: string;
}

// ---------------------------------------------------------------------------
// Classification (Member 2, commander/fingerprint.ts)
// ---------------------------------------------------------------------------

export type AttackClass =
	| 'sqli'
	| 'xss'
	| 'path_traversal'
	| 'rce'
	| 'ssrf'
	| 'nosqli'
	| 'log4shell'
	| 'scanner'
	| 'unknown';

export interface Classification {
	attackClass: AttackClass;
	/** 0-100 baseline severity for this class. */
	severity: number;
	/** 0-1, how sure we are. Rises with the number of independent indicators. */
	confidence: number;
	/** Human-readable matched indicators, e.g. `union select`. */
	indicators: string[];
	/** Stable hash of the *shape* of the attack — identical across IPs and literals. */
	fingerprint: string;
	/** Request path with ids normalized, e.g. `/api/users/:id`. */
	pathTemplate: string;
}

// ---------------------------------------------------------------------------
// Member 2 -> Member 3
// ---------------------------------------------------------------------------

/** Everything The Analyst needs to diagnose an incident. */
export interface IncidentBrief {
	incidentId: string;
	ip: string;
	openedAt: number;
	eventCount: number;
	/** Most recent events, newest last. Payloads are truncated. */
	events: SuspiciousEvent[];
	classification: Classification;
	/** Distinct attack classes seen on this IP during the incident. */
	classesSeen: AttackClass[];
	threatScore: number;
	stage: Stage;
	/** How many separate incidents this IP has caused before. Drives repeat-offender logic. */
	priorIncidents: number;
	/** Set when the same fingerprint is active on several IPs at once. */
	campaign?: CampaignSummary;
}

export type MitigationKind = 'block_ip' | 'pattern_rule' | 'rate_limit' | 'observe';
export type MitigationAction = 'block' | 'challenge' | 'log';

/** What The Analyst returns. Member 2 validates and applies it — Member 3 does not write KV. */
export interface MitigationPlan {
	kind: MitigationKind;
	action: MitigationAction;
	/** Required for `pattern_rule`: a JS regex source string. */
	pattern?: string;
	/** Regex flags, e.g. "i". `g` and `y` are stripped (stateful lastIndex). */
	flags?: string;
	ttlSeconds: number;
	attackClass: AttackClass;
	/** One or two sentences, shown in the dashboard. */
	diagnosis: string;
	confidence: number;
	/** "workers-ai" | "heuristic" | "vectorize-match" | ... */
	source: string;
}

export interface ValidationResult {
	ok: boolean;
	reasons: string[];
	/** Benign corpus entries the proposed rule would have falsely blocked. */
	falsePositives: string[];
}

/**
 * One step of the Analyst's reasoning, flattened for the dashboard.
 *
 * The LLM path fills this from the tool loop's trace (`inspect_incident`, `propose`,
 * a rejection, a revised proposal). The deterministic path fills it from the
 * synthesizer's candidate/validation steps. Either way the UI shows real work —
 * it never renders text that the engine did not actually produce.
 */
export interface AnalystStep {
	step: number;
	tool: string;
	ok?: boolean;
	/** Human-readable one-liner. Already truncated; safe to render verbatim. */
	summary: string;
}

/** What the Commander learned by asking the Analyst. Surfaced in the feed. */
export interface AnalystReport {
	/** `workers-ai:<model>` when the LLM answered, `commander-synthesizer` otherwise. */
	source: string;
	latencyMs: number;
	/** Present when the LLM path failed and the deterministic path answered instead. */
	degradedReason?: string;
	trace: AnalystStep[];
	validation?: ValidationResult;
}

/** The request that was actually observed, for the dashboard's payload panel. */
export interface RequestEvidence {
	method: string;
	/** Path + query only; the host is ours and is not evidence. */
	target: string;
	/** Request body, truncated and shown verbatim. */
	payload: string;
	userAgent?: string;
}

/**
 * A request the Shield refused at the edge, reported off the hot path.
 * Without this the dashboard can only count blocks the Red Team console saw itself.
 */
export interface EdgeBlockEvent {
	ip: string;
	method: string;
	target: string;
	/** Which enforcement layer stopped it. */
	reason: 'ip_block' | 'pattern_rule';
	ruleId?: string;
	pattern?: string;
	attackClass?: AttackClass;
}

// ---------------------------------------------------------------------------
// Commander state
// ---------------------------------------------------------------------------

export type Stage = 'observe' | 'monitor' | 'challenge' | 'block';

export interface IpProfile {
	ip: string;
	firstSeen: number;
	lastSeen: number;
	/** Decayed threat score, 0-100+. */
	score: number;
	/** Timestamp `score` was last decayed to. */
	scoredAt: number;
	stage: Stage;
	totalEvents: number;
	totalIncidents: number;
	classesSeen: AttackClass[];
	lastFingerprint?: string;
	country?: string;
	/** Manually pardoned by an operator; suppresses re-escalation until it expires. */
	pardonedUntil?: number;
}

export interface IncidentRecord {
	id: string;
	ip: string;
	openedAt: number;
	lastEventAt: number;
	closedAt?: number;
	eventCount: number;
	peakScore: number;
	stage: Stage;
	classesSeen: AttackClass[];
	fingerprint: string;
	status: 'open' | 'analyzing' | 'mitigated' | 'closed';
	analysisCount: number;
	lastAnalysisAt?: number;
	plan?: MitigationPlan;
	validation?: ValidationResult;
	summary?: string;
}

export interface DeployedMitigation {
	id: string;
	incidentId: string;
	ip: string;
	kind: MitigationKind;
	action: MitigationAction;
	pattern?: string;
	flags?: string;
	deployedAt: number;
	expiresAt: number;
	source: string;
	/** KV keys written, so we can revoke precisely. */
	keys: string[];
}

/** Returned by `IncidentCommander.ingest` — also what the live dashboard feed carries. */
export interface IngestResult {
	ip: string;
	accepted: boolean;
	duplicate: boolean;
	score: number;
	stage: Stage;
	classification: Classification;
	incidentId?: string;
	triggeredAnalysis: boolean;
	mitigation?: DeployedMitigation;
	reasons: string[];
	/** The observed request. Lets the dashboard show the real payload, not a mock. */
	evidence?: RequestEvidence;
	/** Set whenever this ingest ran the Analyst. */
	analyst?: AnalystReport;
}

export interface CommanderSnapshot {
	profile: IpProfile;
	openIncident?: IncidentRecord;
	recentIncidents: IncidentRecord[];
	activeMitigations: DeployedMitigation[];
	windowEventCount: number;
	nextAlarmAt: number | null;
	scheduledJobs: { kind: string; dueAt: number }[];
}

// ---------------------------------------------------------------------------
// Cross-IP correlation
// ---------------------------------------------------------------------------

export interface CampaignSignal {
	ip: string;
	fingerprint: string;
	attackClass: AttackClass;
	severity: number;
	pathTemplate: string;
	sampleIndicator: string;
	ts: number;
}

export interface CampaignSummary {
	fingerprint: string;
	attackClass: AttackClass;
	ipCount: number;
	eventCount: number;
	firstSeen: number;
	lastSeen: number;
	ips: string[];
	/** True once the distinct-IP threshold is crossed: block the pattern, not the IPs. */
	distributed: boolean;
}

/** Events broadcast over the `/commander/stream` WebSocket. */
export type FeedEvent =
	| { type: 'ingest'; at: number; data: IngestResult }
	| { type: 'campaign'; at: number; data: CampaignSummary }
	| { type: 'mitigation'; at: number; data: DeployedMitigation }
	| { type: 'edge_block'; at: number; data: EdgeBlockEvent }
	| { type: 'hello'; at: number; data: { campaigns: CampaignSummary[] } };
