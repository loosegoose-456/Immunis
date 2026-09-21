/**
 * Wire types for the Commander feed.
 *
 * Mirrors the contracts in apps/orchestrator/src/types.ts and commander/mitigation.ts.
 * Duplicated rather than imported because the orchestrator's types depend on
 * @cloudflare/workers-types, which the dashboard has no reason to install.
 */

export type AttackClass = 'sqli' | 'xss' | 'path_traversal' | 'rce' | 'ssrf' | 'nosqli' | 'log4shell' | 'scanner' | 'unknown';
export type Stage = 'observe' | 'monitor' | 'challenge' | 'block';
export type MitigationKind = 'block_ip' | 'pattern_rule' | 'rate_limit' | 'observe';
export type MitigationAction = 'block' | 'challenge' | 'log';

export interface Classification {
  attackClass: AttackClass;
  severity: number;
  confidence: number;
  indicators: string[];
  fingerprint: string;
  pathTemplate: string;
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
  keys: string[];
}

export interface AnalystStep {
  step: number;
  tool: string;
  ok?: boolean;
  summary: string;
}

export interface ValidationResult {
  ok: boolean;
  reasons: string[];
  falsePositives: string[];
}

export interface AnalystReport {
  source: string;
  latencyMs: number;
  degradedReason?: string;
  trace: AnalystStep[];
  validation?: ValidationResult;
}

export interface RequestEvidence {
  method: string;
  target: string;
  payload: string;
  userAgent?: string;
}

export interface EdgeBlockEvent {
  ip: string;
  method: string;
  target: string;
  reason: 'ip_block' | 'pattern_rule';
  ruleId?: string;
  pattern?: string;
  attackClass?: AttackClass;
}

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
  evidence?: RequestEvidence;
  analyst?: AnalystReport;
}

export interface CampaignSummary {
  fingerprint: string;
  attackClass: AttackClass;
  ipCount: number;
  eventCount: number;
  firstSeen: number;
  lastSeen: number;
  ips: string[];
  distributed: boolean;
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
  ips: string[];
}

/** Events broadcast over `/commander/stream`. */
export type FeedEvent =
  | { type: 'ingest'; at: number; data: IngestResult }
  | { type: 'campaign'; at: number; data: CampaignSummary }
  | { type: 'mitigation'; at: number; data: DeployedMitigation }
  | { type: 'edge_block'; at: number; data: EdgeBlockEvent }
  | { type: 'hello'; at: number; data: { campaigns: CampaignSummary[] } };

/** A row of GET /commander/incidents (D1 ledger). Only the fields we read. */
export interface IncidentRow {
  id: string;
  summary: string | null;
}

// ---------------------------------------------------------------------------
// Dashboard-side view models
// ---------------------------------------------------------------------------

export type Connection = 'connecting' | 'live' | 'offline';
export type Tone = 'info' | 'warn' | 'danger' | 'ok';

export interface LogEntry {
  id: string;
  at: number;
  kind: 'ingest' | 'campaign' | 'mitigation' | 'edge' | 'system';
  tone: Tone;
  text: string;
  ip?: string;
  attackClass?: AttackClass;
  stage?: Stage;
  score?: number;
  confidence?: number;
  detail?: string;
  analysis?: boolean;
  /** The real observed request, when this entry is a classified ingest. */
  evidence?: RequestEvidence;
  /** The Analyst's real reasoning trace, when this ingest ran analysis. */
  analyst?: AnalystReport;
  /** Matched indicator names, for the analyzer panel. */
  indicators?: string[];
}

export interface MitigationCard {
  id: string;
  kind: MitigationKind;
  action: MitigationAction;
  pattern?: string;
  flags?: string;
  ip: string;
  attackClass?: AttackClass;
  /** The Analyst's own explanation, when the rule list supplies one. */
  reason?: string;
  /** Commander's reasoning trail from the ingest that deployed this. */
  reasons?: string[];
  source: string;
  deployedAt: number;
  expiresAt: number;
  incidentId?: string;
}

// ---------------------------------------------------------------------------
// Red Team console (POST /api/red-team)
// ---------------------------------------------------------------------------

export type RedTeamAction = 'benign' | 'attack' | 'burst' | 'botnet' | 'reset' | 'auto';
export type Verdict = 'breached' | 'blocked' | 'rejected' | 'error';

export interface RedTeamResult {
  at: number;
  label: string;
  status: number;
  verdict: Verdict;
  ms: number;
  note: string;
  payload?: string;
  thought?: string;
}

export interface RedTeamResponse {
  results: RedTeamResult[];
  reset?: { ip: string; ok: boolean }[];
  error?: string;
}
