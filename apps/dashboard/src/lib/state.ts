import type {
  AttackClass,
  CampaignSummary,
  Connection,
  DeployedMitigation,
  EdgeBlockEvent,
  FeedEvent,
  IncidentRow,
  LogEntry,
  MitigationCard,
  PatternRule,
  RedTeamResult,
  Stage,
} from './types';

const MAX_LOG = 300;
const MAX_EDGE_HISTORY = 12;

export interface State {
  connection: Connection;
  /** Oldest first, so the terminal reads top-to-bottom. */
  log: LogEntry[];
  /** Newest first. */
  mitigations: MitigationCard[];
  campaigns: Record<string, CampaignSummary>;
  incidentIds: string[];
  /** incidentId -> the Commander's plain-English diagnosis, from the D1 ledger when it's available. */
  diagnoses: Record<string, string>;
  detected: number;
  lastClassByIp: Record<string, AttackClass>;
  knownIps: string[];
  threat: { ip: string; score: number; stage: Stage; at: number } | null;
  /** Red Team console counters (sent/breached/rejected) plus its observed history. */
  edge: { sent: number; blocked: number; breached: number; rejected: number; history: RedTeamResult[] };
  /** Blocks the Shield itself reported over the feed, deduped by id. */
  edgeBlocks: Record<string, EdgeBlockEvent>;
}

export const initialState: State = {
  connection: 'connecting',
  log: [],
  mitigations: [],
  campaigns: {},
  incidentIds: [],
  diagnoses: {},
  detected: 0,
  lastClassByIp: {},
  knownIps: [],
  threat: null,
  edge: { sent: 0, blocked: 0, breached: 0, rejected: 0, history: [] },
  edgeBlocks: {},
};

export type Action =
  | { type: 'connection'; value: Connection; at: number }
  | { type: 'feed'; events: FeedEvent[] }
  | { type: 'rules'; rules: PatternRule[] }
  | { type: 'incidents'; rows: IncidentRow[] }
  | { type: 'edge'; results: RedTeamResult[] }
  | { type: 'clear' };

export function reducer(state: State, action: Action): State {
  switch (action.type) {
    case 'connection': {
      if (state.connection === action.value) return state;
      const next: State = { ...state, connection: action.value };
      // "connecting" is transient noise; only log the states an operator cares about.
      if (action.value === 'connecting') return next;
      const live = action.value === 'live';
      return {
        ...next,
        log: pushLog(state.log, {
          id: `sys:${action.at}:${action.value}`,
          at: action.at,
          kind: 'system',
          tone: live ? 'ok' : 'warn',
          text: live ? 'Connected to Commander stream' : 'Commander stream lost — retrying',
        }),
      };
    }
    case 'feed':
      return action.events.reduce(applyFeedEvent, state);
    case 'rules':
      return action.rules.reduce(
        (acc, rule) =>
          upsertMitigation(
            acc,
            {
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
            { attackClass: rule.attackClass, reason: rule.reason, silent: true },
          ),
        state,
      );
    case 'incidents': {
      const diagnoses = { ...state.diagnoses };
      for (const row of action.rows) if (row.summary) diagnoses[row.id] = row.summary;
      return {
        ...state,
        diagnoses,
        mitigations: state.mitigations.map((card) => (card.reason || !card.incidentId || !diagnoses[card.incidentId] ? card : { ...card, reason: diagnoses[card.incidentId] })),
      };
    }
    case 'edge':
      return applyEdgeResults(state, action.results);
    case 'clear':
      return { ...initialState, connection: state.connection, edgeBlocks: {} };
  }
}

// ---------------------------------------------------------------------------
// Feed events
// ---------------------------------------------------------------------------

function applyFeedEvent(state: State, event: FeedEvent): State {
  switch (event.type) {
    case 'hello':
      return { ...state, campaigns: mergeCampaigns(state.campaigns, event.data.campaigns) };

    case 'campaign': {
      const summary = event.data;
      const id = `campaign:${summary.fingerprint}:${event.at}`;
      const next = { ...state, campaigns: mergeCampaigns(state.campaigns, [summary]) };
      if (state.log.some((entry) => entry.id === id)) return next;
      return {
        ...next,
        log: pushLog(state.log, {
          id,
          at: event.at,
          kind: 'campaign',
          tone: 'danger',
          attackClass: summary.attackClass,
          text: `Distributed ${summary.attackClass} campaign — ${summary.ipCount} IPs sharing one fingerprint`,
        }),
      };
    }

    case 'mitigation':
      return upsertMitigation(state, event.data, {}, event.at);

    case 'edge_block': {
      const b = event.data;
      // The Shield can fire several 403s a second; dedupe by the request shape within
      // this timestamp so the counter tracks distinct blocks, not raw socket traffic.
      const id = `edge_block:${b.ip}:${b.target}:${event.at}`;
      if (state.edgeBlocks[id]) return state;
      const logId = `edgeblk:${id}`;
      const label = b.reason === 'pattern_rule' ? `pattern rule ${b.pattern ? `/${b.pattern.slice(0, 40)}/` : ''}` : 'IP block';
      return {
        ...state,
        edgeBlocks: { ...state.edgeBlocks, [id]: b },
        log: state.log.some((e) => e.id === logId)
          ? state.log
          : pushLog(state.log, {
              id: logId,
              at: event.at,
              kind: 'edge',
              tone: 'ok',
              ip: b.ip,
              attackClass: b.attackClass,
              text: `Blocked at edge — ${b.method} ${b.target} · ${label}`,
            }),
      };
    }

    case 'ingest': {
      const result = event.data;
      if (!result.accepted || result.duplicate) return state;
      const id = `ingest:${event.at}:${result.ip}:${result.score}`;
      if (state.log.some((entry) => entry.id === id)) return state;

      const c = result.classification;
      let next: State = {
        ...state,
        detected: state.detected + 1,
        lastClassByIp: c.attackClass === 'unknown' ? state.lastClassByIp : { ...state.lastClassByIp, [result.ip]: c.attackClass },
        knownIps: state.knownIps.includes(result.ip) ? state.knownIps : [...state.knownIps, result.ip],
        incidentIds: result.incidentId && !state.incidentIds.includes(result.incidentId) ? [...state.incidentIds, result.incidentId] : state.incidentIds,
        threat: !state.threat || event.at >= state.threat.at ? { ip: result.ip, score: result.score, stage: result.stage, at: event.at } : state.threat,
        log: pushLog(state.log, {
          id,
          at: event.at,
          kind: 'ingest',
          tone: result.stage === 'block' ? 'danger' : result.stage === 'observe' ? 'info' : 'warn',
          ip: result.ip,
          attackClass: c.attackClass,
          stage: result.stage,
          score: result.score,
          confidence: c.confidence,
          text: c.pathTemplate || '/',
          detail: c.indicators.slice(0, 4).join(' · ') || undefined,
          analysis: result.triggeredAnalysis,
          evidence: result.evidence,
          analyst: result.analyst,
          indicators: c.indicators,
        }),
      };
      if (result.mitigation) {
        next = upsertMitigation(next, result.mitigation, { attackClass: c.attackClass, reasons: result.reasons }, event.at);
      }
      return next;
    }
  }
}

function mergeCampaigns(current: Record<string, CampaignSummary>, incoming: CampaignSummary[]): Record<string, CampaignSummary> {
  const next = { ...current };
  for (const summary of incoming) next[summary.fingerprint] = summary;
  return next;
}

// ---------------------------------------------------------------------------
// Mitigations
// ---------------------------------------------------------------------------

interface MitigationExtras {
  attackClass?: AttackClass;
  reason?: string;
  reasons?: string[];
  /** Hydration from /commander/rules shouldn't announce itself in the live log. */
  silent?: boolean;
}

/**
 * The same mitigation reaches us up to three ways — a `mitigation` event, the `ingest`
 * result that deployed it, and /commander/rules — each carrying different fields.
 * Merge by id so the card ends up with the union.
 */
function upsertMitigation(state: State, m: DeployedMitigation, extra: MitigationExtras, at = m.deployedAt): State {
  const existing = state.mitigations.find((card) => card.id === m.id);
  const ip = m.ip || existing?.ip || '';
  const card: MitigationCard = {
    id: m.id,
    kind: m.kind,
    action: m.action,
    pattern: m.pattern ?? existing?.pattern,
    flags: m.flags ?? existing?.flags,
    ip,
    attackClass: extra.attackClass ?? existing?.attackClass ?? state.lastClassByIp[ip],
    reason: extra.reason ?? existing?.reason ?? (m.incidentId ? state.diagnoses[m.incidentId] : undefined),
    reasons: extra.reasons ?? existing?.reasons,
    source: m.source,
    deployedAt: m.deployedAt,
    expiresAt: m.expiresAt,
    incidentId: m.incidentId || existing?.incidentId,
  };

  if (existing) {
    return { ...state, mitigations: state.mitigations.map((c) => (c.id === card.id ? card : c)) };
  }

  const mitigations = [card, ...state.mitigations].sort((a, b) => b.deployedAt - a.deployedAt);
  if (extra.silent) return { ...state, mitigations };

  const what =
    card.kind === 'pattern_rule' && card.pattern
      ? `Rule deployed → ${card.action} /${card.pattern}/${card.flags ?? ''}`
      : `Edge ${card.action} deployed on ${card.ip || 'source IP'}`;
  return {
    ...state,
    mitigations,
    log: pushLog(state.log, {
      id: `mitigation:${card.id}`,
      at,
      kind: 'mitigation',
      tone: 'ok',
      ip: card.ip || undefined,
      attackClass: card.attackClass,
      text: what,
    }),
  };
}

// ---------------------------------------------------------------------------
// Red Team console
// ---------------------------------------------------------------------------

function applyEdgeResults(state: State, results: RedTeamResult[]): State {
  if (!results.length) return state;
  const edge = { ...state.edge };
  let log = state.log;
  for (const [index, result] of results.entries()) {
    edge.sent += 1;
    if (result.verdict === 'blocked') edge.blocked += 1;
    else if (result.verdict === 'breached') edge.breached += 1;
    else if (result.verdict === 'rejected') edge.rejected += 1;
    log = pushLog(log, {
      id: `edge:${result.at}:${index}`,
      at: result.at,
      kind: 'edge',
      tone: result.verdict === 'blocked' ? 'ok' : result.verdict === 'breached' ? 'danger' : result.verdict === 'error' ? 'warn' : 'info',
      text: `${result.label} → ${result.status || 'no response'} · ${result.note}`,
    });
  }
  edge.history = [...results].reverse().concat(edge.history).slice(0, MAX_EDGE_HISTORY);
  return { ...state, edge, log };
}

function pushLog(log: LogEntry[], entry: LogEntry): LogEntry[] {
  return [...log, entry].sort((a, b) => a.at - b.at).slice(-MAX_LOG);
}
