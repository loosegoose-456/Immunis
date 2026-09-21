/**
 * Append-only incident ledger on D1. OWNER: Member 2.
 *
 * Durable Object storage is the Commander's working memory — fast, per-IP, and pruned.
 * D1 is its long-term memory: a queryable history of every incident, every rule we
 * deployed, and every rule we *refused* to deploy. That last one matters, because
 * "the AI proposed `.*` and the Commander rejected it" is only provable if it's written down.
 *
 * Every write here is fail-soft. A ledger outage must never stop us from blocking an attack.
 */

import type { DeployedMitigation, Env, IncidentRecord, ValidationResult } from '../types';

async function safe<T>(label: string, operation: () => Promise<T>): Promise<T | undefined> {
	try {
		return await operation();
	} catch (error) {
		console.error(`[ledger] ${label} failed (non-fatal):`, (error as Error).message);
		return undefined;
	}
}

export async function recordIncident(env: Env, incident: IncidentRecord): Promise<void> {
	if (!env.INCIDENT_DB) return;
	await safe('recordIncident', () =>
		env.INCIDENT_DB!.prepare(
			`INSERT INTO incidents (id, ip, opened_at, last_event_at, closed_at, attack_class, fingerprint,
			                        event_count, peak_score, stage, status, analysis_count, summary)
			 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)
			 ON CONFLICT(id) DO UPDATE SET
			   last_event_at = excluded.last_event_at,
			   closed_at     = excluded.closed_at,
			   attack_class  = excluded.attack_class,
			   event_count   = excluded.event_count,
			   peak_score    = excluded.peak_score,
			   stage         = excluded.stage,
			   status        = excluded.status,
			   analysis_count= excluded.analysis_count,
			   summary       = excluded.summary`,
		)
			.bind(
				incident.id,
				incident.ip,
				incident.openedAt,
				incident.lastEventAt,
				incident.closedAt ?? null,
				incident.classesSeen[incident.classesSeen.length - 1] ?? 'unknown',
				incident.fingerprint,
				incident.eventCount,
				incident.peakScore,
				incident.stage,
				incident.status,
				incident.analysisCount,
				incident.summary ?? null,
			)
			.run(),
	);
}

export async function recordMitigation(env: Env, mitigation: DeployedMitigation, diagnosis: string, validation: ValidationResult): Promise<void> {
	if (!env.INCIDENT_DB) return;
	await safe('recordMitigation', () =>
		env.INCIDENT_DB!.prepare(
			`INSERT OR REPLACE INTO mitigations
			   (id, incident_id, ip, kind, action, pattern, flags, deployed_at, expires_at, revoked_at, source, diagnosis, validation)
			 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, NULL, ?10, ?11, ?12)`,
		)
			.bind(
				mitigation.id,
				mitigation.incidentId,
				mitigation.ip,
				mitigation.kind,
				mitigation.action,
				mitigation.pattern ?? null,
				mitigation.flags ?? null,
				mitigation.deployedAt,
				mitigation.expiresAt,
				mitigation.source,
				diagnosis,
				JSON.stringify(validation),
			)
			.run(),
	);
}

export async function markMitigationRevoked(env: Env, mitigationId: string, reason: string): Promise<void> {
	if (!env.INCIDENT_DB) return;
	await safe('markMitigationRevoked', () =>
		env.INCIDENT_DB!.prepare(`UPDATE mitigations SET revoked_at = ?1, revoke_reason = ?2 WHERE id = ?3`)
			.bind(Date.now(), reason, mitigationId)
			.run(),
	);
}

export type AuditKind =
	| 'event_ingested'
	| 'incident_opened'
	| 'incident_closed'
	| 'analysis_requested'
	| 'analysis_returned'
	| 'rule_rejected'
	| 'rule_deployed'
	| 'rule_revoked'
	| 'campaign_detected'
	| 'operator_pardon'
	| 'queue_poison';

export async function audit(env: Env, kind: AuditKind, ip: string, detail: Record<string, unknown>): Promise<void> {
	if (!env.INCIDENT_DB) return;
	await safe('audit', () =>
		env.INCIDENT_DB!.prepare(`INSERT INTO audit_log (ts, ip, kind, detail) VALUES (?1, ?2, ?3, ?4)`)
			.bind(Date.now(), ip, kind, JSON.stringify(detail).slice(0, 8000))
			.run(),
	);
}

export async function listIncidents(env: Env, limit = 25): Promise<unknown[]> {
	if (!env.INCIDENT_DB) return [];
	const result = await safe('listIncidents', () =>
		env.INCIDENT_DB!.prepare(`SELECT * FROM incidents ORDER BY opened_at DESC LIMIT ?1`).bind(Math.min(200, limit)).all(),
	);
	return result?.results ?? [];
}

export async function listAudit(env: Env, limit = 50): Promise<unknown[]> {
	if (!env.INCIDENT_DB) return [];
	const result = await safe('listAudit', () =>
		env.INCIDENT_DB!.prepare(`SELECT * FROM audit_log ORDER BY id DESC LIMIT ?1`).bind(Math.min(500, limit)).all(),
	);
	return result?.results ?? [];
}

/** Aggregate stats for the dashboard header. */
export async function summaryStats(env: Env): Promise<Record<string, unknown>> {
	if (!env.INCIDENT_DB) return { ledger: 'unavailable' };
	const result = await safe('summaryStats', async () => {
		const [incidents, mitigations, rejected] = await env.INCIDENT_DB!.batch([
			env.INCIDENT_DB!.prepare(`SELECT COUNT(*) AS n, COALESCE(SUM(event_count), 0) AS events FROM incidents`),
			env.INCIDENT_DB!.prepare(`SELECT COUNT(*) AS n FROM mitigations WHERE revoked_at IS NULL AND expires_at > ?1`).bind(Date.now()),
			env.INCIDENT_DB!.prepare(`SELECT COUNT(*) AS n FROM audit_log WHERE kind = 'rule_rejected'`),
		]);
		return {
			totalIncidents: (incidents.results?.[0] as { n?: number })?.n ?? 0,
			totalEvents: (incidents.results?.[0] as { events?: number })?.events ?? 0,
			activeMitigations: (mitigations.results?.[0] as { n?: number })?.n ?? 0,
			rulesRejected: (rejected.results?.[0] as { n?: number })?.n ?? 0,
		};
	});
	return result ?? { ledger: 'unavailable' };
}
