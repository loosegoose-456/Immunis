/**
 * The Commander's client for the Analyst. OWNER: Member 2.
 *
 * Wraps Member 3's analyst with a timeout and a fallback, so the Commander always ends
 * up with a plan. Member 3 can deploy a half-finished analyst without breaking the
 * defence — the worst case is that we synthesize our own rule instead.
 *
 * It also flattens whatever reasoning happened into `AnalystStep[]`. Both paths produce
 * one, so the dashboard's reasoning panel is always showing real work: the model's tool
 * calls when the model answered, the synthesizer's candidates and validation verdicts
 * when it did not.
 */

import type { AnalystReport, AnalystStep, Env, IncidentBrief, MitigationPlan } from '../types';
import { runAnalystDetailed } from '../analyst';
import { AnalystError, type TraceEntry } from '../analyst/loop';
import { extractSignatureSamples } from './fingerprint';
import { fallbackPlan } from './fallback-plan';

/** Queue consumers have a wall-clock budget; we refuse to spend all of it on one model call. */
const ANALYST_TIMEOUT_MS = 10_000;

export interface AnalystOutcome {
	plan: MitigationPlan;
	/** Attack strings from this incident. Any proposed regex must match one of these. */
	proofSamples: string[];
	/** Set when we fell back — surfaced in the dashboard and the audit log. */
	degradedReason?: string;
	latencyMs: number;
	report: AnalystReport;
}

function withTimeout<T>(promise: Promise<T>, ms: number): Promise<T> {
	return Promise.race([
		promise,
		new Promise<never>((_, reject) => setTimeout(() => reject(new Error(`analyst timed out after ${ms}ms`)), ms)),
	]);
}

function truncate(value: string, max = 220): string {
	return value.length > max ? `${value.slice(0, max - 1)}…` : value;
}

/** Flatten the tool loop's trace into something a human can read at a glance. */
function describeTrace(trace: TraceEntry[]): AnalystStep[] {
	return trace.map((entry) => {
		const result = entry.result as Record<string, unknown> | undefined;
		const ok = result && typeof result === 'object' && 'ok' in result ? Boolean(result.ok) : undefined;

		let summary: string;
		if (entry.tool === 'propose' && ok) {
			const plan = (result as { plan?: MitigationPlan }).plan;
			summary = plan?.kind === 'pattern_rule' ? `proposed /${plan.pattern}/${plan.flags ?? ''} — ${plan.diagnosis}` : `proposed ${plan?.kind ?? 'a plan'} — ${plan?.diagnosis ?? ''}`;
		} else if (ok === false) {
			const reasons = (result as { reasons?: unknown }).reasons;
			summary = `refused: ${Array.isArray(reasons) ? reasons.join('; ') : 'invalid response'}`;
		} else if (entry.tool === 'inspect_incident') {
			summary = `read the incident evidence (${(result as { eventCount?: number })?.eventCount ?? 0} request(s))`;
		} else if (entry.tool === 'read_campaign') {
			summary = (result as { distributed?: boolean })?.distributed ? 'checked correlation: this fingerprint is distributed across addresses' : 'checked correlation: no distributed campaign';
		} else if (entry.tool === 'read_history') {
			summary = `read this address's history (${(result as { priorIncidents?: number })?.priorIncidents ?? 0} prior incident(s))`;
		} else {
			summary = `${entry.tool}`;
		}
		return { step: entry.step, tool: entry.tool, ok, summary: truncate(summary) };
	});
}

export async function requestPlan(env: Env, brief: IncidentBrief): Promise<AnalystOutcome> {
	const startedAt = Date.now();
	const proofSamples = brief.events.flatMap((event) => extractSignatureSamples(event, 2)).slice(0, 12);

	const degraded = (rawReason: string | undefined, modelTrace: AnalystStep[]): AnalystOutcome => {
		// Model errors arrive with a full stack trace; the dashboard wants the headline.
		const reason = rawReason ? rawReason.split('\n')[0].replace(/^Error:\s*/, '').slice(0, 160) : undefined;
		const { plan, steps } = fallbackPlan(brief, proofSamples);
		// Renumber so the model's attempt and the deterministic recovery read as one story.
		const trace = [...modelTrace, ...steps].map((entry, index) => ({ ...entry, step: index + 1 }));
		return {
			plan,
			proofSamples,
			degradedReason: reason,
			latencyMs: Date.now() - startedAt,
			report: { source: plan.source, latencyMs: Date.now() - startedAt, degradedReason: reason, trace },
		};
	};

	// ANALYST_MODE=fallback forces deterministic behaviour — useful when a flaky model
	// call would be worse than no model call at all.
	if ((env.ANALYST_MODE ?? 'auto').toLowerCase() === 'fallback') {
		return degraded('ANALYST_MODE=fallback', []);
	}

	try {
		const { plan, trace } = await withTimeout(runAnalystDetailed(env, brief), ANALYST_TIMEOUT_MS);
		if (!plan || typeof plan !== 'object') throw new Error('analyst returned no plan');
		const latencyMs = Date.now() - startedAt;
		return { plan, proofSamples, latencyMs, report: { source: plan.source, latencyMs, trace: describeTrace(trace) } };
	} catch (error) {
		// Keep whatever the model managed before it failed: a refused proposal is evidence.
		const partial = error instanceof AnalystError ? describeTrace(error.trace) : [];
		const degradedReason = (error as Error).message;
		console.warn(`[commander] analyst unavailable (${degradedReason}); synthesizing deterministically`);
		return degraded(degradedReason, partial);
	}
}
