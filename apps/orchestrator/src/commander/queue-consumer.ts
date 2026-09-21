/**
 * ==========================================================================
 * MEMBER 2: QUEUE CONSUMER — the hand-off from The Shield.
 * ==========================================================================
 *
 * Member 1's edge worker pushes suspicious requests onto ANALYSIS_QUEUE and returns
 * immediately, so nothing here is on a user's critical path. That buys us the time to
 * do real work, and it means this handler's job is to be *correct*, not fast:
 *
 *   - Group by IP so each Durable Object is addressed once per batch, in order.
 *     Different IPs run in parallel; one IP's events stay sequential, because scoring
 *     an attack chain out of order gives the wrong answer.
 *   - Ack and retry per message, never per batch. Throwing would redeliver all ten
 *     messages and re-score the nine that already succeeded.
 *   - Drop poison messages instead of retrying them forever. A malformed body will
 *     never parse, so retrying it just burns the queue's retry budget.
 */

import type { Env, IngestResult, SuspiciousEvent } from '../types';
import { sanitizeEvent } from './policy';
import { audit } from './ledger';

/** Past this many attempts a message is a lost cause; record it and move on. */
const MAX_ATTEMPTS = 3;
/** Exponential backoff, capped. Queues take a delay in seconds. */
function backoffSeconds(attempts: number): number {
	return Math.min(60, 2 ** Math.max(0, attempts - 1));
}

export interface BatchOutcome {
	received: number;
	accepted: number;
	duplicates: number;
	retried: number;
	poisoned: number;
	triggered: number;
	results: IngestResult[];
}

export async function handleAnalysisBatch(batch: MessageBatch<unknown>, env: Env): Promise<BatchOutcome> {
	const outcome: BatchOutcome = { received: batch.messages.length, accepted: 0, duplicates: 0, retried: 0, poisoned: 0, triggered: 0, results: [] };

	// --- Validate and group ---
	const groups = new Map<string, { message: Message<unknown>; event: SuspiciousEvent }[]>();

	for (const message of batch.messages) {
		const event = sanitizeEvent(message.body, message.id);
		if (!event) {
			// Unparseable: no amount of retrying will fix it.
			outcome.poisoned += 1;
			console.warn(`[queue] dropping malformed message ${message.id}`);
			await audit(env, 'queue_poison', 'unknown', { messageId: message.id, attempts: message.attempts });
			message.ack();
			continue;
		}
		const group = groups.get(event.ip);
		if (group) group.push({ message, event });
		else groups.set(event.ip, [{ message, event }]);
	}

	// --- Fan out by IP, sequential within each IP ---
	const settled = await Promise.allSettled(
		[...groups.entries()].map(async ([ip, items]) => {
			const stub = env.INCIDENT_COMMANDER.get(env.INCIDENT_COMMANDER.idFromName(ip));
			const results: IngestResult[] = [];

			for (const { message, event } of items) {
				try {
					const result = await stub.ingest(event);
					results.push(result);

					if (result.duplicate) outcome.duplicates += 1;
					else if (result.accepted) outcome.accepted += 1;
					if (result.triggeredAnalysis) outcome.triggered += 1;

					message.ack();
				} catch (error) {
					const attempts = message.attempts ?? 1;
					if (attempts >= MAX_ATTEMPTS) {
						// Give up on this message, but keep the evidence.
						outcome.poisoned += 1;
						console.error(`[queue] giving up on ${message.id} after ${attempts} attempts:`, (error as Error).message);
						await audit(env, 'queue_poison', event.ip, { messageId: message.id, attempts, error: (error as Error).message });
						message.ack();
					} else {
						outcome.retried += 1;
						console.warn(`[queue] retrying ${message.id} (attempt ${attempts}):`, (error as Error).message);
						message.retry({ delaySeconds: backoffSeconds(attempts) });
					}
					// Stop processing this IP's remaining events: they are later in the
					// chain, and scoring them without their predecessor is worse than
					// letting the queue redeliver the whole tail.
					break;
				}
			}
			return results;
		}),
	);

	for (const entry of settled) {
		if (entry.status === 'fulfilled') outcome.results.push(...entry.value);
		else console.error('[queue] IP group failed:', entry.reason);
	}

	console.log(
		`[queue] batch: ${outcome.received} received, ${outcome.accepted} accepted, ${outcome.duplicates} duplicate, ` +
			`${outcome.triggered} triggered analysis, ${outcome.retried} retried, ${outcome.poisoned} dropped`,
	);
	return outcome;
}
