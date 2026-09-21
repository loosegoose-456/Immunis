/**
 * Multi-job alarm scheduler for Durable Objects. OWNER: Member 2.
 *
 * A Durable Object has exactly one alarm, but the Commander needs several independent
 * timers running at once (garbage collection, incident timeout, mitigation expiry,
 * score decay). This keeps a durable, time-sorted job queue in storage and always
 * points the single alarm at the earliest due job.
 *
 * Keys sort lexicographically, so zero-padded timestamps give us a range scan for
 * "everything due now" without loading the whole queue.
 */

export type JobKind = 'gc' | 'close_incident' | 'expire_mitigation' | 'decay';

export interface Job<T = unknown> {
	kind: JobKind;
	dueAt: number;
	payload?: T;
}

const JOB_PREFIX = 'job:';
/** 16 digits covers epoch-ms well past the year 275760. */
const TIME_WIDTH = 16;

function padTime(ms: number): string {
	return Math.max(0, Math.floor(ms)).toString().padStart(TIME_WIDTH, '0');
}

function jobKey(dueAt: number, kind: JobKind, id?: string): string {
	// kind is part of the key, so scheduling the same recurring job twice for the same
	// millisecond replaces rather than duplicates it. `id` opts out of that collapsing
	// for jobs that carry distinct payloads (e.g. expiring two different mitigations).
	return id ? `${JOB_PREFIX}${padTime(dueAt)}:${kind}:${id}` : `${JOB_PREFIX}${padTime(dueAt)}:${kind}`;
}

export interface ScheduleOptions {
	/** Skip if a job of this kind is already pending. Default true. */
	dedupe?: boolean;
	/** Distinct id so same-millisecond jobs of one kind coexist. Implies dedupe: false. */
	id?: string;
}

export class AlarmScheduler {
	constructor(private readonly storage: DurableObjectStorage) {}

	/**
	 * Queue a job and move the alarm earlier if needed.
	 *
	 * `dedupe` (default true) drops the new job when one of the same kind is already
	 * pending, which keeps a flood of events from queueing a thousand identical GC runs.
	 */
	async schedule(kind: JobKind, dueAt: number, payload?: unknown, options: ScheduleOptions = {}): Promise<void> {
		const dedupe = options.id ? false : (options.dedupe ?? true);
		if (dedupe && (await this.hasPending(kind))) return;
		const job: Job = { kind, dueAt, payload };
		await this.storage.put(jobKey(dueAt, kind, options.id), job);
		await this.sync();
	}

	/** Schedule `delayMs` from now. */
	async scheduleIn(kind: JobKind, delayMs: number, payload?: unknown, options: ScheduleOptions = {}): Promise<void> {
		await this.schedule(kind, Date.now() + Math.max(0, delayMs), payload, options);
	}

	async hasPending(kind: JobKind): Promise<boolean> {
		const pending = await this.storage.list<Job>({ prefix: JOB_PREFIX });
		for (const job of pending.values()) {
			if (job.kind === kind) return true;
		}
		return false;
	}

	async cancel(kind: JobKind): Promise<void> {
		const pending = await this.storage.list<Job>({ prefix: JOB_PREFIX });
		const doomed: string[] = [];
		for (const [key, job] of pending) {
			if (job.kind === kind) doomed.push(key);
		}
		if (doomed.length) {
			await this.storage.delete(doomed);
			await this.sync();
		}
	}

	/** Claim every job due at or before `now`, removing them from the queue. */
	async claimDue(now: number): Promise<Job[]> {
		const due = await this.storage.list<Job>({
			prefix: JOB_PREFIX,
			// `end` is exclusive; `:￿` sorts after every job kind at this timestamp.
			end: `${JOB_PREFIX}${padTime(now)}:￿`,
		});
		if (due.size === 0) return [];
		await this.storage.delete([...due.keys()]);
		return [...due.values()];
	}

	async pending(): Promise<Job[]> {
		const jobs = await this.storage.list<Job>({ prefix: JOB_PREFIX });
		return [...jobs.values()].sort((a, b) => a.dueAt - b.dueAt);
	}

	/** Point the single DO alarm at the earliest pending job. */
	async sync(): Promise<void> {
		const jobs = await this.storage.list<Job>({ prefix: JOB_PREFIX, limit: 1 });
		const next = [...jobs.values()][0];
		const current = await this.storage.getAlarm();

		if (!next) {
			if (current !== null) await this.storage.deleteAlarm();
			return;
		}
		if (current === null || current > next.dueAt) {
			await this.storage.setAlarm(next.dueAt);
		}
	}
}
