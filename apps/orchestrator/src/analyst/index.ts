import type { Env, IncidentBrief, MitigationPlan } from '../types';
import { investigate, type TraceEntry } from './loop';

export const MODEL = '@cf/meta/llama-3.3-70b-instruct-fp8-fast';

function client(env: Env) {
  return {
    source: 'workers-ai:' + MODEL,
    complete: (messages: { role: string; content: string }[]) =>
      env.AI!.run(MODEL, { messages, max_tokens: 900, temperature: 0, stream: false }),
  };
}

/** Returns a plan only. Commander retains all deployment and fallback authority. */
export async function runAnalyst(env: Env, brief: IncidentBrief): Promise<MitigationPlan> {
  if (!env.AI) throw new Error('analyst_ai_unavailable');
  const result = await investigate(brief, client(env));
  return result.plan;
}

/**
 * Same investigation, but keeps the tool-loop trace.
 *
 * The Commander surfaces this in the live feed so an operator can see what the model
 * actually did — which tools it called, which proposals were refused and why. A trace
 * is also attached to failures (see `AnalystError`), because a rejected proposal is
 * the most interesting thing the Analyst produces.
 */
export async function runAnalystDetailed(env: Env, brief: IncidentBrief): Promise<{ plan: MitigationPlan; trace: TraceEntry[] }> {
  if (!env.AI) throw new Error('analyst_ai_unavailable');
  return investigate(brief, client(env));
}
