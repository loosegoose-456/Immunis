import { NextResponse } from 'next/server';

import type { RedTeamAction, RedTeamResponse, RedTeamResult } from '@/lib/types';

export const dynamic = 'force-dynamic';

/**
 * Fires demo traffic at the Orchestrator (the Shield) from the server side.
 *
 * Doing this from the browser would hide the interesting part: the Shield's 403 carries
 * no CORS headers, so a cross-origin fetch would just throw "Failed to fetch" and we
 * couldn't tell "blocked at the edge" from "orchestrator is down".
 */
const ORCHESTRATOR_URL = (process.env.ORCHESTRATOR_URL ?? process.env.NEXT_PUBLIC_ORCHESTRATOR_URL ?? 'http://127.0.0.1:8787').replace(/\/$/, '');

const BENIGN = { label: 'Benign login', form: { username: 'alice', password: 'correct-horse-battery' } };
// Numeric tautology + trailing comment: the origin's query becomes `... WHERE username = 'admin' OR 1=1 -- ' AND ...`.
// Picked for the Shield's classifier, not just the origin's parser: it trips two indicators (0.8 confidence, enough for a
// synthesized regex rule instead of a bare IP block), and the deterministic path covers it, so the demo
// still yields a rule when Workers AI is unavailable. A bare `' OR '1'='1` isn't recognised by the classifier at all.
const ATTACK = { label: 'SQLi login bypass', form: { username: "admin' OR 1=1 -- ", password: 'wrong' } };
const BURST_SIZE = 3; // the Commander opens an incident on 3 suspicious requests inside 60s
const BOTNET_SIZE = 4; // distinct source IPs sharing one fingerprint -> distributed campaign (min 3)

const IP_PATTERN = /^[0-9a-fA-F:.]{1,64}$|^unknown$/;

async function fire({ label, form }: { label: string; form: Record<string, string> }, sourceIp?: string): Promise<RedTeamResult> {
  const started = Date.now();
  try {
    const headers: Record<string, string> = { 'content-type': 'application/x-www-form-urlencoded' };
    // Simulate a botnet from one machine. The Shield only trusts this when the operator
    // set DEMO_ALLOW_SOURCE_SPOOF=true; otherwise it is ignored and the real caller stands.
    if (sourceIp) headers['x-demo-source-ip'] = sourceIp;
    const response = await fetch(`${ORCHESTRATOR_URL}/login`, {
      method: 'POST',
      headers,
      body: new URLSearchParams(form),
      redirect: 'manual',
      cache: 'no-store',
      signal: AbortSignal.timeout(8_000),
    });
    const text = await response.text();
    const ms = Date.now() - started;
    const base = { at: Date.now(), label, status: response.status, ms };

    if (response.status === 403) return { ...base, verdict: 'blocked', note: 'stopped at the edge — origin never saw it' };
    if (response.status === 200 && /"success"\s*:\s*true/.test(text)) return { ...base, verdict: 'breached', note: 'origin returned the admin token' };
    if (response.status === 401) return { ...base, verdict: 'rejected', note: 'origin rejected the credentials (normal)' };
    return { ...base, verdict: 'error', note: text.slice(0, 120).trim() || `unexpected HTTP ${response.status}` };
  } catch (error) {
    const reason = (error as Error).name === 'TimeoutError' ? 'timed out' : 'unreachable';
    return { at: Date.now(), label, status: 0, verdict: 'error', ms: Date.now() - started, note: `orchestrator ${reason} at ${ORCHESTRATOR_URL}` };
  }
}

async function resetIps(ips: string[]): Promise<{ ip: string; ok: boolean }[]> {
  return Promise.all(
    ips.map(async (ip) => {
      try {
        // Not percent-encoded on purpose: the Commander names its Durable Objects from the raw path
        // segment, so `%3A%3A1` would reset a different object than `::1`. `ip` is already validated.
        const response = await fetch(`${ORCHESTRATOR_URL}/commander/reset/${ip}`, {
          method: 'POST',
          cache: 'no-store',
          signal: AbortSignal.timeout(8_000),
        });
        return { ip, ok: response.ok };
      } catch {
        return { ip, ok: false };
      }
    }),
  );
}

export async function POST(request: Request): Promise<NextResponse<RedTeamResponse>> {
  let body: { action?: RedTeamAction; ips?: unknown; history?: any[] };
  try {
    body = await request.json();
  } catch {
    return NextResponse.json({ results: [], error: 'invalid JSON body' }, { status: 400 });
  }

  switch (body.action) {
    case 'benign':
      return NextResponse.json({ results: [await fire(BENIGN)] });
    case 'attack':
      return NextResponse.json({ results: [await fire(ATTACK)] });
    case 'burst': {
      // Sequential, so the results (and the Shield's queue order) are deterministic.
      const results: RedTeamResult[] = [];
      for (let i = 0; i < BURST_SIZE; i++) results.push(await fire({ ...ATTACK, label: `${ATTACK.label} ${i + 1}/${BURST_SIZE}` }));
      return NextResponse.json({ results });
    }
    case 'botnet': {
      // The same exploit from several distinct source IPs. No single address bursts, so
      // the only reason Blue reacts is cross-IP correlation: a distributed campaign, met
      // with a technique-level pattern rule rather than an IP block.
      const results: RedTeamResult[] = [];
      for (let i = 0; i < BOTNET_SIZE; i++) {
        const ip = `198.51.100.${10 + i}`;
        results.push(await fire({ ...ATTACK, label: `botnet ${ip}` }, ip));
      }
      return NextResponse.json({ results });
    }
    case 'reset': {
      const ips = (Array.isArray(body.ips) ? body.ips : []).filter((ip): ip is string => typeof ip === 'string' && IP_PATTERN.test(ip));
      // Always clear the loopback identities and the simulated attacker IPs, plus whatever
      // the dashboard has seen. Any reset also wipes the global tracker server-side, so the
      // room does not repopulate on reload.
      const simulated = ['203.0.113.50', ...Array.from({ length: BOTNET_SIZE }, (_, i) => `198.51.100.${10 + i}`)];
      const targets = [...new Set([...ips, '::1', '127.0.0.1', 'unknown', ...simulated])];
      return NextResponse.json({ results: [], reset: await resetIps(targets) });
    }
    case 'auto': {
      try {
        const agentRes = await fetch(`${ORCHESTRATOR_URL}/commander/red-agent`, {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({ history: body.history || [] }),
        });
        if (!agentRes.ok) {
          const errText = await agentRes.text();
          throw new Error(`Orchestrator returned ${agentRes.status}: ${errText}`);
        }
        const { thought, payload, source } = await agentRes.json();
        // Generate a random IP for this mutation so if the Blue Agent falls back to an IP Block,
        // it doesn't permanently kill the infinite demo loop.
        const dynamicIp = `203.0.113.${Math.floor(Math.random() * 254) + 1}`;
        const result = await fire({ label: 'AI Mutation', form: { username: payload, password: 'wrong' } }, dynamicIp);

        // Fire twice more to guarantee we cross the Commander's burst threshold (3 events).
        // This ensures the Blue AI wakes up and shows its reasoning on the dashboard!
        await Promise.all([
          fire({ label: 'AI Mutation 2/3', form: { username: payload, password: 'wrong' } }, dynamicIp),
          fire({ label: 'AI Mutation 3/3', form: { username: payload, password: 'wrong' } }, dynamicIp)
        ]);

        return NextResponse.json({ results: [{ ...result, thought, payload }] });
      } catch (e) {
        return NextResponse.json({ results: [], error: 'Red Agent failed: ' + (e as Error).message }, { status: 500 });
      }
    }
    default:
      return NextResponse.json({ results: [], error: 'action must be benign | attack | burst | botnet | auto | reset' }, { status: 400 });
  }
}
