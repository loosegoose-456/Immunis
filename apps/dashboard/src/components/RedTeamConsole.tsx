'use client';

import { useState, useEffect } from 'react';
import { clock } from '@/lib/format';
import type { RedTeamAction, RedTeamResponse, RedTeamResult, Verdict } from '@/lib/types';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { ScrollArea } from '@/components/ui/scroll-area';
import { AlertCircle, Terminal, BrainCircuit } from 'lucide-react';

const VERDICT: Record<Verdict, { label: string; color: string; variant: any }> = {
  breached: { label: 'breached', color: 'text-rose-500', variant: 'destructive' },
  blocked: { label: 'blocked', color: 'text-emerald-500', variant: 'success' },
  rejected: { label: 'rejected', color: 'text-zinc-400', variant: 'secondary' },
  error: { label: 'error', color: 'text-amber-500', variant: 'warning' },
};

interface Props {
  history: RedTeamResult[];
  knownIps: string[];
  onResults: (results: RedTeamResult[]) => void;
  onReset: () => void;
  busy: RedTeamAction | null;
  error: string | null;
  autoRun: boolean;
  autoIterations: number;
  run: (action: RedTeamAction, autoHistory?: { payload: string; result: string }[]) => Promise<any>;
  setAutoRun: (v: boolean) => void;
  setAutoIterations: (v: number) => void;
}

export function RedTeamConsole({ history, knownIps, onResults, onReset, busy, error, autoRun, autoIterations, run, setAutoRun, setAutoIterations }: Props) {
  const disabled = busy !== null;

  return (
    <div className="flex flex-col gap-4">
      <div className="flex items-center gap-2 text-xs text-zinc-500 font-mono mb-2">
        <Terminal className="h-3 w-3" />
        <span>→ Shield :8787 → Origin :3001</span>
      </div>

      <div className="grid grid-cols-3 gap-2">
        <Button variant="secondary" size="sm" disabled={disabled} onClick={() => run('benign')} className="text-xs">
          {busy === 'benign' ? 'Sending…' : 'Benign login'}
        </Button>
        <Button variant="destructive" size="sm" disabled={disabled} onClick={() => run('attack')} className="text-xs">
          {busy === 'attack' ? 'Sending…' : 'SQLi attack'}
        </Button>
        <Button variant="outline" size="sm" disabled={disabled} onClick={() => run('burst')} className="text-xs border-zinc-800 hover:bg-zinc-900 hover:text-zinc-100">
          {busy === 'burst' ? 'Firing…' : 'Burst ×3'}
        </Button>
      </div>

      <Button variant="outline" size="sm" disabled={disabled} onClick={() => run('botnet')}
        className="w-full text-xs border-zinc-800 hover:bg-zinc-900 hover:text-zinc-100 gap-2 mt-[-8px]">
        {busy === 'botnet' ? 'Spraying…' : 'Botnet ×4 (distributed campaign)'}
      </Button>

      <div className="flex gap-2">
        <Button
          variant="outline"
          size="sm"
          onClick={() => { setAutoIterations(0); setAutoRun(true); }}
          disabled={disabled || autoRun}
          className="flex-1 border-zinc-800 hover:bg-zinc-900 hover:text-zinc-100 gap-2"
        >
          <BrainCircuit className="h-4 w-4" />
          {autoRun ? `Red agent attacking… (${autoIterations})` : 'Unleash AI (adaptive attacker)'}
        </Button>
        {autoRun && (
          <Button
            variant="destructive"
            size="sm"
            onClick={() => setAutoRun(false)}
            className="shrink-0"
          >
            Terminate
          </Button>
        )}
      </div>

      <div className="text-[11px] text-zinc-500 leading-relaxed bg-zinc-900/50 p-3 rounded-md border border-zinc-800">
        <strong>Burst ×3</strong> then wait ~3s for Blue to synthesize a rule, then <strong>SQLi attack</strong> to see the edge block it.
        <strong> Botnet</strong> sprays one exploit from 4 IPs to trip distributed-campaign detection.
        <strong> Unleash AI</strong> mutates its payload against whatever Blue deploys.{' '}
        <button className="underline hover:text-zinc-300 ml-1" disabled={disabled} onClick={() => run('reset')}>
          {busy === 'reset' ? 'Resetting…' : 'Reset demo'}
        </button>
      </div>

      {error && (
        <div className="flex items-center gap-2 text-xs text-rose-400 bg-rose-950/40 p-2 rounded border border-rose-900/50">
          <AlertCircle className="h-4 w-4" />
          {error}
        </div>
      )}

      {history.length > 0 && (
        <ScrollArea className="h-40 border border-zinc-800 rounded-md bg-zinc-950 p-2">
          <ul className="flex flex-col gap-1">
            {history.slice(0, 5).map((r, i) => (
              <li key={`${r.at}:${i}`} className="flex items-start gap-2 p-2 hover:bg-zinc-900/50 rounded font-mono text-[10px]">
                <Badge variant={VERDICT[r.verdict].variant} className="h-4 px-1 rounded-sm shrink-0 uppercase text-[9px]">
                  {r.status || '—'} {VERDICT[r.verdict].label}
                </Badge>
                <span className="flex-1 text-zinc-400 break-words">
                  {r.label} · <span className="text-zinc-500">{r.note}</span>
                  {r.thought && (
                    <div className="mt-1 pl-2 border-l border-zinc-800 text-zinc-400 italic text-[11px]">
                      "{r.thought}"
                    </div>
                  )}
                  {r.payload && (
                    <div className="mt-1 pl-2 font-mono text-[9px] text-rose-400/80">
                      {r.payload}
                    </div>
                  )}
                </span>
                <span className="shrink-0 text-zinc-600">
                  {r.ms}ms
                </span>
              </li>
            ))}
          </ul>
        </ScrollArea>
      )}
    </div>
  );
}
