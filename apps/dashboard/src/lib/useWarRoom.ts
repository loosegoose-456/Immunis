'use client';

import { useCallback, useEffect, useMemo, useReducer } from 'react';

import { initialState, reducer } from './state';
import type { FeedEvent, IncidentRow, PatternRule, RedTeamResult } from './types';

/** Orchestrator (Shield + Commander). Inlined at build time — restart `next dev` after changing it. */
export const ORCHESTRATOR_URL = (process.env.NEXT_PUBLIC_ORCHESTRATOR_URL ?? 'http://127.0.0.1:8787').replace(/\/$/, '');
const STREAM_URL = `${ORCHESTRATOR_URL.replace(/^http/, 'ws')}/commander/stream`;

const PING_MS = 20_000;
const MAX_BACKOFF_MS = 5_000;

export function useWarRoom() {
  const [state, dispatch] = useReducer(reducer, initialState);

  /** Active rules carry the Analyst's reason and attack class, which the live events don't. */
  const refreshRules = useCallback(async () => {
    try {
      const response = await fetch(`${ORCHESTRATOR_URL}/commander/rules`);
      if (!response.ok) return;
      const body = (await response.json()) as { publishedToKv?: PatternRule[]; trackedInDurableObject?: PatternRule[] };
      dispatch({ type: 'rules', rules: body.trackedInDurableObject ?? body.publishedToKv ?? [] });
    } catch {
      // Enrichment only — the live stream still works without it.
    }
  }, []);

  /** The ledger's diagnosis for each incident. Needs the D1 tables (`npm run db:init`); silently absent otherwise. */
  const refreshIncidents = useCallback(async () => {
    try {
      const response = await fetch(`${ORCHESTRATOR_URL}/commander/incidents?limit=25`);
      if (!response.ok) return;
      const body = (await response.json()) as { incidents?: IncidentRow[] };
      if (body.incidents?.length) dispatch({ type: 'incidents', rows: body.incidents });
    } catch {
      // Enrichment only.
    }
  }, []);

  /** Replay recent history so a page refresh (or a dropped socket) doesn't blank the room. */
  const hydrate = useCallback(async () => {
    try {
      const response = await fetch(`${ORCHESTRATOR_URL}/commander/feed?limit=100`);
      if (response.ok) {
        const body = (await response.json()) as { feed?: FeedEvent[] };
        if (body.feed?.length) dispatch({ type: 'feed', events: body.feed });
      }
    } catch {
      // Orchestrator not up yet; the socket's reconnect loop will retry and hydrate on open.
    }
    await Promise.all([refreshRules(), refreshIncidents()]);
  }, [refreshRules, refreshIncidents]);

  useEffect(() => {
    let socket: WebSocket | null = null;
    let retryTimer: ReturnType<typeof setTimeout> | undefined;
    let pingTimer: ReturnType<typeof setInterval> | undefined;
    let attempts = 0;
    let disposed = false;

    const connect = () => {
      if (disposed) return;
      dispatch({ type: 'connection', value: 'connecting', at: Date.now() });
      const ws = new WebSocket(STREAM_URL);
      socket = ws;

      ws.onopen = () => {
        attempts = 0;
        dispatch({ type: 'connection', value: 'live', at: Date.now() });
        void hydrate();
        pingTimer = setInterval(() => {
          if (ws.readyState === WebSocket.OPEN) ws.send('ping');
        }, PING_MS);
      };

      ws.onmessage = (message) => {
        if (typeof message.data !== 'string' || message.data === 'pong') return;
        let event: FeedEvent;
        try {
          event = JSON.parse(message.data) as FeedEvent;
        } catch {
          return;
        }
        dispatch({ type: 'feed', events: [event] });
        if (event.type === 'mitigation' || (event.type === 'ingest' && event.data.mitigation)) {
          void refreshRules();
          void refreshIncidents();
        }
      };

      ws.onclose = () => {
        clearInterval(pingTimer);
        if (disposed) return;
        dispatch({ type: 'connection', value: 'offline', at: Date.now() });
        attempts += 1;
        retryTimer = setTimeout(connect, Math.min(MAX_BACKOFF_MS, 400 * 2 ** attempts));
      };

      // An error is always followed by close; route both through the same reconnect path.
      ws.onerror = () => ws.close();
    };

    connect();
    return () => {
      disposed = true;
      clearTimeout(retryTimer);
      clearInterval(pingTimer);
      socket?.close();
    };
  }, [hydrate, refreshRules, refreshIncidents]);

  const actions = useMemo(
    () => ({
      recordEdge: (results: RedTeamResult[]) => dispatch({ type: 'edge', results }),
      clear: () => dispatch({ type: 'clear' }),
      refreshRules,
    }),
    [refreshRules],
  );

  return { state, actions };
}
