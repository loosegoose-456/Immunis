import type { AttackClass, Stage } from './types';

export const CLASS_COLORS: Record<AttackClass, string> = {
  sqli: '#ff5470',
  xss: '#ff9f43',
  path_traversal: '#ffd166',
  rce: '#e879f9',
  ssrf: '#a78bfa',
  nosqli: '#f472b6',
  log4shell: '#fb7185',
  scanner: '#7aa2ff',
  unknown: '#8b90a3',
};

export const STAGE_COLORS: Record<Stage, string> = {
  observe: '#8b90a3',
  monitor: '#ffb454',
  challenge: '#ff8a4c',
  block: '#ff5470',
};

export function classLabel(attackClass: AttackClass): string {
  return attackClass.replace(/_/g, ' ');
}

export function clock(at: number): string {
  return new Date(at).toLocaleTimeString([], { hour12: false });
}

/** "12m 04s", "45s" — or "expired". */
export function countdown(expiresAt: number, now: number): string {
  const remaining = Math.floor((expiresAt - now) / 1000);
  if (remaining <= 0) return 'expired';
  const h = Math.floor(remaining / 3600);
  const m = Math.floor((remaining % 3600) / 60);
  const s = remaining % 60;
  if (h > 0) return `${h}h ${String(m).padStart(2, '0')}m`;
  if (m > 0) return `${m}m ${String(s).padStart(2, '0')}s`;
  return `${s}s`;
}
