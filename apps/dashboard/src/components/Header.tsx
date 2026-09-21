import { Shield, Activity, Zap } from "lucide-react"

interface HeaderProps {
  connection: "live" | "offline" | "connecting"
  /** Latency of the most recent Analyst run, ms. Null until one has happened. */
  analystMs: number | null
}

export function Header({ connection, analystMs }: HeaderProps) {
  const status = {
    live: { label: "Edge Active", color: "bg-emerald-500", text: "text-emerald-400" },
    offline: { label: "Offline", color: "bg-rose-500", text: "text-rose-400" },
    connecting: { label: "Connecting", color: "bg-amber-500", text: "text-amber-400" },
  }[connection]

  return (
    <header className="flex h-14 items-center justify-between border-b border-zinc-800/80 bg-zinc-950/80 px-6 backdrop-blur-md">
      <div className="flex items-center gap-3">
        <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-zinc-900 border border-zinc-800 shadow-[0_0_15px_rgba(139,92,246,0.3)]">
          <Shield className="h-4 w-4 text-violet-400" />
        </div>
        <div className="flex flex-col">
          <span className="text-sm font-semibold tracking-wide text-zinc-100 flex items-center gap-2">
            IMMUNNIS <span className="text-zinc-600 font-normal">War Room</span>
          </span>
        </div>
      </div>

      <div className="flex items-center gap-6">
        <div className="flex items-center gap-2 rounded-full border border-zinc-800 bg-zinc-900/50 px-3 py-1 text-xs font-mono text-zinc-300">
          <span className={`h-2 w-2 rounded-full ${status.color} ${connection === 'live' ? 'animate-pulse-subtle' : ''}`} />
          <span className={status.text}>{status.label}</span>
          <span className="text-zinc-600">|</span>
          <span className="flex items-center gap-1" title="Latency of the last Blue Team analysis">
            <Zap className="h-3 w-3 text-zinc-500"/> {analystMs != null ? `${analystMs}ms` : '—'}
          </span>
        </div>
        
        <div className="flex items-center gap-3 border-l border-zinc-800 pl-6">
          <div className="text-right">
            <div className="text-xs font-medium text-zinc-200">SecOps</div>
            <div className="text-[10px] text-zinc-500 font-mono">admin@edge.immunnis.io</div>
          </div>
          <div className="h-8 w-8 rounded-full bg-zinc-800 border border-zinc-700 flex items-center justify-center overflow-hidden">
            <Activity className="h-4 w-4 text-zinc-400" />
          </div>
        </div>
      </div>
    </header>
  )
}
