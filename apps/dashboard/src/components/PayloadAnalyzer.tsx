import { motion } from "framer-motion"
import { Cpu, Database, Shield, ShieldCheck, ShieldX, Search } from "lucide-react"
import { Card } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import { ScrollArea } from "@/components/ui/scroll-area"
import type { AnalystStep, LogEntry } from "@/lib/types"

interface PayloadAnalyzerProps {
  entry: LogEntry | null
}

/** Icon + tone for one step of the Analyst's trace, driven by its real ok/tool fields. */
function stepStyle(step: AnalystStep): { color: string; Icon: typeof Shield } {
  if (step.ok === false) return { color: "text-rose-400", Icon: ShieldX }
  if (step.tool === "propose" || step.tool === "validate") return { color: "text-emerald-400", Icon: ShieldCheck }
  return { color: "text-zinc-400", Icon: Search }
}

export function PayloadAnalyzer({ entry }: PayloadAnalyzerProps) {
  if (!entry) {
    return (
      <div className="flex flex-col items-center justify-center h-full text-zinc-500 bg-zinc-950">
        <Shield className="h-12 w-12 mb-4 opacity-20" />
        <p>Select a request from the feed to inspect it</p>
      </div>
    )
  }

  const isThreat = entry.tone === "danger" || entry.tone === "warn" || !!entry.attackClass
  const evidence = entry.evidence
  const analyst = entry.analyst
  const confidencePct = entry.confidence != null ? Math.round(entry.confidence * 100) : null

  return (
    <div className="flex flex-col bg-zinc-950 p-4 gap-4 overflow-hidden border border-zinc-800 rounded-lg shadow-sm h-full">
      <div className="flex items-center justify-between shrink-0">
        <h2 className="text-sm font-semibold text-zinc-200 flex items-center gap-2">
          <Cpu className="h-4 w-4 text-zinc-100" />
          Payload Analyzer
        </h2>
        {analyst ? (
          <Badge variant="ai">{analyst.source.startsWith("workers-ai") ? "Workers AI" : "Synthesizer"} · {analyst.latencyMs}ms</Badge>
        ) : isThreat ? (
          <Badge variant="warning">Classified threat</Badge>
        ) : null}
      </div>

      {/* Identity + classification, from real fields */}
      <div className="grid grid-cols-2 gap-3 shrink-0">
        <Card className="p-3 bg-zinc-900/40">
          <div className="text-[10px] text-zinc-500 uppercase tracking-wider mb-1">Source</div>
          <div className="font-mono text-sm text-zinc-300 break-all">{entry.ip || "unknown"}</div>
          <div className="text-xs text-zinc-500 mt-1 font-mono break-all">
            {evidence ? `${evidence.method} ${evidence.target}` : entry.text}
          </div>
        </Card>
        <Card className="p-3 bg-zinc-900/40 relative overflow-hidden">
          <div className="text-[10px] text-zinc-500 uppercase tracking-wider mb-1">Classifier confidence</div>
          <div className="font-mono text-xl text-zinc-200">
            {confidencePct != null ? `${confidencePct}%` : "—"}
            {entry.attackClass && entry.attackClass !== "unknown" && (
              <span className="ml-2 text-xs text-rose-400 uppercase">{entry.attackClass}</span>
            )}
          </div>
          <div className="absolute bottom-0 left-0 h-1 bg-zinc-800 w-full">
            <motion.div
              className={`h-full ${isThreat ? "bg-rose-500" : "bg-emerald-500"}`}
              initial={{ width: 0 }}
              animate={{ width: `${confidencePct ?? 0}%` }}
              transition={{ duration: 0.6, ease: "easeOut" }}
            />
          </div>
        </Card>
      </div>

      {entry.indicators && entry.indicators.length > 0 && (
        <div className="flex flex-wrap gap-1.5 shrink-0">
          {entry.indicators.map((ind) => (
            <Badge key={ind} variant="destructive" className="text-[9px] h-5 px-1.5 font-mono">{ind}</Badge>
          ))}
        </div>
      )}

      {/* The real intercepted request */}
      <div className="flex flex-col gap-2">
        <div className="text-xs font-medium text-zinc-400">Intercepted request</div>
        <div className="bg-zinc-950 border border-zinc-800 rounded-md p-3 font-mono text-[11px] leading-relaxed">
          {evidence ? (
            <pre className="text-zinc-300 whitespace-pre-wrap break-all">
{`${evidence.method} ${evidence.target}
${evidence.userAgent ? `user-agent: ${evidence.userAgent}\n` : ""}
${evidence.payload || "(no body)"}`}
            </pre>
          ) : (
            <div className="text-zinc-600">No captured payload for this entry.</div>
          )}
        </div>
      </div>

      {/* The real analyst reasoning trace */}
      <div className="flex flex-col gap-2 flex-1 min-h-0">
        <div className="text-xs font-medium text-zinc-400 flex items-center gap-2">
          <Database className="h-3 w-3" />
          Blue Team reasoning
          {analyst?.degradedReason && (
            <span className="text-[10px] text-amber-400/80 font-mono normal-case">fallback: {analyst.degradedReason}</span>
          )}
        </div>
        <ScrollArea className="bg-zinc-950 border border-zinc-800 rounded-md p-3 font-mono text-[11px] leading-relaxed shadow-sm flex-1">
          {analyst ? (
            <div className="flex flex-col gap-2">
              {analyst.trace.map((step) => {
                const { color, Icon } = stepStyle(step)
                return (
                  <div key={step.step} className="flex items-start gap-2">
                    <Icon className={`h-3.5 w-3.5 mt-0.5 shrink-0 ${color}`} />
                    <div className="flex-1">
                      <span className="text-zinc-500">{step.tool}</span>
                      <span className="text-zinc-300"> — {step.summary}</span>
                    </div>
                  </div>
                )
              })}
              {analyst.validation && (
                <div className={`mt-1 pt-2 border-t border-zinc-800 ${analyst.validation.ok ? "text-emerald-400" : "text-rose-400"}`}>
                  {analyst.validation.ok ? "✓ " : "✗ "}
                  {analyst.validation.reasons.join("; ")}
                </div>
              )}
            </div>
          ) : entry.analysis ? (
            <div className="text-zinc-500">Analysis ran but no trace was attached.</div>
          ) : (
            <div className="text-zinc-600">
              This request was classified and scored but did not open an incident. Blue reasons only when an
              attack pattern warrants it — a burst, a stage escalation, a new attack class, or a distributed campaign.
            </div>
          )}
        </ScrollArea>
      </div>
    </div>
  )
}
