import { useEffect, useRef } from "react"
import { motion, AnimatePresence } from "framer-motion"
import { ScrollArea } from "@/components/ui/scroll-area"
import { Badge } from "@/components/ui/badge"
import type { LogEntry } from "@/lib/types"

function clock(ms: number) {
  const d = new Date(ms)
  return d.toLocaleTimeString("en-US", { hour12: false, hour: "2-digit", minute: "2-digit", second: "2-digit", fractionalSecondDigits: 3 })
}

interface TrafficFeedProps {
  entries: LogEntry[]
  selectedId: string | null
  onSelect: (entry: LogEntry) => void
}

export function TrafficFeed({ entries, selectedId, onSelect }: TrafficFeedProps) {
  const scrollRef = useRef<HTMLDivElement>(null)

  useEffect(() => {
    if (scrollRef.current) {
      scrollRef.current.scrollTop = scrollRef.current.scrollHeight
    }
  }, [entries])

  return (
    <div className="flex flex-col bg-zinc-950 border border-zinc-800 rounded-lg overflow-hidden shadow-sm h-fit">
      <div className="flex items-center justify-between p-4 border-b border-zinc-800">
        <h2 className="text-sm font-semibold text-zinc-200">Live Threat Feed</h2>
        <Badge variant="outline" className="font-mono text-[10px]">{entries.length} events</Badge>
      </div>
      
      <div ref={scrollRef} className="flex-1 p-2 overflow-y-auto max-h-[80vh] scrollbar-thin scrollbar-thumb-zinc-800 scrollbar-track-transparent">
        <div className="flex flex-col gap-1 pb-4">
          <AnimatePresence initial={false}>
            {entries.map((entry) => {
              const isMalicious = entry.tone === 'danger' || entry.tone === 'warn' || entry.attackClass
              const isSelected = selectedId === entry.id
              
              return (
                <motion.div
                  key={entry.id}
                  initial={{ opacity: 0, x: -10 }}
                  animate={{ opacity: 1, x: 0 }}
                  onClick={() => onSelect(entry)}
                  className={`
                    group flex items-start gap-3 p-2.5 rounded-md cursor-pointer transition-all border text-xs font-mono
                    ${isSelected ? 'bg-zinc-900 border-zinc-700' : 'border-transparent hover:bg-zinc-900/50'}
                  `}
                >
                  <div className="w-20 shrink-0 text-zinc-500">{clock(entry.at)}</div>
                  
                  <div className="flex-1 min-w-0 break-words flex flex-col gap-1">
                    <div className="flex items-center gap-2 flex-wrap">
                      {entry.ip && <span className={isMalicious ? "text-rose-400" : "text-zinc-300"}>{entry.ip}</span>}
                      
                      {entry.attackClass && entry.kind !== 'edge' && (
                        <Badge variant="destructive" className="h-4 text-[9px] px-1 font-sans">{entry.attackClass.toUpperCase()}</Badge>
                      )}
                      
                      <span className={isMalicious ? "text-zinc-300" : "text-zinc-500"}>
                        {entry.text}
                      </span>
                    </div>

                    {(entry.detail || entry.stage) && (
                      <div className="flex items-center gap-2 mt-0.5">
                        {entry.stage && (
                          <Badge variant={entry.stage === 'block' ? 'success' : 'warning'} className="h-4 text-[9px] px-1 font-sans">
                            {entry.stage.toUpperCase()}
                          </Badge>
                        )}
                        {entry.detail && <span className="text-zinc-600 truncate">{entry.detail}</span>}
                        {entry.score !== undefined && <span className="text-zinc-500">score: {Math.round(entry.score)}</span>}
                      </div>
                    )}
                  </div>
                </motion.div>
              )
            })}
          </AnimatePresence>
        </div>
      </div>
    </div>
  )
}
