import * as React from "react"
import { cva, type VariantProps } from "class-variance-authority"
import { cn } from "@/lib/utils"

const badgeVariants = cva(
  "inline-flex items-center rounded-full border px-2.5 py-0.5 text-xs font-semibold transition-colors focus:outline-none focus:ring-2 focus:ring-ring focus:ring-offset-2",
  {
    variants: {
      variant: {
        default: "border-transparent bg-zinc-100 text-zinc-900 hover:bg-zinc-200",
        secondary: "border-transparent bg-zinc-800 text-zinc-100 hover:bg-zinc-800/80",
        destructive: "border-transparent bg-rose-500/20 text-rose-400 hover:bg-rose-500/30",
        outline: "text-zinc-100 border-zinc-700",
        success: "border-transparent bg-emerald-500/20 text-emerald-400 hover:bg-emerald-500/30",
        warning: "border-transparent bg-amber-500/20 text-amber-400 hover:bg-amber-500/30",
        ai: "border-transparent bg-violet-500/20 text-violet-400 hover:bg-violet-500/30",
      },
    },
    defaultVariants: {
      variant: "default",
    },
  }
)

export interface BadgeProps extends React.HTMLAttributes<HTMLDivElement>, VariantProps<typeof badgeVariants> {}

function Badge({ className, variant, ...props }: BadgeProps) {
  return (
    <div className={cn(badgeVariants({ variant }), className)} {...props} />
  )
}

export { Badge, badgeVariants }
