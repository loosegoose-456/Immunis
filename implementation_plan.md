Replace the current dasshboard and build a Next.js 15, Tailwind CSS, and TypeScript dashboard for a cybersecurity application named "Immunnis". 

I want to avoid generic, blocky "AI-generated" designs. The UI must look like a premium, enterprise-grade developer tool (think Vercel, Linear, or Stripe).

Setup Instructions for the Agent:
1. Initialize a new Next.js project with the App Router.
2. Install and configure `shadcn/ui`. Add the following components: card, badge, button, table, scroll-area, and dialog.
3. Install `lucide-react` for iconography and `framer-motion` for fluid animations.
4. Enforce a strict "Dark Mode Only" theme. The background should be a very dark slate (e.g., bg-zinc-950), with subtle 1px borders (border-zinc-800) and glowing accent colors for alerts.

Architecture of the "War Room" Dashboard:
- Header: Minimalist top nav with the "Immunnis" logo (use a shield icon), live system status (pulsing green dot for "Edge Active"), and a mock user profile.
- Left Panel (Live Traffic Feed): A scrolling `scroll-area` showing incoming HTTP requests. Normal traffic is muted text. Anomalous traffic flashes red/orange before being intercepted.
- Center Panel (The Payload Analyzer): When a malicious payload is clicked in the feed, this panel displays a mock JSON of the payload, the Vectorize similarity score, and a "typing" animation showing the LLM synthesizing the regex rule. 
- Right Panel (Active Mitigations): A table showing the active WAF regex rules deployed to Cloudflare KV, with a "Block Rate" metric.

Agent Execution:
Please generate the structured implementation plan. Once approved, use the Terminal to install all dependencies and the Browser Sub-Agent to visually verify that the dark mode and Framer Motion animations are rendering correctly without hydration errors.