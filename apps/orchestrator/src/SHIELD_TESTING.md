# Shield and Analyst regression checks

From apps/orchestrator with Node 24:

```sh
node --import ./src/analyst/test-loader.mjs --test ./src/analyst/analyst.test.mjs ./src/shield.test.mjs
```

Expected: 48 passing tests (33 Analyst, 15 Shield). Tests use mocked KV, queue,
upstream fetch, and AI responses. The login test executes the target's vulnerable
query shape using Node's in-memory SQLite database; it does not start Express.
No network requests, deployment, or Cloudflare credentials are required.

## Required configuration

Set DEMO_UPSTREAM explicitly to your controlled target's HTTP(S) address. Locally,
this may be http://localhost:3001. A deployed Worker needs an address reachable
from that Worker, not your laptop's localhost. Missing or invalid configuration
returns 503; there is no third-party fallback.

The origin host remains fixed when request paths start with //; incoming pathname
and query are assigned separately. Origin redirects are returned to the caller
rather than automatically followed with incoming credentials.

## Review fixes

- Shield logic is extracted into shield.ts for direct testing. index.ts retains
  Commander routing, Durable Object exports, and the queue consumer.
- Shield uses Commander's classification instead of a separate keyword list.
  A quoted SQL-comment detector covers the target's comment-based login bypass.
- Blocking patterns are evaluated independently of earlier log/challenge rules.
  This does not implement challenge or logging actions themselves.
- The fabricated CVE lookup and its asynchronous callback were removed completely.
  search_cve is neither advertised nor dispatched; there is no lookup to hang.

These checks do not establish complete attack coverage, live model performance,
Workers runtime compatibility, or immediate KV propagation. Existing queue
acceptance remains awaited. Typechecking and deployed E2E verification are still
required. No credentials or deployment configuration were changed.
