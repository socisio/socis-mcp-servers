# socis-mcp-servers

MCP servers SOCIS ships with the agent, forked from their upstreams so fixes
reach customers on our schedule rather than someone else's merge queue.

Each directory under `servers/` carries:

- `UPSTREAM.md` — source repo, the SHA we forked at, and why
- `PATCHES.md` — every SOCIS change: what, why, and the upstream PR if opened
- `LICENSE` — the upstream's original, unmodified

All current servers are MIT. See `NOTICE` for attribution.

## Working on a server

    cd servers/<name>
    npm ci && npm run build && npm test

Fix `src/`, never `dist/` — `dist` is generated and the next build reverts it.

## Why this exists

`threatintel_lookup_hash` shipped two one-line bugs: an extra segment in the
OTX path (404 on every hash) and a missing `Auth-Key` header on the
MalwareBazaar call (401 with a valid key). Both failed in the direction that
reads as "nothing is known about this indicator" rather than "the lookup was
wrong" — the worst way for security tooling to fail.
