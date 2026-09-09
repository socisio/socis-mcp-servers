# SOCIS changes — cti-platform

Every deviation from upstream. If it is not listed here it should not exist.

| # | Change | Why | Upstream PR |
|---|--------|-----|-------------|
| 1 | Bump `@modelcontextprotocol/sdk` 0.6.0 → ^1.24.0 | The exact pin at 0.6.0 carried GHSA-w48q-cv73-mx4w (high, DNS rebinding). `npm audit fix` could not resolve it without a major bump, so it exited 1 and the install aborted entirely. Builds clean on 1.x with no source changes. | |
