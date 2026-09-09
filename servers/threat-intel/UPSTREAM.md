# Upstream — threat-intel

- Repository: https://github.com/aplaceforallmystuff/mcp-threatintel
- Forked at SHA: b71210b2e21766411de858844c1c864291630f30
- Date forked: 2026-09-09
- Licence: MIT (preserved unmodified in LICENSE)

## Why forked

Aggregate lookups called abuse.ch unauthenticated and the OTX hash path
carried a segment the API rejects. Both failed as 'no data' rather than 'error'.

## Pulling upstream changes

    git subtree pull --prefix=servers/threat-intel https://github.com/aplaceforallmystuff/mcp-threatintel.git <ref> --squash
