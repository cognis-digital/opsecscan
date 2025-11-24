# OPSECSCAN — Architecture

> Scan documents and file metadata for OPSEC leaks: geotags, author, GPS EXIF, unit identifiers.

```
input ──▶ collect ──▶ rules/analyzers ──▶ score ──▶ findings ──▶ table · json
                              │                          │
                         (this repo)                 MCP tool (agents)
```

- **collect** normalizes the target (file/dir/API) into records.
- **rules/analyzers** apply the heuristics shipped in `opsecscan/core.py`.
- **score** ranks by severity.
- **MCP server** (`opsecscan mcp`) exposes `scan` for Cognis.Studio agents.

Extend by adding a rule + a test + a `demos/NN-*/SCENARIO.md`. See [CONTRIBUTING.md](../CONTRIBUTING.md).
