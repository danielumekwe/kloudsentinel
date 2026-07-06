# sentinel-core

Core Monitoring Engine for Kloud101 AI Sentinel — the on-host agent responsible for
discovery, file integrity monitoring, inventory, configuration monitoring, process
and cron monitoring, log collection, and event generation for cPanel/WordPress
hosts.

See `docs/architecture/` for the full system design.

## Development

```bash
uv sync --dev
uv run alembic upgrade head
uv run uvicorn sentinel.bootstrap:app --reload
```

## Tests

```bash
uv run pytest
```

## CLI

The `sentinel` command-line tool runs the same signature/heuristic malware
scanner offline, against an arbitrary local directory (e.g. a downloaded
WordPress backup) — no server, database, or prior baseline required:

```bash
uv run sentinel scan-archive /path/to/extracted-backup
uv run sentinel scan-archive /path/to/extracted-backup --apply-quarantine
uv run sentinel scan-archive /path/to/extracted-backup --json
```

Findings above `--min-severity` (default `LOW`) are reported; pass
`--apply-quarantine` to also move the affected files into a sibling
`<dir>.sentinel-quarantine` directory (or `--quarantine-dir` to choose
another location) instead of just reporting them.
