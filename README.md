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
