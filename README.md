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

## Deployment

**TLS is mandatory before exposing the dashboard.** `api` serves plain
HTTP on 8443 — it does not terminate TLS. The web dashboard's login form
and the CLI-issued credentials all travel in cleartext unless a reverse
proxy with a real certificate sits in front of this port and 8443 itself
is firewalled off from direct internet access. See
`docs/deployment/bare-metal-almalinux.md`'s TLS section for the full
reasoning — it applies here too, `docker-compose.yml` publishes 8443
exactly the same way.

```bash
docker compose up migrate   # applies alembic migrations, then exits
docker compose up -d api worker
docker compose exec api sentinel doctor   # pre-flight check before trusting a deployment
```

`sentinel doctor` validates host directory mounts, database connectivity,
and quarantine-path configuration — run it after every deploy and after any
change to `docker-compose.yml`'s mounts or environment.

**Mode.** `SENTINEL_MODE=active` is the v1 default on both `api` and
`worker`: auto-quarantine runs on a schedule, acting only on CRITICAL,
not-yet-remediated findings, capped per account per run by
`auto_quarantine_max_per_account_per_run` (default 5) — see
`docs/architecture/decisions/0001-v1-deployment-privilege-and-mode.md` for
the circuit-breaker behavior this relies on. To roll back, set `SENTINEL_MODE`
to `manual` (remediation stays human-triggered via the API/CLI) or `observe`
(every mutation endpoint returns 403) and restart both services — the
change takes effect immediately, no code change needed. Quarantine is
always reversible (`sentinel restore` / `sentinel quarantine restore`), so a
bad auto-quarantine decision is never data loss.

**Privilege.** `api` and `worker` run as root in production, because real
cPanel account files are owned by each account's own system UID, not a
shared one — see the ADR above for why. `api` only mounts `/home`
(read-write, for quarantine/restore/delete); it has no use for `/etc`,
`/proc`, `/var/log`, cPanel binaries, or the temp directories, which only
feed `worker`'s discovery/forensics scans.

**Persistence.** Quarantined files live under `/data/quarantine`, inside
the `sentinel-data` volume alongside the database — back it up the same way
you back up `sentinel.db`.
