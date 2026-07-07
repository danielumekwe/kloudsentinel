# Bare-Metal Deployment — cPanel/WHM AlmaLinux

This is the systemd-based deployment path: Sentinel installed directly on
the cPanel/WHM host, no containers. It reads real host paths directly
(`/etc`, `/home`, `/var/spool/cron`, ...) — there's no `/host/...`
remapping the way the Docker deployment (`docker-compose.yml`) needs.

Both `sentinel-api` and `sentinel-worker` run as **root**, and
`SENTINEL_MODE=active` (auto-quarantine live) is the default. See
[ADR 0001](../architecture/decisions/0001-v1-deployment-privilege-and-mode.md)
for why — this doc only covers the *how*.

## Prerequisites

AlmaLinux 9:
```bash
dnf install -y python3.12
```

AlmaLinux 8 (module streams vary by minor release — check availability first):
```bash
dnf module list python3*
dnf module enable -y python3.12   # if listed
dnf install -y python3.12
```

If `python3.12` isn't packaged for your AlmaLinux 8 minor release, install
it from the [EPEL](https://docs.fedoraproject.org/en-US/epel/) or
[IUS](https://ius.io/) repositories, or build it from source — `scripts/install.sh`
only requires `python3.12` on `PATH`, it doesn't care how it got there.

## Install

```bash
sudo git clone <this-repo-url> /opt/sentinel-core
cd /opt/sentinel-core
sudo ./scripts/install.sh
```

`install.sh` installs `uv` if missing, syncs dependencies, creates
`/etc/sentinel/sentinel.env` from the template (only if it doesn't already
exist), runs migrations, installs and enables the two systemd units, runs
`sentinel doctor` as a pre-flight gate (aborts before starting services if
it reports a FAIL), then starts `sentinel-worker` and `sentinel-api`.

**Before going further, review `/etc/sentinel/sentinel.env`** — the
template ships with `config.py`'s production defaults, but confirm the
host paths match this server's actual layout.

Then, in a shell with the config sourced:
```bash
set -a; source /etc/sentinel/sentinel.env; set +a

/opt/sentinel-core/.venv/bin/sentinel create-api-key --name "initial-key"
/opt/sentinel-core/.venv/bin/sentinel health
```

`create-api-key` prints the plaintext key exactly once — save it now; only
its hash is persisted. Every `/api/v1/*` endpoint requires it.

```bash
journalctl -u sentinel-api -u sentinel-worker -f
```

## Upgrade

```bash
cd /opt/sentinel-core
sudo git pull
sudo ./scripts/install.sh
sudo systemctl restart sentinel-api sentinel-worker
```

`install.sh` re-syncs dependencies, re-applies any new migrations, and
re-renders the systemd units — but it never restarts already-running
services on its own, so the restart above is a separate, deliberate step.

## Rollback

```bash
cd /opt/sentinel-core
sudo git checkout <previous-tag-or-commit>
sudo ./scripts/install.sh
sudo systemctl restart sentinel-api sentinel-worker
```

Do **not** run `alembic downgrade` as a default rollback step — it can
lose data and is only needed if a specific release's notes say a migration
must be reverted. Rolling back the code alone (schema is additive/forward-
compatible in the common case) is almost always sufficient.

After any rollback: `sentinel doctor` to confirm the deployment is still
healthy.

## Backup

Database (online-safe, no need to stop services):
```bash
sqlite3 /var/lib/sentinel/sentinel.db ".backup '/backup/sentinel-$(date +%Y%m%d).db'"
```

Quarantined files:
```bash
tar czf "/backup/sentinel-quarantine-$(date +%Y%m%d).tar.gz" -C /var/lib/sentinel quarantine
```

Example nightly cron (`/etc/cron.d/sentinel-backup`):
```
0 2 * * * root sqlite3 /var/lib/sentinel/sentinel.db ".backup '/backup/sentinel-$(date +\%Y\%m\%d).db'" && tar czf "/backup/sentinel-quarantine-$(date +\%Y\%m\%d).tar.gz" -C /var/lib/sentinel quarantine
```

## Restore from backup

```bash
sudo systemctl stop sentinel-api sentinel-worker
sudo cp /backup/sentinel-<date>.db /var/lib/sentinel/sentinel.db
sudo rm -rf /var/lib/sentinel/quarantine
sudo tar xzf /backup/sentinel-quarantine-<date>.tar.gz -C /var/lib/sentinel
sudo systemctl start sentinel-api sentinel-worker
sudo -i sentinel doctor   # with sentinel.env sourced, per Install section above
```

## Uninstall

```bash
sudo ./scripts/uninstall.sh
```

Stops and disables both services and removes the unit files only — config
(`/etc/sentinel`), data (`/var/lib/sentinel`, including the database and
any quarantined files), and the code checkout are left untouched by
default. Pass `--purge-data` to also remove `/etc/sentinel` and
`/var/lib/sentinel` (prompts for a typed `yes` confirmation first — this is
the one irreversible step, so it's opt-in, never the default).
