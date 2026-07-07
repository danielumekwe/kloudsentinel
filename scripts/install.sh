#!/usr/bin/env bash
# Installs/upgrades Sentinel Core as two systemd services (sentinel-api,
# sentinel-worker) directly on this host — the bare-metal counterpart to
# docker-compose.yml. See docs/deployment/bare-metal-almalinux.md for the
# full runbook and docs/architecture/decisions/0001-v1-deployment-privilege-and-mode.md
# for why this runs as root with SENTINEL_MODE=active.
#
# Usage: sudo ./scripts/install.sh
# Safe to re-run (e.g. after `git pull`) to apply an upgrade: it never
# overwrites an existing /etc/sentinel/sentinel.env, and never restarts
# already-running services on its own — see the runbook's "Upgrade" section
# for the explicit restart step.
set -euo pipefail

log() { echo "[install] $*"; }
die() { echo "[install] ERROR: $*" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] || die "must be run as root (sudo ./scripts/install.sh)"

if [ -r /etc/os-release ]; then
    . /etc/os-release
    case "${ID:-}${ID_LIKE:-}" in
        *almalinux*|*rhel*|*fedora*) ;;
        *) log "WARNING: /etc/os-release does not look like AlmaLinux/RHEL-family (ID=${ID:-unknown}); continuing anyway, this script only needs systemd + Python 3.12." ;;
    esac
else
    log "WARNING: /etc/os-release not found; continuing anyway."
fi

SENTINEL_HOME="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
log "SENTINEL_HOME=${SENTINEL_HOME}"

if ! command -v python3.12 >/dev/null 2>&1; then
    die "python3.12 not found on PATH. On AlmaLinux 9: sudo dnf install -y python3.12. On AlmaLinux 8: sudo dnf module enable -y python3.12 && sudo dnf install -y python3.12 (module name/availability varies by minor release — check 'dnf module list python3*' if this fails)."
fi
log "python3.12 found: $(command -v python3.12)"

export PATH="${HOME}/.local/bin:${PATH}"
if ! command -v uv >/dev/null 2>&1; then
    log "uv not found; installing (https://astral.sh/uv)..."
    curl -LsSf https://astral.sh/uv/install.sh | sh
    export PATH="${HOME}/.local/bin:${PATH}"
    command -v uv >/dev/null 2>&1 || die "uv install completed but 'uv' is still not on PATH"
fi
log "uv found: $(command -v uv)"

log "syncing dependencies (uv sync --frozen --no-dev)..."
( cd "${SENTINEL_HOME}" && uv sync --frozen --no-dev )

log "creating /etc/sentinel and /var/lib/sentinel/quarantine..."
mkdir -p /etc/sentinel /var/lib/sentinel/quarantine

if [ ! -f /etc/sentinel/sentinel.env ]; then
    log "no existing /etc/sentinel/sentinel.env — installing template from scripts/sentinel.env.example"
    cp "${SENTINEL_HOME}/scripts/sentinel.env.example" /etc/sentinel/sentinel.env
    chmod 600 /etc/sentinel/sentinel.env
    log "review/edit /etc/sentinel/sentinel.env before relying on this deployment"
else
    log "/etc/sentinel/sentinel.env already exists — leaving it untouched"
fi

log "applying database migrations (alembic upgrade head)..."
set -a
# shellcheck disable=SC1091
source /etc/sentinel/sentinel.env
set +a
( cd "${SENTINEL_HOME}" && "${SENTINEL_HOME}/.venv/bin/alembic" upgrade head )

log "installing systemd units..."
for unit in sentinel-api sentinel-worker; do
    sed "s#__SENTINEL_HOME__#${SENTINEL_HOME}#g" \
        "${SENTINEL_HOME}/scripts/systemd/${unit}.service" \
        > "/etc/systemd/system/${unit}.service"
done
systemctl daemon-reload

if [ -d /usr/local/cpanel ]; then
    log "WHM detected — installing the KloudSentinel WHM plugin..."

    if [ ! -f /etc/sentinel/whm-plugin.secret ]; then
        log "generating /etc/sentinel/whm-plugin.secret..."
        openssl rand -base64 32 > /etc/sentinel/whm-plugin.secret
        chmod 600 /etc/sentinel/whm-plugin.secret
    fi
    WHM_PLUGIN_SECRET="$(cat /etc/sentinel/whm-plugin.secret)"

    if ! grep -q '^SENTINEL_WHM_PLUGIN_SHARED_SECRET=' /etc/sentinel/sentinel.env; then
        log "adding SENTINEL_WHM_PLUGIN_SHARED_SECRET to /etc/sentinel/sentinel.env..."
        echo "SENTINEL_WHM_PLUGIN_SHARED_SECRET=${WHM_PLUGIN_SECRET}" >> /etc/sentinel/sentinel.env
    fi
    if ! grep -q '^SENTINEL_DASHBOARD_BASE_PATH=' /etc/sentinel/sentinel.env; then
        # Includes the CGI script name (not just the directory) — the
        # plugin routes sub-pages via standard CGI PATH_INFO
        # (/cgi/kloudsentinel/index.cgi/threats -> PATH_INFO=/threats), so
        # every link Sentinel renders must be built on that full path.
        log "adding SENTINEL_DASHBOARD_BASE_PATH to /etc/sentinel/sentinel.env..."
        echo "SENTINEL_DASHBOARD_BASE_PATH=/cgi/kloudsentinel/index.cgi" >> /etc/sentinel/sentinel.env
    fi

    log "installing WHM plugin CGI script and icon..."
    mkdir -p /usr/local/cpanel/whostmgr/docroot/cgi/kloudsentinel
    cp "${SENTINEL_HOME}/whm-plugin/cgi-bin/index.cgi" \
        /usr/local/cpanel/whostmgr/docroot/cgi/kloudsentinel/index.cgi
    cp "${SENTINEL_HOME}/whm-plugin/kloudsentinel.png" \
        /usr/local/cpanel/whostmgr/docroot/cgi/kloudsentinel/kloudsentinel.png
    chown root:root /usr/local/cpanel/whostmgr/docroot/cgi/kloudsentinel/index.cgi \
        /usr/local/cpanel/whostmgr/docroot/cgi/kloudsentinel/kloudsentinel.png
    chmod 755 /usr/local/cpanel/whostmgr/docroot/cgi/kloudsentinel/index.cgi

    log "registering the plugin with AppConfig..."
    cp "${SENTINEL_HOME}/whm-plugin/kloudsentinel.conf" /var/cpanel/apps/kloudsentinel.conf
    /usr/local/cpanel/bin/register_appconfig /var/cpanel/apps/kloudsentinel.conf

    log "restarting cpsrvd to apply the new plugin registration..."
    /scripts/restartsrv_cpsrvd

    log "KloudSentinel WHM plugin installed — only WHM accounts with the 'kloudsentinel'"
    log "ACL see it under Plugins (root has every ACL by default; grant it to a reseller"
    log "via WHM > Reseller Center if needed)."
else
    log "no /usr/local/cpanel found — skipping WHM plugin registration (not a WHM host)."
fi

log "reloading /etc/sentinel/sentinel.env (may have just been updated above)..."
set -a
# shellcheck disable=SC1091
source /etc/sentinel/sentinel.env
set +a

log "running pre-flight checks (sentinel doctor)..."
if ! "${SENTINEL_HOME}/.venv/bin/sentinel" doctor; then
    die "sentinel doctor reported a FAIL above — fix the configuration and re-run this script before starting services. Services were NOT enabled/started."
fi

log "enabling and starting services..."
systemctl enable --now sentinel-worker sentinel-api

cat <<EOF

[install] Done.

The CLI reads the same SENTINEL_ environment variables as the services, so
source the config file before running it directly (the services already
get this via EnvironmentFile=):

  set -a; source /etc/sentinel/sentinel.env; set +a

Next steps (in that shell):
  1. Create an API key (required for any /api/v1/* call):
       ${SENTINEL_HOME}/.venv/bin/sentinel create-api-key --name "initial-key"
  2. Check operational status:
       ${SENTINEL_HOME}/.venv/bin/sentinel health
  3. Follow logs:
       journalctl -u sentinel-api -u sentinel-worker -f

sentinel-api listens on 127.0.0.1:8443 only — it is never reachable from
outside this host. On a WHM host, open WHM > Plugins > KloudSentinel (only
visible to WHM accounts with the 'kloudsentinel' ACL); that plugin is the
only intended access path. There is no separate dashboard login to create.

See docs/deployment/bare-metal-almalinux.md for upgrade, rollback, and
backup procedures.
EOF
