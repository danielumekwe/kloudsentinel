#!/usr/bin/env bash
# Stops and removes the Sentinel Core systemd services installed by
# scripts/install.sh.
#
# Safe by default: only stops/disables the services and removes the unit
# files. Code, venv, /etc/sentinel (config), and /var/lib/sentinel
# (database + quarantined files) are left untouched — matching Sentinel's
# own "never auto-delete" design (quarantine is reversible, not
# destructive). Pass --purge-data to additionally remove /etc/sentinel and
# /var/lib/sentinel, after typed confirmation.
#
# Usage: sudo ./scripts/uninstall.sh [--purge-data]
set -euo pipefail

log() { echo "[uninstall] $*"; }
die() { echo "[uninstall] ERROR: $*" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] || die "must be run as root (sudo ./scripts/uninstall.sh)"

PURGE_DATA=0
if [ "${1:-}" = "--purge-data" ]; then
    PURGE_DATA=1
fi

log "stopping and disabling services..."
systemctl disable --now sentinel-api sentinel-worker 2>/dev/null || true

log "removing systemd unit files..."
rm -f /etc/systemd/system/sentinel-api.service /etc/systemd/system/sentinel-worker.service
systemctl daemon-reload

if [ "${PURGE_DATA}" -eq 0 ]; then
    cat <<EOF

[uninstall] Services stopped and unit files removed.

The following were left untouched. Remove manually if you're certain you
want them gone (this includes the database and any quarantined files):
  - Config:        /etc/sentinel
  - Data:          /var/lib/sentinel   (sentinel.db, quarantine/)
  - Code + venv:   wherever you cloned/installed this repo

Re-run with --purge-data to remove the config and data directories above
(with a confirmation prompt) as part of this script.
EOF
    exit 0
fi

log "WARNING: --purge-data will permanently delete /etc/sentinel and /var/lib/sentinel,"
log "including the database and ALL quarantined files. This cannot be undone."
read -r -p "Type 'yes' to confirm: " confirmation
if [ "${confirmation}" != "yes" ]; then
    die "confirmation not received — aborting without deleting data"
fi

log "removing /etc/sentinel and /var/lib/sentinel..."
rm -rf /etc/sentinel /var/lib/sentinel

log "done. Code and venv were not removed — delete the repo checkout manually if desired."
