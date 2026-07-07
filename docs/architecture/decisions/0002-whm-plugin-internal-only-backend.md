# 2. Internal-only backend, accessed exclusively via a WHM plugin

## Context

The dashboard shipped after ADR 0001 was a standalone, publicly-reachable
website: `sentinel-api` bound `0.0.0.0:8443`, was expected to sit behind an
operator-supplied reverse proxy with a real TLS certificate, and had its own
username/password login (`AdminUser`/`AdminSession`).

That model works, but it doesn't match how comparable host security agents
on cPanel/WHM boxes are actually operated. Imunify360, JetBackup, and
similar tools don't run a public website with their own login — they run an
internal-only backend and surface their UI as a WHM plugin under
**Plugins**, reusing WHM's own authentication (a user who can already log
into WHM as root/reseller doesn't want a second password to manage a
security tool on the same box). It also removes an entire category of
production risk (TLS misconfiguration, a forgotten firewall rule on 8443)
by making it structurally impossible to reach Sentinel's HTTP port from
outside the host at all.

## Decision

- `sentinel-api` binds `127.0.0.1:8443` only, on both the systemd unit and
  the `docker-compose.yml` port publish (the Docker container's internal
  process still binds `0.0.0.0`, as Docker's own networking requires — only
  the host-facing `ports:` mapping is restricted).
- A new WHM plugin (`whm-plugin/`) is installed by `scripts/install.sh` when
  `/usr/local/cpanel` is detected: registered via cPanel's `AppConfig`
  mechanism under a dedicated ACL (`acls=kloudsentinel`, not `acls=any`) so
  only WHM accounts explicitly granted that ACL can open it — Sentinel's
  data spans every account on the server, so a limited reseller shouldn't
  see it by default.
- The plugin's `cgi-bin/index.cgi` is a thin Perl reverse proxy. WHM's
  `cpsrvd` only invokes it after its own login + ACL check already passed,
  so `$ENV{REMOTE_USER}` is a trustworthy, WHM-authenticated identity. The
  script HMAC-signs a call to a new internal-only endpoint
  (`POST /dashboard/whm-session`, loopback-restricted) to mint a normal
  `AdminSession` row for a `whm:<username>` account (auto-provisioned,
  password login never enabled for it), then forwards every request through
  to the already-existing Jinja2 dashboard. No dashboard route, template
  business logic, or the quarantine/detection/incident use-cases underneath
  them changed — only the access path did.
- The existing `AdminUser`/`AdminSession` username+password login
  (`sentinel create-admin-user`) is kept as a secondary, SSH-tunnel-only
  fallback for recovery/debugging — not removed, since it costs nothing to
  keep now that the port it depends on is no longer publicly reachable
  either way.

## Consequences

- The TLS-reverse-proxy requirement documented for the previous model is
  moot and has been removed from the deployment docs — nothing is publicly
  bound, so there is nothing to terminate TLS in front of.
- Every dashboard link/redirect had to become prefix-configurable
  (`Settings.dashboard_base_path`) so the same rendered HTML works whether
  loaded directly at `/dashboard` or proxied under
  `/cgi/kloudsentinel/index.cgi` by the WHM plugin (via standard CGI
  `PATH_INFO`) — a one-time template/route change, not an ongoing cost.
- The WHM plugin path only applies to the bare-metal deployment
  (`scripts/install.sh` on a real cPanel/WHM host) — a container doesn't
  have `/usr/local/cpanel` to register against, so the Docker path stays
  loopback-only with no WHM integration, intended for local/dev use.
- A new shared secret (`/etc/sentinel/whm-plugin.secret`, root-only,
  generated once by `install.sh`) authenticates the CGI-to-backend call.
  Its blast radius if leaked is bounded: it only allows minting a Sentinel
  session claiming to be a given WHM username, and only from loopback — an
  attacker in a position to read a root-only file on the host, or to speak
  to 127.0.0.1 as root, already has much stronger access than that secret
  grants on its own.
