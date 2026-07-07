# 1. v1 deployment runs as root with SENTINEL_MODE=active by default

## Context

Sentinel's v1 release ships auto-quarantine: `AutoQuarantineCriticalFindingsUseCase`
automatically quarantines CRITICAL, not-yet-remediated `IntegrityFinding`s,
capped per account per run by `auto_quarantine_max_per_account_per_run`
(default 5) — beyond the cap it stops and raises one
`auto_quarantine_circuit_breaker_tripped` event instead of continuing
unattended. This only activates when `SENTINEL_MODE=active`; the use case
checks this fresh on every scheduled run.

Two things had to be decided before this could actually work against a real
cPanel host, both confirmed directly with the operator:

1. **Whether v1 ships with `SENTINEL_MODE=active` by default**, vs. shipping
   detection/manual-quarantine live but leaving auto-quarantine off until a
   deliberate per-server opt-in.
2. **What privilege level `api`/`worker` run at.** Real cPanel account files
   are owned by each account's own individual system UID (not a shared
   UID), typically mode 750. The Docker image's default `USER sentinel`
   (uid 1000) can read most of what discovery/integrity scanning needs, but
   quarantine's file *move* would get `PermissionError` against almost
   every real account's files. `AutoQuarantineCriticalFindingsUseCase`
   already tolerates per-finding failures — it wouldn't crash — but it
   would silently remediate nothing, quietly defeating the feature it was
   built to ship.

## Decision

- `SENTINEL_MODE=active` on both `api` and `worker` in `docker-compose.yml`.
- `api` and `worker` run as `root` (`user: root` in `docker-compose.yml`,
  overriding the image's default `USER sentinel` — the `migrate` service is
  unaffected). This matches how comparable host security agents (Imunify360,
  ClamAV, CSF) operate on cPanel boxes: root, not a fixed unprivileged UID,
  because the set of file owners it must act against is the entire set of
  hosting accounts on the box, unknown at image-build time.
- To keep the root-privileged, network-facing `api` service's host exposure
  minimal, it only mounts `/home` (read-write, required for
  quarantine/restore/delete) — not `/etc`, `/proc`, `/var/log`, cPanel
  binaries, or the forensics temp directories, all of which only feed
  `worker`'s discovery/forensics scans and are mounted read-only there.

## Consequences

- Auto-quarantine is live immediately on deploy, with no follow-up action
  required — matches "auto-quarantine is production ready."
- Both `home_directory`-based path resolution (`api` and `worker` must
  bind-mount the host's `/home` at the identical container path,
  `/host/home`) and `sentinel doctor`'s startup validation now check a real
  host mount rather than an empty container-local directory.
- The blast radius of a container compromise is larger than an unprivileged
  process would be. This is accepted for v1 on the basis that the
  alternative (per-account ACL/group grants, configured per server) is
  significant, error-prone operational setup that a v1 release should not
  depend on; it can be revisited if a lower-privilege access model is
  designed later.
- Rollback requires no code change: `SENTINEL_MODE=manual` (human-triggered
  remediation only) or `SENTINEL_MODE=observe` (mutation endpoints return
  403) plus a restart. Quarantine is always reversible via `sentinel
  restore`, so even a wrong auto-quarantine call is not data loss.
