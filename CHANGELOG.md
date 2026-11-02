# Changes

## 0.2.0 (2026-11)

Fixes from a full code review, preparation for access from the Internet, and
operational features. Still a test deployment: run it next to an established RP.

### Upgrading from 0.1.0

- Install the new `deploy/haetae.service` too (`Type=notify`, watchdog,
  `GOMEMLIMIT`) and run `systemctl daemon-reload`, then restart once.
- On the first start Haetae reads the old state files once and writes
  `state/payload.gob`; routers keep the same RTR session.
- From 0.2.0 on, later versions can be installed without a restart (see
  *Seamless upgrade* below).

### Validation

- Manifest fallback (RFC 9286 section 6.7): every publication point that passes
  is kept under `<cache>/valid/`; if the freshly fetched manifest, CRL or files
  fail, the CA is validated again from that copy. A manifest number lower than
  the stored one is treated as a failure.
- A run with a failed TA or zero VRPs is not applied, also on the first run
  (RTR is not opened with a partial result).
- SKI check (RFC 6487 section 4.8.2): an SKI that is not the SHA-1 hash of the
  public key is counted as a warning (`SKI is not SHA-1 of public key`).
- Object size limit 20 MB (was 4 MB; the largest real object is close to 4 MB).

### Fetching

- RRDP: elements longer than the base64 limit are rejected before they reach
  memory; a delta that fails because of the network does not trigger a
  snapshot; a saved state without its directory triggers a snapshot; empty
  snapshots work.
- RRDP conditional GET (`If-None-Match` / `If-Modified-Since`); unconditional
  at least once an hour.
- Dead repositories are backed off (10 minutes up to 1 hour after 3 failures),
  `Retry-After` is honoured. `/repos.json` shows `consecutive_failures`,
  `last_success`, `next_try`, `skipped`.
- RRDP to rsync fallback after 1 hour of failures, 3 hours for repositories with
  10,000 or more objects. The RRDP result `fallback-rsync` now means rsync
  succeeded; if rsync also failed the result is `failed`.
- TA certificates are checked against the TAL key before they replace the
  cached copy. rsync modules are limited in file count and size.

### RTR

- Connection limits (256 in total, 4 per address or IPv6 /64), first query
  within 30 seconds, idle limit 2 hours, a full set at most once a minute per
  connection.
- Restart state in one file (`state/payload.gob`: served set, session, serial,
  deltas), so a restart can never send a delta that does not match.
- Error Report PDUs from routers are logged with their text.

### HTTP API

- Two access tiers: `http.allow` (management, every path) and `http.public`
  (lookup paths only; internal fields such as router addresses are left out).
- Connection limit and request time limits.
- `GET /healthz` for monitoring (200 or 503 with `starting`, `stale`,
  `rtr-closed`).
- `/api/v1/objects?kind=TA|CA|router`; rejected certificates carry
  `summary.kind`.
- `/api/v1/vrps/delta?session=` (reset when the session differs).
- All APIs show the same run: the served set and the lookup data are switched
  together.
- `/metrics` names follow Prometheus conventions: `*_timestamp_seconds`,
  byte counts in bytes, `haetae_build_info`, `haetae_runs_not_applied_total`,
  `haetae_handovers_total`. **Renamed**: `haetae_data_time_seconds`,
  `haetae_last_applied_seconds` and `haetae_last_run_start_seconds` are now
  `..._timestamp_seconds`.
- `/api/v1/status`: `stale`, `handover`, `last_run.downloaded_bytes`.

### Operations

- Stale data alarm (`stale-warn`, default 1 hour) and optional `stale-close`
  (close RTR so routers use another RP).
- systemd `Type=notify` with watchdog; clean stop on SIGTERM (waits for a save
  in progress).
- **Seamless upgrade**: on SIGUSR2 the running process waits for the current
  cycle, then hands its RTR sessions and listening sockets to the new binary
  (same pid). Routers stay connected; RTR pauses for about 2 seconds, the
  lookup paths answer 503 for about 30 seconds.
- Range checks for configuration values.

## 0.1.0 (2026-11-01)

First public version: fetching (RRDP, rsync), validation of all standard RPKI
objects, RTR v0 / v1 / v2, HTTP API, SLURM, configuration file and reload,
built-in TALs.
