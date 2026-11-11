# Changes

## 0.3.0 (2026-11-11)

Fixes from a second full code review (resource limits against hostile
repositories and clients), a stricter systemd sandbox, and prebuilt binaries.
Still a test deployment: run it next to an established RP.

### Binaries

- Static Linux binaries for amd64 and arm64 are attached to the release
  (`haetae-0.3.0-linux-amd64`, `haetae-0.3.0-linux-arm64`, `SHA256SUMS`). No
  dependencies; the TALs are built in. They are built from the tag with
  `CGO_ENABLED=0 go build -trimpath -ldflags='-s -w'`, so the same Go version
  gives the same files.

### Upgrading

- Upgrade from 0.2.0 with `tools/upgrade.sh` (no restart, RTR sessions stay).
- The new `deploy/haetae.service` adds sandboxing (no capabilities, private
  devices, `ProtectProc=invisible`, `SystemCallFilter=@system-service`,
  `MemoryDenyWriteExecute`, ...). A seamless upgrade does not reload the unit
  file: install it, run `systemctl daemon-reload` and restart once (routers
  reconnect with the same session).
- Upgrading directly from 0.1.0 now starts a new RTR session (the pre-0.2.0
  state files are no longer read); routers fetch everything once. Go through
  0.2.0 first to keep the session.

### Validation

- TAK (RFC 9691): when a TAK issued by a TA announces a successor key, Haetae
  logs `WARNING TA key rollover announced` on every cycle and counts the warning
  `TAK announces successor TA key` (summary.txt, status API, `/metrics`). The TAL
  is not switched automatically.
- The stored copy of a publication point (RFC 9286 section 6.7) is keyed by the
  CA public key, RRDP notify URI and manifest URI, so a CA that copies another
  CA's manifest URI cannot replace the other CA's copy.
- A manifest number lower than the stored one is accepted when the stored copy
  is no longer valid (for example expired), so a re-created CA comes back.
- A panic while processing one object rejects only that object
  (`panic: ...`); the rest of the CA is processed.
- DER: the element count limit is checked while children are collected, not
  afterwards.

### Fetching

- New `fetch.deadline` (default 20 minutes): repositories not reached by then
  are validated from previous data and do not count as failures.
- RRDP: every XML token and the text of each `publish` element is limited
  before it is held in memory.
- Notify URIs are normalised (same repository fetched once); URIs with a query,
  fragment or user info are not used (rsync instead). At most 1,000 repositories
  below one TA.
- New repositories are not fetched when less than 10 GB is free on the cache
  file system; repositories unused for 3 days are removed from the cache.
- A publication point may total 512 MB, and at most 2 GB of publication points
  are held in memory at once.
- A cycle longer than 3 minutes logs the five slowest repositories.

### RTR

- New `rtr.trusted` / `rtr.trusted-max-conns`: your own routers' prefixes are
  always allowed and counted apart from other clients (status `trusted`).
- Other clients: at most 16 connections per IPv6 /48, and a full set at most
  twice a minute per address (reconnecting no longer gets around the limit).
- A failed TLS handshake now frees its connection slot.
- During a seamless upgrade, a client that does not read its answer is closed
  after 1 minute instead of blocking the upgrade.
- RTR full sets and deltas are sent in a fixed order.
- `-rtr-stdio`: if the router closes only its sending side, the response is
  still passed through to the end.

### HTTP API

- Public clients: at most 8 connections per address and 224 in total (32 kept
  for internal clients); a response that cannot send 256 KiB within 60 s is cut.
- Public `/api/v1/as/{AS}`: at most once a second per client (429 otherwise).
- `/json-delta`: a 404 body says why (missing `session` / `serial`, session
  mismatch, range not in history). `/api/v1/vrps/delta` uses a fixed order.

### Operations

- Configuration file: `#` inside double quotes is not a comment, and quotes
  around a value are removed.
- At start-up the state directory is set to 0750 and the lock file to 0600, so
  other accounts cannot hold the lock.

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
