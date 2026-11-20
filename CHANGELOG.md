# Changes

## 0.4.0 (2026-11-20)

### License

- License changed from ISC to Apache-2.0 (`LICENSE`, new `NOTICE`); 0.3.0 and
  earlier remain ISC.

### Fixes

- CRL Number (RFC 9829): a CRL whose CRL Number extension is critical,
  negative or larger than 2^159-1 is rejected.
- Manifest numbers (RFC 9981, RFC 9286 section 4.2.1): a manifest whose
  thisUpdate is earlier than that of the stored valid copy is treated like a
  lower manifest number (the stored copy is used). A changed manifest filename
  starts the number over and is reported as the warning `manifest filename
  changed, manifest number reset (RFC 9981)`. A manifest whose EE signedObject
  differs from its location now fails (the stored copy is used); before it was
  only a warning. The warning `manifest number went back, ...` is now
  `manifest went back, ...`.
- TA certificate tiebreaking (RFC 10097, November 2026): a downloaded TA
  certificate replaces the cached one only if it is currently valid and not
  older (later notBefore wins; on equal notBefore the shorter validity wins).
  Before, any downloaded certificate with the TAL key replaced the cache, so
  a replayed older TA certificate was accepted and an expired one rejected the
  whole TA until the next fetch.
- When several ASPAs exist for one customer AS, AS0 is no longer kept next to
  other providers in the merged provider list (draft-ietf-sidrops-aspa-profile
  section 5.2). Before, such a list was sent over RTR v2, where
  draft-ietf-sidrops-8210bis-29 has routers reject it with Error Code 9.
  Routinator 0.16 does the same; **rpki-client 9.9 keeps AS0** in the merged
  list. For such a customer AS (in 2026-11 only AS59182, an ASPA `[0]` from a
  sub-CA and `[9885, 55824]` from its parent) Haetae and Routinator give
  `[9885, 55824]` where rpki-client gives `[0, 9885, 55824]`, in `json`, RTR
  and the CCR ASPA state. VRPs and the other CCR states are unaffected.
  rpki-client changed its merge in the OpenBSD source on 2026-11-16
  (aspa.c 1.58), so its next release should give the same result.
- Checked against the latest drafts:
  - draft-ietf-sidrops-8210bis-29 (RTR v2): an ASPA that appeared and
    disappeared between a router's serial and now is no longer sent as a
    withdrawal (the router never had it; strict routers answer Error 6);
    PDU types a router must not send get Error 3 (Invalid Request) instead
    of 5; an Error Report from a router is never answered, even with a wrong
    version; RTR over TLS requires TLS 1.3 (RFC 9852 in BCP 195).
  - draft-ietf-sidrops-aspa-profile-31: ASPAs with customer AS 0, with AS0
    next to other providers, or whose EE certificate does not hold exactly
    one `id` equal to the customer AS are rejected; if the merged providers
    of one customer AS exceed 10,000, all ASPAs of that customer are dropped
    (a warning names it) instead of a partial list.
  - draft-ietf-sidrops-rpki-prefixlist-05: SPLs with asID 0 are rejected.
  - draft-ietf-sidrops-aspa-slurm-04: SLURM ASPA entries now use
    `slurmVersion` 2 with `customerAsn` / `providerAsns`, both `aspaFilters`
    and `aspaAssertions` present, providers ascending and unique. **Files
    using the old keys (`customer_asid` / `provider_set` in version 1) are
    rejected.**
  None of these changed the result on a 2026-10 repository snapshot.
- Signed objects must carry the CMS signing-time attribute and must not carry
  binary-signing-time (RFC 9589); both were accepted before. rpki-client 9.9
  applies the same rule. No object in a 2026-10 repository snapshot was affected.
- RRDP session desynchronisation is detected (RFC 9697): the delta hashes of
  the last applied notification file (the latest 300) are kept with the RRDP
  state, and if a previously seen serial shows a different hash in the same
  session, Haetae logs a warning and fetches the snapshot.

### New

- Optional TA constraints (draft-ietf-sidrops-constraining-rpki-trust-anchors-02):
  `paths.constraints` / `-constraints` names a directory of
  `<TAL name>.constraints` files in the format OpenBSD ships; off by default.
  The resources listed in the EE certificates of ROAs, ASPAs and SPLs and in
  BGPsec router certificates must not overlap a `deny` entry and must lie
  within the `allow` entries. On a repository snapshot the result matches
  rpki-client 9.9 (VRPs, ASPAs and the 61 rejected objects).
- Optional CCR output (draft-ietf-sidrops-rpki-ccr-11), off by default:
  `[ccr] mode = latest` writes `rpki.ccr` in the output directory on every
  applied run, served as `/rpki.ccr` (internal access only), with the state
  hashes `ccr_*_hash` in the `json` metadata under the same names as
  rpki-client; `daily`, `hourly` and `cycle` also keep gzip archives for
  `ccr.keep` (default 168h). On a repository snapshot the file is byte for byte identical to
  rpki-client 9.9's.

### Documentation

- Build from source with `CGO_ENABLED=0` (static, as the release binaries;
  also in `tools/upgrade.sh`). A dynamically linked build uses libc, and on
  Ubuntu needrestart restarts the service after every libc update, which
  drops the RTR sessions.

- Corrected comparisons with rpki-client (thanks to issue #1). The speed slide
  compared Haetae with rpki-client 9.0 from the Ubuntu 24.04 package, an old
  release that validates on a single thread. Re-measured against rpki-client
  9.9 with `-p`, the two are on par, so the slide no longer compares timings
  with other RPs and shows Haetae's own operating figures instead. The TA constraints text now cites
  draft-ietf-sidrops-constraining-rpki-trust-anchors (an IETF SIDROPS working
  group draft) and attributes the rejected objects to an outdated constraints
  file from a 2024 package, not to the mechanism.

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
