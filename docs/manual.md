# Haetae User Manual

Haetae is an RPKI Relying Party (RP). It fetches objects from the RPKI repositories
worldwide, validates them, and provides the results to routers over RTR (VRPs, router keys, ASPA)
and to other systems over an HTTP API.

| Item | Value |
|---|---|
| Version | Haetae 0.2.0 |
| Binary | a single `haetae` executable (Go, standard library only). It does fetching, validation, RTR and the HTTP API |
| Requirements | Linux, the `rsync` command (fallback when RRDP fails), an accurate system clock (NTP) |
| Standards | RPKI objects RFC 6487 / 6488 / 3779 / 9582 / 9286 / 8630, RRDP RFC 8182, RTR RFC 6810 / 8210 (+ draft-ietf-sidrops-8210bis for v2), SLURM RFC 8416 |

This manual assumes you know the basic RPKI concepts. The HTTP API is described in detail in [api.md](api.md).

---

## 1. Overview

```
 5 RIR TAs (TALs built into the binary)                ┌─> Routers: RTR (default 3323)
        │                                               │     v0 VRP / v1 + router keys / v2 + ASPA
 Repositories ──fetch──> cache ──validate──> result ────┼─> HTTP API (default 127.0.0.1:8323)
 (RRDP first / rsync fallback) (file tree) (tree walk) (serial) │
                                                        └─> Output files (json / csv / objects.jsonl ...)
```

- **Cycle**: by default every 10 minutes: fetch -> validate -> apply -> export. A cycle usually takes 1 to 3 minutes
- **Apply**: when the result changes, the serial is incremented by 1, the changes (delta) are kept, and a Serial Notify is sent to routers
- **Restart**: the served set, session, serial and deltas are saved in one file (`state/payload.gob`), so Haetae continues where it left off -> routers fetch only the changes
- **Configuration**: command-line options + a configuration file (`/etc/haetae/haetae.conf`). The command line wins. `systemctl reload` re-reads it while running

---

## 2. Terms

| Term | Meaning |
|---|---|
| TA / TAL | Trust Anchor (the top-level certificate of an RIR) / the file holding its location and public key (RFC 8630) |
| VRP | Validated ROA Payload: "this prefix may be originated by this AS, up to maxLength" |
| ASPA | AS Provider Authorization: "the providers (upstreams) of this AS are these" |
| Router key | (AS, SKI, public key) from a BGPsec router certificate |
| TAK | Trust Anchor Key (RFC 9691). An object announcing the next key during a TA key rollover |
| SLURM | Local exceptions file (RFC 8416): remove VRPs (filters) / add VRPs (assertions) |
| session / serial | RTR data version. With the same session after a restart, routers fetch only the changes |
| Cycle | One round of fetch + validate + apply |
| Unsafe VRP | A VRP of another CA that overlaps the resources of a rejected CA (a route that may become Invalid if that CA breaks and its more-specific ROAs disappear) |

---

## 3. Installation

### 3.1 New installation (sudo)
```bash
# 1) Dedicated account (do not run as root)
sudo useradd --system --home-dir /var/lib/haetae --shell /usr/sbin/nologin haetae

# 2) Build (Go 1.26)
cd <source directory> && go build -o haetae . && go test ./...
#    or download a release binary instead (linux amd64 / arm64, see below)

# 3) Binary / configuration / service
sudo install -m 755 haetae /usr/local/bin/haetae
sudo install -d -m 755 /etc/haetae
sudo install -m 644 deploy/haetae.conf.example /etc/haetae/haetae.conf   # adjust the values (chapter 5)
sudo install -m 644 deploy/haetae.service /etc/systemd/system/haetae.service
sudo systemctl daemon-reload
sudo systemctl enable --now haetae

# 4) Check
journalctl -u haetae -f                      # start-up log (chapter 9), then one "run ..." line every 10 minutes
curl -s http://127.0.0.1:8323/status
```
- Release binaries (0.3.0): each GitHub release has `haetae-<version>-linux-amd64`, `haetae-<version>-linux-arm64` and `SHA256SUMS`.
  They are static (no libraries needed) and contain the TALs. Check with `sha256sum -c --ignore-missing SHA256SUMS`, then use the
  file as `haetae` in step 3. `deploy/haetae.service` and `deploy/haetae.conf.example` come from the repository at the same tag.
  The binaries are built from the tag with `CGO_ENABLED=0 go build -trimpath -ldflags='-s -w'`: the same Go version gives the same files
- Requirements: Linux, about 8 GB of memory, and the `rsync` command for the rsync fallback (or `fetch.rsync = false`)
- On the first start the cache is empty, so everything is fetched (about 1.5 GB, around 4 minutes). RTR is not opened during that time
- Firewall: for RTR (3323) and any HTTP port used from outside, allow only the sources that need it (two layers together with Haetae's own allow lists)

### 3.2 Directories and files
| Location | Content | Written by |
|---|---|---|
| `/usr/local/bin/haetae` | Binary (the 5 TALs are built in) | installation |
| `/etc/haetae/haetae.conf` | Configuration file | operator |
| `/etc/haetae/` (optional) | SLURM file, RTR authentication keys, TLS certificates | operator |
| `/var/lib/haetae/cache/` | Fetched objects (`rrdp/`, `rsync/`, `ta/`, `tmp/`), last valid publication points (`valid/`, section 6.1) | Haetae |
| `/var/lib/haetae/out/` | Output files (section 8.3) | Haetae |
| `/var/lib/haetae/state/` | `payload.gob` (restart state: served set + session / serial + last 200 deltas), `state.json` (session / serial, for humans), `history.jsonl` (30-day history), `lock` | Haetae |

The systemd service can write only to `/var/lib/haetae` (`ProtectSystem=strict`). It also drops all capabilities, hides
devices, kernel settings and other processes (`ProtectProc=invisible`), allows only IPv4 / IPv6 / Unix sockets, forbids
writable-and-executable memory and limits system calls to `@system-service` (`systemd-analyze security haetae`: about 1.5).
A unit file change needs `systemctl daemon-reload` and a restart (a seamless upgrade does not reload it). Its memory limit is `MemoryMax=12G`
(actual use is about 5.3 GB; the value reported by systemd also includes page cache, which can bring it close to 8 GB).
`Environment=GOMEMLIMIT=9GiB` sets the Go garbage collector's soft memory target: near 9 GiB the collector runs more
often so the process stays below `MemoryMax`. It changes nothing in normal operation.

The service is `Type=notify` with a watchdog (`NotifyAccess=main`, `WatchdogSec=3min`, `Restart=on-failure`); see section 6.6.

---

## 4. Running and command-line options

### 4.1 Modes
One option selects the mode. With none of them, Haetae runs as a **daemon** (production).

| Mode | Command | What it does |
|---|---|---|
| Daemon | `haetae [-c <config>] [options]` | Periodic fetch + validation, RTR, HTTP API. Reads the configuration file |
| Single cycle | `haetae -t [options]` | Same as the daemon but runs one cycle and exits (no RTR / HTTP). For testing |
| Offline validation | `haetae -validate -cache <cache> -o <out> [-tal <dir>] [-P <time>] [-fetch]` | Validates once and writes only the output files. `-cache` and `-o` are required (so a production cache is not used by accident). Does not read the configuration file |
| Parse | `haetae -parse <file\|dir> [-fail <list>]` | Parses objects only (list of failures) |
| RSC check | `haetae -rsc <x.sig> [-cache <cache>] [file ...]` | Checks an RSC (RFC 9323) signature and the file hashes |
| RTR over SSH | `haetae -rtr-stdio 127.0.0.1:3323` | Connects stdin/stdout to RTR (run by an sshd subsystem, section 7.4) |

### 4.2 All options
Options with a "Config key" can also be set in the configuration file (chapter 5). "Reload" = whether the value changes with `systemctl reload`.
Value ranges given in parentheses are checked at start and on reload: an out-of-range value stops the start (on reload the current values are kept).

**Directories / input**

| Option | Default | Config key | Reload | Meaning |
|---|---|---|---|---|
| `-c` | (empty = `/etc/haetae/haetae.conf` if it exists) | - | - | Configuration file. Daemon mode only |
| `-cache` | daemon: `/var/lib/haetae/cache` | `paths.cache` | restart | Cache directory |
| `-o` | daemon: `/var/lib/haetae/out` | `paths.out` | restart | Output directory |
| `-state` | `/var/lib/haetae/state` | `paths.state` | restart | State directory (includes the lock: two instances cannot use the same directory). At start-up the directory is set to 0750 and the lock file to 0600, so other accounts cannot hold the lock and block the next restart |
| `-tal` | (empty = the 5 built-in TALs) | `paths.tal` | next cycle | TAL directory (`*.tal`). Only for emergency RIR key rollovers (section 7.6) |
| `-slurm` | (none) | `paths.slurm` | next cycle | SLURM file (if it is broken, that cycle is not applied) |

**Fetching / validation**

| Option | Default | Config key | Reload | Meaning |
|---|---|---|---|---|
| `-interval` | `10m` | `fetch.interval` | next cycle | Cycle interval (at least `1m`) |
| `-fetch-j` | `32` | `fetch.jobs` | next cycle | Number of repositories fetched in parallel (1 to 1024) |
| `-fetch-deadline` | `20m` | `fetch.deadline` | next cycle | Fetch deadline per cycle: repositories not reached by then are validated from previous data (0 = none, otherwise >= 5m, section 6.1) |
| `-norsync` | `false` | `fetch.rsync` (inverted, `true` = use rsync) | next cycle | Do not fall back to rsync when RRDP fails |
| `-j` | number of CPUs | `validation.workers` | next cycle | Number of parallel validation workers (1 to 1024) |
| `-drop-warn` | `0.1` | `validation.drop-warn` | next cycle | Warn when the VRP count drops by more than this fraction compared with the previous result (0 to 1) |
| `-hold-drop` | `false` | `validation.hold-drop` | next cycle | On such a drop, hold the update (keep serving the previous VRPs) |
| `-max-start-age` | `2h` | `validation.max-start-age` | restart | At start-up, open RTR immediately if the saved set is newer than this (>= 0) |
| `-stale-warn` | `1h` | `validation.stale-warn` | immediate | Warn (log, status `stale`, `/healthz` 503) when the served set was validated longer ago than this (>= 0, 0 = off). Section 6.5 |
| `-P` | `0` (now) | - | - | Validation time (Unix seconds). For offline comparison |
| `-fetch` | `false` | - | - | Fetch from the repositories before `-validate` |
| `-fail` | (none) | - | - | Failure list file for `-parse` |

**RTR**

| Option | Default | Config key | Reload | Meaning |
|---|---|---|---|---|
| `-rtr` | `:3323` | `rtr.listen` | restart | RTR address (empty = not opened) |
| `-rtr-allow` | `127.0.0.1,::1` | `rtr.allow` | immediate | Allowed addresses / prefixes. Other sources are closed at once. On reload, connections no longer in the list are also closed |
| `-rtr-refresh` | `600` | `rtr.refresh` | next End of Data | How often the router asks without a Notify (seconds, 1 to 86400) |
| `-rtr-retry` | `300` | `rtr.retry` | next End of Data | Reconnect interval after a failure (seconds, 1 to 7200) |
| `-rtr-expire` | `7200` | `rtr.expire` | next End of Data | The router discards the VRPs if it cannot refresh for this long (seconds, 600 to 172800, must be larger than refresh and retry) |
| `-rtr-auth` | (none) | `rtr.auth` | restart | TCP-MD5 / TCP-AO key file (section 7.4) |
| `-rtr-tls` | (none) | `rtr-tls.listen` | restart | RTR over TLS address (e.g. `:3324`) |
| `-rtr-tls-cert` / `-rtr-tls-key` | (none) | `rtr-tls.cert` / `rtr-tls.key` | next TLS connection | Server certificate / key (PEM) |
| `-rtr-tls-ca` | (none) | `rtr-tls.ca` | next TLS connection | If set, a router certificate issued by this CA is required |
| `-rtr-max-conns` | `256` | `rtr.max-conns` | next connection | Concurrent RTR connections (0 = no limit). Section 7.2 |
| `-rtr-max-per-ip` | `4` | `rtr.max-per-ip` | next connection | Concurrent RTR connections per address, IPv6 counted per /64 (0 = no limit). At most 16 per IPv6 /48 (fixed) |
| `-rtr-trusted` | (none) | `rtr.trusted` | next connection | Prefixes of your own routers: always allowed, each address counted alone, only `rtr.trusted-max-conns` applies (section 7.2) |
| `-rtr-trusted-max-conns` | `20000` | `rtr.trusted-max-conns` | next connection | Concurrent RTR connections from trusted prefixes (0 = no limit, up to 100000) |
| `-stale-close` | `0` (off) | `rtr.stale-close` | immediate | Close RTR (listeners and sessions) when the served set was validated longer ago than this, so routers fail over to another RP (0 = off, otherwise >= `30m`). Section 6.5 |
| `-rtr-stdio` | - | - | - | Mode (4.1) |

**HTTP API**

| Option | Default | Config key | Reload | Meaning |
|---|---|---|---|---|
| `-http` | `127.0.0.1:8323` | `http.listen` | restart | HTTP address(es), comma separated (empty = not opened) |
| `-http-allow` | `127.0.0.1,::1` | `http.allow` | immediate | Internal clients (all paths), applied to all HTTP addresses |
| `-http-public` | (empty = none) | `http.public` | immediate | Public clients: lookup paths only, status without internal data, `/json` / `/csv` rate-limited (section 8.1). Sources in neither list get 403; in both = internal |
| `-jsonext` | `false` | `http.jsonext` | immediate | Enable `/jsonext` (about 470 MB, about 5 seconds per request. For investigation) |
| `-delta-full-interval` | `1m` | `http.delta-full-interval` | immediate | A full `/json-delta` (and, for public clients, `/json` / `/csv`) is served once per this interval per client (IPv4 address, IPv6 /64); within it the answer is 429 (0 = no limit, >= 0) |

Value formats: durations = `10m`, `2h`, `90s` / lists = comma separated (`127.0.0.1,::1,10.0.0.0/8`) / booleans = `true` / `false`.

---

## 5. Configuration file

### 5.1 Rules
- Location: `-c <file>`; otherwise `/etc/haetae/haetae.conf`, only if it exists. Read **in daemon mode only**
- Precedence: **command-line option > configuration file > default**
- Format
  - `key = value` under a `[section]`
  - Everything after `#` is a comment (anywhere on a line), except inside double quotes
  - A value may be enclosed in double quotes, which are removed: `slurm = "/etc/haetae/slurm#2.json"` (0.3.0). In a list, quote each item (`allow = "127.0.0.1", ::1`)
  - Lists are comma separated. **A line ending in a comma continues on the next line** (one line is fine too)
  - An empty value (`tal =`) means "none", the same as the default
- Errors: unknown key / the same key twice / invalid value / a trailing comma with no following value / an unclosed quote or a quote in the middle of a value (`/etc/"a".json`)
  - at start-up -> Haetae does not start (the journal shows the line number and the reason)
  - on reload -> nothing is changed and the current values stay in effect

### 5.2 All keys (example filled with the defaults)
```ini
[paths]
cache = /var/lib/haetae/cache        # (restart)
out   = /var/lib/haetae/out          # (restart)
state = /var/lib/haetae/state        # (restart)
tal   =                              # empty = built-in TALs
slurm =                              # empty = none

[fetch]
interval = 10m
jobs     = 32
rsync    = true                      # false = -norsync

[validation]
workers       = 32                   # default = number of CPUs
drop-warn     = 0.1
hold-drop     = false
stale-warn    = 1h                   # 0 = off
max-start-age = 2h                   # (restart)

[rtr]
listen  = :3323                      # (restart)
allow   = 127.0.0.1, ::1
auth    =                            # (restart)
refresh = 600
retry   = 300
expire  = 7200
stale-close = 0                      # 0 = off, otherwise >= 30m

[rtr-tls]
listen =                             # (restart)
cert   =
key    =
ca     =

[http]
listen = 127.0.0.1:8323              # (restart)
allow  = 127.0.0.1, ::1              # internal: every path
public =                             # public: lookup paths only (empty = none)
jsonext             = false
delta-full-interval = 1m
```
`(restart)` = not changed by reload; a restart is needed (section 6.4).

### 5.3 Example: routers and a second HTTP address
Only the keys that differ from the defaults. The full example is `deploy/haetae.conf.example`.

```ini
[rtr]
allow  = 127.0.0.1, ::1,
         192.0.2.1, 2001:db8::1          # routers

[http]
listen = 127.0.0.1:8323, 0.0.0.0:8324    # local + one address reachable from other servers
allow  = 127.0.0.1, ::1, 198.51.100.0/24 # management network: every path
public = 203.0.113.0/24, 2001:db8:200::/48 # other users: lookup paths only (0.0.0.0/0, ::/0 = internet)
```
Apply the same sources in the host firewall, so access is limited in two layers.

---

## 6. Behaviour

### 6.1 Cycle (default 10 minutes)
1. **Fetch**: each repository once, 32 in parallel, at most 5 minutes per repository
   - RRDP (https) first: based on the serial in the notification file, only the changes (deltas). A snapshot on first contact or when the chain is broken
   - Deltas are applied in two steps (everything is checked first, then moved in at once) -> there is never a half-applied state
   - Conditional GET: the ETag / Last-Modified of the last fully applied notification file is stored with the RRDP state and
     sent as `If-None-Match` / `If-Modified-Since`; a 304 answer means nothing changed (result `none`). At least once an hour
     the file is fetched unconditionally
   - If RRDP keeps failing for a certain time (1 hour; 3 hours for large repositories with 10,000 or more objects), rsync is
     used instead; if both fail, the previously fetched data is used (within the manifest validity, usually about a day).
     Large repositories wait longer on purpose: their rsync modules rarely finish within the 5-minute limit, and when all RPs fall
     back at once the rsync servers are overloaded. This is longer than the 1 hour in draft-ietf-sidrops-prefer-rrdp-02.
     The RRDP row result is `fallback-old` (within 1 hour, previous data), `fallback-rsync` (rsync succeeded) or `failed`
     (rsync failed too, or rsync is disabled)
   - Limits against hostile repositories: size / count / depth / time limits, https only for RRDP, no path escape.
     Size limits: one object file (binary) 20 MB, the same as the Routinator default (rpki-client uses 4 MB; the largest
     real object, an ARIN CA manifest, is 3.87 MB in 2026-11). rsync files and TA certificates use the same limit.
     An RRDP file is rejected if any XML token (text, comment, CDATA, ...) or the text of one `publish` element is longer than
     the base64 limit derived from it (about 54 MB = twice the base64 size of 20 MB), before it is loaded into memory
   - Repository addresses: notify URIs are normalised (lower-case host, no `:443`), so the same repository written differently
     is fetched once. A notify URI with a query, fragment or user info is not used (rsync instead, warning
     `rpkiNotify not usable, using rsync`). At most 1,000 different repositories below one TA (more: the CA is rejected)
   - Fetch deadline `fetch.deadline` (default 20 minutes): repositories not reached by then are not fetched and are validated
     from previous data; fetches in progress get the remaining time. They are reported as `skipped` and do not count as failures
   - Disk: if less than 10 GB is free on the cache file system at the start of a cycle, new repositories (never fetched before)
     are not fetched (log `WARNING low disk`)
   - Cleanup: after a cycle in which all TAs completed, repositories in `cache/rrdp/` and `cache/rsync/` not used by any cycle
     for 3 days are removed (log `cache: removed N repositories unused for 72h0m0s`)
   - Publication point size: a manifest and its listed files may total 512 MB (otherwise the CA is rejected), and at most 2 GB of
     publication points are held in memory at once (further CAs wait), so many large repositories cannot exhaust memory
   - If the saved RRDP state exists but its directory is missing (e.g. a crash during a snapshot swap), a fresh snapshot is fetched
   - A downloaded TA certificate is checked against the TAL key (self-signed CA, same key, valid signature) before it
     replaces the cached one; a wrong file from the server never removes a good cached TA
   - An empty snapshot (no objects) still replaces the directory. An rsync module larger than 2,000,000 files or 4 GB is
     removed and counted as failed (while it is being fetched, the 5-minute limit bounds it)
   - A delta that cannot be fetched because of a network problem (connect / timeout / 5xx / 429 / cut off) does not trigger a
     snapshot: that repository uses its previous data and continues next cycle. A delta with wrong content (hash mismatch,
     missing serial, 4xx) triggers a snapshot
   - Backoff: a repository (RRDP notification URI or rsync module) that fails 3 times in a row is not contacted for
     10 minutes, then 20, 40, at most 1 hour after each further failure; one success resets it. A `Retry-After` header
     on a 429 / 503 answer (seconds or an HTTP date) is honoured when longer, up to 1 hour. While skipped, the repository
     is treated as failed for that cycle (previous data, or rsync fallback, as above), with the error
     `skipped after N failures until <time> (last: <error>)`. `/repos.json` and `repos_problems` in the status show
     `consecutive_failures`, `last_success`, `next_try` and `skipped`. The counters are kept in memory only and start
     again from zero after a restart
2. **Validate**: TAL -> TA certificate -> CA -> manifest -> CRL / ROA / ASPA / router certificate / GBR / SPL / TAK
   - Checks signatures, manifest hashes, CRLs, validity periods, and resource containment (child ⊆ parent)
   - A bad object rejects only that object; a broken manifest rejects the whole CA publication point (RFC 9286; the same strictness as rpki-client)
   - If processing one object hits a panic (a bug in Haetae), only that object is rejected (reason `panic: ...` with the location)
     and the next object is processed; a panic in the manifest / CRL step rejects the CA. The process keeps running
   - SKI check: if the SKI of a certificate (TA / CA / router / object EE) is not the SHA-1 hash of its public key
     (RFC 6487 section 4.8.2), only a warning is counted: `SKI is not SHA-1 of public key` in `summary.txt` /
     `last_run.counts`, with up to 5 example URIs. The certificate is not rejected (for now)
   - Manifest fallback (RFC 9286 section 6.7): every publication point that passes is stored under
     `<cache>/valid/<hex>/` (the manifest, the listed files as hard links, `NUMBER`), where `<hex>` is the SHA-256 of the CA public key,
     its RRDP notify URI and its manifest URI (a CA that copies another CA's manifest URI gets a different copy). If the freshly fetched
     manifest / CRL / files fail, the CA is validated again from the stored copy. The copy must still be within its validity,
     so it expires by itself. Such manifests get `"fallback": true` in `objects.jsonl`, and the warning
     `manifest failed, using previous valid publication point` is counted in `summary.txt` / `last_run.counts`
   - A manifest number lower than the stored one is treated as a failure (rollback protection, RFC 9286 section 4.2.1),
     unless the stored copy is no longer valid (for example expired): then the new manifest is accepted, so a CA that was
     re-created with numbering from the start comes back (warning `manifest number went back, previous copy no longer valid: accepted`)
   - Stored copies of CAs not seen in a cycle are removed, only when all TAs completed (log `valid: removed N stale publication points`)
   - Daemon (and `-t`) mode only. `-validate` (offline comparison) does not use it, like `rpki-client -n`.
     Tested on a real snapshot with an empty repository cache: all 55,828 publication points fell back and the
     VRP / ASPA / router key output was identical
3. **Apply decision** (6.2 below)
4. **Export**: result files, RTR Serial Notify, one history line per cycle (log + `history.jsonl`)

If the configuration is reloaded during a cycle, that cycle finishes with the configuration it started with (new values apply from the next cycle).

### 6.2 Apply decision (protecting the previous result)
| Case | Action |
|---|---|
| Any TA failed | Not applied, previous result kept |
| 0 VRPs | Not applied |
| VRP count dropped by more than `drop-warn` (10 %) | Warning. With `hold-drop = true` the update is held |
| SLURM file broken | That cycle is skipped without fetching / validating and not applied (exceptions suddenly disappearing would be dangerous). Status `slurm.error`, `run skipped` in history and log |
| TAL folder unreadable (`paths.tal`) | Same: the cycle is skipped and recorded in `last_run.reason` and history |
| Otherwise | Applied: serial +1, changes kept (last 200 cycles, about 33 hours), `state/payload.gob` saved |

A failed TA or 0 VRPs is never applied, even on the very first cycle (no previous result), so RTR never opens with a partial set.
The drop check compares against a previous result and does not apply to the first cycle.

### 6.3 Start and restart
- At start-up: configuration -> TAL check (Haetae does not start if a TAL is broken) -> `state/payload.gob`
  (the set served over RTR after SLURM, session, serial and the last 200 deltas; about 1.6 s and 44 MB for about 1M VRPs)
- `payload.gob` is written atomically (temporary file, fsync, rename) after every applied cycle, so set, session, serial and deltas always belong to the same cycle
- If the saved set is within `max-start-age` (2 hours), **RTR is opened immediately** -> routers reconnect with the same session and fetch only the changes
- If `payload.gob` is older than that or unreadable, a new session (always different from the old one) is created and RTR is opened after the first applied cycle (routers fetch everything again)
- Upgrade from a version before 0.2.0: since 0.3.0 the older state files (`state.json` + `out/json` + `deltas.gob`) are no longer read,
  so `payload.gob` is missing and a new session is created (routers fetch everything once). Upgrade through 0.2.0 to keep the session.
  `state.json` is still written for humans only
- RTR counts as open (`rtr_open`) only when every configured RTR listener (plain, TLS) is open. A listener that fails (e.g. port in use) is retried after each applied cycle
- During a restart the API / RTR are unavailable for about 5 seconds

### 6.4 Reloading the configuration (`systemctl reload haetae`)
Re-reads only the configuration while running (not a restart: RTR sessions, the in-memory result and the cycle stay as they are).

1. The command line + configuration file are read again with the start-up rules (the command line still wins)
2. All new values are checked first. If any is invalid or the file is missing, **nothing is changed**
3. If a restart-only item changed, the current value is kept and a warning is logged
4. Everything else is switched at once, and the log lists only the changed items as `key "old" -> "new"`

| Changes immediately | From when |
|---|---|
| `rtr.allow`, `http.allow`, `http.public` | Next connection / request. RTR closes connections that are no longer in the list at once |
| `validation.stale-warn`, `rtr.stale-close` | Next stale check (within 1 minute) |
| `rtr.refresh / retry / expire` | Next End of Data |
| `fetch.*`, `validation.workers / drop-warn / hold-drop`, `paths.tal / slurm` | Next cycle |
| `http.jsonext`, `http.delta-full-interval` | Next request |
| `rtr-tls.cert / key / ca` | Next TLS connection (certificate rotation) |

| Needs a restart | Why |
|---|---|
| `paths.cache / out / state` | Changing directories while running is unsafe |
| `rtr.listen`, `rtr-tls.listen`, `http.listen` | Sockets must be reopened |
| `rtr.auth` | Keys are installed in the kernel (a wrong change would drop router sessions) |
| `validation.max-start-age` | Used only at start-up |

The `config` field (`file`, `loaded`) of the status API shows when the configuration was last read.

### 6.5 Stale data
Every minute, independently of cycles (also while a cycle hangs), Haetae checks the age of the served set
(time since it was validated, `data_age_s` in `/healthz`, `haetae_data_age_seconds` in `/metrics`).

| Threshold | Action |
|---|---|
| `stale-warn` (default `1h`, 0 = off) | Log `WARNING stale data: set built 1h10m0s ago (stale-warn 1h0m0s)` when it becomes stale and every 30 minutes while it stays stale; status field `stale: true`; `/healthz` answers 503 `stale`. Log `stale data cleared (...)` when a newer set is applied |
| `stale-close` (default 0 = off, otherwise >= `30m`) | RTR listeners are closed and all router sessions dropped (log `rtr closed (set built ... ago, over stale-close ...), N connections dropped`). RTR is opened again when a new set is applied |

When to use `stale-close`: only when the routers also have another RP configured. Closing RTR makes them fail over
to it instead of keeping old data. Without another RP leave it off: a router keeps the data it already has until its
RTR expire interval (`rtr.expire`, default 2 hours) runs out, which is normally better than losing the connection.
Choose `stale-close` larger than the time a cycle may be delayed; if it is smaller than `max-start-age`, a set loaded at
start-up may be closed again within a minute.

### 6.6 systemd integration and stopping
The service unit uses `Type=notify`, `NotifyAccess=main`, `WatchdogSec=3min`:
- Haetae sends `READY=1` after its listeners are open (RTR too, if the saved set was usable), so `systemctl start` returns then
- While it is alive it sends `WATCHDOG=1` every third of the watchdog interval (1 minute). Alive = the internal locks
  respond within 10 seconds and no cycle has been running for more than 1 hour. Otherwise it stops sending
  (log `watchdog: not alive (lock held or cycle over 1h0m0s), systemd will restart`), systemd kills it after 3 minutes and
  restarts it (`Restart=on-failure`)
- On stop it sends `STOPPING=1`
- Outside systemd (no `NOTIFY_SOCKET` / `WATCHDOG_USEC`) none of this is active

Stopping (`SIGTERM`, `SIGINT`; `systemctl stop` / `restart`):
1. Log `terminated: stopping` (`interrupt: stopping` for SIGINT)
2. RTR is closed: listeners and all router sessions (log `rtr closed (stopping), N connections dropped`)
3. HTTP stops accepting; requests in progress get up to 5 seconds to finish
4. If a set is being applied / saved (`payload.gob`, output files), Haetae waits for it, up to 60 seconds. A fetch or
   validation in progress is simply abandoned
5. Log `stopped`, exit code 0

**Upgrading from an older binary:** install the new binary and the new unit file together (then `systemctl daemon-reload`).
A binary without `READY=1` support started by a `Type=notify` unit never reports ready, so the start times out.

### 6.7 Seamless upgrade (SIGUSR2)
The router RTR sessions and the HTTP listening sockets are handed to the new binary, so **router sessions are not
dropped** (a restart drops them and the routers reconnect). Like nginx's binary upgrade, the **same process (pid)**
executes the new file, so for systemd nothing happens (no restart; the watchdog keeps running).

| Step | Old binary | New binary |
|---|---|---|
| 1 | Checks the new file: `haetae <options> -handover-check` (same state format, accepts the current configuration and TALs). Stops here if not | |
| 2 | **Waits for a running cycle (fetch + validate + apply) to finish** (up to 15 minutes). That cycle has already saved the set in `payload.gob` | |
| 3 | Stops accepting RTR / HTTP connections (new ones queue in the kernel). HTTP requests in progress may finish (up to 30 s) | |
| 4 | Each RTR connection finishes its current response and stops reading at a PDU boundary (a partly received PDU is handed over, up to 2 minutes) | |
| 5 | Writes `state/handover.gob` (lock, listener and connection file descriptors, connection state such as the RTR version, repository back-off) and executes the new file with the same pid (options + `-resume`) | |
| 6 | | Loads `payload.gob`: same session / serial (about 2 s) |
| 7 | | Takes over the sockets and connections and continues reading = **pause ends** |
| 8 | | **Validates the cached repository data without fetching** to rebuild the lookup data (objects, ca, expiring, unsafe, VRP sources) in about 40 s; the RTR set, output files and history are not touched. Only these paths answer 503 meanwhile |
| 9 | | Runs a normal cycle (fetch + validate + apply) right after |

- Pause measured with a production-size set (1.03 million VRPs): about 2 s; longer by the remaining transfer time if a
  connection is receiving a full set at that moment. Routers simply wait on TCP
- Not handed over: **RTR over TLS connections** (the TLS state lives in process memory): those routers reconnect.
  Idle HTTP keep-alive connections are closed
- On failure in steps 1–5 (including a failed exec) everything is undone and the old binary keeps running (log
  `handover: aborted ...`, status `handover.last_error`). If the new binary cannot read the state file it exits and
  systemd restarts it, which is the same as a restart
- The new binary reads the configuration again; the listening addresses (`rtr.listen`, `rtr-tls.listen`, `http.listen`)
  keep the inherited sockets (changing them needs a restart)
- **The running binary must support this.** A binary without it is terminated by SIGUSR2 (systemd restarts it after
  30 s). The first installation of a version with this feature is a normal restart
- If the unit file changed, use `daemon-reload` and a restart instead

`tools/upgrade.sh` does all of this and waits for the result (exit code 0 = resumed, 1 = aborted; `-n` skips `go test`).
It assumes the unit `haetae` and the binary at `/usr/local/bin/haetae`. The same by hand (the new binary is installed
over the old one, then the running process is told to hand over):

```
go build -o haetae . && go test ./...
sudo install -m 755 haetae /usr/local/bin/haetae
sudo systemctl kill -s USR2 --kill-whom=main haetae
journalctl -u haetae -f      # wait for "handover: resumed ..." (or "handover: aborted ...")
```

`systemctl status haetae` keeps the same main PID and start time; `/api/v1/status` field `handover.count` goes up by one.

---

## 7. RTR (router connections)

### 7.1 Version negotiation
| Version | Provides | Notes |
|---|---|---|
| v0 (RFC 6810) | VRPs | Older routers |
| v1 (RFC 8210) | VRPs + router keys | Three timers in End of Data |
| v2 (draft-ietf-sidrops-8210bis) | VRPs + router keys + ASPA | Still being standardised |

Haetae follows the version sent by the router; if it is higher than 2, Haetae answers with an "Unsupported Protocol Version" error so the router downgrades.

### 7.2 Exchange
- Reset Query -> everything / Serial Query -> only the changes (if the serial is not in the history: Cache Reset -> the router fetches everything)
- When a new serial is created, a Serial Notify is sent to all connected routers
- Addresses outside the allow list are closed at once, with one log line
- Limits for an RTR port open to many clients. Connections from `rtr.trusted` (your own routers) and from everyone else are counted apart:
  - Others: at most `rtr.max-conns` (256) connections, `rtr.max-per-ip` (4, IPv6 per /64) per address and 16 per IPv6 /48
  - Trusted: always allowed (even outside `rtr.allow`), each address counted alone (many router loopbacks in one /64 are fine),
    only `rtr.trusted-max-conns` (20000). They still connect when the other connections fill their limit
  - More are closed at once (logged at most once a minute: `rtr ...: connection limit ...`). A connection that sends
    no PDU within 30 s, or nothing for 2 hours afterwards, is closed
  - A full set (Reset Query answer) is sent at most once a minute per connection, and at most twice a minute per untrusted
    address (so reconnecting does not get around it); a faster Reset Query gets an Error Report "No Data Available"
    (not fatal: the router retries after its retry interval, the session stays up)
  - During a version upgrade (6.7), a connection that does not read its answer is closed after 1 minute instead of blocking the upgrade
- Plain TCP RTR open to the Internet cannot protect routers against on-path tampering: production routers should use TCP-AO
  or another transport security (7.4), or an allow list

### 7.3 Checking
```bash
curl -s localhost:8323/api/v1/status        # rtr_clients: address, transport, version, serial received
curl -s localhost:8323/json -o haetae.json  # compare what an RTR client receives with this file
```
Any RTR client can be used to dump what Haetae sends, for example `rtrdump` from the StayRTR package
(v0 / v1; it does not decode v2 ASPA PDUs). The VRP and router key counts should match `/json` for the same serial.
On the router: Cisco IOS XR `show bgp rpki server summary`, FRR `show rpki cache-connection`.

### 7.4 Transport security (default: plain TCP + allow list)
| Method | Port | Configuration |
|---|---|---|
| TCP-AO (RFC 5925) | the RTR port | `rtr.auth` key file: `<address> ao <algorithm> <sendid> <recvid> <key>` |
| TCP-MD5 (RFC 2385) | the RTR port | `rtr.auth` key file: `<address> md5 <key>` |
| TLS | separate (e.g. 3324) | `[rtr-tls]` listen / cert / key (/ ca) |
| SSH | 22 (system sshd) | the sshd `rpki-rtr` subsystem runs `haetae -rtr-stdio 127.0.0.1:3323` |
| IPsec | the RTR port | nothing in Haetae: the OS (strongSwan etc.) protects packets between the server and the router |

All six transports of RFC 8210 section 9 can be used. Pick the method your routers support; methods can be combined
(e.g. TCP-AO for some routers, plain TCP for others).

**TCP-MD5 / TCP-AO (Linux kernel, same port as plain RTR)**

The keys are installed per router address on the listening socket, so the Linux kernel signs and checks every TCP segment.
From an address that has a key, unsigned or wrongly signed connections are dropped by the kernel
(they do not appear in the Haetae log; the router just sees no connection). Addresses without a key keep using plain TCP;
the allow list applies in both cases.

```bash
sudo install -d -m 755 /etc/haetae
sudo install -m 600 -o haetae -g haetae /dev/null /etc/haetae/rtr-auth.conf
sudoedit /etc/haetae/rtr-auth.conf
```
Key file format (one line per address or prefix, `#` starts a comment):
```
# address or prefix   method   rest
192.0.2.1             md5      <password>
198.51.100.0/24       ao       hmac(sha1)  <sendid> <recvid>  <password>
```
- TCP-AO algorithms: `hmac(sha1)` (HMAC-SHA-1-96, RFC 5926), `cmac(aes128)` (AES-128-CMAC-96), `hmac(sha256)`. MAC length 12 bytes
- `sendid` / `recvid` are from Haetae's point of view: the router's send-id = Haetae's `recvid`, the router's receive-id = Haetae's `sendid`
- Keep the file readable by the haetae account only (mode 0600). Haetae logs a warning if group or others can read it.
  Keys are kept in a file so they never appear on the command line
- Set `rtr.auth = /etc/haetae/rtr-auth.conf` and **restart** (`rtr.auth` is not changed by reload, also when keys change)
- Check: `transport` in `rtr_clients[]` of `/api/v1/status` shows `tcp-md5` / `tcp-ao`; `ss -tni` also shows md5 / ao

**TLS (separate port)**
```ini
[rtr-tls]
listen = :3324
cert   = /etc/haetae/tls.pem
key    = /etc/haetae/tls.key
ca     = /etc/haetae/routers-ca.pem      # optional: require router certificates issued by this CA
```
With `ca` set, connections without a valid router certificate are closed. The RTR allow list applies to TLS as well.
Changing `listen` needs a restart; new `cert` / `key` / `ca` files take effect with reload, from the next TLS connection.
- A web server certificate (e.g. Let's Encrypt) works, provided the routers trust its root CA and connect by its DNS name.
  Renew it with a deploy hook that runs `systemctl reload haetae`; existing connections are not affected.
- The RFC port for TLS, 324, is below 1024 and cannot be opened by the haetae account; use e.g. 3324 and set the port on the router.

**SSH (system sshd)**

The Go standard library has no SSH server, so the system sshd is used. A dedicated account for routers logs in,
and the `rpki-rtr` subsystem runs `haetae -rtr-stdio`, which connects the SSH channel to the local RTR port.
```bash
sudo useradd --system --create-home --shell /bin/sh rpki-rtr && sudo passwd rpki-rtr   # username / password configured on the router
```
Add to `/etc/ssh/sshd_config`, check with `sudo sshd -t`, then `sudo systemctl reload ssh`:
```
Subsystem rpki-rtr /usr/local/bin/haetae -rtr-stdio 127.0.0.1:3323
Match User rpki-rtr
    ForceCommand /usr/local/bin/haetae -rtr-stdio 127.0.0.1:3323
    AllowTcpForwarding no
    X11Forwarding no
    PermitTTY no
```
- To Haetae these connections come from 127.0.0.1 (included in the default `rtr.allow`; `rtr_clients` shows 127.0.0.1)
- Restrict which routers may log in at the sshd level (firewall for port 22, `AllowUsers`, keys instead of passwords where the router supports it)
- If the router closes only its sending side (EOF), `-rtr-stdio` still passes Haetae's response through to the end before it exits (0.3.0)

**IPsec (operating system)**

IPsec is configured in the operating system (for example strongSwan or libreswan with a pre-shared key or certificates)
between this server and the routers. The kernel protects the packets; Haetae keeps listening on the plain RTR port and
sees ordinary TCP connections (`transport` is `tcp`). Narrow `rtr.allow` to the IPsec peers so that nobody can reach
the RTR port outside IPsec. The router must support IPsec for its own (control-plane) traffic.

### 7.5 Timers
refresh / retry / expire (default 600 / 300 / 7200 seconds) are sent in the End of Data PDU of v1 / v2.
Some routers prefer their own configured values. v0 has no such fields.

### 7.6 TALs (the starting point of trust)
- The TALs of the 5 RIRs are **built into the binary** (from `tals/` in the source tree at build time). Haetae does not depend on TALs installed by other software
- Start-up log `TAL (...): afrinic ad69…, apnic a3a0…, …` = public key hashes (must match the table in `tals/README.md`)
- When an RIR rolls its TA key (rare):
  - normally: update `tals/` and the table, rebuild and reinstall
  - urgently: put the new TAL files in a directory, set `paths.tal = <dir>` -> `systemctl reload` (no rebuild, from the next cycle)
- TAK (RFC 9691) objects are parsed and shown in the object list (current / predecessor / successor key identifiers).
  If a TAK issued by the TA lists a **successor key** (= a key rollover is announced), Haetae warns on every cycle (0.3.0):
  log `WARNING TA key rollover announced (TAK, update TAL): <TA>: successor SKI …, certificate <URI> (<TAK URI>)`,
  and `TAK announces successor TA key` in summary.txt, status API counts and `/metrics haetae_warnings`.
  When you see it, update the TAL as above (Haetae does not switch keys by itself). The warning stops once the TAK names the new key as current.
  A TAK issued by a non-TA CA, or whose current key is not the TA key, is ignored (warning `TAK not signed by TA key (ignored)`)

**TA constraints are not used.** Some RPs (rpki-client) can restrict each TA's resources with local `*.constraints` files
derived from IANA / RIR allocation data. This is not part of any RFC, and RIR TAs normally hold all resources.
Such files must be kept in sync with allocation changes; an outdated file rejects legitimate ROAs and ASPAs
(for example, a prefix newly allocated by IANA to an RIR). Haetae therefore validates by the RFCs only.

---

## 8. HTTP API and output files

### 8.1 Addresses and access
- The same API is served on every address in `http.listen`. Each request is classified by its source address:

  | Source | Access |
  |---|---|
  | in `http.allow` (internal) | every path |
  | in `http.public` only (public) | `/status`, `/api/v1/status` (without `rtr_clients`, `config`, `slurm`, `mem_mb`, `started`, `last_run.mem_mb`), `/api/v1/validity/...`, `/api/v1/as/...`, `/api/v1/prefix/...`, `/api/v1/aspa/verify`, `/api/v1/vrps/delta`, `/json-delta`, `/healthz`, `/json` and `/csv` (once per `delta-full-interval` per client, else 429 + `Retry-After`). Other paths: 403 `not available on public access` |
  | in neither | 403 `forbidden` |

  An address in both lists is internal. Recommended: keep `http.allow` to management networks and open anything wider
  (including the internet) only through `http.public`
- Each listen address is opened at start-up. One that cannot be bound is logged (`http listen <addr>: ...`) and skipped;
  Haetae keeps running (other addresses, RTR)
- Everything is GET (read only; there is no API that changes state)
- Before the first validation (1 to 2 minutes after a restart), objects / expiring / CA / unsafe / jsonext return 503

### 8.2 Main paths (details: [api.md](api.md))
| What you want | Path |
|---|---|
| Is it running well? | `/status` (human readable), `/api/v1/status` (JSON) |
| RPKI validity of one route | `/api/v1/validity/AS64496/192.0.2.0/24` |
| ASPA verification of an AS_PATH | `/api/v1/aspa/verify?path=64496+64497+64498` |
| AS / prefix lookup | `/api/v1/as/<AS>`, `/api/v1/prefix/<prefix>` |
| Everything once, then only changes | `/json-delta`, `/json-delta?session=S&serial=N[&to=M]` |
| Health check (load balancer / monitoring) | `/healthz` (200 or 503) |
| Objects / CAs / expiring | `/api/v1/objects`, `/api/v1/ca?uri=`, `/api/v1/expiring?days=30` |
| Unsafe / exceptions / repositories / rejects | `/api/v1/unsafe`, `/api/v1/slurm`, `/repos.json`, `/rejects.txt` |
| Trends | `/api/v1/history?hours=48`, `/metrics` (Prometheus) |
| Full files (large) | `/json`, `/csv`, `/objects.jsonl`, `/jsonext` (optional) |

### 8.3 Output files (`/var/lib/haetae/out`, rewritten every cycle)
| File | Size (2026-10) | Content |
|---|---|---|
| `json` | about 107 MB | VRPs + ASPA + router keys + statistics (rpki-client format) |
| `csv` | about 45 MB | ASN, prefix, maxLength, TA, expiry |
| `objects.jsonl` | about 360 MB | Every validated object (one per line: type, URI, SHA-256, validity period, status, content summary) |
| `rejects.txt` | small | Rejected objects and reasons |
| `repos.json` | small | Fetch result per repository |
| `summary.txt` | small | Counts per type, warning counts with examples |

### 8.4 Load protection
| Target | Protection |
|---|---|
| Full `/json-delta` (85 MB, about 1 s CPU) | Once per `delta-full-interval` per client; otherwise 429 + `Retry-After` |
| `/json`, `/csv` for public clients | Once per `delta-full-interval` per client and file; otherwise 429 + `Retry-After` |
| Per-client counting | IPv4 by address, IPv6 by /64 |
| Connections | At most 256 concurrent connections per listen address (more wait in the kernel backlog). Addresses outside `http.allow`: at most 8 per client and 224 in total, extra connections are closed at once; 32 are kept for internal clients |
| Slow / idle clients | Request header 10 s, whole request 30 s, idle keep-alive 2 min, header size 64 KiB. No overall write timeout (large files over slow links), but a response that cannot send 256 KiB within 60 s is cut |
| `/jsonext` (470 MB, about 5 s) | Off by default (`http.jsonext`) |
| Clients | Fetch the full set once, then only the changes by `serial`. On reset replace everything; on 429 keep what you have and retry later |

---

## 9. Logs (journal)

Use `journalctl -u haetae`. Main lines (in version 0.2.0 some messages are still in Korean; the English meaning is given):

| When | Message (example) | Meaning |
|---|---|---|
| start | `설정 /etc/haetae/haetae.conf : paths.cache=... rtr.allow=...` | Configuration file read and the values taken from it |
| start | `TAL (내장): afrinic ad69cadc45c0cd41, ...` | TAL source (`내장` = built-in, or the directory) and public key hashes |
| start | `state: session 12345 serial 245, 1030503 VRPs from <time>, deltas 200 (payload.gob saved <time>)` | Continuing; RTR opened immediately with the saved set |
| start | `state: new session 23456 (payload.gob: too old (3h0m0s))` | New session: routers fetch everything again after the first applied cycle |
| start | `http allow [...] public [...]`, `http listening ...`, `rtr listening :3323 (allow [...], tcp auth keys 0)` | Listening addresses and allow lists |
| start | `http listen 0.0.0.0:8324: ... address already in use` | That HTTP address could not be opened (skipped; Haetae keeps running) |
| start / cycle | `rtr listen :3323: ... (retry after next applied run)` | RTR listener (or `rtr tls listen`) could not be opened; retried after each applied cycle |
| cycle | `valid: removed 12 stale publication points` | Stored valid copies of CAs that no longer exist were removed (6.1) |
| cycle | `run 1m12s: vrps 1030362 vaps 3925 keys 3 +4 -1 serial 142 repos map[...] 13MB applied=true` | Cycle summary (duration, counts, added / removed, repository results, bytes fetched, applied or not) |
| cycle | `WARNING run deadline 20m0s: 37 repositories not fetched (using previous data)` | Repositories skipped because of the fetch deadline (6.1) |
| cycle | `WARNING low disk: 8123 MB free under /var/lib/haetae/cache (< 10240 MB), new repositories are not fetched` | Low disk space (6.1) |
| cycle | `cache: removed 3 repositories unused for 72h0m0s` | Cleanup of unused repository directories (6.1) |
| cycle | `slow run 10m25s: slowest repos https://.../notification.xml rrdp ok 5m0s, ...` | Cycle longer than 3 minutes: the five repositories that took longest to fetch (over 1 s only, longest first). `(none over 1s, ...)` means validation was slow |
| cycle | `... applied=false TA failed [...], keep previous` / `WARNING VRP drop ...` | Not applied / drop warning (6.2) |
| cycle | `WARNING TA key rollover announced (TAK, update TAL): ...` | A TA announced its next key; update the TAL (7.6) |
| cycle | `run skipped: SLURM /etc/haetae/slurm.json: ..., keep previous (serial 401)` | Cycle skipped because of a TAL / SLURM error (6.2) |
| RTR | `rtr 192.0.2.1:51234: connected (tcp)`, `not in allow list, closed` | Router connected / refused |
| RTR | `rtr 192.0.2.1:51234: error report from router: code 2, PDU type 1 (v1), text "..."` | Error Report from the router (code, offending PDU, text); the connection is closed |
| stale | `WARNING stale data: set built 1h10m0s ago (stale-warn 1h0m0s)` | The served set is older than `stale-warn` (on change and every 30 minutes, 6.5) |
| stale | `stale data cleared (set built 2m0s ago)` | A newer set was applied |
| stale / stop | `rtr closed (set built ... ago, over stale-close 2h0m0s), 2 connections dropped` | RTR closed because of `stale-close` (or `(stopping)` on stop) |
| watchdog | `watchdog: not alive (lock held or cycle over 1h0m0s), systemd will restart` | Haetae stopped notifying the systemd watchdog (6.6) |
| stop | `terminated: stopping`, `stopped` | SIGTERM received / clean exit (6.6) |
| upgrade | `handover: start (SIGUSR2) ...`, `handover: paused N rtr connections ... : exec ...` | Old binary hands over (6.7) |
| upgrade | `rtr ...: resumed (tcp, v1, ...)`, `handover: resumed from 0.2.0 (#1) : N rtr connections, ... paused 2.1s` | New binary took over |
| upgrade | `handover: lookup data rebuilt from the cache in 38s (571900 objects), fetching next` | New binary: lookup paths answer again |
| upgrade | `handover: aborted, old process keeps running : ...` | Upgrade not done, nothing changed |
| stop | `stop: apply still running after 60 s, exiting anyway (...)` | The apply did not finish within 60 s (`payload.gob` is written atomically) |
| reload | `설정 다시 읽음 (...) : rtr.allow "..." -> "..."` | Configuration reloaded: changed items |
| reload | `설정 다시 읽음 : 재시작해야 바뀌는 항목 (지금 값 유지) : ...` | Restart-only items changed (current values kept) |
| reload | `설정 다시 읽기 실패, 지금 값 유지 : <file> 10 줄 : 모르는 키 [http] bogus` | Reload failed, current values kept (here: line 10, unknown key) |

---

## 10. Operations

| Task | How |
|---|---|
| View status | `systemctl status haetae`, `curl -s localhost:8323/status` |
| Change configuration | Edit the configuration file, `sudo systemctl reload haetae` -> check the log. For restart-only items use `restart` |
| Install a new version | `tools/upgrade.sh` = seamless upgrade with SIGUSR2 (6.7). Otherwise `go build -o haetae .` -> `sudo install -m 755 haetae /usr/local/bin/haetae` -> `sudo systemctl restart haetae` (about 5 s pause, routers reconnect with the same session). If `deploy/haetae.service` changed, install it too and run `systemctl daemon-reload` first (6.6) |
| Health check | `curl -s -o /dev/null -w '%{http_code}' localhost:8323/healthz` (200 = ok, 503 = see chapter 11) |
| Enable RTR fail-over | `rtr.stale-close = 2h` (for example) -> reload; only if routers have another RP (6.5) |
| Add a router | Add its address to `rtr.allow` -> reload; also allow it in the firewall (RTR port) |
| Add an HTTP client | Management systems: `http.allow`; others (lookups only): `http.public` -> reload; also the firewall |
| Local exceptions | Write a SLURM file -> `paths.slurm` -> reload (from the next cycle) |
| RIR TA key rollover | Section 7.6 |
| Enable drop protection | `validation.hold-drop = true` -> reload |

---

## 11. Troubleshooting

| Symptom | Where to look / what to do |
|---|---|
| Does not start | `journalctl -u haetae -n 20`: configuration error (line number), TAL error, `already running (lock ...)` (another instance uses the same state directory) |
| `data_time` unchanged for more than 30 minutes | Cycles are not applied -> the reason after `applied=false` in the log (TA failure, drop held, SLURM error) |
| Everything rejected as expired | Check the system clock (`timedatectl`, NTP synchronisation) |
| Router does not connect | `rtr.allow`, firewall, `not in allow list` in the log, the TCP-AO / MD5 keys are the same on both sides |
| Router fetches everything again | `new session` in the log (`payload.gob` too old / unreadable) |
| Router does not connect, `rtr_open` false | `rtr listen ...` in the log (port in use); retried after each applied cycle |
| HTTP 403 `forbidden` | Source in neither `http.allow` nor `http.public`. Add it and reload |
| HTTP 403 `not available on public access` | A public client asked for an internal-only path. Use `http.allow` for that client, or a public path |
| HTTP API not reachable on one address | `http listen <addr>: ...` in the start-up log (port in use / bad address). Fix and restart |
| HTTP 429 | Full `/json-delta` (or public `/json` / `/csv`) requested too often by the same client (IPv6: same /64). Retry after `Retry-After`; normally fetch only the changes |
| Repository fetch failures | `/repos.json`, repo-problem in `/status`. About ten small repositories are permanently unreachable (normal); after 3 failures in a row they are retried only every 10 minutes to 1 hour (`skipped: true`, `next_try`, 6.1) |
| `/healthz` 503 `starting` | No set yet: first start with an empty or too old state, waiting for the first applied cycle |
| `/healthz` 503 `stale` / `WARNING stale data` in the log | No set applied for longer than `stale-warn`. Look at `last_run.reason` / `applied=false` lines (TA failure, drop held, SLURM error) and repository failures |
| `/healthz` 503 `rtr-closed` | RTR is configured but not open: before the first applied cycle, a listener could not be opened (`rtr listen ...`), or `stale-close` closed it (`rtr closed (...)`) |
| `systemctl start` times out after an upgrade | `Type=notify` unit with an older binary that never sends `READY=1`: install binary and unit file together (6.6) |
| Restarted by systemd (`Watchdog timeout` in the journal) | Haetae was not alive (lock held or a cycle over 1 hour). Look at the log before the restart (`watchdog: not alive ...`) |
| Memory | Usually about 3 to 5 GB (higher during a cycle). systemd `MemoryMax=12G` (the value systemd reports includes about 2.7 GB of reclaimable page cache) |

---

## Appendix A. Option <-> configuration key

| Config key | Option | | Config key | Option |
|---|---|---|---|---|
| `paths.cache` | `-cache` | | `rtr.listen` | `-rtr` |
| `paths.out` | `-o` | | `rtr.allow` | `-rtr-allow` |
| `paths.state` | `-state` | | `rtr.auth` | `-rtr-auth` |
| `paths.tal` | `-tal` | | `rtr.refresh` | `-rtr-refresh` |
| `paths.slurm` | `-slurm` | | `rtr.retry` | `-rtr-retry` |
| `fetch.interval` | `-interval` | | `rtr.expire` | `-rtr-expire` |
| `fetch.jobs` | `-fetch-j` | | `rtr-tls.listen` | `-rtr-tls` |
| `fetch.deadline` | `-fetch-deadline` | | | |
| `fetch.rsync` | `-norsync` (inverted) | | `rtr-tls.cert` | `-rtr-tls-cert` |
| `validation.workers` | `-j` | | `rtr-tls.key` | `-rtr-tls-key` |
| `validation.drop-warn` | `-drop-warn` | | `rtr-tls.ca` | `-rtr-tls-ca` |
| `validation.hold-drop` | `-hold-drop` | | `http.listen` | `-http` |
| `validation.max-start-age` | `-max-start-age` | | `http.allow` | `-http-allow` |
| `validation.stale-warn` | `-stale-warn` | | `http.public` | `-http-public` |
| `rtr.stale-close` | `-stale-close` | | `http.jsonext` | `-jsonext` |
| `rtr.max-conns` | `-rtr-max-conns` | | | |
| `rtr.max-per-ip` | `-rtr-max-per-ip` | | | |
| `rtr.trusted` | `-rtr-trusted` | | | |
| `rtr.trusted-max-conns` | `-rtr-trusted-max-conns` | | | |
| | | | `http.delta-full-interval` | `-delta-full-interval` |

Options not available in the configuration file (command line only): `-c`, `-t`, `-validate`, `-parse`, `-rsc`, `-rtr-stdio`, `-P`, `-fetch`, `-fail`.
