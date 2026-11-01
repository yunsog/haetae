# Haetae User Manual

Haetae is an RPKI Relying Party (RP). It fetches objects from the RPKI repositories
worldwide, validates them, and provides the results to routers over RTR (VRPs, router keys, ASPA)
and to other systems over an HTTP API.

| Item | Value |
|---|---|
| Version | Haetae 0.1 |
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
- **Restart**: session, serial, the previous result and the deltas are saved, so Haetae continues where it left off -> routers fetch only the changes
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
- On the first start the cache is empty, so everything is fetched (about 1.5 GB, around 4 minutes). RTR is not opened during that time
- Firewall: for RTR (3323) and any HTTP port used from outside, allow only the sources that need it (two layers together with Haetae's own allow lists)

### 3.2 Directories and files
| Location | Content | Written by |
|---|---|---|
| `/usr/local/bin/haetae` | Binary (the 5 TALs are built in) | installation |
| `/etc/haetae/haetae.conf` | Configuration file | operator |
| `/etc/haetae/` (optional) | SLURM file, RTR authentication keys, TLS certificates | operator |
| `/var/lib/haetae/cache/` | Fetched objects (`rrdp/`, `rsync/`, `ta/`, `tmp/`) | Haetae |
| `/var/lib/haetae/out/` | Output files (section 8.3) | Haetae |
| `/var/lib/haetae/state/` | `state.json` (session / serial), `deltas.gob` (changes), `history.jsonl` (30-day history), `lock` | Haetae |

The systemd service can write only to `/var/lib/haetae` (`ProtectSystem=strict`). Its memory limit is `MemoryMax=12G`
(actual use is about 5.3 GB; the value reported by systemd also includes page cache, which can bring it close to 8 GB).

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

**Directories / input**

| Option | Default | Config key | Reload | Meaning |
|---|---|---|---|---|
| `-c` | (empty = `/etc/haetae/haetae.conf` if it exists) | - | - | Configuration file. Daemon mode only |
| `-cache` | daemon: `/var/lib/haetae/cache` | `paths.cache` | restart | Cache directory |
| `-o` | daemon: `/var/lib/haetae/out` | `paths.out` | restart | Output directory |
| `-state` | `/var/lib/haetae/state` | `paths.state` | restart | State directory (includes the lock: two instances cannot use the same directory) |
| `-tal` | (empty = the 5 built-in TALs) | `paths.tal` | next cycle | TAL directory (`*.tal`). Only for emergency RIR key rollovers (section 7.6) |
| `-slurm` | (none) | `paths.slurm` | next cycle | SLURM file (if it is broken, that cycle is not applied) |

**Fetching / validation**

| Option | Default | Config key | Reload | Meaning |
|---|---|---|---|---|
| `-interval` | `10m` | `fetch.interval` | next cycle | Cycle interval |
| `-fetch-j` | `32` | `fetch.jobs` | next cycle | Number of repositories fetched in parallel |
| `-norsync` | `false` | `fetch.rsync` (inverted, `true` = use rsync) | next cycle | Do not fall back to rsync when RRDP fails |
| `-j` | number of CPUs | `validation.workers` | next cycle | Number of parallel validation workers |
| `-drop-warn` | `0.1` | `validation.drop-warn` | next cycle | Warn when the VRP count drops by more than this fraction compared with the previous result |
| `-hold-drop` | `false` | `validation.hold-drop` | next cycle | On such a drop, hold the update (keep serving the previous VRPs) |
| `-max-start-age` | `2h` | `validation.max-start-age` | restart | At start-up, open RTR immediately if the previous result is newer than this |
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
| `-rtr-stdio` | - | - | - | Mode (4.1) |

**HTTP API**

| Option | Default | Config key | Reload | Meaning |
|---|---|---|---|---|
| `-http` | `127.0.0.1:8323` | `http.listen` | restart | HTTP address(es), comma separated (empty = not opened) |
| `-http-allow` | `127.0.0.1,::1` | `http.allow` | immediate | Allowed addresses / prefixes, applied to all HTTP addresses. Others get 403 |
| `-jsonext` | `false` | `http.jsonext` | immediate | Enable `/jsonext` (about 470 MB, about 5 seconds per request. For investigation) |
| `-delta-full-interval` | `1m` | `http.delta-full-interval` | immediate | A full `/json-delta` is served once per this interval per client address; within it the answer is 429 (0 = no limit) |

Value formats: durations = `10m`, `2h`, `90s` / lists = comma separated (`127.0.0.1,::1,10.0.0.0/8`) / booleans = `true` / `false`.

---

## 5. Configuration file

### 5.1 Rules
- Location: `-c <file>`; otherwise `/etc/haetae/haetae.conf`, only if it exists. Read **in daemon mode only**
- Precedence: **command-line option > configuration file > default**
- Format
  - `key = value` under a `[section]`
  - Everything after `#` is a comment (anywhere on a line)
  - Lists are comma separated. **A line ending in a comma continues on the next line** (one line is fine too)
  - An empty value (`tal =`) means "none", the same as the default
- Errors: unknown key / the same key twice / invalid value / a trailing comma with no following value
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
max-start-age = 2h                   # (restart)

[rtr]
listen  = :3323                      # (restart)
allow   = 127.0.0.1, ::1
auth    =                            # (restart)
refresh = 600
retry   = 300
expire  = 7200

[rtr-tls]
listen =                             # (restart)
cert   =
key    =
ca     =

[http]
listen = 127.0.0.1:8323              # (restart)
allow  = 127.0.0.1, ::1
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
allow  = 127.0.0.1, ::1, 198.51.100.0/24 # servers that may use the API
```
Apply the same sources in the host firewall, so access is limited in two layers.

---

## 6. Behaviour

### 6.1 Cycle (default 10 minutes)
1. **Fetch**: each repository once, 32 in parallel, at most 5 minutes per repository
   - RRDP (https) first: based on the serial in the notification file, only the changes (deltas). A snapshot on first contact or when the chain is broken
   - Deltas are applied in two steps (everything is checked first, then moved in at once) -> there is never a half-applied state
   - If RRDP keeps failing for a certain time, rsync is used instead; if both fail, the previously fetched data is used
2. **Validate**: TAL -> TA certificate -> CA -> manifest -> CRL / ROA / ASPA / router certificate / GBR / SPL / TAK
   - Checks signatures, manifest hashes, CRLs, validity periods, and resource containment (child ⊆ parent)
   - A bad object rejects only that object; a broken manifest rejects the whole CA publication point (RFC 9286; the same strictness as rpki-client)
3. **Apply decision** (6.2 below)
4. **Export**: result files, RTR Serial Notify, one history line per cycle (log + `history.jsonl`)

If the configuration is reloaded during a cycle, that cycle finishes with the configuration it started with (new values apply from the next cycle).

### 6.2 Apply decision (protecting the previous result)
| Case | Action |
|---|---|
| Any TA failed | Not applied, previous result kept |
| 0 VRPs | Not applied |
| VRP count dropped by more than `drop-warn` (10 %) | Warning. With `hold-drop = true` the update is held |
| SLURM file broken | That cycle is not applied (exceptions suddenly disappearing would be dangerous) |
| Otherwise | Applied: serial +1, changes kept (last 200 cycles, about 33 hours) |

The first three checks compare against a previous result; on the very first cycle (no previous result) the result is applied.

### 6.3 Start and restart
- At start-up: configuration -> TAL check (Haetae does not start if a TAL is broken) -> `state.json` (session / serial) -> previous result (`out/json`) -> delta history
- If the previous result is within `max-start-age` (2 hours), **RTR is opened immediately** -> routers reconnect with the same session and fetch only the changes
- If there is no previous result or it is too old, a new session is created and RTR is opened after the first cycle (routers fetch everything again)
- During a restart the API / RTR are unavailable for about 5 seconds

### 6.4 Reloading the configuration (`systemctl reload haetae`)
Re-reads only the configuration while running (not a restart: RTR sessions, the in-memory result and the cycle stay as they are).

1. The command line + configuration file are read again with the start-up rules (the command line still wins)
2. All new values are checked first. If any is invalid or the file is missing, **nothing is changed**
3. If a restart-only item changed, the current value is kept and a warning is logged
4. Everything else is switched at once, and the log lists only the changed items as `key "old" -> "new"`

| Changes immediately | From when |
|---|---|
| `rtr.allow`, `http.allow` | Next connection / request. RTR closes connections that are no longer in the list at once |
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

Pick the method your routers support; methods can be combined (e.g. TCP-AO for some routers, plain TCP for others).

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

### 7.5 Timers
refresh / retry / expire (default 600 / 300 / 7200 seconds) are sent in the End of Data PDU of v1 / v2.
Some routers prefer their own configured values. v0 has no such fields.

### 7.6 TALs (the starting point of trust)
- The TALs of the 5 RIRs are **built into the binary** (from `tals/` in the source tree at build time). Haetae does not depend on TALs installed by other software
- Start-up log `TAL (...): afrinic ad69…, apnic a3a0…, …` = public key hashes (must match the table in `tals/README.md`)
- When an RIR rolls its TA key (rare):
  - normally: update `tals/` and the table, rebuild and reinstall
  - urgently: put the new TAL files in a directory, set `paths.tal = <dir>` -> `systemctl reload` (no rebuild, from the next cycle)
- TAK (RFC 9691) objects are parsed and shown in the object list. There is no warning yet for an announced next key

**TA constraints are not used.** Some RPs (rpki-client) can restrict each TA's resources with local `*.constraints` files
derived from IANA / RIR allocation data. This is not part of any RFC, and RIR TAs normally hold all resources.
Such files must be kept in sync with allocation changes; an outdated file rejects legitimate ROAs and ASPAs
(for example, a prefix newly allocated by IANA to an RIR). Haetae therefore validates by the RFCs only.

---

## 8. HTTP API and output files

### 8.1 Addresses and access
- The same API is served on every address in `http.listen`. Sources outside `http.allow` get 403
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
| Full `/json-delta` (85 MB, about 1 s CPU) | Once per `delta-full-interval` per client address; otherwise 429 + `Retry-After` |
| `/jsonext` (470 MB, about 5 s) | Off by default (`http.jsonext`) |
| Clients | Fetch the full set once, then only the changes by `serial`. On reset replace everything; on 429 keep what you have and retry later |

---

## 9. Logs (journal)

Use `journalctl -u haetae`. Main lines (in version 0.1 some messages are still in Korean; the English meaning is given):

| When | Message (example) | Meaning |
|---|---|---|
| start | `설정 /etc/haetae/haetae.conf : paths.cache=... rtr.allow=...` | Configuration file read and the values taken from it |
| start | `TAL (내장): afrinic ad69cadc45c0cd41, ...` | TAL source (`내장` = built-in, or the directory) and public key hashes |
| start | `state: session 12345 serial 245 (saved ...)` | Continuing (with `new session` routers fetch everything again) |
| start | `previous VRP loaded: 1030503 VRPs from ...` | RTR opened immediately with the previous result |
| start | `http allow [...]`, `http listening ...`, `rtr listening :3323 (allow [...], tcp auth keys 0)` | Listening addresses and allow lists |
| cycle | `run 1m12s: vrps 1030362 vaps 3925 keys 3 +4 -1 serial 142 repos map[...] 13MB applied=true` | Cycle summary (duration, counts, added / removed, repository results, bytes fetched, applied or not) |
| cycle | `... applied=false TA failed [...], keep previous` / `WARNING VRP drop ...` | Not applied / drop warning (6.2) |
| RTR | `rtr 192.0.2.1:51234: connected (tcp)`, `not in allow list, closed` | Router connected / refused |
| reload | `설정 다시 읽음 (...) : rtr.allow "..." -> "..."` | Configuration reloaded: changed items |
| reload | `설정 다시 읽음 : 재시작해야 바뀌는 항목 (지금 값 유지) : ...` | Restart-only items changed (current values kept) |
| reload | `설정 다시 읽기 실패, 지금 값 유지 : <file> 10 줄 : 모르는 키 [http] bogus` | Reload failed, current values kept (here: line 10, unknown key) |

---

## 10. Operations

| Task | How |
|---|---|
| View status | `systemctl status haetae`, `curl -s localhost:8323/status` |
| Change configuration | Edit the configuration file, `sudo systemctl reload haetae` -> check the log. For restart-only items use `restart` |
| Install a new version | `go build -o haetae .` -> `sudo install -m 755 haetae /usr/local/bin/haetae` -> `sudo systemctl restart haetae` (about 5 s pause, session continues) |
| Add a router | Add its address to `rtr.allow` -> reload; also allow it in the firewall (RTR port) |
| Add an HTTP client | Add the address / prefix to `http.allow` -> reload; also the firewall |
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
| Router fetches everything again | `new session` in the log (previous result too old / missing) |
| HTTP 403 | Source outside `http.allow`. Add it and reload |
| HTTP 429 | Full `/json-delta` requested too often. Retry after `Retry-After`; normally fetch only the changes |
| Repository fetch failures | `/repos.json`, repo-problem in `/status`. About ten small repositories are permanently unreachable (normal) |
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
| `fetch.rsync` | `-norsync` (inverted) | | `rtr-tls.cert` | `-rtr-tls-cert` |
| `validation.workers` | `-j` | | `rtr-tls.key` | `-rtr-tls-key` |
| `validation.drop-warn` | `-drop-warn` | | `rtr-tls.ca` | `-rtr-tls-ca` |
| `validation.hold-drop` | `-hold-drop` | | `http.listen` | `-http` |
| `validation.max-start-age` | `-max-start-age` | | `http.allow` | `-http-allow` |
| | | | `http.jsonext` | `-jsonext` |
| | | | `http.delta-full-interval` | `-delta-full-interval` |

Options not available in the configuration file (command line only): `-c`, `-t`, `-validate`, `-parse`, `-rsc`, `-rtr-stdio`, `-P`, `-fetch`, `-fail`.
