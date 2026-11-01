# Haetae API Guide

This guide covers Haetae 0.1, an RPKI relying party written in Go. Haetae
publishes its results in three ways:

1. **RTR** (RPKI-to-Router) for routers: TCP port 3323 by default. See [RTR](#rtr).
2. **HTTP API** for operators and other systems: `127.0.0.1:8323` by default. See [HTTP API](#http-api).
3. **Files** in the output directory, which hold the same content as the HTTP file endpoints. See [Output files](#output-files).

For installation, options, the configuration file and logging, see the
[manual](manual.md).

## Contents

- [Quick reference](#quick-reference)
- [HTTP API](#http-api)
  - [Listening and access control](#listening-and-access-control)
  - [Common conventions](#common-conventions)
  - [Status](#status)
  - [History and metrics](#history-and-metrics)
  - [Full VRP sets](#full-vrp-sets)
  - [Incremental updates: /json-delta](#incremental-updates-json-delta)
  - [Route origin validation](#route-origin-validation)
  - [ASPA path verification](#aspa-path-verification)
  - [AS and prefix lookup](#as-and-prefix-lookup)
  - [Objects, CAs and expiry](#objects-cas-and-expiry)
  - [Unsafe VRPs, SLURM, repositories, rejects](#unsafe-vrps-slurm-repositories-rejects)
- [Output files](#output-files)
- [RTR](#rtr)

## Quick reference

| Task | Endpoint |
|---|---|
| Is Haetae healthy? | `GET /status` (text), `GET /api/v1/status` (JSON) |
| Validate one route (RFC 6811) | `GET /api/v1/validity/AS13335/1.1.1.0/24` |
| Check an AS_PATH against ASPA | `GET /api/v1/aspa/verify?path=64503+64502+64501` |
| VRPs, ASPA and router keys of one AS | `GET /api/v1/as/13335` |
| VRPs covering / inside a prefix | `GET /api/v1/prefix/1.1.0.0/16` |
| Full set, then only changes | `GET /json-delta`, then `GET /json-delta?session=S&serial=N` |
| Changes of a single run | `GET /json-delta?session=S&serial=N-1&to=N` |
| Objects that expire soon | `GET /api/v1/expiring?days=30&as=13335` |
| Search objects | `GET /api/v1/objects?type=gbr` |
| One CA and its children | `GET /api/v1/ca?uri=rsync://...cer` |
| Repository fetch results | `GET /repos.json` |
| Rejected objects and reasons | `GET /rejects.txt` |
| Unsafe VRPs | `GET /api/v1/unsafe` |
| Trends | `GET /api/v1/history?hours=48`, `GET /metrics` |
| Full VRP set as files | `GET /json`, `GET /csv` |

## HTTP API

All endpoints are read-only `GET` requests. There is no endpoint that changes
Haetae's state. Bulk `POST` endpoints for route validity and ASPA verification
existed in early development and have been removed; validate one route or one
path per request.

### Listening and access control

| Option | Config key | Default | Meaning |
|---|---|---|---|
| `-http` | `[http] listen` | `127.0.0.1:8323` | Listen address. Several addresses are separated by commas, for example `127.0.0.1:8323,0.0.0.0:8324`. All addresses serve the same API. An empty value disables HTTP. |
| `-http-allow` | `[http] allow` | `127.0.0.1,::1` | Allowed client addresses or prefixes, comma separated. Applies to every `-http` address. |
| `-jsonext` | `[http] jsonext` | `false` | Enables `/jsonext`. |
| `-delta-full-interval` | `[http] delta-full-interval` | `60s` | Minimum interval between two full `/json-delta` responses per client address. `0` disables the limit. |

- A request from an address outside `-http-allow` gets `403 Forbidden`
  (body `forbidden`). An empty allow list blocks everyone.
  IPv4-mapped IPv6 addresses are compared as IPv4.
- `-http-allow`, `-jsonext` and `-delta-full-interval` change on
  `systemctl reload haetae` (SIGHUP). Changing `-http` needs a restart.
- The allow list is the only access control in Haetae. There is no
  authentication and no TLS on the HTTP API. Treat the API as internal and also
  restrict it with a host firewall. `/status`, `/api/v1/status` and `/metrics`
  show the addresses of connected routers; do not expose them to the internet
  without a filtering proxy in front.

Example: open the API on a second address for a management network.

```
haetae -http 127.0.0.1:8323,0.0.0.0:8324 -http-allow 127.0.0.1,::1,192.0.2.0/24,2001:db8:100::/48
```

### Common conventions

- **Times.** Time strings are RFC 3339. Most are UTC (`Z`), but some status
  fields (`started`, `set_updated`, `last_applied`, `config.loaded`,
  `last_run.start`) use the server's local offset, for example `+09:00`.
  Always parse them; do not compare them as strings. Numeric times such as
  `expires` and `generated` are Unix epoch seconds.
- **AS numbers.** The `/api/v1/*` lookup endpoints return plain numbers
  (`13335`). Endpoints that follow Routinator's format (`/api/v1/validity`,
  `/json-delta`, `/jsonext`, `/api/v1/vrps/delta`) and the CSV use strings with
  an `AS` prefix (`"AS13335"`). As input, both `13335` and `AS13335` are
  accepted (case-insensitive).
- **Prefixes.** Input prefixes must be network addresses: `1.1.1.0/24` is
  accepted, `1.1.1.1/24` returns 400.
- **Errors.** Errors are a one-line plain-text body with these status codes:

  | Code | Meaning |
  |---|---|
  | 400 | Bad input (the body gives the reason) |
  | 403 | Client address not in `-http-allow` |
  | 404 | Not found (unknown URI, `/jsonext` disabled, delta range not kept, output file not written yet) |
  | 429 | Full `/json-delta` requested again too soon; see `Retry-After` |
  | 503 | No data yet (`no data yet (wait for first validation)`) |

- **After a restart.** Haetae reloads the previous VRP set from its output
  directory if it is newer than `-max-start-age` (default 2 hours). Endpoints
  that need only the VRP set (`/api/v1/validity`, `/api/v1/as`,
  `/api/v1/prefix`, `/api/v1/aspa/verify`, `/json-delta`) work immediately. The
  object-level data (`/api/v1/objects`, `/api/v1/expiring`, `/api/v1/ca`,
  `/api/v1/unsafe`, `/jsonext`) exists only after the first validation run of
  the new process (usually 1 to 2 minutes) and returns 503 until then. In the
  same window the `roas` lists in `/api/v1/as` and `/api/v1/prefix` and
  `aspa.sources` in `/api/v1/as` are empty.
- **Compatibility.** New fields may be added to any JSON response. Clients
  should ignore fields they do not know.
- **Large responses.** `/json` (about 100 MB), `/objects.jsonl` (about 360 MB),
  full `/json-delta` (about 85 MB) and `/jsonext` (about 470 MB) are large. Do
  not fetch them on every user request; use the small lookup endpoints for
  interactive use. Sizes are for the global RPKI in late 2026.

### Status

#### GET /api/v1/status

The state of the daemon as JSON. A few kilobytes; polling every one to five
minutes is fine.

```json
{
 "version": "haetae 0.1",
 "started": "2026-11-01T09:18:02Z",
 "config": {"file": "/etc/haetae/haetae.conf", "loaded": "2026-11-01T09:18:02Z"},
 "session": 51234,
 "serial": 381,
 "deltas_kept": 200,
 "data_time": "2026-11-01T09:21:10Z",
 "set_updated": "2026-11-01T09:22:15Z",
 "last_applied": "2026-11-01T09:22:15Z",
 "runs": 1,
 "vrps": 1030620, "vaps": 3914, "router_keys": 3,
 "unsafe_vrps": 98,
 "rtr_open": true,
 "rtr_clients": [
  {"remote": "192.0.2.10:51234", "transport": "tcp", "version": 1,
   "since": "2026-11-01T09:18:08Z", "last_query": "2026-11-01T09:28:08Z", "serial": 381}
 ],
 "tas": [{"name": "apnic", "uri": "rsync://rpki.apnic.net/repository/apnic-rpki-root-iana-origin.cer"}],
 "last_run": {
  "start": "2026-11-01T09:21:10Z", "duration": "1m5s", "duration_s": 65.2,
  "applied": true,
  "vrps": 1030620, "vaps": 3914, "router_keys": 3,
  "vrps_per_ta": {"afrinic": 32048, "apnic": 300748, "arin": 277413, "lacnic": 46108, "ripe": 374303},
  "counts": {"roa valid": 400374, "roa rejected": 23, "cer valid": 55955, "cer rejected": 23,
             "mft valid": 55867, "mft rejected": 85, "crl valid": 55867, "asa valid": 3918,
             "gbr valid": 1, "warn: AIA does not match issuer location": 4142},
  "repos": {"rrdp ok": 104, "rrdp fallback-rsync": 11, "rsync ok": 1, "rsync failed": 10},
  "announced": 5, "withdrawn": 2, "downloaded_mb": 16, "unsafe_vrps": 98, "mem_mb": 5200
 },
 "repos_problems": [
  {"uri": "https://rrdp.example.net/notification.xml", "type": "rrdp", "result": "fallback-rsync",
   "start": "2026-11-01T09:21:11Z", "duration_ns": 300000000000, "error": "..."}
 ],
 "mem_mb": 5230
}
```

| Field | Meaning |
|---|---|
| `session`, `serial` | RTR session ID and serial. The serial increases by one each time the served set changes. |
| `deltas_kept` | Number of serials kept for incremental updates (up to 200). |
| `data_time` | Validation time of the data being served. If it does not move for much longer than the run interval (10 minutes by default), something is wrong. |
| `set_updated` | When the served set was last replaced (every applied run, even if nothing changed). |
| `last_applied` | When a run result was last applied. |
| `runs` | Validation runs since the process started. |
| `vrps`, `vaps`, `router_keys` | Unique VRPs, ASPA customers and router keys served over RTR (after SLURM). |
| `unsafe_vrps` | See [/api/v1/unsafe](#get-apiv1unsafe). Present after the first run. |
| `rtr_open` | Whether the RTR listener is open. |
| `rtr_clients` | Connected routers, or `null`. `transport` is `tcp`, `tcp-md5`, `tcp-ao` or `tls`. `version` is the negotiated RTR version (`-1` before the first PDU). `serial` is the last serial sent. Routers connected over SSH appear as `127.0.0.1` with `tcp`. |
| `tas` | Trust anchor certificates, the starting points for [/api/v1/ca](#get-apiv1cauri). |
| `last_run` | The last run. `applied: false` means Haetae kept serving the previous set; `reason` says why (for example a failed TA or a VRP drop held by `-hold-drop`). `reason` can also carry a warning when `applied` is true (`WARNING VRP drop ...`). `failed_tas` lists TAs that failed. |
| `last_run.counts` | Keys are `<type> valid` or `<type> rejected` (type = `cer crl mft roa asa gbr spl tak`), `warn: <message>`, and `unknown file type .<ext>` for non-standard files. |
| `last_run.repos` | Keys are `<rrdp|rsync> <result>`; see [/repos.json](#get-reposjson). |
| `repos_problems` | Repositories whose result is not `ok`. |
| `slurm` | Present only when a SLURM file is configured: `{"file", "loaded", "filtered": {"vrps", "router_keys", "aspas"}, "added": {"vrps", "router_keys", "aspas"}}`. |
| `mem_mb` | Current resident memory. |

#### GET /status

The same information as plain text for humans:

```
$ curl -s localhost:8323/status
version:       haetae 0.1
started:       2026-11-01T09:18:02Z
session:       51234
serial:        381
data_time:     2026-11-01T09:21:10Z
...
last-run:      2026-11-01T09:21:10Z 1m5s applied=true
vrps-per-ta:   afrinic=32048 apnic=300748 arin=277413 lacnic=46108 ripe=374303
repos:         map[rrdp ok:104 ...]
rtr-client:    192.0.2.10:51234 v1 since 2026-11-01T09:18:08Z serial 381
repo-problem:  rrdp fallback-rsync https://rrdp.example.net/notification.xml
```

### History and metrics

#### GET /api/v1/history

One entry per run, oldest first. Haetae keeps 30 days in its state directory,
so the history survives restarts.

| Parameter | Default | Range |
|---|---|---|
| `hours` | 24 | 1 to 720 (400 otherwise) |

```json
{"runs": [
 {"start": "2026-11-01T09:21:10Z", "duration_s": 65, "applied": true,
  "serial": 381, "vrps": 1030620, "vaps": 3914, "router_keys": 3,
  "announced": 5, "withdrawn": 2,
  "vrps_per_ta": {"afrinic": 32048, "apnic": 300748, "arin": 277413, "lacnic": 46108, "ripe": 374303},
  "rejected": {"cer": 23, "mft": 85, "roa": 23},
  "repos_failed": 21, "unsafe_vrps": 98, "downloaded_mb": 16, "mem_mb": 5200}
]}
```

`repos_failed` counts repositories whose result is not `ok`
(`fallback-old`, `fallback-rsync` and `failed`). `reason` appears when not
empty.

#### GET /metrics

Prometheus text exposition format (`text/plain; version=0.0.4`). All names
start with `haetae_`.

| Metric | Labels | Meaning |
|---|---|---|
| `haetae_session`, `haetae_serial` | | RTR session ID and serial |
| `haetae_runs_total` | | Runs since start (counter) |
| `haetae_rtr_open` | | RTR listener open (1 / 0) |
| `haetae_rtr_clients` | | Connected RTR clients |
| `haetae_vrps`, `haetae_vaps`, `haetae_router_keys` | | Served payload counts |
| `haetae_data_time_seconds` | | Validation time of served data (epoch) |
| `haetae_last_applied_seconds` | | Last time a run was applied (epoch) |
| `haetae_last_run_start_seconds`, `haetae_last_run_duration_seconds` | | Last run start (epoch) and duration |
| `haetae_last_run_applied` | | Last run applied (1 / 0) |
| `haetae_last_run_downloaded_bytes` | | Bytes downloaded in the last run (MB resolution) |
| `haetae_vrps_per_ta` | `ta` | VRPs per trust anchor |
| `haetae_objects` | `type`, `state` | Objects by type and `valid` / `rejected` |
| `haetae_warnings` | `warning` | Warning counts |
| `haetae_repositories` | `type`, `result` | Repositories by `rrdp` / `rsync` and result |
| `haetae_unsafe_vrps` | | Unsafe VRPs |
| `haetae_memory_rss_bytes` | | Resident memory |

A useful alert: `time() - haetae_data_time_seconds > 1800`.

### Full VRP sets

These endpoints serve the files of the last applied run from the output
directory as they are. They support `Range` and `If-Modified-Since`. Before the
first run has written a file, they return 404.

#### GET /json

rpki-client compatible JSON (`metadata`, `roas`, `aspas`, `bgpsec_keys`).
Tools that read rpki-client's `json` output can read this file.

```json
{
	"metadata": {
		"buildtime": "2026-11-01T09:21:10Z",
		"evaltime": "2026-11-01T09:21:10Z",
		"elapsedtime": 65,
		"uniquevrps": 1030620,
		"uniquevaps": 3914,
		"bgpsec_keys": 3,
		"failed_tals": null,
		"counts": {"roa valid": 400374, "...": 0}
	},
	"roas": [
		{ "asn": 13335, "prefix": "1.1.1.0/24", "maxLength": 24, "ta": "apnic", "expires": 1793500000 }
	],
	"aspas": [
		{ "customer_asid": 64496, "ta": "ripe", "expires": 1793500000, "providers": [64497, 64498] }
	],
	"bgpsec_keys": [
		{ "asn": 64496, "ski": "AB12...", "pubkey": "<base64 SubjectPublicKeyInfo>", "ta": "ripe", "expires": 1793500000 }
	]
}
```

- Each `roas` entry is on its own line, so the file can also be read line by
  line. Entries are sorted by address, prefix length, maxLength, ASN, TA.
- The same (ASN, prefix, maxLength) under two TAs gives two entries; `uniquevrps`
  counts these separately.
- `expires` is the earliest expiry in the chain of the object.
- `aspas` has one entry per (customer, TA), providers in ascending order.
- This file is the validation result **before SLURM**. SLURM filters and
  assertions apply to RTR, `/json-delta` and the `/api/v1/*` lookups, not to
  `/json` or `/csv`.

#### GET /csv

```
ASN,IP Prefix,Max Length,Trust Anchor,Expires
AS13335,1.1.1.0/24,24,apnic,1793500000
```

Same content and order as `roas` in `/json` (also before SLURM). `Expires` is
epoch seconds.

#### GET /jsonext

Routinator `jsonext` compatible output: every VRP with its source ROAs. Only
available when Haetae runs with `-jsonext`; otherwise 404. It is computed on each
request (about 5 seconds, about 470 MB) and is meant for occasional diagnosis.
Returns 503 before the first run.

```json
{
  "metadata": {"generated": 1793524870, "generatedTime": "2026-11-01T09:21:10Z"},
  "roas": [
    {"asn": "AS13335", "prefix": "1.1.1.0/24", "maxLength": 24, "source": [
      {"type":"roa","uri":"rsync://rpki.apnic.net/.../xxx.roa","tal":"apnic",
       "validity":{"notBefore":"...","notAfter":"..."},
       "chainValidity":{"notBefore":"...","notAfter":"..."},"stale":"..."}]}
  ],
  "routerKeys": [
    {"asn": "AS64496", "SKI": "AB12...", "routerPublicKey": "<base64>",
     "source": [{"type":"cer","uri":"rsync://...cer","tal":"ripe","expires":1793500000}]}
  ],
  "aspas": [
    {"customer": "AS64496", "providers": ["AS64497", "AS64498"]}
  ]
}
```

VRPs with the same (ASN, prefix, maxLength) under several TAs are one entry
with several sources. VRPs added by SLURM have a source
`{"type":"exception","path":"<SLURM file>"}`. `stale` is the earliest
next-update time of the manifests and CRLs in the chain.

### Incremental updates: /json-delta

#### GET /json-delta

The recommended way for another system to keep a copy of the VRP set. The
format follows Routinator's `/json-delta` and adds router keys and ASPA. It
reflects exactly what RTR serves (after SLURM).

| Parameter | Meaning |
|---|---|
| `session` | Session ID from a previous response (decimal string) |
| `serial` | Serial the client already has |
| `to` | Optional. Return the changes from `serial` up to `to` only (instead of up to the current serial). |

Without parameters, or when `session` does not match or `serial` is no longer
in the kept history (200 serials, about 33 hours at a 10-minute interval), the
response is the full set with `"reset": true`.

```json
{"reset":false,"session":"51234","serial":381,"fromSerial":378,
 "generated":1793524870,"generatedTime":"2026-11-01T09:21:10Z",
"announced":[
{"type":"routeOrigin","asn":"AS64496","prefix":"192.0.2.0/24","maxLength":24},
{"type":"routerKey","asn":"AS64496","SKI":"AB12...","routerPublicKey":"<base64>"},
{"type":"aspa","customer":"AS64496","providers":["AS64497","AS64498"]}],
"withdrawn":[
{"type":"routeOrigin","asn":"AS64500","prefix":"2001:db8::/32","maxLength":48},
{"type":"aspa","customer":"AS64501","providers":[]}]}
```

- `session` is a string (as in Routinator); `serial` is the serial the
  response brings the client to. `fromSerial` appears only when `reset` is
  false.
- With `reset: true`, `announced` holds the complete set and `withdrawn` is
  empty: replace the local copy.
- Each element is on its own line.
- ASPA is per customer. When a customer's provider list changes, `announced`
  holds the complete new list. When a customer disappears, it is in
  `withdrawn` with an empty `providers` list.
- Several serials are merged: an item announced and later withdrawn within the
  range does not appear.
- `to`: `serial=M-1&to=M` gives the exact changes of run M; ASPA lists are as
  of serial M. `to` greater than the current serial returns 400. If the range is
  not in the history (or the session does not match) and `to` is not the
  current serial, the response is 404, not a full set.
- Returns 503 if there is no data yet.

**Rate limit on full sets.** A full response (`reset: true`) is about 85 MB and
one second of CPU. Each client address may receive one per
`-delta-full-interval` (default 60 seconds). A second full request within the
interval gets:

```
HTTP/1.1 429 Too Many Requests
Retry-After: 42

full set (reset) allowed once per 1m0s per client, retry after 42 s
```

Incremental responses (`reset: false`) are not limited. A client that gets 429
must keep its current copy unchanged and retry after `Retry-After` seconds. Do
not treat 429 as an empty set.

**Client loop.**

1. Fetch `/json-delta` without parameters. Store all items, `session` and
   `serial`.
2. Every one to five minutes, fetch `/json-delta?session=S&serial=N`.
   - `reset: false`: delete `withdrawn`, add `announced`, store the new `serial`.
   - `reset: true`: replace everything, store `session` and `serial`.
   - 429: change nothing, retry later.
3. Optionally compare with a full set once a day.

A new session (and therefore one full reset) happens when Haetae starts without
a usable previous result (missing, or older than `-max-start-age`).

#### GET /api/v1/vrps/delta?serial=N

Older, VRP-only form. Kept for compatibility; prefer `/json-delta`.

```json
{"session":51234,"serial":381,"from":378,"reset":false,
 "announced":[{"asn":"AS64496","prefix":"192.0.2.0/24","max_length":24}],
 "withdrawn":[]}
```

`serial` is required (400 otherwise). If `N` is not in the history, the
response has `"reset": true` and no lists; fetch a full set from `/json` or
`/json-delta`. There is no session check.

### Route origin validation

#### GET /api/v1/validity/{AS}/{prefix}

Route origin validation (RFC 6811) of one route against the served VRPs (after
SLURM). Path and response follow Routinator.

```
curl -s localhost:8323/api/v1/validity/AS13335/1.1.1.0/24
```

```json
{
 "generatedTime": "2026-11-01T09:21:10Z",
 "validated_route": {
  "route": {"origin_asn": "AS13335", "prefix": "1.1.1.0/24"},
  "validity": {
   "state": "valid",
   "description": "At least one VRP Matches the Route Prefix",
   "VRPs": {
    "matched": [{"asn": "AS13335", "prefix": "1.1.1.0/24", "max_length": 24}],
    "unmatched_as": [],
    "unmatched_length": []
   }
  }
 }
}
```

- `state`: `valid`, `invalid` or `not-found`.
- `reason` (only when invalid): `as` (covering VRPs exist but none has the
  origin AS) or `length` (a VRP with the origin AS covers the route, but the
  route is longer than its maxLength).
- An AS 0 VRP never matches.
- 400 for a bad AS or a prefix that is not a network address; 503 before data.

### ASPA path verification

#### GET /api/v1/aspa/verify

Verifies one AS_PATH against the served ASPA data (union of all TAs, after
SLURM), following draft-ietf-sidrops-aspa-verification-29, sections 5.3 to
5.6. This is a lookup tool that shows what an ASPA-capable router would
decide.

| Parameter | Meaning |
|---|---|
| `path` | Required. The AS_PATH as displayed: leftmost = neighbor, rightmost = origin. Separate with spaces (`+` or `%20` in a URL) or commas. An `AS` prefix is allowed. `{64510 64511}` is an AS_SET. At most 1024 ASes. |
| `neighbor` | Optional. The AS of the BGP neighbor that sent the route. If given and different from the first AS of the path, the result is invalid. Omit it for routes from a route server. |

The result is given for both directions; pick the one that matches the BGP
session the route was received on:

- `upstream`: route received from a customer, a lateral peer or a route server.
- `downstream`: route received from a provider.

```
curl -s 'localhost:8323/api/v1/aspa/verify?path=64503+64502+64501&neighbor=64503'
```

```json
{
 "generatedTime": "2026-11-01T09:21:10Z",
 "serial": 381,
 "result": {
  "path": [64503, 64502, 64501],
  "compressed": [64503, 64502, 64501],
  "as_set": false,
  "neighbor": 64503,
  "upstream": {"state": "valid"},
  "downstream": {"state": "valid"},
  "max_up_ramp": 3, "min_up_ramp": 3, "max_down_ramp": 3, "min_down_ramp": 3,
  "hops": [
   {"from": 64501, "to": 64502, "up": "provider+", "down": "not-provider+"},
   {"from": 64502, "to": 64503, "up": "provider+", "down": "no-attestation"}
  ]
 }
}
```

| Field | Meaning |
|---|---|
| `state` | `valid`, `invalid` or `unknown` |
| `reason` | When not valid: `empty` (empty path), `neighbor`, `as_set`, `not-provider` (a hop is proven not to be a provider: possible route leak), `no-attestation` (an AS without ASPA prevents a full check: unknown) |
| `path` | Parsed path (AS_SET members removed) |
| `compressed` | Path with consecutive duplicates (prepends) merged; verification uses this |
| `hops` | Adjacent AS pairs from the origin side. `up` = is `to` a provider of `from`; `down` = is `from` a provider of `to`. Values: `provider+`, `not-provider+` (the AS has an ASPA without that provider), `no-attestation` (the AS has no ASPA) |
| `*_ramp` | Up-ramp and down-ramp lengths as defined in the draft |

Few ASes publish ASPA objects so far, so most real paths are `unknown`. 400 for
a malformed path (nested or unbalanced braces, bad AS, too long) or a bad
`neighbor`; 503 before data.

### AS and prefix lookup

#### GET /api/v1/as/{AS}

Everything Haetae serves for one AS. `{AS}` is `13335` or `AS13335`.

```json
{
 "asn": 13335,
 "generatedTime": "2026-11-01T09:21:10Z",
 "vrps": [
  {"asn": 13335, "prefix": "1.1.1.0/24", "maxLength": 24, "ta": "apnic", "expires": 1793500000,
   "roas": ["rsync://rpki.apnic.net/repository/.../xxx.roa"]}
 ],
 "aspa": {"providers": [174, 3356],
          "sources": [{"uri": "rsync://.../xxx.asa", "ta": "arin", "notAfter": "2027-06-01T00:00:00Z", "expires": 1793500000}]},
 "provider_of": [64496, 64497],
 "router_keys": [{"ski": "AB12...", "pubkey": "<base64>", "ta": "ripe", "expires": 1793500000, "uri": "rsync://.../xxx.cer"}]
}
```

- `vrps`: VRPs with this origin AS, with their source ROA URIs. VRPs added by
  SLURM have `"ta": "slurm"`.
- `aspa`: this AS's provider list (union over TAs), or `null` if it has no ASPA.
- `provider_of`: customer ASes that list this AS as a provider.
- `router_keys`: BGPsec router keys of this AS.

#### GET /api/v1/prefix/{prefix}

```json
{
 "prefix": "1.1.0.0/16",
 "generatedTime": "2026-11-01T09:21:10Z",
 "covering": [{"asn": 13335, "prefix": "1.0.0.0/8", "maxLength": 24, "ta": "apnic", "expires": 1793500000, "roas": ["..."]}],
 "more_specific": [{"asn": 13335, "prefix": "1.1.1.0/24", "maxLength": 24, "ta": "apnic", "expires": 1793500000, "roas": ["..."]}],
 "more_specific_truncated": false
}
```

- `covering`: VRPs whose prefix equals or contains this prefix (the VRPs that
  decide validation of a route for this prefix).
- `more_specific`: VRPs inside this prefix with a longer prefix length, at most
  10,000; `more_specific_truncated` is true if there were more.

### Objects, CAs and expiry

These endpoints work on the full object list of the last run. They return 503
until the first run of the process completes.

#### Object record

Every validated or rejected object is one record. The same record is a line in
[`/objects.jsonl`](#objectsjsonl) and an element of `objects` in the responses
below.

```json
{"type": "roa", "uri": "rsync://rpki.example.net/repo/ca1/xxx.roa", "sha256": "9f86d0...",
 "ta": "arin", "parent": "rsync://rpki.example.net/repo/ca1.cer",
 "notBefore": "2026-10-18T07:45:11Z", "notAfter": "2027-10-17T07:50:11Z",
 "status": "valid",
 "summary": {"asn": 64496, "vrps": 1, "prefixes": [{"prefix": "192.0.2.0/24", "maxLength": 24}]}}
```

| Field | Meaning |
|---|---|
| `type` | `cer` (TA, CA and router certificates), `crl`, `mft`, `roa`, `asa` (ASPA), `gbr`, `spl`, `tak` |
| `parent` | URI of the issuing CA certificate |
| `notBefore`, `notAfter` | Validity of the object's own certificate. For `mft` and `crl`: thisUpdate and nextUpdate |
| `status`, `reason` | `valid` or `rejected`; `reason` is present for rejected objects |
| `summary` | Depends on the type (below) |

| Type | `summary` |
|---|---|
| `cer` TA / CA | `kind` (`TA` / `CA`), `repository`, `notify`, `resources` `{ipv4, ipv6, asn}` with inheritance resolved; ranges are `a/n` or `a-b` |
| `cer` router | `kind: "router"`, `asns`, `ski` |
| `roa` | `asn`, `vrps`, `prefixes` `[{prefix, maxLength}]` |
| `asa` | `customer`, `providers` |
| `gbr` | `vcard` `{FN, ORG, EMAIL, TEL, ADR}`, `warnings` |
| `spl` | `asn`, `prefixes` |
| `tak` | `current`, `predecessor`, `successor` (key identifiers) |
| `mft` | `number`, `files` |
| `crl` | `revoked` |

#### GET /api/v1/objects

Search objects. All conditions are optional and combined with AND.

| Parameter | Meaning |
|---|---|
| `type` | Object type (see above) |
| `ta` | TA name: `afrinic`, `apnic`, `arin`, `lacnic`, `ripe` |
| `status` | `valid` or `rejected` |
| `uri` | URI prefix match |
| `as` | ROAs with this origin AS, ASPAs with this customer, router certificates with this AS |
| `prefix` | ROAs with an overlapping prefix and CA certificates with overlapping IP resources. A single address is accepted. |
| `limit` | Default 1,000, 1 to 10,000 |
| `offset` | Default 0 |

```
curl -s 'localhost:8323/api/v1/objects?type=roa&as=13335&limit=100'
curl -s 'localhost:8323/api/v1/objects?status=rejected&ta=ripe'
```

```json
{"total": 37, "offset": 0, "objects": [ {"type": "roa", "uri": "...", "...": "..."} ]}
```

`total` is the number of matching objects before `limit` / `offset`. Results
are in URI order.

#### GET /api/v1/expiring

Valid objects whose own certificate expires (`notAfter`) within `days`.
Manifests and CRLs are excluded because their next update moves every day.

| Parameter | Meaning |
|---|---|
| `days` | Default 7, 1 to 90 |
| `type`, `ta`, `as`, `prefix`, `uri` | As in `/api/v1/objects`. `type=mft` or `type=crl` returns 400. |
| `limit` | Default and maximum 10,000 |

```
curl -s 'localhost:8323/api/v1/expiring?days=30&as=13335'
```

```json
{"days": 30, "total": 2, "objects": [ ... ]}
```

Sorted by `notAfter`, earliest first.

#### GET /api/v1/ca?uri=

One CA certificate (TA or CA) with its resources and the objects it issued.
Start at a `tas[].uri` from `/api/v1/status` and follow children with
`type: "cer"`, `kind: "CA"` to walk the tree.

```
curl -s 'localhost:8323/api/v1/ca?uri=rsync://rpki.apnic.net/repository/apnic-rpki-root-iana-origin.cer'
```

```json
{
 "uri": "rsync://rpki.apnic.net/repository/apnic-rpki-root-iana-origin.cer",
 "ta": "apnic", "parent": "", "status": "valid", "kind": "TA", "sha256": "...",
 "notBefore": "...", "notAfter": "...",
 "resources": {"ipv4": ["1.0.0.0/8", "..."], "ipv6": ["..."], "asn": ["..."]},
 "repository": "rsync://rpki.apnic.net/repository/", "notify": "https://rrdp.apnic.net/notification.xml",
 "repo_result": "ok",
 "children": [
  {"uri": "rsync://...cer", "type": "cer", "kind": "CA", "status": "valid"},
  {"uri": "rsync://...roa", "type": "roa", "status": "valid"}
 ],
 "children_truncated": false,
 "counts": {"cer valid": 3, "mft valid": 1, "crl valid": 1}
}
```

- A rejected CA has `status: "rejected"` and `reason`; resources may be missing.
- `repo_result` is the fetch result of the CA's repository (RRDP if it has a
  notify URI, otherwise its rsync module).
- `children` holds at most 10,000 entries (`children_truncated`); `counts`
  always covers all children.
- 404 for an unknown URI, a non-certificate URI or a router certificate.

### Unsafe VRPs, SLURM, repositories, rejects

#### GET /api/v1/unsafe

VRPs that overlap the resources of a rejected CA. When a CA breaks, its more
specific ROAs disappear, and a less specific ROA elsewhere can turn those
routes from not-found into invalid. Haetae only reports these; it still serves
the VRPs.

```json
{"generatedTime": "2026-11-01T09:21:10Z", "total": 1,
 "vrps": [{"asn": 64496, "prefix": "198.51.100.0/22", "maxLength": 24, "ta": "ripe",
           "rejected_ca": "rsync://rpki.example.net/repo/broken-ca.cer"}]}
```

#### GET /api/v1/slurm

Local exceptions (RFC 8416) currently applied.

```json
{"file": "/etc/haetae/slurm.json", "loaded": "2026-11-01T09:21:10Z",
 "filters": { "...RFC 8416 validationOutputFilters..." },
 "assertions": { "...RFC 8416 locallyAddedAssertions..." },
 "added": {"vrps": 1, "router_keys": 0, "aspas": 0},
 "filtered": {"vrps": 3, "router_keys": 0, "aspas": 0}}
```

Without a SLURM file the response is `{"file": "", "loaded": null}`. Haetae
also accepts ASPA entries in SLURM (draft extension); see the [manual](manual.md).

#### GET /repos.json

Fetch result of every repository in the last applied run.

```json
[
 {"uri": "https://rrdp.example.net/notification.xml", "type": "rrdp", "result": "ok",
  "action": "delta", "serial": 12345, "files": 17,
  "start": "2026-11-01T09:21:11Z", "duration_ns": 812000000}
]
```

| `result` | Meaning |
|---|---|
| `ok` | Fetched normally |
| `fallback-rsync` | RRDP failed; rsync was used |
| `fallback-old` | Fetch failed; previously fetched data was used |
| `failed` | Fetch failed and nothing usable was available |

`action` (RRDP) is `none`, `delta` or `snapshot`. `error` is present on failure.

#### GET /rejects.txt

Rejected objects, one per line: `URI<TAB>reason`.

## Output files

The output directory (`-o`, default `/var/lib/haetae/out`) holds the files
that the HTTP file endpoints serve. Each file is written to a temporary name
and renamed, so a reader never sees a partial file. Files are rewritten only
when a run is applied.

| File | HTTP | Content |
|---|---|---|
| `json` | `/json` | rpki-client compatible VRPs, ASPA, router keys (before SLURM) |
| `csv` | `/csv` | rpki-client compatible CSV (before SLURM) |
| `objects.jsonl` | `/objects.jsonl` | Every object, one JSON record per line, URI order |
| `rejects.txt` | `/rejects.txt` | `URI<TAB>reason` |
| `repos.json` | `/repos.json` | Repository fetch results |
| `summary.txt` | (none) | Counts by type and warning, with a few examples per warning |

### objects.jsonl

One [object record](#object-record) per line, for every object Haetae
examined (about 570,000 lines in late 2026). Suited to `grep` and `jq`:

```
jq -c 'select(.type=="gbr")' objects.jsonl
jq -r 'select(.status=="rejected") | [.type, .uri, .reason] | @tsv' objects.jsonl
```

The state directory (`-state`, default `/var/lib/haetae/state`) holds
`state.json` (session and serial), `deltas.gob` (the last 200 serials of
changes), `history.jsonl` (run history) and a lock file. These are internal
formats; use the API instead of reading them.

## RTR

### Summary

| Item | Value |
|---|---|
| Listen | `-rtr` (`[rtr] listen`), default `:3323`. Empty = no plain TCP listener. |
| Access | `-rtr-allow` (`[rtr] allow`), default `127.0.0.1,::1`. Other addresses are closed immediately and logged. An empty list allows nobody. The list applies to TCP and TLS listeners. |
| Versions | 0 (RFC 6810), 1 (RFC 8210), 2 (draft-ietf-sidrops-8210bis, ASPA) |
| Payload | v0: IPv4 / IPv6 Prefix. v1: + Router Key. v2: + ASPA |
| Timers (v1, v2) | refresh 600, retry 300, expire 7200 seconds |

### Version negotiation

The version of the first PDU a router sends sets the version of the session.

- Version 0, 1 or 2 is accepted and used for every PDU on that connection.
- A higher version gets an Error Report with code 4 (Unsupported Protocol
  Version) carrying version 2, and the connection is closed, so the router can
  reconnect with a lower version.
- A later PDU with a different version gets Error Report code 8 (Unexpected
  Protocol Version) and the connection is closed.

### PDUs

Sent by Haetae:

| Type | PDU | Notes |
|---|---|---|
| 0 | Serial Notify | Sent to every connected router when a new serial is produced |
| 3 | Cache Response | Starts a full or incremental response |
| 4 | IPv4 Prefix | flags 1 = announce, 0 = withdraw |
| 6 | IPv6 Prefix | as above |
| 7 | End of Data | v0: session and serial. v1 / v2: also refresh, retry, expire |
| 8 | Cache Reset | Serial Query with another session, or a serial no longer kept |
| 9 | Router Key | v1 and v2 only. SKI (20 bytes), ASN, SubjectPublicKeyInfo |
| 10 | Error Report | See below |
| 11 | ASPA | v2 only. See below |

Accepted from routers: Reset Query (2), Serial Query (1) and Error Report (10).
Any other PDU type gets Error Report code 5 (Unsupported PDU Type). A PDU with
a bad length (less than 8, more than 64 KiB, or the wrong fixed length for a
query) gets code 0 (Corrupt Data). In every error case the connection is
closed. An Error Report from a router is logged and the connection closed.
If no data is available (which only happens before RTR is normally opened), a
query gets code 2 (No Data Available).

**Reset Query** returns Cache Response, every prefix (and router key and ASPA,
by version), End of Data.

**Serial Query** returns only the changes since the router's serial: prefix
withdrawals first, then announcements, then router key withdrawals and
announcements, then ASPA, then End of Data. If the session does not match or
the serial is not in the kept history (200 serials), the answer is Cache Reset
and the router sends a Reset Query.

**ASPA PDU** (type 11, version 2), as in draft-ietf-sidrops-8210bis-27
section 5.12:

```
 0          8          16         24        31
+----------+----------+----------+----------+
| version  |  type 11 |  flags   |   zero   |
+----------+----------+----------+----------+
|                  length                   |
+-------------------------------------------+
|              customer ASN                 |
+-------------------------------------------+
|        provider ASN ... (ascending)       |
+-------------------------------------------+
```

- flags bit 0: 1 = announce, 0 = withdraw.
- One PDU per customer AS with the union of providers from all TAs (after
  SLURM), in ascending order.
- On a change, the full new provider list is announced again. A withdrawal has
  no providers (length 12).
- RTR version 2 and the ASPA PDU are still an Internet-Draft; router support
  varies by vendor and software release. Check that a router implements the
  same draft revision before relying on it.

### Timers

End of Data (v1 and v2) carries the timers, which routers use to schedule
queries:

| Option | Config key | Default | Allowed |
|---|---|---|---|
| `-rtr-refresh` | `[rtr] refresh` | 600 | 1 to 86400 |
| `-rtr-retry` | `[rtr] retry` | 300 | 1 to 7200 |
| `-rtr-expire` | `[rtr] expire` | 7200 | 600 to 172800, greater than refresh and retry |

Haetae refuses to start with values outside RFC 8210's ranges. New timer values
take effect on `systemctl reload haetae` and reach routers with their next
End of Data.

### Sessions, serials and restarts

- The serial increases by one each time the served set changes (normally at
  most once per run, every 10 minutes by default). If a run produces the same
  set, the serial stays.
- Haetae saves the session ID, serial and the last 200 serials of changes in
  its state directory. After a restart, routers reconnect and continue with a
  Serial Query; they do not need a full reload.
- At start, if the previous VRP set is present and no older than
  `-max-start-age` (default 2 hours), Haetae opens RTR immediately with that
  set. Otherwise it picks a new random session ID, waits for the first
  successful validation and only then opens RTR. Routers see the new session
  and reload the full set. Haetae never serves an empty set as its first answer.
- If a run fails badly (a TA fails, or no VRPs at all), the previous set stays
  in service. With `-hold-drop`, a large drop in VRPs is also held back (see the
  [manual](manual.md)).

### Transport security

All four RTR transports from RFC 8210 section 7 are implemented. All are off by
default; plain TCP plus `-rtr-allow` is the default. All transports use the
same session, serials and data.

| Transport | Port | How |
|---|---|---|
| TCP-MD5 (RFC 2385) | `-rtr` (same port) | Per-peer keys in the `-rtr-auth` file |
| TCP-AO (RFC 5925) | `-rtr` (same port) | Per-peer keys in the `-rtr-auth` file |
| TLS | `-rtr-tls`, for example `:3324` | `-rtr-tls-cert`, `-rtr-tls-key`, optional `-rtr-tls-ca` |
| SSH | 22 (system sshd) | sshd `rpki-rtr` subsystem runs `haetae -rtr-stdio` |

The connection's transport is shown in `rtr_clients[].transport` of
`/api/v1/status`.

#### TCP-MD5 and TCP-AO

Keys are installed by the Linux kernel on the listening socket, per peer
address or prefix. The key file (`-rtr-auth`, `[rtr] auth`) has one key per
line:

```
# address or prefix   method   parameters
192.0.2.1             md5      <password>
198.51.100.0/24       ao       hmac(sha1) <sendid> <recvid> <password>
2001:db8:1::1         ao       cmac(aes128) <sendid> <recvid> <password>
```

- Methods: `md5`, or `ao` with algorithm `hmac(sha1)`, `cmac(aes128)` or
  `hmac(sha256)`. The MAC length is 12 bytes. `sendid` and `recvid` (0 to 255)
  are from Haetae's point of view, so they are swapped relative to the router's
  send-id and receive-id. Keys are 1 to 80 bytes.
- The most specific matching prefix wins, as in the kernel.
- A peer with a key must sign every segment; the kernel drops unsigned
  segments from it. Peers **without** a key in the file can still connect over
  plain TCP if they are in `-rtr-allow`. To require authentication, list only
  keyed peers in `-rtr-allow`.
- Keep the file readable only by the Haetae user (mode 0600). Haetae logs a
  warning if others can read it.
- TCP-AO needs a Linux kernel with TCP-AO support (6.7 or later).
- The key file is read at start; changing it needs a restart.

#### TLS

```
haetae -rtr-tls :3324 -rtr-tls-cert /etc/haetae/rtr.crt -rtr-tls-key /etc/haetae/rtr.key \
       -rtr-tls-ca /etc/haetae/routers-ca.pem
```

- TLS 1.2 or later.
- With `-rtr-tls-ca`, routers must present a certificate signed by that CA.
  Without it, any router in `-rtr-allow` can connect.
- `-rtr-allow` applies as for plain TCP.
- `systemctl reload haetae` reloads the certificate and key for new
  connections. Changing the TLS listen address needs a restart.

#### SSH

Go's standard library has no SSH server, so Haetae uses the system sshd. sshd
authenticates the router and runs `haetae -rtr-stdio <addr>`, which connects
standard input and output to Haetae's local RTR port.

```
# /etc/ssh/sshd_config
Subsystem rpki-rtr /usr/local/bin/haetae -rtr-stdio 127.0.0.1:3323
Match User rpki-rtr
    ForceCommand /usr/local/bin/haetae -rtr-stdio 127.0.0.1:3323
    AllowTcpForwarding no
    X11Forwarding no
    PermitTTY no
```

- Configure the router to use subsystem `rpki-rtr` with the account you create
  for it.
- To Haetae, SSH sessions are TCP connections from `127.0.0.1`, so
  `-rtr-allow` must include `127.0.0.1` (it does by default). They appear in
  `rtr_clients` as `127.0.0.1` with transport `tcp`.
- See the [manual](manual.md) for the full setup.

### Checking RTR

On a router, use the vendor's RPKI cache status commands and compare the
session and serial with `/api/v1/status`. FRR examples:

```
show rpki cache-connection
show rpki prefix-table
```

The prefix count a router shows should equal `vrps` in `/api/v1/status` for the
same serial (some routers count IPv4 and IPv6 separately).
