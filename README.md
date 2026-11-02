<p align="center"><img src="docs/logo/haetae_logo.png" alt="Haetae" width="320"></p>

# Haetae

Haetae is an RPKI relying party (RP) written in Go. It fetches the RPKI
repositories of the five RIRs, validates every published object and serves the
result to routers over RTR and to other systems over an HTTP API.

The name comes from the *haetae* (해태), a mythical guardian in Korean tradition
that tells right from wrong.

Haetae 0.2.0 runs in a test deployment alongside other RPs, serving a test router
over RTR. It is new software: please run it next to an established RP and compare
before relying on it.

## Features

- **Objects** : TA / CA certificates, CRLs, manifests, ROAs, ASPA, BGPsec router
  keys, Ghostbusters records, Signed Prefix Lists, TAKs. RSC (RFC 9323) can be
  checked as a single file (`-rsc`).
- **Fetching** : RRDP (snapshot / delta, conditional GET, preferred) with rsync
  fallback via the external `rsync` command, 32 repositories in parallel, size /
  time / depth limits, back-off for dead repositories.
- **Validation** : RFC 6487 / 3779 / 6488 / 9286 / 9582, rpki-client level
  strictness, manifest-based publication point handling with the last valid
  copy as fallback (RFC 9286 section 6.7). TA constraints files are not used
  (they are not part of any RFC).
- **RTR** : RFC 8210 version 1 (with version 0 negotiation and Router Key PDUs)
  and version 2 (ASPA PDUs, draft-ietf-sidrops-8210bis). Session and serial are
  kept across restarts. Transport security : TCP-MD5, TCP-AO, TLS, SSH subsystem.
- **HTTP API** : rpki-client style JSON, CSV, Routinator style `json-delta`,
  validity lookup, AS / prefix queries, ASPA path verification, object listing,
  status, `/healthz` and Prometheus metrics. Two access tiers: management
  networks see everything, the public only the lookup paths.
- **Operations** : SLURM (RFC 8416), configuration file with `systemctl reload`,
  keeps serving the last good VRPs when a cycle fails, warning / hold on large VRP
  drops, stale data alarm, systemd watchdog, the five RIR TALs built into the binary.
- **Seamless upgrade** : on `SIGUSR2` the running process hands its RTR sessions
  and listening sockets to the new binary (same pid). Routers stay connected;
  RTR pauses for about 2 seconds.
- **No dependencies** : Go standard library only.

On the same repository snapshot and validation time, Haetae and rpki-client 9.0
produce the same VRPs, ASPA and router keys.

## Build

Go 1.26 or later.

```
go install github.com/yunsog/haetae@latest
```

or from a clone :

```
git clone https://github.com/yunsog/haetae.git
cd haetae
go build -o haetae .
go test ./...
```

## Quick start

```
# one validation run into a folder (fetch + validate)
./haetae -validate -fetch -cache /tmp/haetae/cache -o /tmp/haetae/out

# daemon : RTR on :3323, HTTP API on 127.0.0.1:8323, a cycle every 10 minutes
./haetae -cache /var/lib/haetae/cache -o /var/lib/haetae/out -state /var/lib/haetae/state
```

For a systemd installation see `deploy/haetae.service`,
`deploy/haetae.conf.example` and the manual.

## Documentation

- [User manual](docs/manual.md) : install, options, configuration, operation
- [API guide](docs/api.md) : HTTP API and RTR
- [Trust anchors](tals/README.md)
- [Changes](CHANGELOG.md)
- Introduction slides : [English](docs/haetae_v0.2_en.pdf), [Korean](docs/haetae_v0.2_ko.pdf)

Source code comments, command line help and some log messages are in Korean.

## License

ISC. See [LICENSE](LICENSE).
