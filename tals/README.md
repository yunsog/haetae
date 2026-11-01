# Trust Anchor Locators

The five RIR TALs Haetae trusts. They are embedded in the binary at build time
(Go `embed`, `tal.go`); `-tal <dir>` uses a folder instead (testing / emergency).

Each file was downloaded from the RIR's official site. The start-up log line
`TAL (내장): afrinic ad69cadc45c0cd41, ...` ("built-in") prints the hashes below.
The file name without `.tal` is the trust anchor name used in the `ta` field of
the output (afrinic / apnic / arin / lacnic / ripe) — do not rename the files.

| File | Source | Public key SHA-256 (of the base64 text, first 16 hex) |
|---|---|---|
| afrinic.tal | https://rpki.afrinic.net/tal/afrinic.tal | ad69cadc45c0cd41 |
| apnic.tal | https://tal.apnic.net/tal-archive/apnic-rfc7730-https.tal | a3a053a192ca1c57 |
| arin.tal | https://www.arin.net/resources/manage/rpki/arin.tal | 50471ac41c29b263 |
| lacnic.tal | https://www.lacnic.net/innovaportal/file/4983/1/lacnic.tal | aa4375000f5431be |
| ripe.tal | https://tal.rpki.ripe.net/ripe-ncc.tal | 44a4f26e67d2e2ce |

When an RIR rolls its TA key (rare; announced by the RIR or by a TAK object):

1. Download the new TAL from the official site and check the key against a second
   source (RIR announcement, another RP's distribution).
2. Update this folder, the table above and `wantTALKeys` in `tal_test.go`, rebuild
   and restart. If you cannot rebuild in time, put the new TALs in a folder and run
   with `-tal <dir>` for a while.

TA constraints files (`*.constraints`, an rpki-client feature) are not used.
The disclaimer at the top of `arin.tal` is ARIN's own and is kept unchanged.
