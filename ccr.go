// SPDX-License-Identifier: Apache-2.0

package main

// ccr.go : CCR (Canonical Cache Representation, draft-ietf-sidrops-rpki-ccr-11, 0.4.0)
//
// 검증이 끝난 캐시 상태를 정해진 DER 모양으로 씀 (출력 rpki.ccr, HTTP /rpki.ccr 내부만). 같은 입력이면 어느 RP 가 만들어도
// 한 바이트까지 같음 = RP 끼리 비교용. 칸마다 SHA-256 해시가 있어 json metadata 의 ccr_*_hash 만 봐도 같은지 알 수 있음
// (rpki-client 9.9 와 같은 이름). 서명 객체가 아니라 출처 확인은 없음. 회차당 약 1 초 / 25 MB (gzip 약 12 MB)
//
// 설정 [ccr] mode (옵션 -ccr, 11-18) : off (기본, 안 만듦) | latest (rpki.ccr 덮어씀) | daily | hourly | cycle
//   daily / hourly / cycle = latest + <dir>/YYYYMMDD/rpki-YYYYMMDDTHHMMSSZ.ccr.gz 보관 (그날 / 그 시각 (UTC) 첫 반영 회차, 또는 반영 회차마다).
//   keep 지난 것은 지움. rpki-client 9.9 는 늘 rpki.ccr 하나를 씀 (끄는 옵션 없음, 보관 없음)
//
//   ContentInfo { OID 1.2.840.113549.1.9.16.1.54, [0] {
//     version [0] = 0 (기본값이라 DER 에서 뺌), hashAlg = sha256, producedAt = 검증 기준 시각,
//     [1] mfts : 현재 manifest 목록 (해시 / 크기 / AKI / 번호 / thisUpdate / EE 의 SIA / 아래 CA 의 SKI) + 가장 늦은 thisUpdate + 해시
//     [2] vrps : VRP 를 AS 별로 ROA 모양으로 묶음 (RFC 9582 정규형) + 해시
//     [3] vaps : ASPA 를 customer 별로 합침 + 해시
//     [4] tas  : 쓴 TA 인증서의 SKI + 해시
//     [5] rks  : BGPsec 라우터 키 (AS 별, SKI 순) + 해시 } }
//
// 정렬은 모두 오름차순, 같은 것은 하나만. 모양을 바꾸면 스냅샷에서 rpki-client 9.9 의 rpki.ccr 와 cmp 로 확인 (docs/manual.md)

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/base64"
	"math/big"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// oidCTCCR : CCR content type (oidSHA256 은 cms.go)
var oidCTCCR = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 1, 54}

// ccrMft : manifest 하나 (검증 중 processCA 가 만들고, 아래 CA 의 SKI 는 processCert 가 더함)
type ccrMft struct {
	Hash       [32]byte // manifest 파일 DER 의 SHA-256
	Size       int
	AKI        []byte
	Number     *big.Int
	ThisUpdate time.Time
	Locations  [][]byte // manifest EE 의 SIA 안 AccessDescription (DER 그대로)
	Subs       [][]byte // 이 CA 가 낸 유효한 CA 인증서의 SKI
}

// ccrHashes : json metadata 에 싣는 칸별 해시 (base64, rpki-client 와 같은 모양)
type ccrHashes struct {
	Mfts, VRPs, VAPs, TAs, RKs string
}

// ---- DER 쓰기 (der.go 는 읽기만) ----

// derTLV : tag 하나 + 길이 + 내용. 길이는 DER 규칙 (128 이상이면 길이 바이트 수를 먼저)
func derTLV(tag byte, parts ...[]byte) []byte {
	n := 0
	for _, p := range parts {
		n += len(p)
	}
	out := make([]byte, 0, n+6)
	out = append(out, tag)
	if n < 128 {
		out = append(out, byte(n))
	} else {
		var lb []byte
		for x := n; x > 0; x >>= 8 {
			lb = append([]byte{byte(x)}, lb...)
		}
		out = append(out, 0x80|byte(len(lb)))
		out = append(out, lb...)
	}
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

func derSeqOf(parts ...[]byte) []byte { return derTLV(0x30, parts...) }
func derOctet(b []byte) []byte        { return derTLV(0x04, b) }
func derExplicit(n int, inner []byte) []byte {
	return derTLV(0xa0|byte(n), inner)
}

// derInteger : 0 이상 정수 (앞자리 비트가 1 이면 0x00 을 붙여 양수로)
func derInteger(x *big.Int) []byte {
	b := x.Bytes()
	if len(b) == 0 || b[0]&0x80 != 0 {
		b = append([]byte{0}, b...)
	}
	return derTLV(0x02, b)
}

func derUint32(x uint32) []byte { return derInteger(new(big.Int).SetUint64(uint64(x))) }

func derOID(o asn1.ObjectIdentifier) []byte {
	b, _ := asn1.Marshal(o) // 고정 OID 라 오류 없음
	return b
}

// derGenTime : GeneralizedTime "YYYYMMDDHHMMSSZ" (초 아래는 버림)
func derGenTime(t time.Time) []byte {
	return derTLV(0x18, []byte(t.UTC().Format("20060102150405Z")))
}

// derPrefixBits : prefix 를 BIT STRING 으로 (RFC 3779 2.1.2 : 앞 n 비트만, 첫 바이트 = 남는 비트 수)
func derPrefixBits(p netip.Prefix) []byte {
	nb := (p.Bits() + 7) / 8
	a := p.Addr().AsSlice()
	return derTLV(0x03, append([]byte{byte(nb*8 - p.Bits())}, a[:nb]...))
}

// ccrState : 목록 SEQUENCE + 그 SHA-256 (칸 안의 hash). 해시는 SEQUENCE 의 DER 전체로
func ccrState(list []byte, extra ...[]byte) ([]byte, string) {
	h := sha256.Sum256(list)
	parts := append([][]byte{list}, extra...)
	parts = append(parts, derOctet(h[:]))
	return derSeqOf(parts...), base64.StdEncoding.EncodeToString(h[:])
}

// ---- 검증 중 모으기 ----

// newCCRMft : 확인을 통과한 manifest 하나 (위치 = EE 의 SIA 중 signedObject, 인증서 확장의 DER 그대로)
func newCCRMft(der []byte, m *rpkiManifest) *ccrMft {
	r := &ccrMft{Hash: sha256.Sum256(der), Size: len(der), AKI: m.EE.AKI, Number: m.Number, ThisUpdate: m.ThisUpdate}
	for _, e := range m.EE.X509.Extensions {
		if !e.Id.Equal(oidExtSIA) {
			continue
		}
		if n, err := derOne(e.Value); err == nil {
			if ads, err := derChildren(n, 64); err == nil {
				for _, ad := range ads {
					// signedObject 위치만 (rpkiNotify 등 다른 것은 뺌 = rpki-client 9.9 와 같게)
					if kids, err := derChildren(ad, 2); err == nil && len(kids) == 2 {
						if o, err := derOIDOf(kids[0]); err == nil && o.Equal(oidADSignedObject) {
							r.Locations = append(r.Locations, ad.Full)
						}
					}
				}
			}
		}
	}
	return r
}

// ---- 만들기 ----

// buildCCR : 회차 결과 -> CCR DER + 칸별 해시. 검증이 다 끝난 뒤 (v.mu 를 잡지 않음)
func (v *validator) buildCCR() ([]byte, ccrHashes) {
	var hs ccrHashes
	mfts, mostRecent := v.ccrMftList()
	mftState, h := ccrState(mfts, derGenTime(mostRecent))
	hs.Mfts = h
	vrpState, h := ccrState(v.ccrVRPList())
	hs.VRPs = h
	vapState, h := ccrState(v.ccrASPAList())
	hs.VAPs = h
	taState, h := ccrState(v.ccrTAList())
	hs.TAs = h
	rkState, h := ccrState(v.ccrRouterKeyList())
	hs.RKs = h

	// version 은 기본값 0 이라 DER 에서 뺌
	body := derSeqOf(
		derSeqOf(derOID(oidSHA256)),
		derGenTime(v.Now),
		derExplicit(1, mftState),
		derExplicit(2, vrpState),
		derExplicit(3, vapState),
		derExplicit(4, taState),
		derExplicit(5, rkState),
	)
	return derSeqOf(derOID(oidCTCCR), derExplicit(0, body)), hs
}

// ccrMftList : ManifestInstance 목록 (manifest 해시 순, 같은 해시는 하나 = 아래 CA SKI 를 합침)
// mostRecent = thisUpdate 중 가장 늦은 것 (없으면 1970-01-01)
func (v *validator) ccrMftList() ([]byte, time.Time) {
	byHash := map[[32]byte]*ccrMft{}
	for _, m := range v.ccrMfts {
		if old := byHash[m.Hash]; old != nil {
			old.Subs = append(old.Subs, m.Subs...)
			continue
		}
		byHash[m.Hash] = m
	}
	list := make([]*ccrMft, 0, len(byHash))
	for _, m := range byHash {
		list = append(list, m)
	}
	sort.Slice(list, func(i, j int) bool { return bytes.Compare(list[i].Hash[:], list[j].Hash[:]) < 0 })

	mostRecent := time.Unix(0, 0)
	var items [][]byte
	for _, m := range list {
		if m.ThisUpdate.After(mostRecent) {
			mostRecent = m.ThisUpdate
		}
		parts := [][]byte{derOctet(m.Hash[:]), derInteger(big.NewInt(int64(m.Size))), derOctet(m.AKI),
			derInteger(m.Number), derGenTime(m.ThisUpdate), derSeqOf(m.Locations...)}
		if subs := uniqueSorted(m.Subs); len(subs) > 0 { // 없으면 칸을 뺌 (OPTIONAL, 빈 목록은 안 됨)
			var ss [][]byte
			for _, s := range subs {
				ss = append(ss, derOctet(s))
			}
			parts = append(parts, derSeqOf(ss...))
		}
		items = append(items, derSeqOf(parts...))
	}
	return derSeqOf(items...), mostRecent
}

// uniqueSorted : 바이트 열 목록을 오름차순 + 중복 제거 (SKI = 160 비트 부호 없는 수로 보면 바이트 비교와 같음)
func uniqueSorted(in [][]byte) [][]byte {
	sort.Slice(in, func(i, j int) bool { return bytes.Compare(in[i], in[j]) < 0 })
	var out [][]byte
	for _, b := range in {
		if len(out) == 0 || !bytes.Equal(out[len(out)-1], b) {
			out = append(out, b)
		}
	}
	return out
}

// ccrVRP : TA 를 뺀 VRP (CCR 은 TA 구별 없이 한 번만)
type ccrVRP struct {
	ASN       uint32
	Prefix    netip.Prefix
	MaxLength int
}

// ccrVRPList : ROAPayloadSet 목록. AS 순, 그 안은 주소 체계 (IPv4 먼저) 별로 주소 -> 길이 -> maxLength 순 (RFC 9582 4.3.3)
// maxLength 가 prefix 길이와 같으면 뺌 (정규형)
func (v *validator) ccrVRPList() []byte {
	seen := map[ccrVRP]bool{}
	var list []ccrVRP
	for k := range v.vrps {
		x := ccrVRP{k.ASN, k.Prefix, k.MaxLength}
		if !seen[x] {
			seen[x] = true
			list = append(list, x)
		}
	}
	sort.Slice(list, func(i, j int) bool {
		a, b := list[i], list[j]
		if a.ASN != b.ASN {
			return a.ASN < b.ASN
		}
		if a.Prefix.Addr().Is4() != b.Prefix.Addr().Is4() {
			return a.Prefix.Addr().Is4()
		}
		if c := a.Prefix.Addr().Compare(b.Prefix.Addr()); c != 0 {
			return c < 0
		}
		if a.Prefix.Bits() != b.Prefix.Bits() {
			return a.Prefix.Bits() < b.Prefix.Bits()
		}
		return a.MaxLength < b.MaxLength
	})

	var sets [][]byte
	for i := 0; i < len(list); {
		asn := list[i].ASN
		var fams [][]byte
		for i < len(list) && list[i].ASN == asn {
			v4 := list[i].Prefix.Addr().Is4()
			afi := []byte{0, 2}
			if v4 {
				afi = []byte{0, 1}
			}
			var addrs [][]byte
			for i < len(list) && list[i].ASN == asn && list[i].Prefix.Addr().Is4() == v4 {
				r := list[i]
				a := [][]byte{derPrefixBits(r.Prefix)}
				if r.MaxLength != r.Prefix.Bits() {
					a = append(a, derInteger(big.NewInt(int64(r.MaxLength))))
				}
				addrs = append(addrs, derSeqOf(a...))
				i++
			}
			fams = append(fams, derSeqOf(derOctet(afi), derSeqOf(addrs...)))
		}
		sets = append(sets, derSeqOf(derUint32(asn), derSeqOf(fams...)))
	}
	return derSeqOf(sets...)
}

// ccrASPAList : ASPAPayloadSet 목록. customer 순, provider 는 TA 를 넘어 합쳐 오름차순 (mergedProviders :
// AS 0 은 다른 provider 와 함께면 뺌, draft 3.4.3 / aspa-profile 5.2. rpki-client 9.9 는 남김 = 그런 customer 가 있으면 이 칸만 다름)
func (v *validator) ccrASPAList() []byte {
	prov := map[uint32]map[uint32]bool{}
	for k, a := range v.aspas {
		m := prov[k.Customer]
		if m == nil {
			m = map[uint32]bool{}
			prov[k.Customer] = m
		}
		for p := range a.Providers {
			m[p] = true
		}
	}
	custs := make([]uint32, 0, len(prov))
	for c := range prov {
		custs = append(custs, c)
	}
	sort.Slice(custs, func(i, j int) bool { return custs[i] < custs[j] })
	var sets [][]byte
	for _, c := range custs {
		var pe [][]byte
		for _, p := range mergedProviders(prov[c]) {
			pe = append(pe, derUint32(p))
		}
		sets = append(sets, derSeqOf(derUint32(c), derSeqOf(pe...)))
	}
	return derSeqOf(sets...)
}

// ccrTAList : 쓴 TA 인증서의 SKI (오름차순)
func (v *validator) ccrTAList() []byte {
	var out [][]byte
	for _, s := range uniqueSorted(append([][]byte(nil), v.ccrTAs...)) {
		out = append(out, derOctet(s))
	}
	return derSeqOf(out...)
}

// ccrRouterKeyList : RouterKeySet 목록. AS 순, 그 안은 SKI 순 (같은 AS / SKI / 키는 하나)
func (v *validator) ccrRouterKeyList() []byte {
	byAS := map[uint32]map[string]routerKey{}
	for _, k := range v.rkeys {
		m := byAS[k.ASN]
		if m == nil {
			m = map[string]routerKey{}
			byAS[k.ASN] = m
		}
		m[string(k.SKI)+string(k.SPKI)] = k.routerKey
	}
	asns := make([]uint32, 0, len(byAS))
	for a := range byAS {
		asns = append(asns, a)
	}
	sort.Slice(asns, func(i, j int) bool { return asns[i] < asns[j] })
	var sets [][]byte
	for _, a := range asns {
		keys := make([]routerKey, 0, len(byAS[a]))
		for _, k := range byAS[a] {
			keys = append(keys, k)
		}
		sort.Slice(keys, func(i, j int) bool {
			if c := bytes.Compare(keys[i].SKI, keys[j].SKI); c != 0 {
				return c < 0
			}
			return bytes.Compare(keys[i].SPKI, keys[j].SPKI) < 0
		})
		var ks [][]byte
		for _, k := range keys {
			ks = append(ks, derSeqOf(derOctet(k.SKI), k.SPKI))
		}
		sets = append(sets, derSeqOf(derUint32(a), derSeqOf(ks...)))
	}
	return derSeqOf(sets...)
}

// ---- 설정과 보관 ----

// validCCRMode : 설정 값 확인
func validCCRMode(m string) bool {
	switch m {
	case "off", "latest", "daily", "hourly", "cycle":
		return true
	}
	return false
}

// ccrArchiveDir : 보관 폴더 (빈 값 = <출력 폴더>/ccr)
func ccrArchiveDir(dir, outDir string) string {
	if dir != "" {
		return dir
	}
	return filepath.Join(outDir, "ccr")
}

// archiveCCR : mode 가 daily / hourly / cycle 이면 gzip 으로 보관하고 keep 지난 것을 지움. 나머지 mode 는 아무것도 안 함.
// 이름 = 검증 기준 시각 (producedAt, UTC). 이번 기간 (그날 / 그 시각) 에 이미 하나 있으면 daily / hourly 는 건너뜀
func archiveCCR(dir string, der []byte, mode string, keep time.Duration, now time.Time) error {
	if der == nil || (mode != "daily" && mode != "hourly" && mode != "cycle") {
		return nil
	}
	t := now.UTC()
	day := filepath.Join(dir, t.Format("20060102"))
	if err := os.MkdirAll(day, 0755); err != nil {
		return err
	}
	// 같은 기간의 파일 이름 앞부분 : daily = rpki-YYYYMMDD, hourly = rpki-YYYYMMDDTHH
	prefix := ""
	switch mode {
	case "daily":
		prefix = "rpki-" + t.Format("20060102")
	case "hourly":
		prefix = "rpki-" + t.Format("20060102T15")
	}
	done := false
	if prefix != "" {
		ents, _ := os.ReadDir(day)
		for _, e := range ents {
			if strings.HasPrefix(e.Name(), prefix) && strings.HasSuffix(e.Name(), ".ccr.gz") {
				done = true
				break
			}
		}
	}
	if !done {
		name := "rpki-" + t.Format("20060102T150405Z") + ".ccr.gz"
		err := writeAtomic(day, name, func(w *bufio.Writer) error {
			gz := gzip.NewWriter(w)
			if _, err := gz.Write(der); err != nil {
				return err
			}
			return gz.Close()
		})
		if err != nil {
			return err
		}
	}
	return pruneCCR(dir, keep, now)
}

// pruneCCR : 이름의 시각이 keep 보다 오래된 보관 파일을 지우고, 빈 날짜 폴더도 지움 (keep 0 = 지우지 않음)
func pruneCCR(dir string, keep time.Duration, now time.Time) error {
	if keep <= 0 {
		return nil
	}
	days, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	for _, d := range days {
		if !d.IsDir() || len(d.Name()) != 8 {
			continue
		}
		p := filepath.Join(dir, d.Name())
		files, _ := os.ReadDir(p)
		left := 0
		for _, f := range files {
			ts := strings.TrimSuffix(strings.TrimPrefix(f.Name(), "rpki-"), ".ccr.gz")
			at, err := time.Parse("20060102T150405Z", ts)
			if err != nil {
				left++ // 우리가 만든 이름이 아니면 건드리지 않음
				continue
			}
			if now.Sub(at) > keep {
				os.Remove(filepath.Join(p, f.Name()))
			} else {
				left++
			}
		}
		if left == 0 {
			os.Remove(p)
		}
	}
	return nil
}
