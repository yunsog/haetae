package main

// view.go : 조회 API 용 검증 결과 (회차마다 새로 만들고, 만든 뒤에는 바꾸지 않음)
//
//   객체 목록 (objects.jsonl 과 같은 것, URI 순), VRP 의 출처 ROA, ASPA / 라우터 키 출처,
//   unsafe VRP (A4), 저장소 결과.
// 재시작 직후 (첫 검증 전) 에는 없음 -> 이것을 쓰는 API 는 503.

import (
	"bytes"
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"time"
)

// roaPrefixOut : objects 의 ROA 요약에 들어가는 prefix 하나
type roaPrefixOut struct {
	Prefix    netip.Prefix `json:"prefix"`
	MaxLength int          `json:"maxLength"`
}

// resSummary : objects 의 CA 요약에 들어가는 자원 (inherit 푼 것)
type resSummary struct {
	IPv4 []string `json:"ipv4,omitempty"`
	IPv6 []string `json:"ipv6,omitempty"`
	ASN  []string `json:"asn,omitempty"`

	v4, v6 []ipRange // prefix 조건 검색용 (JSON 에는 안 나감)
	as     []asRange
}

func newResSummary(ips ipResources, as asResources) *resSummary {
	r := &resSummary{v4: ips.V4.Ranges, v6: ips.V6.Ranges, as: as.Ranges}
	for _, x := range ips.V4.Ranges {
		r.IPv4 = append(r.IPv4, rangeString(x, true))
	}
	for _, x := range ips.V6.Ranges {
		r.IPv6 = append(r.IPv6, rangeString(x, false))
	}
	for _, x := range as.Ranges {
		if x.Min == x.Max {
			r.ASN = append(r.ASN, fmt.Sprint(x.Min))
		} else {
			r.ASN = append(r.ASN, fmt.Sprintf("%d-%d", x.Min, x.Max))
		}
	}
	return r
}

// rangeAddr : ipRange 의 [16]byte -> netip.Addr (IPv4 는 앞 4 바이트)
func rangeAddr(b [16]byte, v4 bool) netip.Addr {
	if v4 {
		return netip.AddrFrom4([4]byte(b[:4]))
	}
	return netip.AddrFrom16(b)
}

// rangeString : prefix 하나로 딱 맞으면 "a/n", 아니면 "a-b"
// Min 과 Max 의 공통 앞 비트 수 = n, 그 뒤가 Min 은 모두 0, Max 는 모두 1 이면 prefix
func rangeString(r ipRange, v4 bool) string {
	lo, hi := rangeAddr(r.Min, v4), rangeAddr(r.Max, v4)
	nbits := lo.BitLen()
	n := 0
	for n < nbits && bit(r.Min, n) == bit(r.Max, n) {
		n++
	}
	for i := n; i < nbits; i++ {
		if bit(r.Min, i) != 0 || bit(r.Max, i) != 1 {
			return lo.String() + "-" + hi.String()
		}
	}
	return netip.PrefixFrom(lo, n).String()
}

// bit : i 번째 비트 (앞에서부터)
func bit(b [16]byte, i int) byte {
	return b[i/8] >> (7 - i%8) & 1
}

// rangesOverlap : 정렬된 rs 중 r 과 겹치는 것이 있는지
func rangesOverlap(rs []ipRange, r ipRange) bool {
	for _, x := range rs {
		if bytes.Compare(x.Min[:], r.Max[:]) <= 0 && bytes.Compare(x.Max[:], r.Min[:]) >= 0 {
			return true
		}
	}
	return false
}

// unsafeVRP : 거부된 CA 의 자원과 겹치는 VRP (A4 : 경고만, VRP 는 그대로 줌)
type unsafeVRP struct {
	ASN        uint32       `json:"asn"`
	Prefix     netip.Prefix `json:"prefix"`
	MaxLength  int          `json:"maxLength"`
	TA         string       `json:"ta"`
	RejectedCA string       `json:"rejected_ca"`
}

// computeUnsafe : VRP 마다 거부된 CA 자원과 겹치는지 (범위를 Min 순으로 정렬 + 누적 최대 Max 로 이분 탐색)
func computeUnsafe(vrps []vrpKey, rs []unsafeRange) []unsafeVRP {
	var out []unsafeVRP
	for _, fam := range []bool{true, false} {
		var list []unsafeRange
		for _, r := range rs {
			if r.V4 == fam {
				list = append(list, r)
			}
		}
		if len(list) == 0 {
			continue
		}
		sort.Slice(list, func(i, j int) bool { return bytes.Compare(list[i].R.Min[:], list[j].R.Min[:]) < 0 })
		runMax := make([][16]byte, len(list)) // list[0..i] 의 Max 중 가장 큰 것
		for i, r := range list {
			runMax[i] = r.R.Max
			if i > 0 && bytes.Compare(runMax[i-1][:], r.R.Max[:]) > 0 {
				runMax[i] = runMax[i-1]
			}
		}
		for _, k := range vrps {
			if k.Prefix.Addr().Is4() != fam {
				continue
			}
			pr := prefixRange(k.Prefix)
			// Min <= pr.Max 인 범위 수
			n := sort.Search(len(list), func(i int) bool { return bytes.Compare(list[i].R.Min[:], pr.Max[:]) > 0 })
			if n == 0 || bytes.Compare(runMax[n-1][:], pr.Min[:]) < 0 {
				continue
			}
			for i := n - 1; i >= 0; i-- { // 어느 CA 인지 (드묾)
				if bytes.Compare(list[i].R.Max[:], pr.Min[:]) >= 0 {
					out = append(out, unsafeVRP{k.ASN, k.Prefix, k.MaxLength, k.TA, list[i].CA})
					break
				}
			}
		}
	}
	sort.Slice(out, func(i, j int) bool {
		return lessVRPKey(vrpKey{out[i].ASN, out[i].Prefix, out[i].MaxLength, out[i].TA},
			vrpKey{out[j].ASN, out[j].Prefix, out[j].MaxLength, out[j].TA})
	})
	return out
}

// queryView : 한 회차의 조회용 결과
type queryView struct {
	Built   time.Time
	Objects []objInfo // URI 순 (writeOutputs 가 정렬)
	VRPSrc  map[vrpKey][]vrpSource
	ASPAs   map[aspaKey]*aspaOut
	RKeys   []routerKeyOut
	Unsafe  []unsafeVRP
	Repos   []repoStatus
}

// newQueryView : writeOutputs 뒤에 부름 (objects 가 URI 순이어야 함)
func newQueryView(v *validator, ps *payloadSet, repos []repoStatus) *queryView {
	return &queryView{
		Built:   v.Now,
		Objects: v.objects,
		VRPSrc:  v.vrpSrc,
		ASPAs:   v.aspas,
		RKeys:   v.rkeys,
		Unsafe:  computeUnsafe(ps.Full, v.unsafe),
		Repos:   repos,
	}
}

// object : URI 로 객체 하나 (같은 URI 가 여럿이면 valid 우선)
func (q *queryView) object(uri string) *objInfo {
	i := sort.Search(len(q.Objects), func(i int) bool { return q.Objects[i].URI >= uri })
	var found *objInfo
	for ; i < len(q.Objects) && q.Objects[i].URI == uri; i++ {
		if found == nil || q.Objects[i].Status == "valid" {
			found = &q.Objects[i]
		}
	}
	return found
}

// objASNs : 객체가 말하는 AS (ROA = asn, ASPA = customer, 라우터 인증서 = asns)
func objASNs(o *objInfo) []uint32 {
	m, ok := o.Summary.(map[string]any)
	if !ok {
		return nil
	}
	switch o.Type {
	case "roa":
		if a, ok := m["asn"].(uint32); ok {
			return []uint32{a}
		}
	case "asa":
		if a, ok := m["customer"].(uint32); ok {
			return []uint32{a}
		}
	case "cer":
		if a, ok := m["asns"].([]uint32); ok {
			return a
		}
	}
	return nil
}

// objOverlaps : 객체가 prefix p 와 겹치는지 (ROA 의 prefix, CA 의 IP 자원)
func objOverlaps(o *objInfo, p netip.Prefix) bool {
	m, ok := o.Summary.(map[string]any)
	if !ok {
		return false
	}
	switch o.Type {
	case "roa":
		ps, _ := m["prefixes"].([]roaPrefixOut)
		for _, x := range ps {
			if x.Prefix.Overlaps(p) {
				return true
			}
		}
	case "cer":
		r, _ := m["resources"].(*resSummary)
		if r == nil {
			return false
		}
		rs := r.v6
		if p.Addr().Is4() {
			rs = r.v4
		}
		return rangesOverlap(rs, prefixRange(p))
	}
	return false
}

// objFilter : /api/v1/objects, /api/v1/expiring 조건
type objFilter struct {
	Type, TA, Status, URIPrefix string
	Kind                        string // 인증서 종류 summary.kind (TA / CA / router), 11-02
	ASN                         *uint32
	Prefix                      *netip.Prefix
	ExpireBefore                time.Time // 0 이 아니면 notAfter 가 이 앞인 것만
}

func (f *objFilter) match(o *objInfo) bool {
	if f.Type != "" && o.Type != f.Type {
		return false
	}
	if f.TA != "" && o.TA != f.TA {
		return false
	}
	if f.Kind != "" {
		m, _ := o.Summary.(map[string]any)
		if k, _ := m["kind"].(string); k != f.Kind {
			return false
		}
	}
	if f.Status != "" && o.Status != f.Status {
		return false
	}
	if f.URIPrefix != "" && !strings.HasPrefix(o.URI, f.URIPrefix) {
		return false
	}
	if !f.ExpireBefore.IsZero() && (o.NotAfter.IsZero() || !o.NotAfter.Before(f.ExpireBefore)) {
		return false
	}
	if f.ASN != nil {
		found := false
		for _, a := range objASNs(o) {
			if a == *f.ASN {
				found = true
			}
		}
		if !found {
			return false
		}
	}
	if f.Prefix != nil && !objOverlaps(o, *f.Prefix) {
		return false
	}
	return true
}

// repoOf : CA 의 저장소 결과 (RRDP notify 가 있으면 그것, 없으면 rsync 모듈)
func (q *queryView) repoOf(notify, repository string) string {
	want := notify
	if want == "" {
		want = rsyncModule(repository)
	}
	for _, r := range q.Repos {
		if r.URI == want {
			return r.Result
		}
	}
	return ""
}
