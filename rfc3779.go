package main

// rfc3779.go : RFC 3779 IP / AS 자원 확장
//
// 인증서마다 "이 키가 서명할 수 있는 주소 / AS 번호" 가 들어 있음.
//   IP : sbgp-ipAddrBlock (1.3.6.1.5.5.7.1.7)
//   AS : sbgp-autonomousSysNum (1.3.6.1.5.5.7.1.8)
// 값은 "inherit" (부모 것 그대로) 또는 범위 목록.
// 내부 표현은 모두 [min, max] 범위 (IPv4 도 16 바이트 배열 앞 4 바이트만 씀).

import (
	"bytes"
	"fmt"
	"net/netip"
	"sort"
)

const (
	afiIPv4 = 1
	afiIPv6 = 2
)

// ipRange : 한 주소 체계 안의 [Min, Max] (양 끝 포함)
type ipRange struct {
	Min, Max [16]byte
}

// ipFamily : 주소 체계 하나 (IPv4 또는 IPv6)
type ipFamily struct {
	Present bool      // 확장에 이 체계가 있음
	Inherit bool      // inherit (부모 것)
	Ranges  []ipRange // Min 순으로 정렬, 겹침 없음
}

// ipResources : IPv4 + IPv6
type ipResources struct {
	V4, V6 ipFamily
}

// asRange : AS 번호 [Min, Max]
type asRange struct {
	Min, Max uint32
}

// asResources : AS 번호 자원 (rdi 는 RPKI 에서 금지)
type asResources struct {
	Present bool
	Inherit bool
	Ranges  []asRange
}

// afiLen : 주소 체계의 바이트 수
func afiLen(afi int) int {
	if afi == afiIPv4 {
		return 4
	}
	return 16
}

// bitsToAddr : BIT STRING 주소 -> 16 바이트 주소. fill = 남는 비트를 0 (min) 또는 1 (max) 로 채움
func bitsToAddr(b []byte, unused, afi int, fill bool) ([16]byte, int, error) {
	var a [16]byte
	alen := afiLen(afi)
	if len(b) > alen {
		return a, 0, fmt.Errorf("address too long (%d bytes, afi %d)", len(b), afi)
	}
	copy(a[:], b)
	plen := len(b)*8 - unused
	if fill {
		// plen 비트 뒤를 모두 1 로 (주소 길이까지만)
		for i := plen; i < alen*8; i++ {
			a[i/8] |= 0x80 >> (i % 8)
		}
	}
	return a, plen, nil
}

// parseIPAddrBlocks : sbgp-ipAddrBlock 확장 값 (extnValue OCTET STRING 의 내용)
func parseIPAddrBlocks(der []byte) (ipResources, error) {
	var res ipResources
	top, err := derOne(der)
	if err != nil {
		return res, err
	}
	fams, err := derSeq(top, 1, 2)
	if err != nil {
		return res, fmt.Errorf("IPAddrBlocks: %w", err)
	}
	for _, f := range fams {
		fc, err := derSeq(f, 2, 2)
		if err != nil {
			return res, fmt.Errorf("IPAddressFamily: %w", err)
		}
		afiB, err := derOctets(fc[0])
		if err != nil {
			return res, err
		}
		// RFC 6487 4.8.10 : SAFI 는 쓰지 않음 -> AFI 2 바이트만
		if len(afiB) != 2 {
			return res, fmt.Errorf("addressFamily length %d (SAFI not allowed)", len(afiB))
		}
		afi := int(afiB[0])<<8 | int(afiB[1])
		var fam *ipFamily
		switch afi {
		case afiIPv4:
			fam = &res.V4
		case afiIPv6:
			fam = &res.V6
		default:
			return res, fmt.Errorf("unknown AFI %d", afi)
		}
		if fam.Present {
			return res, fmt.Errorf("duplicate AFI %d", afi)
		}
		fam.Present = true

		ch := fc[1]
		if ch.is(tagNull) {
			if len(ch.Body) != 0 {
				return res, fmt.Errorf("bad NULL")
			}
			fam.Inherit = true
			continue
		}
		items, err := derSeq(ch, 1, 1<<20)
		if err != nil {
			return res, fmt.Errorf("addressesOrRanges: %w", err)
		}
		for _, it := range items {
			r, err := parseIPAddressOrRange(it, afi)
			if err != nil {
				return res, err
			}
			fam.Ranges = append(fam.Ranges, r)
		}
		if err := sortCheckIP(fam.Ranges); err != nil {
			return res, fmt.Errorf("afi %d: %w", afi, err)
		}
	}
	return res, nil
}

// parseIPAddressOrRange : addressPrefix BIT STRING 또는 addressRange SEQUENCE { min, max }
func parseIPAddressOrRange(n derNode, afi int) (ipRange, error) {
	var r ipRange
	if n.is(tagBitString) {
		b, unused, err := derBits(n)
		if err != nil {
			return r, err
		}
		if r.Min, _, err = bitsToAddr(b, unused, afi, false); err != nil {
			return r, err
		}
		r.Max, _, err = bitsToAddr(b, unused, afi, true)
		return r, err
	}
	mm, err := derSeq(n, 2, 2)
	if err != nil {
		return r, fmt.Errorf("IPAddressRange: %w", err)
	}
	b, unused, err := derBits(mm[0])
	if err != nil {
		return r, err
	}
	if r.Min, _, err = bitsToAddr(b, unused, afi, false); err != nil {
		return r, err
	}
	if b, unused, err = derBits(mm[1]); err != nil {
		return r, err
	}
	if r.Max, _, err = bitsToAddr(b, unused, afi, true); err != nil {
		return r, err
	}
	if bytes.Compare(r.Min[:], r.Max[:]) > 0 {
		return r, fmt.Errorf("range min > max")
	}
	return r, nil
}

// sortCheckIP : Min 순 정렬 후 겹침 거부 (rpki-client 와 같이 겹침만 오류)
func sortCheckIP(rs []ipRange) error {
	sort.Slice(rs, func(i, j int) bool { return bytes.Compare(rs[i].Min[:], rs[j].Min[:]) < 0 })
	for i := 1; i < len(rs); i++ {
		if bytes.Compare(rs[i].Min[:], rs[i-1].Max[:]) <= 0 {
			return fmt.Errorf("overlapping ranges")
		}
	}
	return nil
}

// parseASIdentifiers : sbgp-autonomousSysNum 확장 값
//
//	SEQUENCE { asnum [0] EXPLICIT choice OPTIONAL, rdi [1] EXPLICIT choice OPTIONAL }
func parseASIdentifiers(der []byte) (asResources, error) {
	var res asResources
	top, err := derOne(der)
	if err != nil {
		return res, err
	}
	parts, err := derSeq(top, 1, 2)
	if err != nil {
		return res, fmt.Errorf("ASIdentifiers: %w", err)
	}
	if len(parts) != 1 || !parts[0].isCtx(0) || !parts[0].Constructed {
		// RFC 6487 4.8.11 : rdi 금지, asnum 만
		return res, fmt.Errorf("ASIdentifiers: want asnum [0] only")
	}
	inner, err := derChildren(parts[0])
	if err != nil || len(inner) != 1 {
		return res, fmt.Errorf("asnum: bad EXPLICIT")
	}
	res.Present = true
	ch := inner[0]
	if ch.is(tagNull) {
		if len(ch.Body) != 0 {
			return res, fmt.Errorf("bad NULL")
		}
		res.Inherit = true
		return res, nil
	}
	items, err := derSeq(ch, 1, 1<<20)
	if err != nil {
		return res, fmt.Errorf("asIdsOrRanges: %w", err)
	}
	for _, it := range items {
		var r asRange
		if it.is(tagInteger) {
			v, err := derUint(it, 0xffffffff)
			if err != nil {
				return res, err
			}
			r.Min, r.Max = uint32(v), uint32(v)
		} else {
			mm, err := derSeq(it, 2, 2)
			if err != nil {
				return res, fmt.Errorf("ASRange: %w", err)
			}
			lo, err := derUint(mm[0], 0xffffffff)
			if err != nil {
				return res, err
			}
			hi, err := derUint(mm[1], 0xffffffff)
			if err != nil {
				return res, err
			}
			if lo > hi {
				return res, fmt.Errorf("AS range min > max")
			}
			r.Min, r.Max = uint32(lo), uint32(hi)
		}
		res.Ranges = append(res.Ranges, r)
	}
	sort.Slice(res.Ranges, func(i, j int) bool { return res.Ranges[i].Min < res.Ranges[j].Min })
	for i := 1; i < len(res.Ranges); i++ {
		if res.Ranges[i].Min <= res.Ranges[i-1].Max {
			return res, fmt.Errorf("overlapping AS ranges")
		}
	}
	return res, nil
}

// ---- 포함 관계 (2 단계 검증에서 씀) ----

// ipCovered : r 이 rs (정렬, 겹침 없음) 중 하나에 완전히 들어가는지
func ipCovered(rs []ipRange, r ipRange) bool {
	// Min 이 r.Min 이하인 마지막 범위를 찾음
	i := sort.Search(len(rs), func(i int) bool { return bytes.Compare(rs[i].Min[:], r.Min[:]) > 0 })
	if i == 0 {
		return false
	}
	return bytes.Compare(rs[i-1].Max[:], r.Max[:]) >= 0
}

// asCovered : r 이 rs 중 하나에 완전히 들어가는지
func asCovered(rs []asRange, r asRange) bool {
	i := sort.Search(len(rs), func(i int) bool { return rs[i].Min > r.Min })
	if i == 0 {
		return false
	}
	return rs[i-1].Max >= r.Max
}

// prefixRange : netip.Prefix -> ipRange (ROA 의 prefix 가 EE 자원 안에 있는지 볼 때)
func prefixRange(p netip.Prefix) ipRange {
	var r ipRange
	a := p.Addr().AsSlice()
	copy(r.Min[:], a)
	copy(r.Max[:], a)
	for i := p.Bits(); i < len(a)*8; i++ {
		r.Min[i/8] &^= 0x80 >> (i % 8)
		r.Max[i/8] |= 0x80 >> (i % 8)
	}
	return r
}
