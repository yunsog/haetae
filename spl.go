package main

// spl.go : Signed Prefix List (draft-ietf-sidrops-rpki-prefixlist, rpki-client 9 지원)
//
// "이 AS 가 BGP 로 내보낼 수 있는 prefix 전체 목록" (.spl). ROA 와 달리 maxLength 없음.
//   SignedPrefixList ::= SEQUENCE {
//     version [0] INTEGER DEFAULT 0,
//     asID INTEGER,
//     prefixBlocks SEQUENCE OF AddressFamilyPrefixes }
//   AddressFamilyPrefixes ::= SEQUENCE { addressFamily OCTET STRING (2), addressPrefixes SEQUENCE OF BIT STRING }
// 주소 체계는 IPv4, IPv6 순, prefix 는 정렬 / 중복 없음 (draft 규칙). 빈 목록 = "아무것도 안 내보냄" 도 허용.

import (
	"bytes"
	"encoding/asn1"
	"fmt"
	"net/netip"
)

var oidCTSPL = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 1, 51}

const maxSPLPrefixes = 100000

type rpkiSPL struct {
	*signedObject
	ASN      uint32
	Prefixes []netip.Prefix
}

func parseSPL(der []byte) (*rpkiSPL, error) {
	so, err := parseSignedObject(der, oidCTSPL)
	if err != nil {
		return nil, err
	}
	s := &rpkiSPL{signedObject: so}
	// EE : AS 자원만, asID 포함
	ee := so.EE
	if ee.IPs.V4.Present || ee.IPs.V6.Present {
		return nil, fmt.Errorf("SPL EE with IP resources")
	}

	top, err := derOne(so.Content)
	if err != nil {
		return nil, err
	}
	f, err := derSeq(top, 2, 3)
	if err != nil {
		return nil, fmt.Errorf("SPL: %w", err)
	}
	if len(f) == 3 {
		return nil, fmt.Errorf("SPL version present (only v0)")
	}
	asn, err := derUint(f[0], 0xffffffff)
	if err != nil {
		return nil, fmt.Errorf("SPL asID: %w", err)
	}
	s.ASN = uint32(asn)
	if !ee.ASs.Present || ee.ASs.Inherit || !asCovered(ee.ASs.Ranges, asRange{s.ASN, s.ASN}) {
		return nil, fmt.Errorf("SPL asID AS%d not in EE resources", s.ASN)
	}

	fams, err := derSeq(f[1], 0, 2)
	if err != nil {
		return nil, fmt.Errorf("SPL prefixBlocks: %w", err)
	}
	lastAFI := 0
	for _, fam := range fams {
		p, err := derSeq(fam, 2, 2)
		if err != nil {
			return nil, fmt.Errorf("AddressFamilyPrefixes: %w", err)
		}
		afiB, err := derOctets(p[0])
		if err != nil || len(afiB) != 2 {
			return nil, fmt.Errorf("SPL addressFamily not 2 bytes")
		}
		afi := int(afiB[0])<<8 | int(afiB[1])
		if (afi != afiIPv4 && afi != afiIPv6) || afi <= lastAFI {
			return nil, fmt.Errorf("SPL AFI %d bad or out of order", afi)
		}
		lastAFI = afi

		pfx, err := derSeq(p[1], 1, maxSPLPrefixes)
		if err != nil {
			return nil, fmt.Errorf("SPL addressPrefixes: %w", err)
		}
		var prevA [16]byte
		prevLen := -1
		for _, n := range pfx {
			b, unused, err := derBits(n)
			if err != nil {
				return nil, err
			}
			a, plen, err := bitsToAddr(b, unused, afi, false)
			if err != nil {
				return nil, err
			}
			// 정렬 (주소, 그다음 prefix 길이) / 중복 확인
			if prevLen >= 0 {
				c := bytes.Compare(a[:], prevA[:])
				if c < 0 || c == 0 && plen <= prevLen {
					return nil, fmt.Errorf("SPL prefixes not sorted / duplicate")
				}
			}
			prevA, prevLen = a, plen
			var addr netip.Addr
			if afi == afiIPv4 {
				addr = netip.AddrFrom4([4]byte(a[:4]))
			} else {
				addr = netip.AddrFrom16(a)
			}
			s.Prefixes = append(s.Prefixes, netip.PrefixFrom(addr, plen))
		}
		if len(s.Prefixes) > maxSPLPrefixes {
			return nil, fmt.Errorf("too many SPL prefixes")
		}
	}
	return s, nil
}
