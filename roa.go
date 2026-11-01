package main

// roa.go : ROA (RFC 9582) -> VRP
//
//   RouteOriginAttestation ::= SEQUENCE {
//     version [0] INTEGER DEFAULT 0,
//     asID INTEGER,
//     ipAddrBlocks SEQUENCE (1..2) OF ROAIPAddressFamily }
//   ROAIPAddressFamily ::= SEQUENCE { addressFamily OCTET STRING (2), addresses SEQUENCE OF ROAIPAddress }
//   ROAIPAddress ::= SEQUENCE { address BIT STRING, maxLength INTEGER OPTIONAL }
// prefix 가 EE 자원 안에 있는지는 EE 가 inherit 일 수 있어 validate.go (2 단계) 에서.

import (
	"fmt"
	"net/netip"
)

// ROA 하나의 prefix 수 상한
const maxROAPrefixes = 100000

// vrp : 검증된 ROA payload 하나 (TA 는 검증 단계에서 붙임)
type vrp struct {
	ASN       uint32
	Prefix    netip.Prefix
	MaxLength int
}

type rpkiROA struct {
	*signedObject
	ASN  uint32
	VRPs []vrp
}

func parseROA(der []byte) (*rpkiROA, error) {
	so, err := parseSignedObject(der, oidCTROA)
	if err != nil {
		return nil, err
	}
	r := &rpkiROA{signedObject: so}

	top, err := derOne(so.Content)
	if err != nil {
		return nil, err
	}
	f, err := derSeq(top, 2, 3)
	if err != nil {
		return nil, fmt.Errorf("ROA: %w", err)
	}
	if len(f) == 3 {
		return nil, fmt.Errorf("ROA version present (only v0)")
	}
	asn, err := derUint(f[0], 0xffffffff)
	if err != nil {
		return nil, fmt.Errorf("ROA asID: %w", err)
	}
	r.ASN = uint32(asn)

	fams, err := derSeq(f[1], 1, 2)
	if err != nil {
		return nil, fmt.Errorf("ROA ipAddrBlocks: %w", err)
	}
	seenAFI := map[int]bool{}
	for _, fam := range fams {
		p, err := derSeq(fam, 2, 2)
		if err != nil {
			return nil, fmt.Errorf("ROAIPAddressFamily: %w", err)
		}
		afiB, err := derOctets(p[0])
		if err != nil || len(afiB) != 2 {
			return nil, fmt.Errorf("ROA addressFamily not 2 bytes")
		}
		afi := int(afiB[0])<<8 | int(afiB[1])
		if afi != afiIPv4 && afi != afiIPv6 {
			return nil, fmt.Errorf("ROA unknown AFI %d", afi)
		}
		if seenAFI[afi] {
			return nil, fmt.Errorf("ROA duplicate AFI %d", afi)
		}
		seenAFI[afi] = true

		addrs, err := derSeq(p[1], 1, maxROAPrefixes)
		if err != nil {
			return nil, fmt.Errorf("ROA addresses: %w", err)
		}
		for _, a := range addrs {
			v, err := parseROAAddress(a, afi)
			if err != nil {
				return nil, err
			}
			v.ASN = r.ASN
			r.VRPs = append(r.VRPs, v)
		}
		if len(r.VRPs) > maxROAPrefixes {
			return nil, fmt.Errorf("too many ROA prefixes")
		}
	}
	return r, nil
}

// parseROAAddress : ROAIPAddress { address BIT STRING, maxLength OPTIONAL }
func parseROAAddress(n derNode, afi int) (vrp, error) {
	var v vrp
	p, err := derSeq(n, 1, 2)
	if err != nil {
		return v, fmt.Errorf("ROAIPAddress: %w", err)
	}
	b, unused, err := derBits(p[0])
	if err != nil {
		return v, err
	}
	a, plen, err := bitsToAddr(b, unused, afi, false)
	if err != nil {
		return v, err
	}
	var addr netip.Addr
	if afi == afiIPv4 {
		addr = netip.AddrFrom4([4]byte(a[:4]))
	} else {
		addr = netip.AddrFrom16(a)
	}
	v.Prefix = netip.PrefixFrom(addr, plen)
	maxBits := afiLen(afi) * 8
	v.MaxLength = plen
	if len(p) == 2 {
		ml, err := derUint(p[1], uint64(maxBits))
		if err != nil {
			return v, fmt.Errorf("ROA maxLength: %w", err)
		}
		if int(ml) < plen {
			return v, fmt.Errorf("ROA maxLength %d < prefix length %d", ml, plen)
		}
		v.MaxLength = int(ml)
	}
	return v, nil
}
