package main

// slurm.go : SLURM (RFC 8416) 로컬 예외 (결정 D2)
//
// 운용자가 검증 결과를 직접 고치는 JSON 파일
//   validationOutputFilters : 빼기  (prefixFilters / bgpsecFilters / aspaFilters)
//   locallyAddedAssertions  : 더하기 (prefixAssertions / bgpsecAssertions / aspaAssertions)
// aspa* 는 draft-ietf-sidrops-aspa-slurm (없어도 됨).
// 파일이 없으면 (nil) 아무것도 안 함.

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"time"
)

type slurmPrefixFilter struct {
	Prefix  string  `json:"prefix,omitempty"`
	ASN     *uint32 `json:"asn,omitempty"`
	Comment string  `json:"comment,omitempty"`

	pfx netip.Prefix
}

type slurmBGPsecFilter struct {
	ASN     *uint32 `json:"asn,omitempty"`
	SKI     string  `json:"SKI,omitempty"` // RFC 8416 : base64url (padding 없음)
	Comment string  `json:"comment,omitempty"`

	ski []byte
}

type slurmASPAFilter struct {
	Customer uint32 `json:"customer_asid"`
	Comment  string `json:"comment,omitempty"`
}

type slurmPrefixAssertion struct {
	ASN       uint32 `json:"asn"`
	Prefix    string `json:"prefix"`
	MaxLength int    `json:"maxPrefixLength,omitempty"`
	Comment   string `json:"comment,omitempty"`
}

type slurmBGPsecAssertion struct {
	ASN     uint32 `json:"asn"`
	SKI     string `json:"SKI"`
	Key     string `json:"routerPublicKey"`
	Comment string `json:"comment,omitempty"`
}

type slurmASPAAssertion struct {
	Customer  uint32   `json:"customer_asid"`
	Providers []uint32 `json:"provider_set"`
	Comment   string   `json:"comment,omitempty"`
}

type slurmFile struct {
	Version int `json:"slurmVersion"`
	Filters struct {
		Prefix []slurmPrefixFilter `json:"prefixFilters"`
		BGPsec []slurmBGPsecFilter `json:"bgpsecFilters"`
		ASPA   []slurmASPAFilter   `json:"aspaFilters,omitempty"`
	} `json:"validationOutputFilters"`
	Asserts struct {
		Prefix []slurmPrefixAssertion `json:"prefixAssertions"`
		BGPsec []slurmBGPsecAssertion `json:"bgpsecAssertions"`
		ASPA   []slurmASPAAssertion   `json:"aspaAssertions,omitempty"`
	} `json:"locallyAddedAssertions"`
}

// b64url : RFC 8416 의 SKI / 공개키 = base64url, padding 없음 (있어도 받음)
func b64url(s string) ([]byte, error) {
	if b, err := base64.RawURLEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	return base64.URLEncoding.DecodeString(s)
}

func loadSLURM(path string) (*slurmFile, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var s slurmFile
	if err := json.Unmarshal(b, &s); err != nil {
		return nil, fmt.Errorf("SLURM JSON: %w", err)
	}
	if s.Version != 1 {
		return nil, fmt.Errorf("SLURM version %d", s.Version)
	}
	for i := range s.Filters.Prefix {
		f := &s.Filters.Prefix[i]
		if f.Prefix == "" && f.ASN == nil {
			return nil, fmt.Errorf("prefixFilter without prefix and asn")
		}
		if f.Prefix != "" {
			if f.pfx, err = netip.ParsePrefix(f.Prefix); err != nil || f.pfx != f.pfx.Masked() {
				return nil, fmt.Errorf("prefixFilter bad prefix %q", f.Prefix)
			}
		}
	}
	for i := range s.Filters.BGPsec {
		f := &s.Filters.BGPsec[i]
		if f.SKI == "" && f.ASN == nil {
			return nil, fmt.Errorf("bgpsecFilter without SKI and asn")
		}
		if f.SKI != "" {
			if f.ski, err = b64url(f.SKI); err != nil || len(f.ski) != 20 {
				return nil, fmt.Errorf("bgpsecFilter bad SKI %q", f.SKI)
			}
		}
	}
	for _, a := range s.Asserts.Prefix {
		p, err := netip.ParsePrefix(a.Prefix)
		if err != nil || p != p.Masked() {
			return nil, fmt.Errorf("prefixAssertion bad prefix %q", a.Prefix)
		}
		if a.MaxLength != 0 && (a.MaxLength < p.Bits() || a.MaxLength > p.Addr().BitLen()) {
			return nil, fmt.Errorf("prefixAssertion bad maxPrefixLength %d", a.MaxLength)
		}
	}
	for _, a := range s.Asserts.BGPsec {
		if ski, err := b64url(a.SKI); err != nil || len(ski) != 20 {
			return nil, fmt.Errorf("bgpsecAssertion bad SKI")
		}
		if _, err := b64url(a.Key); err != nil {
			return nil, fmt.Errorf("bgpsecAssertion bad routerPublicKey")
		}
	}
	return &s, nil
}

// filterVRP : true = 이 VRP 를 뺌. 필터의 prefix 는 VRP prefix 를 포함하면 (같거나 더 넓으면) 해당
func (s *slurmFile) filterVRP(asn uint32, p netip.Prefix) bool {
	if s == nil {
		return false
	}
	for _, f := range s.Filters.Prefix {
		if f.ASN != nil && *f.ASN != asn {
			continue
		}
		if f.Prefix != "" && !(f.pfx.Addr().BitLen() == p.Addr().BitLen() && f.pfx.Bits() <= p.Bits() && f.pfx.Contains(p.Addr())) {
			continue
		}
		return true
	}
	return false
}

func (s *slurmFile) filterKey(asn uint32, ski []byte) bool {
	if s == nil {
		return false
	}
	for _, f := range s.Filters.BGPsec {
		if f.ASN != nil && *f.ASN != asn {
			continue
		}
		if f.ski != nil && hex.EncodeToString(f.ski) != hex.EncodeToString(ski) {
			continue
		}
		return true
	}
	return false
}

func (s *slurmFile) filterASPA(customer uint32) bool {
	if s == nil {
		return false
	}
	for _, f := range s.Filters.ASPA {
		if f.Customer == customer {
			return true
		}
	}
	return false
}

// addAssertions : 로컬 추가분을 payloadSet 에 더함 (TA 이름 = "slurm")
func (s *slurmFile) addAssertions(p *payloadSet) {
	if s == nil {
		return
	}
	for _, a := range s.Asserts.Prefix {
		pf, _ := netip.ParsePrefix(a.Prefix)
		ml := a.MaxLength
		if ml == 0 {
			ml = pf.Bits()
		}
		k := vrpKey{a.ASN, pf, ml, "slurm"}
		if _, ok := p.FullExp[k]; !ok {
			p.Full = append(p.Full, k)
		}
		p.FullExp[k] = p.Built.Add(24 * time.Hour)
		p.VRPs[rtrVRP{pf, uint8(ml), a.ASN}] = true
	}
	for _, a := range s.Asserts.BGPsec {
		ski, _ := b64url(a.SKI)
		key, _ := b64url(a.Key)
		var k rtrKey
		copy(k.SKI[:], ski)
		k.ASN, k.SPKI = a.ASN, string(key)
		p.Keys[k] = true
	}
	for _, a := range s.Asserts.ASPA {
		m := map[uint32]bool{}
		for _, x := range p.ASPAs[a.Customer] {
			m[x] = true
		}
		for _, x := range a.Providers {
			if x != a.Customer {
				m[x] = true
			}
		}
		p.ASPAs[a.Customer] = sortedASNs(m)
	}
}
