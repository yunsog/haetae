package main

// aspa.go : ASPA (AS Provider Authorization, draft-ietf-sidrops-aspa-profile)
//
// "고객 AS 의 상위 (provider) AS 는 이것들뿐" 이라는 서명 객체 (.asa).
// 라우터는 AS_PATH 의 각 고객 -> provider 관계를 이것으로 확인 (route leak 검출).
//   ASProviderAttestation ::= SEQUENCE {
//     version [0] EXPLICIT INTEGER (1),   (DEFAULT 아님 -> 반드시 있음)
//     customerASID INTEGER,
//     providers SEQUENCE (1..MAX) OF INTEGER }   (오름차순, 중복 없음, customer 제외)
// EE 인증서 : AS 자원만 (IP 없음, inherit 없음), customerASID 를 포함해야 함.

import (
	"encoding/asn1"
	"fmt"
)

var oidCTASPA = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 1, 49}

// provider 수 상한 (rpki-client 와 같은 크기 정도, 실제로는 수십 개 이하)
const maxASPAProviders = 10000

type rpkiASPA struct {
	*signedObject
	Customer  uint32
	Providers []uint32 // 오름차순
}

func parseASPA(der []byte) (*rpkiASPA, error) {
	so, err := parseSignedObject(der, oidCTASPA)
	if err != nil {
		return nil, err
	}
	a := &rpkiASPA{signedObject: so}

	top, err := derOne(so.Content)
	if err != nil {
		return nil, err
	}
	f, err := derSeq(top, 3, 3)
	if err != nil {
		return nil, fmt.Errorf("ASPA: %w", err)
	}
	ver, err := explicit(f[0], 0)
	if err != nil {
		return nil, fmt.Errorf("ASPA version: %w", err)
	}
	if v, err := derUint(ver, 10); err != nil || v != 1 {
		return nil, fmt.Errorf("ASPA version not 1")
	}
	cust, err := derUint(f[1], 0xffffffff)
	if err != nil {
		return nil, fmt.Errorf("ASPA customerASID: %w", err)
	}
	a.Customer = uint32(cust)

	provs, err := derSeq(f[2], 1, maxASPAProviders)
	if err != nil {
		return nil, fmt.Errorf("ASPA providers: %w", err)
	}
	for i, p := range provs {
		v, err := derUint(p, 0xffffffff)
		if err != nil {
			return nil, fmt.Errorf("ASPA provider: %w", err)
		}
		pv := uint32(v)
		if pv == a.Customer {
			return nil, fmt.Errorf("ASPA provider == customer AS%d", pv)
		}
		if i > 0 && pv <= a.Providers[i-1] {
			return nil, fmt.Errorf("ASPA providers not ascending / duplicate")
		}
		a.Providers = append(a.Providers, pv)
	}

	// EE : AS 자원만, inherit 아님, customer 포함
	ee := so.EE
	if ee.IPs.V4.Present || ee.IPs.V6.Present {
		return nil, fmt.Errorf("ASPA EE with IP resources")
	}
	if !ee.ASs.Present || ee.ASs.Inherit {
		return nil, fmt.Errorf("ASPA EE without AS resources or inherit")
	}
	if !asCovered(ee.ASs.Ranges, asRange{a.Customer, a.Customer}) {
		return nil, fmt.Errorf("ASPA customer AS%d not in EE resources", a.Customer)
	}
	return a, nil
}
