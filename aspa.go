// SPDX-License-Identifier: Apache-2.0

package main

// aspa.go : ASPA (AS Provider Authorization, draft-ietf-sidrops-aspa-profile-31, 11-18 대조)
//
// "고객 AS 의 상위 (provider) AS 는 이것들뿐" 이라는 서명 객체 (.asa).
// 라우터는 AS_PATH 의 각 고객 -> provider 관계를 이것으로 확인 (route leak 검출).
//   ASProviderAttestation ::= SEQUENCE {
//     version [0] EXPLICIT INTEGER (1),   (ASN.1 은 DEFAULT 0 이지만 3.1 장 = 1 을 반드시 적음)
//     customerASID INTEGER (1..4294967295),
//     providers SEQUENCE (1..MAX) OF INTEGER }   (오름차순, 중복 없음, customer 제외, AS0 은 혼자일 때만 = 3.3 장)
// EE 인증서 : AS 자원 = customerASID 하나의 "id" (range / inherit 없음), IP 자원 없음 (4 장).
// 고객 AS 마다 합친 provider 가 maxASPAProviders 를 넘으면 그 고객 AS 의 ASPA 전부 무효 (5 장, vrp.go newPayloadSet)

import (
	"encoding/asn1"
	"fmt"
)

var oidCTASPA = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 1, 49}

// provider 수 상한 : 객체 하나, 그리고 고객 AS 마다 합친 수 (draft 5 장 권고 4,000 ~ 10,000 의 위 끝, 실제로는 수십 개 이하)
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
	if cust == 0 {
		return nil, fmt.Errorf("ASPA customerASID 0")
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
	// AS0 은 혼자일 때만 (오름차순이라 있으면 맨 앞)
	if a.Providers[0] == 0 && len(a.Providers) > 1 {
		return nil, fmt.Errorf("ASPA AS0 with other providers")
	}

	// EE : AS 자원만, inherit 아님, customer 하나의 id (range 로 적은 것도 안 됨)
	ee := so.EE
	if ee.IPs.V4.Present || ee.IPs.V6.Present {
		return nil, fmt.Errorf("ASPA EE with IP resources")
	}
	if !ee.ASs.Present || ee.ASs.Inherit {
		return nil, fmt.Errorf("ASPA EE without AS resources or inherit")
	}
	if len(ee.ASs.Ranges) != 1 || ee.ASs.HasRange || ee.ASs.Ranges[0] != (asRange{a.Customer, a.Customer}) {
		return nil, fmt.Errorf("ASPA EE AS resources not exactly id AS%d", a.Customer)
	}
	return a, nil
}
