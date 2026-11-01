package main

// crl.go : CRL (RFC 6487 5)
//
// CA 마다 CRL 하나. 그 CA 가 낸 인증서 (자식 CA, EE) 중 폐기된 것의 serial 목록.
// 파싱은 x509.ParseRevocationList, 그 위에 RPKI 규칙을 검사.
// 서명 확인 (CA 키), thisUpdate / nextUpdate 시각 확인은 validate.go (2 단계).

import (
	"crypto/x509"
	"encoding/asn1"
	"fmt"
	"time"
)

var oidExtCRLNumber = asn1.ObjectIdentifier{2, 5, 29, 20}

// rpkiCRL : 검사를 통과한 CRL
type rpkiCRL struct {
	X509       *x509.RevocationList
	AKI        []byte
	ThisUpdate time.Time
	NextUpdate time.Time
	Revoked    map[string]bool // serial (10 진 문자열) -> 폐기됨
}

func parseCRL(der []byte) (*rpkiCRL, error) {
	if len(der) > maxObjectSize {
		return nil, fmt.Errorf("CRL too large")
	}
	if _, err := derOne(der); err != nil {
		return nil, err
	}
	rl, err := x509.ParseRevocationList(der)
	if err != nil {
		return nil, err
	}
	if rl.SignatureAlgorithm != x509.SHA256WithRSA {
		return nil, fmt.Errorf("CRL signature algorithm %v", rl.SignatureAlgorithm)
	}
	if len(rl.AuthorityKeyId) != 20 {
		return nil, fmt.Errorf("CRL AKI missing or not 20 bytes")
	}
	if rl.Number == nil {
		return nil, fmt.Errorf("CRL number missing")
	}
	if rl.NextUpdate.IsZero() {
		return nil, fmt.Errorf("CRL nextUpdate missing")
	}
	if !rl.NextUpdate.After(rl.ThisUpdate) {
		return nil, fmt.Errorf("CRL nextUpdate not after thisUpdate")
	}
	// 확장은 AKI 와 CRL number 만 (RFC 6487 5)
	for _, e := range rl.Extensions {
		if !e.Id.Equal(oidExtAKI) && !e.Id.Equal(oidExtCRLNumber) {
			return nil, fmt.Errorf("unexpected CRL extension %s", e.Id)
		}
	}

	c := &rpkiCRL{
		X509:       rl,
		AKI:        rl.AuthorityKeyId,
		ThisUpdate: rl.ThisUpdate,
		NextUpdate: rl.NextUpdate,
		Revoked:    make(map[string]bool, len(rl.RevokedCertificateEntries)),
	}
	for _, r := range rl.RevokedCertificateEntries {
		// RFC 6487 5 : CRL entry 확장 없음
		if len(r.Extensions) != 0 {
			return nil, fmt.Errorf("CRL entry with extensions")
		}
		c.Revoked[r.SerialNumber.String()] = true
	}
	return c, nil
}
