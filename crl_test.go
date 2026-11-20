// SPDX-License-Identifier: Apache-2.0

package main

// crl_test.go : CRL Number 검사 (RFC 9829 3.1 : non-critical, 0 ~ 2^159-1).
// parseCRL 은 서명을 보지 않으므로 (서명은 validate.go) 서명 칸은 0 으로 채운 CRL 을 asn1 로 직접 만듦

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"testing"
	"time"
)

// makeCRLDER : AKI + CRL Number 두 확장만 있는 CRL (num / critical = CRL Number 값과 critical 표시)
func makeCRLDER(t *testing.T, num *big.Int, critical bool) []byte {
	t.Helper()
	numDER, err := asn1.Marshal(num)
	if err != nil {
		t.Fatal(err)
	}
	aki, _ := asn1.Marshal(struct {
		ID []byte `asn1:"optional,tag:0"`
	}{make([]byte, 20)})
	alg := pkix.AlgorithmIdentifier{Algorithm: asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 11}, Parameters: asn1.NullRawValue}
	now := time.Now().UTC().Truncate(time.Second)
	tbs := pkix.TBSCertificateList{
		Version: 1, Signature: alg, Issuer: pkix.Name{CommonName: "test-ca"}.ToRDNSequence(),
		ThisUpdate: now.Add(-time.Hour), NextUpdate: now.Add(time.Hour),
		Extensions: []pkix.Extension{
			{Id: oidExtAKI, Value: aki},
			{Id: oidExtCRLNumber, Critical: critical, Value: numDER},
		},
	}
	der, err := asn1.Marshal(pkix.CertificateList{TBSCertList: tbs, SignatureAlgorithm: alg,
		SignatureValue: asn1.BitString{Bytes: make([]byte, 256), BitLength: 2048}})
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func TestCRLNumber(t *testing.T) {
	max := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 159), big.NewInt(1)) // 2^159-1
	cases := []struct {
		name     string
		num      *big.Int
		critical bool
		ok       bool
	}{
		{"0", big.NewInt(0), false, true},
		{"2^159-1", max, false, true},
		{"2^159", new(big.Int).Add(max, big.NewInt(1)), false, false},
		{"negative", big.NewInt(-1), false, false},
		{"critical", big.NewInt(5), true, false},
	}
	for _, tc := range cases {
		_, err := parseCRL(makeCRLDER(t, tc.num, tc.critical))
		if (err == nil) != tc.ok {
			t.Errorf("%s: err %v", tc.name, err)
		}
	}
}
