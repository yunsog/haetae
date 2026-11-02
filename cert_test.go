package main

// cert_test.go : SKI = SHA-1(공개 키) 검사 (RFC 6487 4.8.2, 지금은 경고만)

import (
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"
)

func TestSKIMatchesKey(t *testing.T) {
	ca, _ := testCA(t, nil)
	if !skiMatchesKey(ca.X509) {
		t.Errorf("good SKI not accepted")
	}

	// 같은 키, SKI 만 다른 값
	k := testKey(t, "ca")
	bad := ski(k)
	bad[0] ^= 0xff
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(3), Subject: pkix.Name{CommonName: "bad-ski"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		BasicConstraintsValid: true, IsCA: true, SubjectKeyId: bad,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	x, _ := x509.ParseCertificate(der)
	if skiMatchesKey(x) {
		t.Errorf("bad SKI accepted")
	}
}
