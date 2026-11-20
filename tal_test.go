// SPDX-License-Identifier: Apache-2.0

package main

// tal_test.go : 실행 파일 안의 TAL (저장소 tals/) 5 개, -tal 폴더 읽기,
// TA 인증서 고르기 (RFC 10097 : preferNewTA 규칙, fetchTA 가 캐시를 덮어쓰는지. 도우미 testKey / tlv / derOID / asIDs / ipBlocks 는 rsc_test.go)

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// tals/README.md 의 표와 같은 값 (공개키 SHA-256 앞 16 자). TAL 을 바꾸면 여기와 README 를 함께 고침
var wantTALKeys = map[string]string{
	"afrinic": "ad69cadc45c0cd41",
	"apnic":   "a3a053a192ca1c57",
	"arin":    "50471ac41c29b263",
	"lacnic":  "aa4375000f5431be",
	"ripe":    "44a4f26e67d2e2ce",
}

func TestBuiltinTALs(t *testing.T) {
	tals, source, err := loadTALs("")
	if err != nil || source != "내장" {
		t.Fatalf("내장 TAL: %v (%s)", err, source)
	}
	if len(tals) != len(wantTALKeys) {
		t.Fatalf("내장 TAL %d 개, %d 개여야 함", len(tals), len(wantTALKeys))
	}
	for _, tl := range tals {
		if got := tl.keyHash(); got != wantTALKeys[tl.Name] {
			t.Errorf("%s: 키 %s, 기대 %s", tl.Name, got, wantTALKeys[tl.Name])
		}
		if tl.rsyncURI() == "" || len(tl.URIs) < 2 {
			t.Errorf("%s: URI %v", tl.Name, tl.URIs)
		}
		if _, err := x509.ParsePKIXPublicKey(tl.SPKI); err != nil {
			t.Errorf("%s: 공개 키 %v", tl.Name, err)
		}
	}
}

// -tal 폴더 : 그 폴더의 것만 씀, 하나라도 깨지면 오류, 비었으면 오류
func TestTALDir(t *testing.T) {
	dir := t.TempDir()
	b, _ := os.ReadFile("tals/ripe.tal")
	os.WriteFile(filepath.Join(dir, "ripe.tal"), b, 0644)
	tals, source, err := loadTALs(dir)
	if err != nil || source != dir || len(tals) != 1 || tals[0].Name != "ripe" {
		t.Fatalf("폴더: %v %s %d", err, source, len(tals))
	}
	os.WriteFile(filepath.Join(dir, "bad.tal"), []byte("not a tal\n"), 0644)
	if _, _, err := loadTALs(dir); err == nil {
		t.Error("깨진 TAL 이 있으면 오류여야 함")
	}
	if _, _, err := loadTALs(t.TempDir()); err == nil {
		t.Error("빈 폴더는 오류여야 함")
	}
}

// makeTA : key 로 자체 서명한 TA 인증서 (RPKI 프로파일 : 정책, SIA, 자원). nb / na = 유효 기간
func makeTA(t *testing.T, k *rsa.PrivateKey, nb, na time.Time) []byte {
	t.Helper()
	pol := tlv(0x30, tlv(0x30, derOID(oidPolicyRPKI)))
	sia := tlv(0x30,
		tlv(0x30, derOID(oidADCARepository), tlv(0x86, []byte("rsync://x/repo/"))),
		tlv(0x30, derOID(oidADManifest), tlv(0x86, []byte("rsync://x/repo/ta.mft"))))
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(nb.Unix()), Subject: pkix.Name{CommonName: "test-ta"},
		NotBefore: nb, NotAfter: na,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign, BasicConstraintsValid: true, IsCA: true, MaxPathLen: -1,
		SubjectKeyId: ski(k),
		ExtraExtensions: []pkix.Extension{
			{Id: oidExtPolicies, Critical: true, Value: pol},
			{Id: oidExtSIA, Value: sia},
			{Id: oidExtASNum, Critical: true, Value: asIDs(64500)},
			{Id: oidExtIPAddr, Critical: true, Value: ipBlocks(192, 0, 2)},
		},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

// RFC 10097 2 장 : notBefore 늦은 쪽 -> 유효 기간 짧은 쪽 -> 같으면 새 것
func TestPreferNewTA(t *testing.T) {
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	c := func(nbDays, lenDays int) *x509.Certificate {
		nb := base.AddDate(0, 0, nbDays)
		return &x509.Certificate{NotBefore: nb, NotAfter: nb.AddDate(0, 0, lenDays)}
	}
	cases := []struct {
		name    string
		nw, old *x509.Certificate
		wantNew bool
	}{
		{"newer notBefore", c(10, 365), c(0, 365), true},
		{"older notBefore", c(0, 365), c(10, 365), false},
		{"older notBefore, shorter", c(0, 30), c(10, 365), false},
		{"same notBefore, shorter", c(0, 30), c(0, 365), true},
		{"same notBefore, longer", c(0, 365), c(0, 30), false},
		{"same", c(0, 365), c(0, 365), true},
	}
	for _, tc := range cases {
		if got := preferNewTA(tc.nw, tc.old); got != tc.wantNew {
			t.Errorf("%s: got %v", tc.name, got)
		}
	}
}

// fetchTA : 옛 TA / 만료 TA 를 받으면 캐시 그대로, 더 새 TA 면 바꿈, 캐시가 만료면 받은 것
func TestFetchTATiebreak(t *testing.T) {
	k := testKey(t, "ca")
	now := time.Now()
	older := makeTA(t, k, now.Add(-48*time.Hour), now.Add(365*24*time.Hour))
	newer := makeTA(t, k, now.Add(-time.Hour), now.Add(365*24*time.Hour))
	expired := makeTA(t, k, now.Add(-72*time.Hour), now.Add(-time.Hour))

	var serve []byte
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(serve)
	}))
	defer srv.Close()
	f, err := newFetcher(t.TempDir(), 2)
	if err != nil {
		t.Fatal(err)
	}
	f.Logf, f.client = nil, srv.Client()
	x, _ := x509.ParseCertificate(newer)
	ta := &tal{Name: "test", URIs: []string{srv.URL + "/ta.cer"}, SPKI: x.RawSubjectPublicKeyInfo}
	cached := filepath.Join(f.CacheDir, "ta", "test", "ta.cer")
	if _, err := ta.checkTA(newer); err != nil {
		t.Fatalf("test TA not accepted: %v", err)
	}

	steps := []struct {
		name         string
		cache, serve []byte
		wantErr      bool
		want         []byte
	}{
		{"no cache", nil, older, false, older},
		{"newer replaces", older, newer, false, newer},
		{"older kept out", newer, older, false, newer},
		{"expired kept out", newer, expired, true, newer},
		{"expired cache replaced", expired, older, false, older},
	}
	for _, s := range steps {
		os.RemoveAll(filepath.Dir(cached))
		if s.cache != nil {
			os.MkdirAll(filepath.Dir(cached), 0755)
			os.WriteFile(cached, s.cache, 0644)
		}
		serve = s.serve
		err := f.fetchTA(ta)
		if (err != nil) != s.wantErr {
			t.Errorf("%s: err %v", s.name, err)
		}
		if got, _ := os.ReadFile(cached); string(got) != string(s.want) {
			t.Errorf("%s: wrong TA in cache", s.name)
		}
	}
}
