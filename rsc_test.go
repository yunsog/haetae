package main

// rsc_test.go : RSC (RFC 9323) 를 직접 만들어 파싱 / 체인 / 파일 확인
// 실제 RSC 는 저장소에 없어서 CA -> EE -> RSC 를 시험 안에서 만듦

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"
)

// tlv : DER TLV 하나 (길이는 짧은 / 긴 형식)
func tlv(tag byte, parts ...[]byte) []byte {
	body := bytes.Join(parts, nil)
	n := len(body)
	var l []byte
	switch {
	case n < 0x80:
		l = []byte{byte(n)}
	case n < 0x100:
		l = []byte{0x81, byte(n)}
	case n < 0x10000:
		l = []byte{0x82, byte(n >> 8), byte(n)}
	default:
		l = []byte{0x83, byte(n >> 16), byte(n >> 8), byte(n)}
	}
	return append(append([]byte{tag}, l...), body...)
}

func derOID(o asn1.ObjectIdentifier) []byte {
	b, _ := asn1.Marshal(o)
	return b
}

func derInt(v int64) []byte {
	b, _ := asn1.Marshal(v)
	return b
}

// 자원 확장 DER : AS 하나, IPv4 prefix 하나 (bits = 앞 바이트들)
func asIDs(as int64) []byte { return tlv(0x30, tlv(0xa0, tlv(0x30, derInt(as)))) }

func ipBlocks(prefix ...byte) []byte {
	return tlv(0x30, tlv(0x30, tlv(0x04, []byte{0, 1}), tlv(0x30, tlv(0x03, append([]byte{0}, prefix...)))))
}

var testKeys = map[string]*rsa.PrivateKey{}

func testKey(t *testing.T, name string) *rsa.PrivateKey {
	if k := testKeys[name]; k != nil {
		return k
	}
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	testKeys[name] = k
	return k
}

func ski(k *rsa.PrivateKey) []byte {
	b := x509.MarshalPKCS1PublicKey(&k.PublicKey)
	h := sha1.Sum(b)
	return h[:]
}

// testCA : 자원 (AS 64500, 192.0.2.0/24 또는 주어진 것) 을 가진 자체 서명 CA
func testCA(t *testing.T, ip []byte) (*rpkiCert, *rsa.PrivateKey) {
	k := testKey(t, "ca")
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test-ca"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign, BasicConstraintsValid: true, IsCA: true, MaxPathLen: -1,
		SubjectKeyId: ski(k),
		ExtraExtensions: []pkix.Extension{
			{Id: oidExtASNum, Critical: true, Value: asIDs(64500)},
			{Id: oidExtIPAddr, Critical: true, Value: ip},
		},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	x, _ := x509.ParseCertificate(der)
	c := &rpkiCert{X509: x, SKI: x.SubjectKeyId, Kind: kindCA}
	c.IPs, _ = parseIPAddrBlocks(ip)
	c.ASs, _ = parseASIdentifiers(asIDs(64500))
	return c, k
}

type rscOpts struct {
	eeIP    []byte // EE 의 IP 자원
	rscIP   []byte // RSC 안의 IP 자원
	withSIA bool
	tamper  bool // 서명 뒤 내용 바꿈
}

// makeRSC : CA 키로 EE 를 내고 EE 키로 RSC 서명
func makeRSC(t *testing.T, ca *rpkiCert, caKey *rsa.PrivateKey, o rscOpts, entries []rscEntry) []byte {
	ee := testKey(t, "ee")
	pol := tlv(0x30, tlv(0x30, derOID(oidPolicyRPKI)))
	exts := []pkix.Extension{
		{Id: oidExtPolicies, Critical: true, Value: pol},
		{Id: oidExtASNum, Critical: true, Value: asIDs(64500)},
		{Id: oidExtIPAddr, Critical: true, Value: o.eeIP},
	}
	if o.withSIA {
		sia := tlv(0x30, tlv(0x30, derOID(oidADSignedObject), tlv(0x86, []byte("rsync://x/a.sig"))))
		exts = append(exts, pkix.Extension{Id: oidExtSIA, Value: sia})
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "test-ee"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, SubjectKeyId: ski(ee),
		CRLDistributionPoints: []string{"rsync://x/ca.crl"}, IssuingCertificateURL: []string{"rsync://x/ca.cer"},
		ExtraExtensions: exts,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, ca.X509, &ee.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}

	// eContent
	var list [][]byte
	for _, e := range entries {
		if e.Name != "" {
			list = append(list, tlv(0x30, tlv(0x16, []byte(e.Name)), tlv(0x04, e.Hash)))
		} else {
			list = append(list, tlv(0x30, tlv(0x04, e.Hash)))
		}
	}
	content := tlv(0x30,
		tlv(0x30, tlv(0xa0, asIDs(64500)), tlv(0xa1, o.rscIP)),
		tlv(0x30, derOID(oidSHA256)),
		tlv(0x30, list...))

	// signedAttrs (DER SET OF = 정렬)
	md := sha256.Sum256(content)
	attrs := [][]byte{
		tlv(0x30, derOID(oidAttrCType), tlv(0x31, derOID(oidCTRSC))),
		tlv(0x30, derOID(oidAttrDigest), tlv(0x31, tlv(0x04, md[:]))),
	}
	sort.Slice(attrs, func(i, j int) bool { return bytes.Compare(attrs[i], attrs[j]) < 0 })
	signed := tlv(0x31, attrs...)
	h := sha256.Sum256(signed)
	sig, err := rsa.SignPKCS1v15(rand.Reader, ee, crypto.SHA256, h[:])
	if err != nil {
		t.Fatal(err)
	}
	if o.tamper {
		content = bytes.Replace(content, []byte{0xfb, 0xf4}, []byte{0xfb, 0xf5}, 1) // AS 64500 -> 64501
	}
	signerInfo := tlv(0x30, derInt(3), tlv(0x80, ski(ee)), tlv(0x30, derOID(oidSHA256)),
		append([]byte{0xa0}, signed[1:]...), tlv(0x30, derOID(oidRSA), []byte{5, 0}), tlv(0x04, sig))
	sd := tlv(0x30, derInt(3), tlv(0x31, tlv(0x30, derOID(oidSHA256))),
		tlv(0x30, derOID(oidCTRSC), tlv(0xa0, tlv(0x04, content))),
		tlv(0xa0, certDER), tlv(0x31, signerInfo))
	return tlv(0x30, derOID(oidSignedData), tlv(0xa0, sd))
}

func TestRSC(t *testing.T) {
	loa := []byte("LOA: AS64500 may announce 192.0.2.0/24\n")
	other := []byte("unnamed file\n")
	h1, h2 := sha256.Sum256(loa), sha256.Sum256(other)
	entries := []rscEntry{{"loa.txt", h1[:]}, {"", h2[:]}}
	ip24 := ipBlocks(192, 0, 2) // 192.0.2.0/24
	ip16 := ipBlocks(198, 51)   // 198.51.0.0/16
	ca, caKey := testCA(t, ip24)

	der := makeRSC(t, ca, caKey, rscOpts{eeIP: ip24, rscIP: ip24}, entries)
	r, err := parseRSC(der)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(r.Entries) != 2 || r.Entries[0].Name != "loa.txt" || r.ASs.Ranges[0].Min != 64500 {
		t.Fatalf("content: %+v", r)
	}

	// 체인 : 검증 트리에서 찾은 CA 대신 직접 넣음
	v := newValidator("", time.Now(), 1)
	v.caBySKI = map[string][]*caRecord{string(ca.SKI): {{Ctx: caCtx{Cert: ca, URI: "rsync://x/ca.cer", TA: "test",
		IPs: ca.IPs, ASs: ca.ASs, Expires: time.Now().Add(time.Hour)}, CRLURI: "rsync://x/ca.crl"}}}
	if _, err := r.checkChain(v); err != nil {
		t.Errorf("chain: %v", err)
	}

	// 파일 : 이름 있는 항목은 이름까지, 이름 없는 항목은 이름 모르는 (stdin) 경우만
	if err := r.checkFile("loa.txt", loa); err != nil {
		t.Errorf("loa.txt: %v", err)
	}
	if err := r.checkFile("loa2.txt", loa); err == nil {
		t.Errorf("loa2.txt: want name mismatch")
	}
	if err := r.checkFile("", other); err != nil {
		t.Errorf("unnamed: %v", err)
	}
	if err := r.checkFile("loa.txt", append(loa, 'x')); err == nil {
		t.Errorf("changed file: want hash mismatch")
	}

	// RSC_OUT=<파일> 이면 시험 RSC 를 남김 (명령 모드를 손으로 해 볼 때)
	if p := os.Getenv("RSC_OUT"); p != "" {
		os.WriteFile(p, der, 0644)
		os.WriteFile(p+".loa.txt", loa, 0644)
	}

	// 명령 모드 (체인 없이) : 파일 이름까지 맞으면 0, 다른 이름이면 1
	dir := t.TempDir()
	sigPath, loaPath, badPath := filepath.Join(dir, "x.sig"), filepath.Join(dir, "loa.txt"), filepath.Join(dir, "loa2.txt")
	os.WriteFile(sigPath, der, 0644)
	os.WriteFile(loaPath, loa, 0644)
	os.WriteFile(badPath, loa, 0644)
	if rc := runRSC(sigPath, []string{loaPath}, "", "", 0, 1); rc != 0 {
		t.Errorf("runRSC ok case: %d", rc)
	}
	if rc := runRSC(sigPath, []string{badPath}, "", "", 0, 1); rc != 1 {
		t.Errorf("runRSC wrong name: %d", rc)
	}

	// 실패해야 하는 것들
	bad := []struct {
		name  string
		o     rscOpts
		inErr string
	}{
		{"RSC 자원 > EE", rscOpts{eeIP: ip24, rscIP: ip16}, "not covered by EE"},
		{"EE 에 SIA", rscOpts{eeIP: ip24, rscIP: ip24, withSIA: true}, "SIA"},
		{"내용 바뀜", rscOpts{eeIP: ip24, rscIP: ip24, tamper: true}, "messageDigest"},
	}
	for _, b := range bad {
		_, err := parseRSC(makeRSC(t, ca, caKey, b.o, entries))
		if err == nil || !strings.Contains(err.Error(), b.inErr) {
			t.Errorf("%s: err %v, want %q", b.name, err, b.inErr)
		}
	}

	// EE 자원이 CA 밖 -> 파싱은 되고 체인에서 실패
	r2, err := parseRSC(makeRSC(t, ca, caKey, rscOpts{eeIP: ip16, rscIP: ip16}, entries))
	if err != nil {
		t.Fatalf("parse r2: %v", err)
	}
	if _, err := r2.checkChain(v); err == nil || !strings.Contains(err.Error(), "not covered by issuer") {
		t.Errorf("EE outside CA: %v", err)
	}

	// 이름 중복, 이상한 이름
	if _, err := parseRSC(makeRSC(t, ca, caKey, rscOpts{eeIP: ip24, rscIP: ip24},
		[]rscEntry{{"a.txt", h1[:]}, {"a.txt", h2[:]}})); err == nil {
		t.Errorf("duplicate name: want error")
	}
	if _, err := parseRSC(makeRSC(t, ca, caKey, rscOpts{eeIP: ip24, rscIP: ip24},
		[]rscEntry{{"../x", h1[:]}})); err == nil {
		t.Errorf("bad filename: want error")
	}
}
