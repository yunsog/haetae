package main

// valid_test.go : 직전 정상 publication point 저장 / 번호 / 정리 (끝에서 끝까지는 실제 스냅샷으로 확인 : 저장소 파일 0 개여도 VRP 차이 0)

import (
	"crypto/x509"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// validCert : 저장 폴더 키 (공개 키 + notify + manifest URI) 만 채운 CA
func validCert(key, notify, mft string) *rpkiCert {
	return &rpkiCert{X509: &x509.Certificate{RawSubjectPublicKeyInfo: []byte(key)}, Notify: notify, Manifest: mft}
}

func TestStoreValid(t *testing.T) {
	cache, vd := t.TempDir(), t.TempDir()
	src := filepath.Join(cache, "a.roa")
	os.WriteFile(src, []byte("roa v1"), 0644)
	pp := &pubPoint{mft: &rpkiManifest{Number: big.NewInt(5)}, mftDER: []byte("mft 5"),
		files: []mftEntry{{Name: "a.roa", Data: []byte("roa v1")}, {Name: "b.crl", Data: []byte("crl")}},
		paths: map[string]string{"a.roa": src}}
	dir := validPPDir(vd, validCert("key", "https://h/n.xml", "rsync://h/repo/ca.mft"))
	if storedNumber(dir) != nil {
		t.Error("number before store")
	}
	if err := storeValid(dir, "ca.mft", pp); err != nil {
		t.Fatal(err)
	}
	if n := storedNumber(dir); n == nil || n.Int64() != 5 {
		t.Errorf("number %v", n)
	}
	at := validAt(dir)
	for name, want := range map[string]string{"ca.mft": "mft 5", "a.roa": "roa v1", "b.crl": "crl"} {
		p, _ := at("rsync://h/repo/" + name)
		if b, _ := os.ReadFile(p); string(b) != want {
			t.Errorf("%s = %q", name, b)
		}
	}
	// 캐시 쪽 파일이 새것으로 바뀌어도 (rename = 새 inode) 저장본은 그대로
	os.WriteFile(src+".new", []byte("roa v2"), 0644)
	os.Rename(src+".new", src)
	if b, _ := os.ReadFile(filepath.Join(dir, "a.roa")); string(b) != "roa v1" {
		t.Errorf("stored changed: %q", b)
	}
	// 새 manifest -> 바꿔 끼움 (옛 파일 없어짐)
	pp2 := &pubPoint{mft: &rpkiManifest{Number: big.NewInt(6)}, mftDER: []byte("mft 6"),
		files: []mftEntry{{Name: "c.roa", Data: []byte("c")}}, paths: map[string]string{}}
	if err := storeValid(dir, "ca.mft", pp2); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "a.roa")); err == nil {
		t.Error("old file left")
	}
	if n := storedNumber(dir); n.Int64() != 6 {
		t.Errorf("number %v", n)
	}
	if _, err := at("rsync://h/repo/.."); err == nil { // 파일 이름만 쓰므로 ".." 만 남는 경우
		t.Error("bad name accepted")
	}
	// 정리 : 본 것은 남기고 안 본 것만 (0.3.0 전 모양의 호스트 폴더, 끊긴 .tmp 도)
	other := validPPDir(vd, validCert("key", "https://h/n.xml", "rsync://h/repo/other.mft"))
	os.MkdirAll(other, 0755)
	os.MkdirAll(dir+".tmp", 0755)
	os.MkdirAll(filepath.Join(vd, "h", "repo", "ca.mft.d"), 0755)
	if n := cleanValid(vd, map[string]bool{dir: true}); n != 2 {
		t.Errorf("removed %d", n)
	}
	if _, err := os.Stat(dir); err != nil {
		t.Error("seen dir removed")
	}
	for _, p := range []string{other, dir + ".tmp", filepath.Join(vd, "h")} {
		if _, err := os.Stat(p); err == nil {
			t.Errorf("%s left", p)
		}
	}
}

// 저장 폴더는 같은 manifest URI 라도 공개 키나 notify 가 다르면 다름 (11-05 검토 3 : 남의 저장본 덮어쓰기)
func TestValidPPDirKey(t *testing.T) {
	vd := t.TempDir()
	victim := validPPDir(vd, validCert("victim key", "https://rir/n.xml", "rsync://rir/repo/ca.mft"))
	for name, c := range map[string]*rpkiCert{
		"other key":    validCert("attacker key", "https://rir/n.xml", "rsync://rir/repo/ca.mft"),
		"other notify": validCert("victim key", "https://evil/n.xml", "rsync://rir/repo/ca.mft"),
	} {
		if validPPDir(vd, c) == victim {
			t.Errorf("%s: same dir", name)
		}
	}
	if filepath.Dir(victim) != vd {
		t.Errorf("not flat: %s", victim)
	}
}

// 번호 역행 : 저장본이 유효하면 저장본, 이미 유효하지 않으면 새것을 받음 (11-05 검토 4)
func TestWithValidNumberBack(t *testing.T) {
	vd := t.TempDir()
	v := newValidator("", time.Now(), 1)
	dir := validPPDir(vd, validCert("k", "", "rsync://h/repo/ca.mft"))
	mk := func(n int64) *pubPoint {
		return &pubPoint{mft: &rpkiManifest{Number: big.NewInt(n)}, mftDER: []byte(big.NewInt(n).String()), paths: map[string]string{}}
	}
	okOld := func() (*pubPoint, error) { return mk(9), nil }
	badOld := func() (*pubPoint, error) { return nil, errors.New("expired") }

	// 처음 : 저장
	if pp, fb, err := v.withValid(dir, "rsync://h/repo/ca.mft", mk(9), nil, badOld); err != nil || fb || pp.mft.Number.Int64() != 9 {
		t.Fatalf("first: %v %v", fb, err)
	}
	// 번호 작아짐 + 저장본 유효 -> 저장본
	if pp, fb, err := v.withValid(dir, "rsync://h/repo/ca.mft", mk(3), nil, okOld); err != nil || !fb || pp.mft.Number.Int64() != 9 {
		t.Fatalf("back, old valid: %v %v", fb, err)
	}
	// 새것이 틀림 + 저장본도 틀림 -> 거부
	if _, _, err := v.withValid(dir, "rsync://h/repo/ca.mft", nil, errors.New("bad hash"), badOld); err == nil || !strings.Contains(err.Error(), "previous valid copy") {
		t.Fatalf("both bad: %v", err)
	}
	// 번호 작아짐 + 저장본 만료 -> 새것을 받고 저장 (전에는 영구 거부)
	if pp, fb, err := v.withValid(dir, "rsync://h/repo/ca.mft", mk(3), nil, badOld); err != nil || fb || pp.mft.Number.Int64() != 3 {
		t.Fatalf("back, old expired: %v %v", fb, err)
	}
	if n := storedNumber(dir); n == nil || n.Int64() != 3 {
		t.Errorf("stored %v", n)
	}
}
