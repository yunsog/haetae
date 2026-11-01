package main

// tal_test.go : 실행 파일 안의 TAL (저장소 tals/) 5 개, -tal 폴더 읽기

import (
	"crypto/x509"
	"os"
	"path/filepath"
	"testing"
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
