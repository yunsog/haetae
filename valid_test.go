package main

// valid_test.go : 직전 정상 publication point 저장 / 번호 / 정리 (끝에서 끝까지는 실제 스냅샷으로 확인 : 저장소 파일 0 개여도 VRP 차이 0)

import (
	"math/big"
	"os"
	"path/filepath"
	"testing"
)

func TestStoreValid(t *testing.T) {
	cache, vd := t.TempDir(), t.TempDir()
	src := filepath.Join(cache, "a.roa")
	os.WriteFile(src, []byte("roa v1"), 0644)
	pp := &pubPoint{mft: &rpkiManifest{Number: big.NewInt(5)}, mftDER: []byte("mft 5"),
		files: []mftEntry{{Name: "a.roa", Data: []byte("roa v1")}, {Name: "b.crl", Data: []byte("crl")}},
		paths: map[string]string{"a.roa": src}}
	dir, err := validPPDir(vd, "rsync://h/repo/ca.mft")
	if err != nil {
		t.Fatal(err)
	}
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
	// 정리 : 본 것은 남기고 안 본 것만
	other, _ := validPPDir(vd, "rsync://h/repo/other.mft")
	os.MkdirAll(other, 0755)
	os.MkdirAll(dir+".tmp", 0755)
	if n := cleanValid(vd, map[string]bool{dir: true}); n != 1 {
		t.Errorf("removed %d", n)
	}
	if _, err := os.Stat(dir); err != nil {
		t.Error("seen dir removed")
	}
	if _, err := os.Stat(other); err == nil {
		t.Error("unseen dir left")
	}
	if _, err := os.Stat(dir + ".tmp"); err == nil {
		t.Error("tmp left")
	}
}
