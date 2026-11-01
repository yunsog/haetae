package main

// rrdp_test.go : delta 두 단계 적용 (확인 실패면 폴더를 건드리지 않음)

import (
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func writeDelta(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "delta.xml")
	x := fmt.Sprintf(`<delta xmlns="%s" version="1" session_id="s" serial="2">%s</delta>`, rrdpNS, body)
	if err := os.WriteFile(p, []byte(x), 0644); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestDeltaTwoPhase(t *testing.T) {
	dir := t.TempDir()
	a := filepath.Join(dir, "h/m/a.roa")
	os.MkdirAll(filepath.Dir(a), 0755)
	os.WriteFile(a, []byte("old"), 0644)
	b64 := func(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }

	// 새 파일 b + a 교체는 맞지만 withdraw 해시가 틀림 -> 오류, 폴더 그대로
	bad := writeDelta(t, fmt.Sprintf(`<publish uri="rsync://h/m/b.roa">%s</publish>`+
		`<publish uri="rsync://h/m/a.roa" hash="%s">%s</publish>`+
		`<withdraw uri="rsync://h/m/c.roa" hash="%s"/>`, b64("new b"), hashHex([]byte("old")), b64("new a"), hashHex([]byte("x"))))
	if _, dirty, err := applyDeltaFile(bad, "s", 2, dir); err == nil || dirty {
		t.Fatalf("bad delta: err %v dirty %v", err, dirty)
	}
	if got, _ := os.ReadFile(a); string(got) != "old" {
		t.Errorf("a changed: %q", got)
	}
	if _, err := os.Stat(filepath.Join(dir, "h/m/b.roa")); err == nil {
		t.Error("b written by failed delta")
	}
	if _, err := os.Stat(dir + ".stage"); err == nil {
		t.Error("stage left")
	}

	// 맞는 delta -> 적용
	good := writeDelta(t, fmt.Sprintf(`<publish uri="rsync://h/m/b.roa">%s</publish>`+
		`<withdraw uri="rsync://h/m/a.roa" hash="%s"/>`, b64("new b"), hashHex([]byte("old"))))
	n, dirty, err := applyDeltaFile(good, "s", 2, dir)
	if err != nil || dirty || n != 2 {
		t.Fatalf("good delta: n %d err %v dirty %v", n, err, dirty)
	}
	if got, _ := os.ReadFile(filepath.Join(dir, "h/m/b.roa")); string(got) != "new b" {
		t.Errorf("b = %q", got)
	}
	if _, err := os.Stat(a); err == nil {
		t.Error("a not withdrawn")
	}

	// 같은 URI 두 번 : publish d 다음 같은 d 를 해시로 교체 -> 두 번째는 첫 번째 내용 기준
	two := writeDelta(t, fmt.Sprintf(`<publish uri="rsync://h/m/d.roa">%s</publish><publish uri="rsync://h/m/d.roa" hash="%s">%s</publish>`,
		b64("1"), hashHex([]byte("1")), b64("2")))
	if _, _, err := applyDeltaFile(two, "s", 2, dir); err != nil {
		t.Fatalf("publish twice: %v", err)
	}
	if got, _ := os.ReadFile(filepath.Join(dir, "h/m/d.roa")); string(got) != "2" {
		t.Errorf("d = %q", got)
	}
}
