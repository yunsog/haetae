package main

// repo_test.go : RRDP 와 rsync 가 모두 실패하면 예전에 받은 RRDP 데이터를 씀 (A2)

import (
	"os"
	"testing"
	"time"
)

func TestFallbackToOldRRDP(t *testing.T) {
	f, err := newFetcher(t.TempDir(), 2)
	if err != nil {
		t.Fatal(err)
	}
	f.Logf = nil
	f.RsyncBin = "/bin/false" // rsync 실패
	f.FallbackAfter = 0       // RRDP 실패하면 바로 rsync 로
	f.Timeout = 5 * time.Second
	notify := "https://127.0.0.1:1/notification.xml" // 접속 안 됨
	c := &rpkiCert{Notify: notify, CARepository: "rsync://127.0.0.1/repo/ca/"}

	// 예전 RRDP 데이터 없음 -> rsync 폴더
	if got := f.ensure(c); got != f.CacheDir+"/rsync" {
		t.Errorf("no old data: %s", got)
	}

	// 예전 RRDP 데이터 (상태 파일) 있음 -> RRDP 폴더
	f.reset()
	dir, statePath := rrdpPaths(f.CacheDir, notify)
	os.MkdirAll(dir, 0755)
	if err := saveRRDPState(statePath, &rrdpState{Notify: notify, Session: "s", Serial: 5, LastSuccess: time.Now().Add(-2 * time.Hour)}); err != nil {
		t.Fatal(err)
	}
	if got := f.ensure(c); got != dir {
		t.Errorf("old data: %s, want %s", got, dir)
	}
}
