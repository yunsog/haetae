package main

// repo_test.go : RRDP 와 rsync 가 모두 실패하면 예전에 받은 RRDP 데이터를 씀 (A2), TA 는 확인한 뒤에만 캐시에
//   RRDP 줄 결과 = rsync 가 성공해야 fallback-rsync, rsync 도 실패 / rsync 끔이면 failed

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
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
	f.ensure(c) // 같은 notify 의 다른 CA : 오류 덧붙이기는 한 번만
	rrdp := rrdpRow(t, f, notify)
	if rrdp.Result != "failed" || !strings.HasSuffix(rrdp.Error, " / rsync rsync://127.0.0.1/repo failed") ||
		strings.Count(rrdp.Error, "/ rsync ") != 1 {
		t.Errorf("rsync failed: %+v", rrdp)
	}

	// rsync 성공 -> fallback-rsync
	f.reset()
	f.RsyncBin = "/bin/true"
	f.ensure(c)
	if rrdp := rrdpRow(t, f, notify); rrdp.Result != "fallback-rsync" || strings.Contains(rrdp.Error, "/ rsync ") {
		t.Errorf("rsync ok: %+v", rrdp)
	}

	// rsync 끔 -> failed
	f.reset()
	f.NoRsync = true
	f.ensure(c)
	if rrdp := rrdpRow(t, f, notify); rrdp.Result != "failed" {
		t.Errorf("no rsync: %+v", rrdp)
	}
}

func rrdpRow(t *testing.T, f *fetcher, notify string) repoStatus {
	t.Helper()
	for _, st := range f.statuses() {
		if st.Type == "rrdp" && st.URI == notify {
			return st
		}
	}
	t.Fatalf("no rrdp row for %s", notify)
	return repoStatus{}
}

// 서버가 TA 가 아닌 파일을 주면 오류, 캐시에 있던 TA 파일은 그대로
func TestFetchTAKeepsCacheOnBadCert(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "not a certificate")
	}))
	defer srv.Close()
	f, err := newFetcher(t.TempDir(), 2)
	if err != nil {
		t.Fatal(err)
	}
	f.Logf, f.client = nil, srv.Client()
	ta := &tal{Name: "test", URIs: []string{srv.URL + "/ta.cer"}, SPKI: []byte{1}}
	cached := filepath.Join(f.CacheDir, "ta", "test", "ta.cer")
	os.MkdirAll(filepath.Dir(cached), 0755)
	os.WriteFile(cached, []byte("good old TA"), 0644)

	if err := f.fetchTA(ta); err == nil {
		t.Fatal("bad TA accepted")
	}
	if got, _ := os.ReadFile(cached); string(got) != "good old TA" {
		t.Errorf("cached TA replaced: %q", got)
	}
}

// rsync 로 받은 폴더의 파일 수 / 크기 상한
func TestCheckTreeLimit(t *testing.T) {
	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, "a/b"), 0755)
	os.WriteFile(filepath.Join(dir, "a/x.roa"), make([]byte, 100), 0644)
	os.WriteFile(filepath.Join(dir, "a/b/y.roa"), make([]byte, 100), 0644)
	if err := checkTreeLimit(dir, 2, 200); err != nil {
		t.Errorf("at limit: %v", err)
	}
	if err := checkTreeLimit(dir, 1, 1000); err == nil {
		t.Error("too many files accepted")
	}
	if err := checkTreeLimit(dir, 10, 150); err == nil {
		t.Error("too many bytes accepted")
	}
}

// 큰 저장소 (객체 1 만 이상) 는 rsync 로 넘어가기 전에 3 시간, 작은 곳은 1 시간 (11-02)
func TestFallbackAfterLarge(t *testing.T) {
	f, err := newFetcher(t.TempDir(), 2)
	if err != nil {
		t.Fatal(err)
	}
	small, large := t.TempDir(), t.TempDir()
	os.WriteFile(filepath.Join(small, "a.roa"), nil, 0644)
	for i := 0; i < largeRepoObjects; i++ {
		d := filepath.Join(large, fmt.Sprintf("d%d", i/1000))
		os.MkdirAll(d, 0755)
		os.WriteFile(filepath.Join(d, fmt.Sprintf("%d.roa", i)), nil, 0644)
	}
	if got := f.fallbackAfter(small); got != time.Hour {
		t.Errorf("small: %s", got)
	}
	if got := f.fallbackAfter(large); got != 3*time.Hour {
		t.Errorf("large: %s", got)
	}

	// 큰 저장소의 RRDP 가 2 시간째 실패 : 아직 rsync 로 넘어가지 않고 예전 RRDP (fallback-old)
	f.Logf, f.Timeout = nil, 5*time.Second
	notify := "https://127.0.0.1:1/notification.xml"
	dir, statePath := rrdpPaths(f.CacheDir, notify)
	os.MkdirAll(filepath.Dir(dir), 0755)
	if err := os.Rename(large, dir); err != nil {
		t.Fatal(err)
	}
	saveRRDPState(statePath, &rrdpState{Notify: notify, Session: "s", Serial: 1, LastSuccess: time.Now().Add(-2 * time.Hour)})
	if base, ok := f.ensureRRDP(notify); !ok || base != dir {
		t.Errorf("large repo after 2h: %s %v", base, ok)
	}
	if st := f.statuses(); len(st) != 1 || st[0].Result != "fallback-old" {
		t.Errorf("status %+v", st)
	}
}
