package main

// ops_test.go : 묵은 데이터 (경고 / RTR 닫기), /healthz, watchdog 판단, sd_notify, 저장소 재시도 간격 (backoff, Retry-After)

import (
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

func TestHealthzAndStale(t *testing.T) {
	d := testDaemon(t)
	h := d.apiHandler()
	healthz := func() (int, map[string]any) {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest("GET", "/healthz", nil))
		var m map[string]any
		json.Unmarshal(rec.Body.Bytes(), &m)
		return rec.Code, m
	}
	d.cfg.StaleWarn = time.Hour
	d.st.mu.Lock()
	d.st.Cur.Built = time.Now()
	d.st.mu.Unlock()
	var warned time.Time
	d.checkStale(&warned)
	if code, m := healthz(); code != 200 || m["status"] != "ok" {
		t.Errorf("fresh: %d %v", code, m)
	}
	d.st.mu.Lock()
	d.st.Cur.Built = time.Now().Add(-2 * time.Hour)
	d.st.mu.Unlock()
	d.checkStale(&warned)
	if code, m := healthz(); code != 503 || m["status"] != "stale" {
		t.Errorf("stale: %d %v", code, m)
	}
	if st := d.statusData(false); st["stale"] != true {
		t.Errorf("status stale %v", st["stale"])
	}
	// 집합이 없으면 starting
	d.st.mu.Lock()
	d.st.Cur = nil
	d.st.mu.Unlock()
	if code, m := healthz(); code != 503 || m["status"] != "starting" {
		t.Errorf("starting: %d %v", code, m)
	}
}

// stale-close 를 넘으면 RTR 을 닫고, 새 집합이 반영되면 (openRTR) 다시 엶
func TestStaleCloseRTR(t *testing.T) {
	d := testDaemon(t)
	d.cfg.RTRAddr = "127.0.0.1:0"
	d.cfg.StaleWarn, d.cfg.StaleClose = time.Hour, 90*time.Minute
	d.rtr = &rtrServer{St: d.st, Logf: t.Logf}
	d.openRTR()
	if !d.rtrOpen {
		t.Fatal("not open")
	}
	addr := d.rtrListen.Addr().String()
	d.st.mu.Lock()
	d.st.Cur.Built = time.Now().Add(-2 * time.Hour)
	d.st.mu.Unlock()
	var warned time.Time
	d.checkStale(&warned)
	if d.rtrOpen || d.rtrListen != nil {
		t.Fatal("still open after stale-close")
	}
	if c, err := net.DialTimeout("tcp", addr, time.Second); err == nil {
		c.Close()
		t.Error("listener still accepts")
	}
	d.openRTR()
	if !d.rtrOpen {
		t.Error("not reopened")
	}
	d.rtrListen.Close()
}

func TestAlive(t *testing.T) {
	d := testDaemon(t)
	if !d.alive() {
		t.Error("idle not alive")
	}
	d.cycleStart = time.Now().Add(-maxCycle - time.Minute)
	if d.alive() {
		t.Error("cycle over maxCycle alive")
	}
	d.cycleStart = time.Now()
	if !d.alive() {
		t.Error("running cycle not alive")
	}
}

func TestSdNotify(t *testing.T) {
	p := filepath.Join(t.TempDir(), "notify")
	ln, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: p, Net: "unixgram"})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	t.Setenv("NOTIFY_SOCKET", p)
	sdNotify("READY=1")
	buf := make([]byte, 64)
	ln.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, _, err := ln.ReadFromUnix(buf)
	if err != nil || string(buf[:n]) != "READY=1" {
		t.Errorf("got %q err %v", buf[:n], err)
	}
	t.Setenv("NOTIFY_SOCKET", "")
	sdNotify("READY=1") // systemd 밖 : 아무것도 안 함
}

func TestBackoffFor(t *testing.T) {
	for n, want := range map[int]time.Duration{1: 0, 2: 0, 3: 10 * time.Minute, 4: 20 * time.Minute, 5: 40 * time.Minute, 6: time.Hour, 40: time.Hour} {
		if got := backoffFor(n); got != want {
			t.Errorf("backoffFor(%d) = %s, want %s", n, got, want)
		}
	}
}

// 계속 실패하는 저장소 : 3 번 실패하면 다음 회차는 받지 않음 (Skipped), 서버가 Retry-After 를 주면 그만큼
func TestRepoBackoff(t *testing.T) {
	var hits atomic.Int32
	retryAfter := ""
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if retryAfter != "" {
			w.Header().Set("Retry-After", retryAfter)
		}
		w.WriteHeader(503)
	}))
	defer srv.Close()
	f, err := newFetcher(t.TempDir(), 2)
	if err != nil {
		t.Fatal(err)
	}
	f.Logf, f.client, f.NoRsync = nil, srv.Client(), true
	notify := srv.URL + "/notification.xml"
	var last repoStatus
	for i := 1; i <= 4; i++ {
		f.reset()
		f.ensureRRDP(notify)
		st := f.statuses()
		last = st[0]
		if i <= 3 && (last.Skipped || int(hits.Load()) != i || last.Failures != i) {
			t.Errorf("try %d: %+v hits %d", i, last, hits.Load())
		}
	}
	if !last.Skipped || hits.Load() != 3 || last.NextTry == nil {
		t.Errorf("4th not skipped: %+v hits %d", last, hits.Load())
	}

	// Retry-After 120 : 첫 실패부터 120 초 기다림
	g, _ := newFetcher(t.TempDir(), 2)
	g.Logf, g.client, g.NoRsync = nil, srv.Client(), true
	retryAfter = "120"
	g.ensureRRDP(notify + "?b")
	st := g.statuses()[0]
	if st.NextTry == nil || time.Until(*st.NextTry) < 100*time.Second {
		t.Errorf("retry-after not used: %+v", st)
	}
}
