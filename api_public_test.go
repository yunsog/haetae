package main

// api_public_test.go : 내부 / 공개 / 403 나누기, 공개 쪽 상태에서 내부 정보 빠짐, 공개 쪽 큰 파일 제한, 연결 수 상한

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestHTTPPublicAccess(t *testing.T) {
	d := testDaemon(t)
	d.cfg.OutDir = t.TempDir()
	d.cfg.DeltaFullInterval = time.Minute
	d.cfg.SLURM = "/etc/haetae/slurm.json"
	os.WriteFile(filepath.Join(d.cfg.OutDir, "json"), []byte(`{"roas":[]}`), 0644)
	os.WriteFile(filepath.Join(d.cfg.OutDir, "objects.jsonl"), []byte("{}\n"), 0644)
	allow := []netip.Prefix{netip.MustParsePrefix("198.51.100.0/24")}
	pub := []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0"), netip.MustParsePrefix("::/0")}
	d.httpAllow.Store(&allow)
	d.httpPub.Store(&pub)
	h := httpAccess(d.httpAllow.Load, d.httpPub.Load, d.apiHandler(), d.publicHandler())
	call := func(addr, url string) *httptest.ResponseRecorder {
		req := httptest.NewRequest("GET", url, nil)
		req.RemoteAddr = addr
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}
	const inside, outside = "198.51.100.7:1000", "203.0.113.9:1000"

	// 내부 : 모든 경로, 상태에 내부 정보
	for _, u := range []string{"/metrics", "/objects.jsonl", "/api/v1/history", "/api/v1/slurm"} {
		if rec := call(inside, u); rec.Code == 403 {
			t.Errorf("inside %s: 403", u)
		}
	}
	var st map[string]any
	json.Unmarshal(call(inside, "/api/v1/status").Body.Bytes(), &st)
	for _, k := range []string{"config", "slurm", "mem_mb", "started"} {
		if _, ok := st[k]; !ok {
			t.Errorf("inside status: no %s", k)
		}
	}

	// 공개 : 조회는 됨, 내부 경로는 403
	for _, u := range []string{"/api/v1/validity/AS13335/1.1.1.0/24", "/api/v1/as/AS13335", "/api/v1/prefix/1.1.1.0/24",
		"/api/v1/vrps/delta?serial=0", "/json-delta?session=7&serial=0", "/status"} {
		if rec := call(outside, u); rec.Code != 200 {
			t.Errorf("public %s: %d", u, rec.Code)
		}
	}
	for _, u := range []string{"/metrics", "/objects.jsonl", "/rejects.txt", "/repos.json", "/api/v1/history", "/api/v1/slurm",
		"/api/v1/objects", "/api/v1/ca", "/api/v1/unsafe", "/api/v1/expiring", "/jsonext", "/nothing"} {
		if rec := call(outside, u); rec.Code != 403 {
			t.Errorf("public %s: %d, want 403", u, rec.Code)
		}
	}
	st = nil
	json.Unmarshal(call(outside, "/api/v1/status").Body.Bytes(), &st)
	for _, k := range []string{"rtr_clients", "config", "slurm", "mem_mb", "started"} {
		if _, ok := st[k]; ok {
			t.Errorf("public status has %s", k)
		}
	}
	if st["serial"] == nil || st["version"] == nil {
		t.Errorf("public status lacks serial / version: %v", st)
	}
	if strings.Contains(call(outside, "/status").Body.String(), "rtr-client") {
		t.Error("public text status has rtr-client")
	}

	// 공개 쪽 /json : 주소마다 간격에 한 번. 내부는 제한 없음
	if rec := call(outside, "/json"); rec.Code != 200 || rec.Header().Get("Content-Type") != "application/json" {
		t.Fatalf("public json first: %d %q", rec.Code, rec.Header().Get("Content-Type"))
	}
	if rec := call("203.0.113.9:2000", "/json"); rec.Code != 429 || rec.Header().Get("Retry-After") == "" {
		t.Errorf("public json again: %d", rec.Code)
	}
	for i := 0; i < 2; i++ {
		if rec := call(inside, "/json"); rec.Code != 200 {
			t.Errorf("inside json %d: %d", i, rec.Code)
		}
	}

	// 공개 쪽 /api/v1/as : 주소마다 1 초에 한 번 (위에서 한 번 부름), 내부는 제한 없음 (11-05 검토 15)
	if rec := call("203.0.113.9:3000", "/api/v1/as/AS13335"); rec.Code != 429 {
		t.Errorf("public as again: %d", rec.Code)
	}
	for i := 0; i < 2; i++ {
		if rec := call(inside, "/api/v1/as/AS13335"); rec.Code != 200 {
			t.Errorf("inside as %d: %d", i, rec.Code)
		}
	}
	time.Sleep(publicQueryEvery)
	if rec := call(outside, "/api/v1/as/AS13335"); rec.Code != 200 {
		t.Errorf("public as after wait: %d", rec.Code)
	}

	// 공개 목록이 비면 밖은 403 (지금까지와 같음)
	none := []netip.Prefix{}
	d.httpPub.Store(&none)
	if rec := call(outside, "/api/v1/as/AS13335"); rec.Code != 403 {
		t.Errorf("no public list: %d", rec.Code)
	}
}

// IPv6 는 /64 하나를 한 주소로 셈
func TestClientKey(t *testing.T) {
	if a, b := clientKey("[2001:db8:1:2::1]:1"), clientKey("[2001:db8:1:2:ffff::9]:2"); a != b {
		t.Errorf("same /64: %s %s", a, b)
	}
	if a, b := clientKey("[2001:db8:1:2::1]:1"), clientKey("[2001:db8:1:3::1]:1"); a == b {
		t.Error("other /64 same key")
	}
	if got := clientKey("[::ffff:192.0.2.1]:5"); got != "192.0.2.1" {
		t.Errorf("mapped: %s", got)
	}
}

// 연결 수 상한 : n 개가 차 있으면 다음 연결은 앞의 것이 닫힐 때까지 기다림
func TestLimitListener(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	l := newLimitListener(ln, 1, nil, func(netip.Addr) bool { return true })
	defer l.Close()
	got := make(chan net.Conn, 2)
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			got <- c
		}
	}()
	c1, _ := net.Dial("tcp", ln.Addr().String())
	defer c1.Close()
	s1 := <-got
	c2, _ := net.Dial("tcp", ln.Addr().String())
	defer c2.Close()
	select {
	case <-got:
		t.Fatal("second accepted while first open")
	case <-time.After(200 * time.Millisecond):
	}
	s1.Close()
	s1.Close() // 두 번 닫아도 자리는 한 번만
	select {
	case s2 := <-got:
		s2.Close()
	case <-time.After(2 * time.Second):
		t.Fatal("second not accepted after first closed")
	}
}

// 공개 쪽 상한 (11-05 검토 5) : 주소마다 maxHTTPPerClient 개, 넘는 연결은 바로 닫힘. trusted 는 세지 않음
func TestLimitListenerPerClient(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var trusted atomic.Bool
	l := newLimitListener(ln, maxHTTPConns, nil, func(netip.Addr) bool { return trusted.Load() })
	defer l.Close()
	got := make(chan net.Conn, 64)
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			got <- c
		}
	}()
	dial := func() net.Conn {
		c, err := net.Dial("tcp", ln.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	var held []net.Conn
	for i := 0; i < maxHTTPPerClient; i++ {
		held = append(held, dial())
		held = append(held, <-got)
	}
	// 9 번째 : 서버가 바로 닫음 (읽으면 EOF)
	c := dial()
	c.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := c.Read(make([]byte, 1)); err == nil || errors.Is(err, os.ErrDeadlineExceeded) {
		t.Errorf("over per-client: read err %v, want closed", err)
	}
	c.Close()
	// 내부 (trusted) 는 상한 밖
	trusted.Store(true)
	c2 := dial()
	select {
	case s := <-got:
		s.Close()
	case <-time.After(2 * time.Second):
		t.Error("trusted not accepted")
	}
	c2.Close()
	trusted.Store(false)
	// 하나 닫으면 다시 자리
	held[1].Close()
	time.Sleep(50 * time.Millisecond)
	c3 := dial()
	select {
	case s := <-got:
		s.Close()
	case <-time.After(2 * time.Second):
		t.Error("not accepted after one closed")
	}
	c3.Close()
	for _, h := range held {
		h.Close()
	}
}

// 응답을 읽지 않는 연결은 쓰기 기한으로 끊김, 읽는 연결은 기한이 조각마다 늘어나 끝까지 받음
func TestWriteProgress(t *testing.T) {
	old := httpWriteIdle
	httpWriteIdle = 300 * time.Millisecond
	defer func() { httpWriteIdle = old }()
	big := strings.Repeat("x", 64*httpWriteChunk) // 16 MB : 소켓 버퍼보다 큼
	werr := make(chan error, 4)
	srv := httptest.NewServer(writeProgress(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, err := w.Write([]byte(big))
		werr <- err
	})))
	defer srv.Close()

	// 읽는 쪽 : 전부 받음 (전체 시간이 기한보다 길어도)
	resp, err := http.Get(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if len(b) != len(big) || <-werr != nil {
		t.Fatalf("reader got %d bytes", len(b))
	}
	// 읽지 않는 쪽 : 서버 쓰기가 기한으로 실패
	c, err := net.Dial("tcp", srv.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.(*net.TCPConn).SetReadBuffer(4096)
	c.Write([]byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n"))
	select {
	case err := <-werr:
		if err == nil {
			t.Error("non-reader: write succeeded")
		}
	case <-time.After(5 * time.Second):
		t.Error("non-reader: write not cut")
	}
}

// clientWaitEvery : 종류마다 간격이 달라도 정리가 긴 쪽 기록을 지우지 않음 (표에 "다시 되는 시각" 을 둠)
func TestClientWaitMixed(t *testing.T) {
	d := testDaemon(t)
	if d.clientWaitEvery("long", "192.0.2.1:1", time.Hour) != 0 {
		t.Fatal("first long refused")
	}
	d.fullSweep = time.Now()    // 채우는 동안은 정리 안 함 (1 초에 한 번)
	for i := 0; i < 1100; i++ { // 표를 1000 개 넘게 채우고 짧은 것만 지나가게
		d.clientWaitEvery("short", fmt.Sprintf("198.51.%d.%d:1", i/256, i%256), time.Millisecond)
	}
	time.Sleep(5 * time.Millisecond)
	d.fullSweep = time.Time{}
	d.clientWaitEvery("short", "203.0.113.1:1", time.Millisecond) // 정리가 돎
	if len(d.fullLast) > 10 {
		t.Errorf("short entries left: %d", len(d.fullLast))
	}
	if d.clientWaitEvery("long", "192.0.2.1:1", time.Hour) == 0 {
		t.Error("long entry swept by short interval")
	}
}
