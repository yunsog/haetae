package main

// rrdp_test.go : delta 두 단계 적용 (확인 실패면 폴더를 건드리지 않음), 거대한 요소 차단

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
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

// publish 하나가 상한보다 길면 XML 을 해석하기 전에 (메모리에 올리기 전에) 실패
func TestRRDPHugeElement(t *testing.T) {
	huge := writeDelta(t, `<publish uri="rsync://h/m/big.roa">`+strings.Repeat("A", maxTextRun+10)+`</publish>`)
	_, _, err := applyDeltaFile(huge, "s", 2, t.TempDir())
	if err == nil || !strings.Contains(err.Error(), "XML text longer") {
		t.Fatalf("err = %v", err)
	}
	// 상한 안의 보통 객체는 그대로 됨
	ok := writeDelta(t, `<publish uri="rsync://h/m/a.roa">`+base64.StdEncoding.EncodeToString([]byte("x"))+`</publish>`)
	if n, _, err := applyDeltaFile(ok, "s", 2, t.TempDir()); err != nil || n != 1 {
		t.Fatalf("small: n %d err %v", n, err)
	}
}

// 상태는 serial 이 최신인데 폴더가 없으면 (snapshot 바꿔 끼우다 죽음) "none" 이 아니라 snapshot 을 다시 받음
func TestRRDPStateWithoutFolder(t *testing.T) {
	snap := fmt.Sprintf(`<snapshot xmlns="%s" version="1" session_id="s" serial="1">`+
		`<publish uri="rsync://h/m/a.roa">%s</publish></snapshot>`, rrdpNS, base64.StdEncoding.EncodeToString([]byte("a")))
	var srv *httptest.Server
	srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/notification.xml":
			fmt.Fprintf(w, `<notification xmlns="%s" version="1" session_id="s" serial="1">`+
				`<snapshot uri="%s/snapshot.xml" hash="%s"/></notification>`, rrdpNS, srv.URL, hashHex([]byte(snap)))
		case "/snapshot.xml":
			fmt.Fprint(w, snap)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	f, err := newFetcher(t.TempDir(), 2)
	if err != nil {
		t.Fatal(err)
	}
	f.Logf, f.client = nil, srv.Client()
	notify := srv.URL + "/notification.xml"
	dir, statePath := rrdpPaths(f.CacheDir, notify)
	if err := saveRRDPState(statePath, &rrdpState{Notify: notify, Session: "s", Serial: 1, LastSuccess: time.Now()}); err != nil {
		t.Fatal(err)
	}
	_, res, err := f.syncRRDP(context.Background(), notify)
	if err != nil || res.Action != "snapshot" {
		t.Fatalf("action %q err %v", res.Action, err)
	}
	if got, _ := os.ReadFile(filepath.Join(dir, "h/m/a.roa")); string(got) != "a" {
		t.Errorf("a.roa = %q", got)
	}
	// 폴더가 생긴 뒤에는 바뀐 것 없음
	if _, res, err = f.syncRRDP(context.Background(), notify); err != nil || res.Action != "none" {
		t.Errorf("second: action %q err %v", res.Action, err)
	}
}

// delta 를 망 문제 (5xx) 로 못 받으면 snapshot 을 받으러 가지 않고 오류 (직전 데이터로 대체, 다음 회차에 이어서)
// delta 가 내용 문제 (해시 다름) 면 snapshot (객체 0 개인 빈 snapshot 도 폴더를 바꿔 끼움)
func TestRRDPDeltaNetErrorNoSnapshot(t *testing.T) {
	snap := fmt.Sprintf(`<snapshot xmlns="%s" version="1" session_id="s" serial="2"></snapshot>`, rrdpNS)
	deltaStatus, snapshots := 503, 0
	var srv *httptest.Server
	srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/notification.xml":
			fmt.Fprintf(w, `<notification xmlns="%s" version="1" session_id="s" serial="2">`+
				`<snapshot uri="%s/snapshot.xml" hash="%s"/><delta serial="2" uri="%s/d2.xml" hash="%s"/></notification>`,
				rrdpNS, srv.URL, hashHex([]byte(snap)), srv.URL, hashHex([]byte("other")))
		case "/snapshot.xml":
			snapshots++
			fmt.Fprint(w, snap)
		case "/d2.xml":
			w.WriteHeader(deltaStatus)
			fmt.Fprint(w, "delta body") // 200 이면 해시가 notification 과 다름 = 내용 문제
		}
	}))
	defer srv.Close()
	f, err := newFetcher(t.TempDir(), 2)
	if err != nil {
		t.Fatal(err)
	}
	f.Logf, f.client = nil, srv.Client()
	notify := srv.URL + "/notification.xml"
	dir, statePath := rrdpPaths(f.CacheDir, notify)
	os.MkdirAll(dir, 0755)
	saveRRDPState(statePath, &rrdpState{Notify: notify, Session: "s", Serial: 1, LastSuccess: time.Now()})

	if _, _, err := f.syncRRDP(context.Background(), notify); err == nil || !isNetError(err) || snapshots != 0 {
		t.Fatalf("503: err %v snapshots %d", err, snapshots)
	}
	if st, _ := loadRRDPState(statePath); st == nil || st.Serial != 1 {
		t.Errorf("state after 503: %+v", st)
	}
	deltaStatus = 200
	if _, res, err := f.syncRRDP(context.Background(), notify); err != nil || res.Action != "snapshot" || snapshots != 1 {
		t.Errorf("bad delta hash: action %q err %v snapshots %d", res.Action, err, snapshots)
	}
}

// 조건부 GET : 다 맞춘 뒤 ETag 를 적고, 다음에는 If-None-Match -> 304 면 받지 않음 ("none").
// ETag 가 바뀌면 다시 받음, 1 시간 넘게 통째로 받지 않았으면 조건 없이 받음
func TestRRDPConditionalGET(t *testing.T) {
	snap := fmt.Sprintf(`<snapshot xmlns="%s" version="1" session_id="s" serial="1">`+
		`<publish uri="rsync://h/m/a.roa">%s</publish></snapshot>`, rrdpNS, base64.StdEncoding.EncodeToString([]byte("a")))
	etag := `"v1"`
	var full, cond, notModified int
	var srv *httptest.Server
	srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/notification.xml":
			if inm := r.Header.Get("If-None-Match"); inm != "" {
				cond++
				if inm == etag {
					notModified++
					w.WriteHeader(http.StatusNotModified)
					return
				}
			}
			full++
			w.Header().Set("ETag", etag)
			fmt.Fprintf(w, `<notification xmlns="%s" version="1" session_id="s" serial="1">`+
				`<snapshot uri="%s/snapshot.xml" hash="%s"/></notification>`, rrdpNS, srv.URL, hashHex([]byte(snap)))
		case "/snapshot.xml":
			fmt.Fprint(w, snap)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	f, err := newFetcher(t.TempDir(), 2)
	if err != nil {
		t.Fatal(err)
	}
	f.Logf, f.client = nil, srv.Client()
	notify := srv.URL + "/notification.xml"
	_, statePath := rrdpPaths(f.CacheDir, notify)
	sync := func(want string) {
		t.Helper()
		if _, res, err := f.syncRRDP(context.Background(), notify); err != nil || res.Action != want || res.Serial != 1 {
			t.Fatalf("sync: %+v %v, want %s", res, err, want)
		}
	}

	sync("snapshot") // 처음 : 조건 없이
	if st, _ := loadRRDPState(statePath); st == nil || st.ETag != `"v1"` {
		t.Fatalf("etag not saved: %+v", st)
	}
	sync("none") // 304
	if full != 1 || notModified != 1 {
		t.Errorf("full %d notModified %d, want 1 1", full, notModified)
	}
	etag = `"v2"` // 서버 쪽이 바뀜 -> 200 (같은 serial 이라 none), 새 ETag
	sync("none")
	if st, _ := loadRRDPState(statePath); full != 2 || st.ETag != `"v2"` {
		t.Errorf("after change: full %d etag %q", full, st.ETag)
	}
	// 1 시간 넘게 통째로 받지 않음 -> 조건 없이
	st, _ := loadRRDPState(statePath)
	st.NotifyAt = time.Now().Add(-2 * time.Hour)
	saveRRDPState(statePath, st)
	before := cond
	sync("none")
	if cond != before || full != 3 {
		t.Errorf("stale: conditional sent (cond %d -> %d), full %d", before, cond, full)
	}
}
