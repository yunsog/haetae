package main

// repo_guard_test.go : 저장소 수집 제한 (11-05 검토 10 / 11 / 12)
//   notify 정규화, 같은 서버 비교, TA 당 저장소 상한, 회차 기한, 디스크 부족, 오래 안 쓴 폴더 정리, rsync 끔 + 데이터 없음, 바이트 예산
//   + 파일 하나의 panic (13), 잠금 / 상태 폴더 권한 (14)

import (
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestCanonicalNotify(t *testing.T) {
	ok := map[string]string{
		"https://rrdp.ripe.net/notification.xml":     "https://rrdp.ripe.net/notification.xml",
		"https://RRDP.Ripe.NET/notification.xml":     "https://rrdp.ripe.net/notification.xml",
		"https://rrdp.ripe.net:443/notification.xml": "https://rrdp.ripe.net/notification.xml",
		"https://rrdp.example:8443/n.xml":            "https://rrdp.example:8443/n.xml",
		"https://[2001:DB8::1]/n.xml":                "https://[2001:db8::1]/n.xml",
		"https://[2001:db8::1]:443/n.xml":            "https://[2001:db8::1]/n.xml",
	}
	for in, want := range ok {
		if got, err := canonicalNotify(in); err != nil || got != want {
			t.Errorf("%s = %q %v, want %q", in, got, err, want)
		}
	}
	for _, bad := range []string{
		"https://rrdp.ripe.net/notification.xml?1",
		"https://rrdp.ripe.net/notification.xml?",
		"https://rrdp.ripe.net/notification.xml#x",
		"https://user@rrdp.ripe.net/notification.xml",
		"http://rrdp.ripe.net/notification.xml",
		"https:///notification.xml",
	} {
		if got, err := canonicalNotify(bad); err == nil {
			t.Errorf("%s accepted as %q", bad, got)
		}
	}
}

// snapshot / delta 가 notification 과 같은 서버인지 : 대소문자 / :443 차이는 같은 서버
func TestSameOriginCanonical(t *testing.T) {
	if !sameOrigin("https://rrdp.ripe.net/n.xml", "https://RRDP.ripe.net:443/s/snap.xml") {
		t.Error("case / default port: not same")
	}
	if sameOrigin("https://rrdp.ripe.net/n.xml", "https://rrdp.ripe.net:8443/s.xml") || sameOrigin("https://a.example/n.xml", "https://b.example/s.xml") {
		t.Error("other port / host: same")
	}
	a, _ := url.Parse("https://A.example/x")
	b, _ := url.Parse("https://a.example:443/y")
	if !sameHost(a, b) {
		t.Error("sameHost")
	}
}

// TA 하나 아래 서로 다른 저장소는 maxReposPerTA 까지, notify 가 쓸 수 없으면 rsync 로 (경고)
func TestRepoAllowed(t *testing.T) {
	v := newValidator("", time.Now(), 1)
	ca := func(notify, repo string) *caCtx {
		return &caCtx{TA: "ripe", Cert: &rpkiCert{Notify: notify, CARepository: repo}}
	}
	for i := 0; i < maxReposPerTA; i++ {
		if err := v.repoAllowed(ca(fmt.Sprintf("https://r%d.example/n.xml", i), "rsync://x/m/")); err != nil {
			t.Fatalf("repo %d: %v", i, err)
		}
	}
	if err := v.repoAllowed(ca("https://one-more.example/n.xml", "rsync://x/m/")); err == nil {
		t.Error("over max accepted")
	}
	if err := v.repoAllowed(ca("https://R0.example:443/n.xml", "rsync://x/m/")); err != nil { // 정규화하면 이미 센 것
		t.Errorf("same repo again: %v", err)
	}
	other := &caCtx{TA: "apnic", Cert: &rpkiCert{Notify: "https://x.example/n.xml"}}
	if err := v.repoAllowed(other); err != nil { // TA 마다 따로
		t.Errorf("other TA: %v", err)
	}
	// query 가 붙은 notify : notify 를 버리고 rsync 모듈로 셈 (같은 모듈은 한 번)
	q := ca("https://rrdp.ripe.net/notification.xml?1", "rsync://x/m/a/")
	v2 := newValidator("", time.Now(), 1)
	if err := v2.repoAllowed(q); err != nil || q.Cert.Notify != "" {
		t.Errorf("query notify: %v %q", err, q.Cert.Notify)
	}
	v2.repoAllowed(ca("https://rrdp.ripe.net/notification.xml?2", "rsync://x/m/b/"))
	if n := len(v2.taRepos["ripe"]); n != 1 || v2.count["warn: rpkiNotify not usable, using rsync"] != 2 {
		t.Errorf("repos %d, warn %d", n, v2.count["warn: rpkiNotify not usable, using rsync"])
	}
	// 정규화된 notify 가 인증서에 남음 (직전 정상본 폴더도 같은 값)
	c := ca("https://RRDP.example:443/n.xml", "rsync://x/m/")
	v2.repoAllowed(c)
	if c.Cert.Notify != "https://rrdp.example/n.xml" {
		t.Errorf("notify not canonical: %q", c.Cert.Notify)
	}
}

// 회차 기한이 지나면 받지 않음 : 예전 데이터가 있으면 그것 (fallback-old), 연속 실패로 세지 않음
func TestRunDeadline(t *testing.T) {
	f, err := newFetcher(t.TempDir(), 2)
	if err != nil {
		t.Fatal(err)
	}
	f.Logf = nil
	f.RsyncBin = "/bin/false"
	f.RunDeadline = time.Millisecond
	f.reset()
	time.Sleep(5 * time.Millisecond)
	notify := "https://127.0.0.1:1/notification.xml"
	dir, sp := rrdpPaths(f.CacheDir, notify)
	os.MkdirAll(dir, 0755)
	saveRRDPState(sp, &rrdpState{Notify: notify, Session: "s", Serial: 5, LastSuccess: time.Now().Add(-5 * time.Hour)})
	c := &rpkiCert{Notify: notify, CARepository: "rsync://127.0.0.1/repo/ca/"}
	start := time.Now()
	if got := f.ensure(c); got != dir {
		t.Errorf("base %q, want old RRDP dir", got)
	}
	if time.Since(start) > time.Second {
		t.Error("fetched after deadline")
	}
	row := rrdpRow(t, f, notify)
	if row.Result != "fallback-old" || !row.Skipped || !strings.Contains(row.Error, "deadline") || row.Failures != 0 {
		t.Errorf("row %+v", row)
	}
	if f.late.Load() != 1 {
		t.Errorf("late %d", f.late.Load())
	}
	// 저장소 하나의 시간 = 기한까지 남은 시간 (짧으면)
	f.RunDeadline, f.Timeout = time.Minute, 5*time.Minute
	f.reset()
	if d := f.fetchTimeout(); d > time.Minute || d < 50*time.Second {
		t.Errorf("fetchTimeout %s", d)
	}
	f.RunDeadline = 0
	f.reset()
	if f.pastDeadline() || f.fetchTimeout() != 5*time.Minute {
		t.Error("no deadline")
	}
}

// 디스크가 모자라면 새 저장소 (상태 없음) 는 받지 않음, 연속 실패로 세지 않음
func TestLowDiskNewRepo(t *testing.T) {
	f, err := newFetcher(t.TempDir(), 2)
	if err != nil {
		t.Fatal(err)
	}
	f.Logf = nil
	f.RsyncBin = "/bin/false"
	f.LowDisk = true
	notify := "https://127.0.0.1:1/new.xml"
	c := &rpkiCert{Notify: notify, CARepository: "rsync://127.0.0.1/newrepo/ca/"}
	f.ensure(c)
	row := rrdpRow(t, f, notify)
	if row.Result != "failed" || !row.Skipped || !strings.Contains(row.Error, "low disk") || row.Failures != 0 {
		t.Errorf("row %+v", row)
	}
	if freeDisk(f.CacheDir) <= 0 {
		t.Error("freeDisk")
	}
}

// rsync 끔 + RRDP 실패 : 예전 RRDP 데이터가 없으면 "" (spawn 이 CA 실패로), 있으면 그 폴더
func TestNoRsyncNoData(t *testing.T) {
	f, err := newFetcher(t.TempDir(), 2)
	if err != nil {
		t.Fatal(err)
	}
	f.Logf = nil
	f.NoRsync = true
	f.Timeout = 5 * time.Second
	notify := "https://127.0.0.1:1/notification.xml"
	c := &rpkiCert{Notify: notify, CARepository: "rsync://127.0.0.1/repo/ca/"}
	if got := f.ensure(c); got != "" {
		t.Errorf("no data: %q", got)
	}
	f.reset()
	dir, sp := rrdpPaths(f.CacheDir, notify)
	os.MkdirAll(dir, 0755)
	saveRRDPState(sp, &rrdpState{Notify: notify, Session: "s", Serial: 1, LastSuccess: time.Now().Add(-48 * time.Hour)})
	f.health = nil // 앞의 실패 기록 (backoff 아님, 그래도 깨끗이)
	if got := f.ensure(c); got != dir {
		t.Errorf("old data: %q, want %q", got, dir)
	}
}

// 오래 안 쓴 rrdp / rsync 폴더 정리 : 이번에 쓴 것과 최근 것은 남김
func TestCleanRepos(t *testing.T) {
	f, err := newFetcher(t.TempDir(), 2)
	if err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-repoKeepUnused - time.Hour)
	mkRRDP := func(notify string, age time.Time) (string, string) {
		dir, sp := rrdpPaths(f.CacheDir, notify)
		os.MkdirAll(dir, 0755)
		os.WriteFile(filepath.Join(dir, "x.roa"), []byte("x"), 0644)
		os.WriteFile(sp, []byte("{}"), 0644)
		os.Chtimes(sp, age, age)
		return dir, sp
	}
	usedDir, usedSt := mkRRDP("https://used.example/n.xml", old)
	goneDir, goneSt := mkRRDP("https://gone.example/n.xml", old)
	newDir, _ := mkRRDP("https://recent.example/n.xml", time.Now())
	os.MkdirAll(goneDir+".stage", 0755) // 끊긴 흔적도 같이
	mkRsync := func(module string, age time.Time) string {
		d := rsyncDir(f.CacheDir, module)
		os.MkdirAll(d, 0755)
		os.Chtimes(d, age, age)
		return d
	}
	usedMod := mkRsync("rsync://h1.example/repo", old)
	goneMod := mkRsync("rsync://h2.example/repo", old)
	f.repos["rrdp https://used.example/n.xml"] = &repoFetch{}
	f.repos["rsync rsync://h1.example/repo"] = &repoFetch{}

	if n := f.cleanRepos(); n != 2 {
		t.Errorf("removed %d, want 2", n)
	}
	for _, p := range []string{usedDir, usedSt, newDir, usedMod} {
		if _, err := os.Stat(p); err != nil {
			t.Errorf("%s removed", p)
		}
	}
	for _, p := range []string{goneDir, goneSt, goneDir + ".stage", goneMod, filepath.Dir(goneMod)} {
		if _, err := os.Stat(p); err == nil {
			t.Errorf("%s left", p)
		}
	}
	if st, _ := os.Stat(usedSt); time.Since(st.ModTime()) > time.Minute {
		t.Error("used state not touched")
	}
}

// 바이트 예산 : 남은 양이 모자라면 기다리고, 돌려주면 이어감. pubPoint.done 은 한 번만 돌려줌
func TestByteBudget(t *testing.T) {
	b := newByteBudget(100)
	b.acquire(80)
	var got atomic.Bool
	go func() {
		b.acquire(50)
		got.Store(true)
	}()
	time.Sleep(50 * time.Millisecond)
	if got.Load() {
		t.Fatal("acquired over budget")
	}
	pp := &pubPoint{budget: b, held: 80}
	pp.done()
	pp.done()
	time.Sleep(50 * time.Millisecond)
	if !got.Load() {
		t.Fatal("not woken after release")
	}
	if b.left != 50 {
		t.Errorf("left %d, want 50", b.left)
	}
	(*pubPoint)(nil).done()
}

// 나열된 파일 하나의 panic 은 그 파일만 거부하고 다음 파일로, 잠금은 남지 않음 (11-05 검토 13)
func TestSafeFilePanic(t *testing.T) {
	v := newValidator("", time.Now(), 1)
	ctx := &caCtx{TA: "ripe", URI: "rsync://h/ca.cer"}
	ran := 0
	v.safeFile(ctx, mftEntry{Name: "a.roa", URI: "rsync://h/a.roa"}, "roa", func() { panic("boom") })
	v.safeFile(ctx, mftEntry{Name: "b.roa", URI: "rsync://h/b.roa"}, "roa", func() { ran++ })
	if ran != 1 {
		t.Error("next file not processed")
	}
	if v.count["roa rejected"] != 1 || len(v.objects) != 1 || !strings.Contains(v.objects[0].Reason, "panic: boom") ||
		v.objects[0].URI != "rsync://h/a.roa" {
		t.Errorf("reject %v %+v", v.count, v.objects)
	}
	done := make(chan struct{})
	go func() { v.inc("x"); close(done) }() // 잠금이 남았으면 멈춤
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("v.mu still held")
	}
}

// 잠금 파일 0600, 상태 폴더 0750 (11-05 검토 14 : 남이 읽기로 열어 flock 을 쥐면 다음 재시작이 막힘)
func TestPrivateState(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state")
	os.MkdirAll(dir, 0755)
	lf, err := os.OpenFile(filepath.Join(dir, "lock"), os.O_CREATE|os.O_RDWR, 0644)
	if err != nil {
		t.Fatal(err)
	}
	defer lf.Close()
	os.Chmod(lf.Name(), 0644) // umask 와 상관없이 옛 판 모양으로
	privateState(lf, dir)
	if st, _ := os.Stat(lf.Name()); st.Mode().Perm() != 0600 {
		t.Errorf("lock %v", st.Mode().Perm())
	}
	if st, _ := os.Stat(dir); st.Mode().Perm() != 0750 {
		t.Errorf("state %v", st.Mode().Perm())
	}
}
