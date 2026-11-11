package main

// repo.go : 저장소 수집 관리
//
// 검증 트리를 내려가다 CA 를 만나면 그 CA 의 저장소를 (이번 회차에 아직 안 받았으면) 받음.
//   저장소 = RRDP notification URI (있으면) 또는 rsync caRepository
// 같은 저장소는 한 번만 (먼저 온 CA 가 받고 나머지는 기다림), 동시 수집은 Concurrency 개 (B2 = 32).
// 결정 B1 : RRDP 실패 -> 직전에 받은 RRDP 데이터가 FallbackAfter (큰 저장소는 FallbackAfterLarge) 안이면 그것을 계속 씀 (A2),
//           그보다 오래 실패했거나 받은 적이 없으면 rsync 로 대체.
// RRDP 줄의 결과 : ok / fallback-old (1 시간 안 직전 데이터) / fallback-rsync (rsync 가 성공했을 때만) /
//           failed (rsync 도 실패, 또는 rsync 끔). failed 여도 예전 RRDP 데이터가 있으면 읽음 (ensure)
// 결과는 CA 의 객체를 읽을 기준 폴더 (그 아래가 <host>/<path>).

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// repoStatus : 저장소 하나의 이번 회차 결과 (상태 API, E3)
type repoStatus struct {
	URI      string        `json:"uri"`
	Type     string        `json:"type"`   // rrdp / rsync
	Result   string        `json:"result"` // ok / failed / fallback-old / fallback-rsync
	Action   string        `json:"action,omitempty"`
	Serial   uint64        `json:"serial,omitempty"`
	Files    int           `json:"files,omitempty"`
	Start    time.Time     `json:"start"`
	Duration time.Duration `json:"duration_ns"`
	Error    string        `json:"error,omitempty"`
	// 연속 실패와 재시도 간격 (0.2.0, repoHealth). 실패가 3 번 이어지면 간격을 늘림 (backoff)
	Failures    int        `json:"consecutive_failures,omitempty"`
	LastSuccess *time.Time `json:"last_success,omitempty"` // 이 프로세스가 시작한 뒤 마지막 성공
	NextTry     *time.Time `json:"next_try,omitempty"`     // 이 시각 전에는 받지 않음 (Skipped)
	Skipped     bool       `json:"skipped,omitempty"`      // 이번 회차는 backoff 로 받지 않음 (직전 데이터로)
}

// repoHealth : 저장소 하나의 연속 실패 기록 (회차를 넘어 유지, 재시작하면 처음부터, 판 올리기는 넘김)
type repoHealth struct {
	failures    int
	lastErr     string
	lastSuccess time.Time
	nextTry     time.Time
}

// repoHealthState : 판 올리기로 넘기는 repoHealth (gob 은 대문자 칸만)
type repoHealthState struct {
	Failures             int
	LastErr              string
	LastSuccess, NextTry time.Time
}

// healthState : 판 올리기 때 넘김 (handover.go)
func (f *fetcher) healthState() map[string]repoHealthState {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := map[string]repoHealthState{}
	for k, h := range f.health {
		out[k] = repoHealthState{h.failures, h.lastErr, h.lastSuccess, h.nextTry}
	}
	return out
}

// setHealth : 넘겨받은 기록 (새 판 시작 때, 회차 전)
func (f *fetcher) setHealth(m map[string]repoHealthState) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.health = map[string]*repoHealth{}
	for k, s := range m {
		f.health[k] = &repoHealth{s.Failures, s.LastErr, s.LastSuccess, s.NextTry}
	}
}

// backoffFor : 연속 n 번 실패한 뒤 다음 시도까지 (2 번까지는 다음 회차에 바로, 3 번부터 10 분 · 20 분 · 40 분, 최대 1 시간)
func backoffFor(n int) time.Duration {
	if n < 3 {
		return 0
	}
	d := 10 * time.Minute << (n - 3)
	if d > time.Hour || d <= 0 {
		d = time.Hour
	}
	return d
}

type repoFetch struct {
	done chan struct{}
	base string // 객체를 읽을 기준 폴더
}

type fetcher struct {
	CacheDir      string
	RsyncBin      string
	Timeout       time.Duration // 저장소 하나 (B3 = 5 분)
	FallbackAfter time.Duration // RRDP 가 이만큼 연속 실패하면 rsync (B1)
	// 큰 저장소 (객체 largeRepoObjects 이상) 는 더 기다림 (11-02 사용자 : 3 시간 = RIR 이 RRDP 장애에 대응할 시간.
	// 큰 모듈은 rsync 가 5 분 제한에 걸리기 쉽고, 모든 RP 가 한꺼번에 rsync 로 몰리면 rsync 도 넘어감.
	// draft-ietf-sidrops-prefer-rrdp-02 는 1 시간 넘게 미루지 말라 (MUST NOT) 고 하지만 큰 저장소만 일부러 다르게, docs/decisions.md)
	FallbackAfterLarge time.Duration
	NoRsync            bool
	Offline            bool // 받지 않고 캐시에서만 고름 (판 올리기 직후 조회 결과 다시 만들기, daemon.go buildView)
	Logf               func(string, ...any)
	// 회차 기한 (fetch.deadline, 0 = 없음, 11-05) : reset 때부터 이만큼 지나면 남은 저장소는 받지 않고 직전 데이터로 (repo_guard.go)
	RunDeadline time.Duration
	LowDisk     bool // 디스크가 모자람 (checkDisk) : 새 저장소는 받지 않음

	client *http.Client
	tmpDir string
	sem    chan struct{}

	mu     sync.Mutex
	repos  map[string]*repoFetch // 이번 회차에 받은 (받는 중인) 저장소
	status []repoStatus
	health map[string]*repoHealth // key = "rrdp <notify>" / "rsync <module>". reset 해도 남음

	bytes  atomic.Int64
	rsyncs atomic.Int64

	deadline time.Time    // 이번 회차의 수집 기한 (reset 이 정함, 0 = 없음)
	late     atomic.Int64 // 기한이 지나 받지 않은 저장소 수
}

func newFetcher(cacheDir string, concurrency int) (*fetcher, error) {
	f := &fetcher{
		CacheDir:           cacheDir,
		RsyncBin:           "/usr/bin/rsync",
		Timeout:            5 * time.Minute,
		FallbackAfter:      time.Hour,
		FallbackAfterLarge: 3 * time.Hour,
		Logf:               log.Printf,
		client:             newHTTPClient(),
		tmpDir:             filepath.Join(cacheDir, "tmp"),
		sem:                make(chan struct{}, concurrency),
	}
	for _, d := range []string{"rrdp", "rsync", "ta", "tmp"} {
		if err := os.MkdirAll(filepath.Join(cacheDir, d), 0755); err != nil {
			return nil, err
		}
	}
	// 지난번에 남은 임시 파일 정리
	old, _ := filepath.Glob(filepath.Join(f.tmpDir, "*"))
	for _, p := range old {
		os.Remove(p)
	}
	f.reset()
	return f, nil
}

// reset : 새 회차 시작
func (f *fetcher) reset() {
	f.mu.Lock()
	f.repos = map[string]*repoFetch{}
	f.status = nil
	f.deadline = time.Time{}
	if f.RunDeadline > 0 {
		f.deadline = time.Now().Add(f.RunDeadline)
	}
	f.mu.Unlock()
	f.bytes.Store(0)
	f.rsyncs.Store(0)
	f.late.Store(0)
}

func (f *fetcher) logf(format string, a ...any) {
	if f.Logf != nil {
		f.Logf(format, a...)
	}
}

func (f *fetcher) addBytes(n int64) { f.bytes.Add(n) }
func (f *fetcher) addRsync()        { f.rsyncs.Add(1) }

func (f *fetcher) record(s repoStatus) {
	f.mu.Lock()
	f.status = append(f.status, s)
	f.mu.Unlock()
}

// skipUntil : key 를 지금 받지 말아야 하면 다음 시도 시각 (아니면 0), 그리고 지금까지 기록
func (f *fetcher) skipUntil(key string) (time.Time, repoHealth) {
	f.mu.Lock()
	defer f.mu.Unlock()
	h := f.health[key]
	if h == nil {
		return time.Time{}, repoHealth{}
	}
	if time.Now().Before(h.nextTry) {
		return h.nextTry, *h
	}
	return time.Time{}, *h
}

// repoDone : 한 번 시도한 결과를 기록하고 상태 칸을 채움. retryAfter = 서버가 준 Retry-After (없으면 0)
func (f *fetcher) repoDone(key string, st *repoStatus, err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.health == nil {
		f.health = map[string]*repoHealth{}
	}
	h := f.health[key]
	if h == nil {
		h = &repoHealth{}
		f.health[key] = h
	}
	now := time.Now()
	if err == nil {
		h.failures, h.lastErr, h.lastSuccess, h.nextTry = 0, "", now, time.Time{}
	} else {
		h.failures++
		h.lastErr = err.Error()
		wait := backoffFor(h.failures)
		var ne *netError
		if errors.As(err, &ne) && ne.retryAfter > wait {
			wait = min(ne.retryAfter, time.Hour) // 서버가 기다리라고 함 (429 / 503)
		}
		h.nextTry = now.Add(wait)
	}
	fillHealth(st, h)
}

func fillHealth(st *repoStatus, h *repoHealth) {
	st.Failures = h.failures
	if !h.lastSuccess.IsZero() {
		t := h.lastSuccess
		st.LastSuccess = &t
	}
	if time.Now().Before(h.nextTry) {
		t := h.nextTry
		st.NextTry = &t
	}
}

// statuses : 이번 회차 저장소 결과 (URI 순)
func (f *fetcher) statuses() []repoStatus {
	f.mu.Lock()
	out := append([]repoStatus(nil), f.status...)
	f.mu.Unlock()
	sort.Slice(out, func(i, j int) bool { return out[i].URI < out[j].URI })
	return out
}

// once : key 저장소를 이번 회차에 한 번만 받음. 다른 CA 는 끝날 때까지 기다림
func (f *fetcher) once(key string, fn func() string) string {
	f.mu.Lock()
	r, ok := f.repos[key]
	if !ok {
		r = &repoFetch{done: make(chan struct{})}
		f.repos[key] = r
	}
	f.mu.Unlock()
	if ok {
		<-r.done
		return r.base
	}
	f.sem <- struct{}{}
	func() {
		// panic 이 나도 기다리는 CA 들이 멈추지 않게 반드시 done 을 닫음 (base 는 빈 값)
		defer func() {
			if p := recover(); p != nil {
				f.logf("repo %s: panic: %v", key, p)
			}
			<-f.sem
			close(r.done)
		}()
		r.base = fn()
	}()
	return r.base
}

// ensure : CA 인증서의 저장소를 받고 객체 기준 폴더를 돌려줌
func (f *fetcher) ensure(c *rpkiCert) string {
	if f.Offline {
		return f.ensureOffline(c)
	}
	if c.Notify == "" {
		base, _ := f.ensureRsync(c.CARepository)
		return base
	}
	base, ok := f.ensureRRDP(c.Notify)
	if ok {
		return base
	}
	if f.NoRsync {
		// rsync 끔 : 예전에 받은 RRDP 데이터가 있으면 그것 (A2). 없으면 "" = 그 CA 실패 (spawn).
		// 전에는 "" 로 돌아가 uriPath 가 프로세스 현재 폴더 기준 상대 경로를 읽었음 (11-05 검토 낮음)
		dir, statePath := rrdpPaths(f.CacheDir, c.Notify)
		if _, err := loadRRDPState(statePath); err == nil {
			return dir
		}
		return ""
	}
	rbase, rok := f.ensureRsync(c.CARepository)
	f.rsyncOutcome(c.Notify, rsyncModule(c.CARepository), rok)
	if !rok {
		// rsync 도 실패 : 예전에 받은 온전한 RRDP 데이터가 있으면 그것 (A2, 쓸 수 있는지는 manifest 유효기간이 정함)
		dir, statePath := rrdpPaths(f.CacheDir, c.Notify)
		if _, err := loadRRDPState(statePath); err == nil {
			return dir
		}
	}
	return rbase
}

// ensureOffline : 받지 않고 캐시에서 기준 폴더를 고름 (회차 기록 / 연속 실패 기록 없음). 받을 때와 같은 규칙 :
// RRDP 데이터가 있고 마지막 성공이 FallbackAfter (큰 저장소 FallbackAfterLarge) 안이면 RRDP, 아니면 rsync 모듈 폴더가 있으면 rsync, 없으면 예전 RRDP
func (f *fetcher) ensureOffline(c *rpkiCert) string {
	rbase := filepath.Join(f.CacheDir, "rsync")
	if c.Notify == "" {
		return rbase
	}
	return f.once("offline "+c.Notify, func() string {
		dir, sp := rrdpPaths(f.CacheDir, c.Notify)
		st, err := loadRRDPState(sp)
		if err != nil {
			return rbase
		}
		if time.Since(st.LastSuccess) < f.fallbackAfter(dir) || f.NoRsync {
			return dir
		}
		if m := rsyncModule(c.CARepository); m != "" {
			if _, err := os.Stat(filepath.Join(rbase, filepath.FromSlash(strings.TrimPrefix(m, "rsync://")))); err == nil {
				return rbase
			}
		}
		return dir
	})
}

// largeRepoObjects : 이만큼 객체가 있으면 큰 저장소 (RIR 들, 1 만 넘는 곳)
const largeRepoObjects = 10000

// fallbackAfter : 이 RRDP 폴더가 rsync 로 넘어가기 전 기다리는 시간. RRDP 가 실패한 때만 부름 (폴더를 세다가 1 만에서 멈춤)
func (f *fetcher) fallbackAfter(dir string) time.Duration {
	if f.FallbackAfterLarge > f.FallbackAfter && countFiles(dir, largeRepoObjects) >= largeRepoObjects {
		return f.FallbackAfterLarge
	}
	return f.FallbackAfter
}

// countFiles : 폴더 아래 파일 수 (limit 에 닿으면 멈춤)
func countFiles(dir string, limit int) int {
	n := 0
	stop := errors.New("enough")
	filepath.WalkDir(dir, func(_ string, de fs.DirEntry, err error) error {
		if err == nil && !de.IsDir() {
			if n++; n >= limit {
				return stop
			}
		}
		return nil
	})
	return n
}

// ensureRRDP : ok = 이 폴더를 쓰면 됨 (이번에 성공, 또는 실패했지만 직전 데이터가 FallbackAfter / 큰 저장소 FallbackAfterLarge 안)
func (f *fetcher) ensureRRDP(notify string) (string, bool) {
	var ok bool
	base := f.once("rrdp "+notify, func() string {
		start := time.Now()
		key := "rrdp " + notify
		var dir string
		var res rrdpResult
		var err error
		skip, h := f.skipUntil(key)
		_, statePath := rrdpPaths(f.CacheDir, notify)
		_, serr := os.Stat(statePath)
		// held = 이 저장소 탓이 아닌 이유로 받지 않음 (회차 기한, 새 저장소인데 디스크 부족) : 연속 실패로 세지 않음
		held := skip.IsZero() && (f.pastDeadline() || (f.LowDisk && serr != nil))
		switch {
		case held:
			dir, _ = rrdpPaths(f.CacheDir, notify)
			err = errLowDisk
			if f.pastDeadline() {
				err = errRunDeadline
				f.late.Add(1)
			}
		case skip.IsZero():
			ctx, cancel := context.WithTimeout(context.Background(), f.fetchTimeout())
			dir, res, err = f.syncRRDP(ctx, notify)
			cancel()
		default:
			dir, _ = rrdpPaths(f.CacheDir, notify)
			err = fmt.Errorf("skipped after %d failures until %s (last: %s)", h.failures, skip.Format(time.RFC3339), h.lastErr)
		}
		st := repoStatus{URI: notify, Type: "rrdp", Action: res.Action, Serial: res.Serial, Files: res.Files, Start: start, Duration: time.Since(start)}
		if skip.IsZero() && !held {
			f.repoDone(key, &st, err)
		} else {
			st.Skipped = true
			fillHealth(&st, &h)
		}
		if err == nil {
			st.Result = "ok"
			f.record(st)
			return dir
		}
		st.Error = err.Error()
		if old, e := loadRRDPState(statePath); e == nil && (held || time.Since(old.LastSuccess) < f.fallbackAfter(dir)) {
			st.Result = "fallback-old"
			f.record(st)
			return dir
		}
		// 일단 failed. rsync 가 성공하면 ensure 가 fallback-rsync 로 바꿈 (rsyncOutcome)
		st.Result = "failed"
		f.record(st)
		return "" // 빈 값 = rsync 로
	})
	if base != "" {
		ok = true
	}
	return base, ok
}

// rsyncOutcome : RRDP 대신 받은 rsync 결과를 RRDP 줄에 반영.
// 성공 -> fallback-rsync, 실패 -> failed 그대로 두고 오류에 rsync 실패를 덧붙임.
// 같은 notify 의 CA 가 여럿이면 여러 번 불림 -> 한 번이라도 성공하면 fallback-rsync, 덧붙이기는 한 번만
func (f *fetcher) rsyncOutcome(notify, module string, ok bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for i := range f.status {
		st := &f.status[i]
		if st.Type != "rrdp" || st.URI != notify || st.Result != "failed" {
			continue
		}
		note := " / rsync " + module + " failed"
		if ok {
			st.Result = "fallback-rsync"
			st.Error = strings.TrimSuffix(st.Error, note)
		} else if !strings.HasSuffix(st.Error, note) {
			st.Error += note
		}
	}
}

// rsyncModule : rsync://host/module/path -> rsync://host/module (rpki-client 처럼 모듈 단위로 한 번)
func rsyncModule(repo string) string {
	parts := strings.SplitN(strings.TrimPrefix(repo, "rsync://"), "/", 3)
	if len(parts) < 2 || parts[0] == "" || parts[1] == "" {
		return ""
	}
	return "rsync://" + parts[0] + "/" + parts[1]
}

// ensureRsync : caRepository 가 속한 모듈을 rsync. 실패해도 (A2) 지난번 받은 폴더를 그대로 씀
// ok = 이번 rsync 성공
func (f *fetcher) ensureRsync(repo string) (string, bool) {
	base := filepath.Join(f.CacheDir, "rsync")
	key := rsyncModule(repo)
	if key == "" {
		return base, false
	}
	res := f.once("rsync "+key, func() string {
		start := time.Now()
		hkey := "rsync " + key
		var err error
		skip, h := f.skipUntil(hkey)
		_, derr := os.Stat(rsyncDir(f.CacheDir, key))
		held := skip.IsZero() && (f.pastDeadline() || (f.LowDisk && derr != nil)) // rrdp 와 같음 : 연속 실패로 세지 않음
		switch {
		case held:
			err = errLowDisk
			if f.pastDeadline() {
				err = errRunDeadline
				f.late.Add(1)
			}
		case skip.IsZero():
			ctx, cancel := context.WithTimeout(context.Background(), f.fetchTimeout())
			err = f.runRsync(ctx, key)
			cancel()
		default:
			err = fmt.Errorf("skipped after %d failures until %s (last: %s)", h.failures, skip.Format(time.RFC3339), h.lastErr)
		}
		st := repoStatus{URI: key, Type: "rsync", Result: "ok", Start: start, Duration: time.Since(start)}
		if skip.IsZero() && !held {
			f.repoDone(hkey, &st, err)
		} else {
			st.Skipped = true
			fillHealth(&st, &h)
		}
		if err != nil {
			st.Result, st.Error = "failed", err.Error()
			f.record(st)
			return "" // 빈 값 = 실패
		}
		f.record(st)
		return base
	})
	return base, res != ""
}

// fetchTA : TAL 의 URI 들로 TA 인증서를 받아 <cache>/ta/<이름>/ 에 둠 (https 먼저, 실패하면 rsync)
// 다 실패하면 지난번에 받은 것을 그대로 씀
func (f *fetcher) fetchTA(t *tal) error {
	if f.Offline {
		return nil // 캐시의 TA 그대로
	}
	dir := filepath.Join(f.CacheDir, "ta", t.Name)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}
	var lastErr error
	for _, u := range t.URIs {
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		var data []byte
		var err error
		if strings.HasPrefix(u, "https://") {
			var tmp string
			if tmp, err = f.httpGet(ctx, u, maxObjectSize, ""); err == nil {
				data, err = os.ReadFile(tmp)
				os.Remove(tmp)
			}
		} else {
			data, err = f.rsyncFile(ctx, u)
		}
		cancel()
		if err == nil {
			// 캐시에 넣기 전에 TAL 키와 맞는지 확인 : 서버가 엉뚱한 파일을 주어도 캐시의 정상 TA 를 지우지 않음
			if _, cerr := t.checkTA(data); cerr != nil {
				err = fmt.Errorf("not the TA of this TAL: %w", cerr)
			}
		}
		if err == nil {
			for _, other := range t.URIs {
				os.Remove(filepath.Join(dir, filepath.Base(other)))
			}
			return writeFileAtomic(filepath.Join(dir, filepath.Base(u)), data)
		}
		lastErr = fmt.Errorf("%s: %w", u, err)
	}
	return lastErr
}

// rsyncFile : 파일 하나를 rsync 로 받아 내용을 돌려줌
func (f *fetcher) rsyncFile(ctx context.Context, u string) ([]byte, error) {
	if _, err := url.Parse(u); err != nil || !validURI(u, "rsync://") {
		return nil, fmt.Errorf("bad URI")
	}
	tmp, err := os.MkdirTemp(f.tmpDir, "ta.*")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(tmp)
	cmd := exec.CommandContext(ctx, f.RsyncBin, "-t", "--no-motd", "--timeout=60", "--contimeout=15",
		fmt.Sprintf("--max-size=%d", maxObjectSize), "--", u, tmp+"/")
	cmd.Env = []string{"PATH=/usr/bin:/bin", "LANG=C"}
	if out, err := cmd.CombinedOutput(); err != nil {
		return nil, fmt.Errorf("%v: %s", err, strings.TrimSpace(string(out)))
	}
	return os.ReadFile(filepath.Join(tmp, filepath.Base(u)))
}
