package main

// repo.go : 저장소 수집 관리
//
// 검증 트리를 내려가다 CA 를 만나면 그 CA 의 저장소를 (이번 회차에 아직 안 받았으면) 받음.
//   저장소 = RRDP notification URI (있으면) 또는 rsync caRepository
// 같은 저장소는 한 번만 (먼저 온 CA 가 받고 나머지는 기다림), 동시 수집은 Concurrency 개 (B2 = 32).
// 결정 B1 : RRDP 실패 -> 직전에 받은 RRDP 데이터가 FallbackAfter 안이면 그것을 계속 씀 (A2),
//           그보다 오래 실패했거나 받은 적이 없으면 rsync 로 대체.
// 결과는 CA 의 객체를 읽을 기준 폴더 (그 아래가 <host>/<path>).

import (
	"context"
	"fmt"
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
	NoRsync       bool
	Logf          func(string, ...any)

	client *http.Client
	tmpDir string
	sem    chan struct{}

	mu     sync.Mutex
	repos  map[string]*repoFetch // 이번 회차에 받은 (받는 중인) 저장소
	status []repoStatus

	bytes  atomic.Int64
	rsyncs atomic.Int64
}

func newFetcher(cacheDir string, concurrency int) (*fetcher, error) {
	f := &fetcher{
		CacheDir:      cacheDir,
		RsyncBin:      "/usr/bin/rsync",
		Timeout:       5 * time.Minute,
		FallbackAfter: time.Hour,
		Logf:          log.Printf,
		client:        newHTTPClient(),
		tmpDir:        filepath.Join(cacheDir, "tmp"),
		sem:           make(chan struct{}, concurrency),
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
	f.mu.Unlock()
	f.bytes.Store(0)
	f.rsyncs.Store(0)
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
	if c.Notify == "" {
		base, _ := f.ensureRsync(c.CARepository)
		return base
	}
	base, ok := f.ensureRRDP(c.Notify)
	if ok || f.NoRsync {
		return base
	}
	rbase, rok := f.ensureRsync(c.CARepository)
	if !rok {
		// rsync 도 실패 : 예전에 받은 온전한 RRDP 데이터가 있으면 그것 (A2, 쓸 수 있는지는 manifest 유효기간이 정함)
		dir, statePath := rrdpPaths(f.CacheDir, c.Notify)
		if _, err := loadRRDPState(statePath); err == nil {
			return dir
		}
	}
	return rbase
}

// ensureRRDP : ok = 이 폴더를 쓰면 됨 (이번에 성공, 또는 실패했지만 직전 데이터가 FallbackAfter 안)
func (f *fetcher) ensureRRDP(notify string) (string, bool) {
	var ok bool
	base := f.once("rrdp "+notify, func() string {
		start := time.Now()
		ctx, cancel := context.WithTimeout(context.Background(), f.Timeout)
		defer cancel()
		dir, res, err := f.syncRRDP(ctx, notify)
		st := repoStatus{URI: notify, Type: "rrdp", Action: res.Action, Serial: res.Serial, Files: res.Files, Start: start, Duration: time.Since(start)}
		if err == nil {
			st.Result = "ok"
			f.record(st)
			return dir
		}
		st.Error = err.Error()
		_, statePath := rrdpPaths(f.CacheDir, notify)
		if old, e := loadRRDPState(statePath); e == nil && time.Since(old.LastSuccess) < f.FallbackAfter {
			st.Result = "fallback-old"
			f.record(st)
			return dir
		}
		st.Result = "fallback-rsync"
		f.record(st)
		return "" // 빈 값 = rsync 로
	})
	if base != "" {
		ok = true
	}
	return base, ok
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
		ctx, cancel := context.WithTimeout(context.Background(), f.Timeout)
		defer cancel()
		err := f.runRsync(ctx, key)
		st := repoStatus{URI: key, Type: "rsync", Result: "ok", Start: start, Duration: time.Since(start)}
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
			// 받은 것이 TAL 키와 맞는지는 loadTA 가 확인. 여기서는 파일만 바꿔 놓음
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
