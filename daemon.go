package main

// daemon.go : 상주 모드 (4 단계)
//
//   시작 : 잠금 (같은 것 두 개 방지) -> session / serial (state.json) -> 직전 VRP (출력 json) 가
//          MaxStartAge 안이면 그것으로 RTR 바로 시작 (C3, B5) -> HTTP API
//   반복 : Interval (B2 = 10 분) 마다 수집 + 검증 -> 이상 없으면 새 집합으로 (serial + 1, RTR Notify)
//          -> 출력 파일 (json / csv / objects.jsonl / rejects / repos) -> 한 줄 요약 로그 (D5)
//   이상 : TA 하나라도 실패 -> 직전 집합 유지 (A2 와 같은 생각)
//          VRP 가 DropWarn 비율 넘게 줄면 경고 (D1). HoldOnDrop 이면 반영 보류 (시험 기간은 끔)

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

type daemonConfig struct {
	CacheDir          string
	TALDir            string
	OutDir            string
	StateDir          string
	SLURM             string
	Interval          time.Duration
	Workers           int
	FetchJobs         int
	NoRsync           bool
	RTRAddr           string
	RTRAllow          []string
	RTRAuth           string // TCP-MD5 / TCP-AO 키 파일 (rtr_auth.go)
	RTRRefresh        uint32 // C5 : End of Data 에 실어 보내는 타이머 (초, v1 / v2)
	RTRRetry          uint32
	RTRExpire         uint32
	RTRTLSAddr        string // RTR over TLS 주소 (빈 값 = 안 엶)
	RTRTLSCert        string
	RTRTLSKey         string
	RTRTLSCA          string // 있으면 라우터 인증서 필수
	HTTPAddr          string
	HTTPAllow         []string      // HTTP 허용 주소 / 대역 (모든 HTTP 주소에 적용, 밖이면 403)
	JSONExt           bool          // /jsonext 엶 (-jsonext, 기본 끔)
	DeltaFullInterval time.Duration // /json-delta 전체 (reset) 를 주소마다 이 간격에 한 번 (0 = 제한 없음)
	MaxStartAge       time.Duration
	ConfPath          string  // 읽은 설정 파일 (상태 API / 로그용, 없으면 "")
	DropWarn          float64 // 0.1 = 10 % 넘게 줄면 경고
	HoldOnDrop        bool

	// Reload : systemctl reload (SIGHUP) 때 명령줄 + 설정 파일을 다시 읽어 새 값을 만듦 (main.go). nil = reload 안 됨
	Reload func() (daemonConfig, string, error) `json:"-"`
}

// runInfo : 한 회차 결과 (상태 API)
type runInfo struct {
	Start     time.Time      `json:"start"`
	Duration  string         `json:"duration"`
	DurationS float64        `json:"duration_s"`
	Applied   bool           `json:"applied"` // 새 집합으로 바꿨는지
	Reason    string         `json:"reason,omitempty"`
	VRPs      int            `json:"vrps"`
	VAPs      int            `json:"vaps"`
	Keys      int            `json:"router_keys"`
	PerTA     map[string]int `json:"vrps_per_ta"`
	FailedTA  []string       `json:"failed_tas,omitempty"`
	Counts    map[string]int `json:"counts"`
	Repos     map[string]int `json:"repos"`
	Announced int            `json:"announced"`
	Withdrawn int            `json:"withdrawn"`
	MB        int64          `json:"downloaded_mb"`
	Unsafe    int            `json:"unsafe_vrps"`
	MemMB     int64          `json:"mem_mb"`
}

// taInfo : TA 이름과 인증서 URI (CA 트리 조회의 시작점)
type taInfo struct {
	Name string `json:"name"`
	URI  string `json:"uri"`
}

type daemon struct {
	cfg   daemonConfig
	st    *store
	fetch *fetcher
	rtr   *rtrServer

	mu        sync.Mutex
	started   time.Time
	last      *runInfo
	lastOK    time.Time // 마지막으로 새 집합을 반영한 시각
	runs      int
	rtrOpen   bool
	rtrListen net.Listener
	rtrTLS    *tls.Config
	repos     []repoStatus
	view      *queryView // 조회 API 용 (첫 검증 전에는 nil)
	tas       []taInfo
	hist      []histRun
	histLines int // history.jsonl 줄 수
	slurm     *slurmFile
	slurmAt   time.Time // SLURM 을 읽은 시각

	fullMu   sync.Mutex
	fullLast map[string]time.Time // /json-delta 전체를 준 시각 (받는 쪽 주소별)

	// reload 로 바뀌는 값 (reload.go). 읽는 쪽은 d.c() 로 지금 묶음을 꺼내 씀 (C 의 포인터 교체와 같음)
	live      atomic.Pointer[daemonConfig]
	httpAllow atomic.Pointer[[]netip.Prefix]
	rtrTLSCur atomic.Pointer[tls.Config]
	confPath  string    // 읽은 설정 파일 (없으면 "")
	confAt    time.Time // 마지막으로 설정을 읽은 시각 (시작 / reload)
}

// c : 지금 설정 (reload 된 값). 시험처럼 live 가 없으면 d.cfg
func (d *daemon) c() *daemonConfig {
	if p := d.live.Load(); p != nil {
		return p
	}
	return &d.cfg
}

func runDaemon(cfg daemonConfig, once bool) int {
	for _, d := range []string{cfg.CacheDir, cfg.OutDir, cfg.StateDir} {
		if err := os.MkdirAll(d, 0755); err != nil {
			log.Print(err)
			return 1
		}
	}
	// 잠금 : 같은 상태 폴더로 두 개 뜨지 않게
	lf, err := os.OpenFile(filepath.Join(cfg.StateDir, "lock"), os.O_CREATE|os.O_RDWR, 0644)
	if err != nil {
		log.Print(err)
		return 1
	}
	if err := syscall.Flock(int(lf.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		log.Printf("already running (lock %s)", lf.Name())
		return 1
	}
	// TAL : 시작 때 한 번 확인하고 어느 것을 쓰는지 기록 (깨졌으면 시작하지 않음). 회차마다 다시 읽음
	tals, source, err := loadTALs(cfg.TALDir)
	if err != nil {
		log.Printf("TAL: %v", err)
		return 1
	}
	log.Printf("TAL (%s): %s", source, talSummary(tals))

	d := &daemon{cfg: cfg, st: &store{}, started: time.Now(), confPath: cfg.ConfPath, confAt: time.Now()}
	d.live.Store(&cfg)
	if d.fetch, err = newFetcher(cfg.CacheDir, cfg.FetchJobs); err != nil {
		log.Print(err)
		return 1
	}
	d.fetch.NoRsync = cfg.NoRsync
	d.loadState()
	d.hist, d.histLines = loadHistory(cfg.StateDir)

	if once {
		// -t 시험 모드 : 한 번 돌고 끝 (RTR / HTTP 안 엶)
		d.cycle()
		return 0
	}

	d.rtr = &rtrServer{St: d.st, Refresh: cfg.RTRRefresh, Retry: cfg.RTRRetry, Expire: cfg.RTRExpire, Logf: log.Printf}
	for _, a := range cfg.RTRAllow {
		p, err := parsePrefixOrAddr(a)
		if err != nil {
			log.Printf("rtr allow %q: %v", a, err)
			return 1
		}
		d.rtr.Allow = append(d.rtr.Allow, p)
	}
	if cfg.RTRAuth != "" {
		keys, err := loadRTRAuth(cfg.RTRAuth, log.Printf)
		if err != nil {
			log.Printf("rtr auth: %v", err)
			return 1
		}
		d.rtr.Auth = keys
	}
	if cfg.RTRTLSAddr != "" {
		tc, err := rtrTLSConfig(cfg.RTRTLSCert, cfg.RTRTLSKey, cfg.RTRTLSCA)
		if err != nil {
			log.Printf("rtr tls: %v", err)
			return 1
		}
		d.rtrTLS = tlsLive(&d.rtrTLSCur, tc)
	}
	// HTTP API : 주소 여러 개 (쉼표) 를 같은 처리기로 엶. 예 127.0.0.1:8323 (서버 안) + 0.0.0.0:8324 (밖, 허용 목록 + 방화벽으로 제한)
	if cfg.HTTPAddr != "" {
		var allow []netip.Prefix
		for _, a := range cfg.HTTPAllow {
			p, err := parsePrefixOrAddr(a)
			if err != nil {
				log.Printf("http allow %q: %v", a, err)
				return 1
			}
			allow = append(allow, p)
		}
		d.httpAllow.Store(&allow)
		h := httpAllowOnly(d.httpAllow.Load, d.apiHandler())
		log.Printf("http allow %v", cfg.HTTPAllow)
		for _, addr := range strings.Split(cfg.HTTPAddr, ",") {
			addr = strings.TrimSpace(addr)
			if addr == "" {
				continue
			}
			go func() {
				srv := &http.Server{Addr: addr, Handler: h, ReadHeaderTimeout: 10 * time.Second}
				log.Printf("http listening %s", addr)
				log.Print(srv.ListenAndServe())
			}()
		}
	}
	// 직전 VRP 로 이미 데이터가 있으면 RTR 바로
	d.st.mu.RLock()
	have := d.st.Cur != nil
	d.st.mu.RUnlock()
	if have {
		d.openRTR()
	}
	go d.watchReload() // systemctl reload haetae (SIGHUP) -> 설정 다시 읽음

	for {
		start := time.Now()
		d.cycle()
		if wait := d.c().Interval - time.Since(start); wait > 0 {
			time.Sleep(wait)
		}
	}
}

// loadState : session / serial, 직전 VRP, delta 기록
// 직전 VRP 를 못 쓰면 (없음 / 오래됨) 새 session : 같은 serial 에 다른 내용을 주면 라우터가 틀린 것을 가짐 -> 새로 받게
func (d *daemon) loadState() {
	sp := filepath.Join(d.cfg.StateDir, "state.json")
	st, err := loadRTRState(sp)
	if err == nil {
		d.st.Session, d.st.Serial = st.Session, st.Serial
		log.Printf("state: session %d serial %d (saved %s)", st.Session, st.Serial, st.Saved.Format(time.RFC3339))
	}
	jp := filepath.Join(d.cfg.OutDir, "json")
	p, perr := loadPayloadJSON(jp)
	if perr == nil && time.Since(p.Built) > d.cfg.MaxStartAge {
		perr = fmt.Errorf("too old (%s)", time.Since(p.Built).Round(time.Second))
	}
	if err != nil || perr != nil {
		var b [2]byte
		rand.Read(b[:])
		d.st.Session = binary.BigEndian.Uint16(b[:]) ^ d.st.Session
		log.Printf("state: new session %d (previous VRP: %v)", d.st.Session, perr)
		return
	}
	if hist, err := loadDeltas(filepath.Join(d.cfg.StateDir, "deltas.gob"), d.st.Session, d.st.Serial); err == nil {
		d.st.History = hist
		log.Printf("deltas loaded: %d", len(hist))
	} else {
		log.Printf("deltas: %v (start empty)", err)
	}
	d.st.update(p)
	log.Printf("previous VRP loaded: %d VRPs from %s", len(p.VRPs), p.Built.Format(time.RFC3339))
}

func (d *daemon) openRTR() {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.rtrOpen || d.rtr == nil {
		return
	}
	d.rtrOpen = true
	// 평문 TCP 포트 : TCP-MD5 / TCP-AO 키는 여기 듣기 소켓에 (키 없는 주소는 그냥 TCP)
	if d.cfg.RTRAddr != "" {
		ln, err := authListenConfig(d.rtr.Auth).Listen(context.Background(), "tcp", d.cfg.RTRAddr)
		if err != nil {
			log.Printf("rtr listen %s: %v", d.cfg.RTRAddr, err)
		} else {
			d.rtrListen = ln
			log.Printf("rtr listening %s (allow %v, tcp auth keys %d)", d.cfg.RTRAddr, d.cfg.RTRAllow, len(d.rtr.Auth))
			go d.rtr.serve(ln)
		}
	}
	// TLS 포트 (허용 목록은 같음)
	if d.cfg.RTRTLSAddr != "" && d.rtrTLS != nil {
		ln, err := authListenConfig(nil).Listen(context.Background(), "tcp", d.cfg.RTRTLSAddr)
		if err != nil {
			log.Printf("rtr tls listen %s: %v", d.cfg.RTRTLSAddr, err)
			return
		}
		log.Printf("rtr tls listening %s (client cert %v)", d.cfg.RTRTLSAddr, d.cfg.RTRTLSCA != "")
		go d.rtr.serve(tls.NewListener(ln, d.rtrTLS))
	}
}

// cycle : 한 회차 (수집 + 검증 + 반영 + 출력)
func (d *daemon) cycle() {
	defer func() {
		if p := recover(); p != nil {
			log.Printf("cycle panic: %v", p)
		}
	}()
	ri := &runInfo{Start: time.Now()}
	c := d.c() // 이 회차는 끝까지 이 설정 (도중에 reload 되면 다음 회차부터)

	tals, _, err := loadTALs(c.TALDir)
	if err != nil {
		log.Printf("TAL: %v", err)
		return
	}
	tas := make([]taInfo, 0, len(tals))
	for _, t := range tals {
		tas = append(tas, taInfo{t.Name, t.rsyncURI()})
	}
	var slurm *slurmFile
	if c.SLURM != "" {
		if slurm, err = loadSLURM(c.SLURM); err != nil {
			// SLURM 이 깨졌으면 반영하지 않음 (예외가 갑자기 사라지면 위험)
			log.Printf("SLURM %s: %v -> keep previous set", c.SLURM, err)
			return
		}
	}

	d.fetch.reset()
	d.fetch.NoRsync = c.NoRsync
	if cap(d.fetch.sem) != c.FetchJobs { // 회차 사이라 수집 중인 것 없음
		d.fetch.sem = make(chan struct{}, c.FetchJobs)
	}
	v := newValidator(d.cfg.CacheDir, time.Now(), c.Workers)
	v.Fetch = d.fetch
	v.run(tals)
	ps := newPayloadSet(v, slurm)

	ri.VRPs, ri.VAPs, ri.Keys = len(ps.VRPs), len(ps.ASPAs), len(ps.Keys)
	ri.FailedTA, ri.Counts = v.failedTA, v.count
	ri.PerTA = map[string]int{}
	for _, k := range ps.Full {
		ri.PerTA[k.TA]++
	}
	repos := d.fetch.statuses()
	ri.Repos = map[string]int{}
	for _, r := range repos {
		ri.Repos[r.Type+" "+r.Result]++
	}
	ri.MB = d.fetch.bytes.Load() >> 20
	var view *queryView

	// 반영할지
	d.st.mu.RLock()
	prev := d.st.Cur
	d.st.mu.RUnlock()
	apply := true
	switch {
	case len(v.failedTA) > 0 && prev != nil:
		apply, ri.Reason = false, fmt.Sprintf("TA failed %v, keep previous", v.failedTA)
	case len(ps.VRPs) == 0 && prev != nil:
		apply, ri.Reason = false, "no VRP, keep previous"
	case prev != nil && float64(len(ps.VRPs)) < float64(len(prev.VRPs))*(1-c.DropWarn):
		ri.Reason = fmt.Sprintf("WARNING VRP drop %d -> %d", len(prev.VRPs), len(ps.VRPs))
		if c.HoldOnDrop {
			apply = false
			ri.Reason += " (held)"
		}
	}
	if apply {
		dl, changed := d.st.update(ps)
		ri.Announced, ri.Withdrawn = len(dl.AnnVRP), len(dl.WdrVRP)
		if err := saveRTRState(filepath.Join(d.cfg.StateDir, "state.json"), d.st); err != nil {
			log.Printf("state save: %v", err)
		}
		if changed {
			if err := saveDeltas(filepath.Join(d.cfg.StateDir, "deltas.gob"), d.st); err != nil {
				log.Printf("deltas save: %v", err)
			}
		}
		if err := v.writeOutputs(d.cfg.OutDir, ri.Start); err != nil {
			log.Printf("output: %v", err)
		}
		writeRepoStatusQuiet(d.cfg.OutDir, repos)
		view = newQueryView(v, ps, repos) // writeOutputs 가 objects 를 URI 순으로 정렬한 뒤
		ri.Unsafe = len(view.Unsafe)
	}
	ri.Applied = apply
	ri.Duration = time.Since(ri.Start).Round(time.Second).String()
	ri.DurationS = time.Since(ri.Start).Seconds()
	ri.MemMB = memRSS() >> 20

	d.mu.Lock()
	d.last, d.repos, d.tas = ri, repos, tas
	d.runs++
	if apply {
		d.lastOK = time.Now()
		d.view = view
		d.slurm, d.slurmAt = slurm, ri.Start
	}
	d.mu.Unlock()
	if apply {
		d.openRTR()
	}

	d.st.mu.RLock()
	ser := d.st.Serial
	d.st.mu.RUnlock()
	d.addHistory(newHistRun(ri, ser, repos))
	// 한 줄 요약 (D5)
	log.Printf("run %s: vrps %d vaps %d keys %d +%d -%d serial %d repos %v %dMB applied=%v %s",
		ri.Duration, ri.VRPs, ri.VAPs, ri.Keys, ri.Announced, ri.Withdrawn, ser, ri.Repos, ri.MB, apply, ri.Reason)
}

// newHistRun : 회차 결과 -> 이력 한 줄
func newHistRun(ri *runInfo, serial uint32, repos []repoStatus) histRun {
	h := histRun{Start: ri.Start, DurationS: int(ri.DurationS), Applied: ri.Applied, Reason: ri.Reason, Serial: serial,
		VRPs: ri.VRPs, VAPs: ri.VAPs, Keys: ri.Keys, Announced: ri.Announced, Withdrawn: ri.Withdrawn,
		PerTA: ri.PerTA, Rejected: map[string]int{}, Unsafe: ri.Unsafe, MB: ri.MB, MemMB: ri.MemMB}
	for k, n := range ri.Counts {
		if t, ok := strings.CutSuffix(k, " rejected"); ok {
			h.Rejected[t] = n
		}
	}
	for _, r := range repos {
		if r.Result != "ok" {
			h.ReposFailed++
		}
	}
	return h
}

// httpAllowOnly : 허용 목록 밖에서 온 요청은 403 (ufw 와 두 겹). 목록이 비면 아무도 못 씀 (RTR 과 같음)
// allow 는 요청마다 불러 지금 목록을 얻음 (reload 로 바뀜)
func httpAllowOnly(allow func() *[]netip.Prefix, h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ap, err := netip.ParseAddrPort(r.RemoteAddr)
		var list []netip.Prefix
		if p := allow(); p != nil {
			list = *p
		}
		if err == nil {
			ip := ap.Addr().Unmap()
			for _, p := range list {
				if p.Contains(ip) {
					h.ServeHTTP(w, r)
					return
				}
			}
		}
		http.Error(w, "forbidden", http.StatusForbidden)
	})
}
