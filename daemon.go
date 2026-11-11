package main

// daemon.go : 상주 모드 (4 단계)
//
//   시작 : 잠금 (같은 것 두 개 방지) -> 직전 집합 + session / serial (state/payload.gob) 이
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
	"sort"
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
	FetchDeadline     time.Duration // 회차의 수집 기한 (0 = 없음, 11-05)
	NoRsync           bool
	RTRAddr           string
	RTRAllow          []string
	RTRAuth           string // TCP-MD5 / TCP-AO 키 파일 (rtr_auth.go)
	RTRRefresh        uint32 // C5 : End of Data 에 실어 보내는 타이머 (초, v1 / v2)
	RTRRetry          uint32
	RTRExpire         uint32
	RTRMaxConns       int      // RTR 동시 연결 상한 (0 = 없음)
	RTRMaxPerIP       int      // 주소 하나 (IPv6 /64) 의 RTR 동시 연결 상한 (0 = 없음)
	RTRTrusted        []string // 운영 라우터 대역 (11-05) : 늘 허용, 상한은 RTRTrustedMax 만
	RTRTrustedMax     int      // trusted 대역의 RTR 동시 연결 상한 (0 = 없음)
	RTRTLSAddr        string   // RTR over TLS 주소 (빈 값 = 안 엶)
	RTRTLSCert        string
	RTRTLSKey         string
	RTRTLSCA          string // 있으면 라우터 인증서 필수
	HTTPAddr          string
	HTTPAllow         []string      // HTTP 허용 주소 / 대역 (모든 HTTP 주소에 적용, 밖이면 403)
	HTTPPublic        []string      // HTTP 공개 쪽 허용 (조회 경로만, api_public.go). 빈 값 = 공개 쪽 없음
	JSONExt           bool          // /jsonext 엶 (-jsonext, 기본 끔)
	DeltaFullInterval time.Duration // /json-delta 전체 (reset) 를 주소마다 이 간격에 한 번 (0 = 제한 없음)
	MaxStartAge       time.Duration
	StaleWarn         time.Duration // 집합이 이보다 오래되면 경고 / 상태 stale (ops.go, 0 = 안 봄)
	StaleClose        time.Duration // 집합이 이보다 오래되면 RTR 닫음 (0 = 끔)
	ConfPath          string        // 읽은 설정 파일 (상태 API / 로그용, 없으면 "")
	DropWarn          float64       // 0.1 = 10 % 넘게 줄면 경고
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
	Bytes     int64          `json:"downloaded_bytes"` // 원값 (MB 는 반올림, 11-02)
	Unsafe    int            `json:"unsafe_vrps"`
	MemMB     int64          `json:"mem_mb,omitempty"` // 공개 쪽 상태에서는 0 (빠짐)
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

	mu          sync.Mutex
	started     time.Time
	last        *runInfo
	lastOK      time.Time // 마지막으로 새 집합을 반영한 시각
	runs        int
	stale       bool           // 집합이 stale-warn 보다 오래됨 (ops.go)
	stopping    bool           // SIGTERM 받음 : RTR 을 다시 열지 않음
	cycleStart  time.Time      // 지금 도는 회차의 시작 (없으면 0, watchdog 이 봄)
	applyMu     sync.Mutex     // 반영 + 저장 (payload.gob, 출력 파일) 구간. SIGTERM 은 이것이 끝나길 기다림
	httpSrv     []*http.Server // SIGTERM 때 닫음
	httpLn      []httpListen   // 듣기 소켓 (판 올리기 때 새 판으로 넘김)
	httpHandler http.Handler
	httpHold    acceptHold        // 판 올리기 동안 받기 멈춤
	httpBusyMu  sync.Mutex        // httpBusy 보호
	httpBusy    map[net.Conn]bool // 요청을 처리 중인 연결 (판 올리기는 이것이 0 이 되길 기다림)
	lockFile    *os.File          // 상태 폴더 잠금 (flock). 프로세스가 끝날 때까지 쥐고 있어야 함 : 안 쓰면 GC 가 닫아 잠금이 풀림
	rtrOpen     bool              // 설정된 RTR 포트 (평문 / TLS) 를 모두 열었음
	rtrListen   net.Listener
	rtrTLSLn    net.Listener
	rtrTLS      *tls.Config
	repos       []repoStatus
	view        *queryView // 조회 API 용 (첫 검증 전에는 nil)
	tas         []taInfo
	hist        []histRun
	histLines   int // history.jsonl 줄 수
	slurm       *slurmFile
	slurmAt     time.Time // SLURM 을 읽은 시각
	slurmErr    string    // 마지막 회차의 SLURM 읽기 오류 (없으면 "", 상태 API slurm.error)

	notApplied map[string]int // 반영 안 한 회차 수, 이유별 (/metrics haetae_runs_not_applied_total, d.mu)

	fullMu    sync.Mutex
	fullLast  map[string]time.Time // 종류 + 받는 쪽 주소 -> 다시 받아도 되는 시각 (/json-delta 전체, 공개 쪽 /json /csv /api/v1/as)
	fullSweep time.Time            // fullLast 를 마지막으로 정리한 때

	// reload 로 바뀌는 값 (reload.go). 읽는 쪽은 d.c() 로 지금 묶음을 꺼내 씀 (C 의 포인터 교체와 같음)
	live      atomic.Pointer[daemonConfig]
	httpAllow atomic.Pointer[[]netip.Prefix]
	httpPub   atomic.Pointer[[]netip.Prefix] // 공개 쪽 허용 (api_public.go)
	rtrTLSCur atomic.Pointer[tls.Config]
	confPath  string    // 읽은 설정 파일 (없으면 "")
	confAt    time.Time // 마지막으로 설정을 읽은 시각 (시작 / reload)

	// 판 올리기 (handover.go)
	gate   chan struct{} // 회차 하나 = 이 자리 하나. 판 올리기는 이것을 잡아 돌던 회차가 끝나길 기다림
	exe    string        // 시작 때의 실행 파일 경로 (새 판이 같은 경로에 깔림)
	upBusy atomic.Bool
	ho     handoverInfo // 상태 API (d.mu)
}

// httpListen : HTTP 주소 하나의 듣기 소켓
type httpListen struct {
	Addr string
	Ln   net.Listener
}

// c : 지금 설정 (reload 된 값). 시험처럼 live 가 없으면 d.cfg
func (d *daemon) c() *daemonConfig {
	if p := d.live.Load(); p != nil {
		return p
	}
	return &d.cfg
}

// privateState : 잠금 파일 0600, 상태 폴더 0750 (11-05 검토 14). 처음 만든 판이 0644 / 0755 였으므로 시작 때마다 고침.
// 리눅스 flock 은 읽기로 연 파일에도 걸려, 남이 읽을 수 있으면 다른 계정이 잠금을 쥐어 다음 재시작을 막을 수 있음.
// 출력 (out) / 캐시 (cache) 는 공개 데이터라 그대로 (다른 도구가 out/json 을 직접 읽을 수 있음).
// 주인이 아니면 (개발 때 다른 계정의 폴더) 바꾸지 못해도 경고만
func privateState(lf *os.File, stateDir string) {
	if err := lf.Chmod(0600); err != nil {
		log.Printf("WARNING lock %s: chmod 0600: %v", lf.Name(), err)
	}
	if err := os.Chmod(stateDir, 0750); err != nil {
		log.Printf("WARNING state %s: chmod 0750: %v", stateDir, err)
	}
}

// runDaemon : 상주. resume = 판 올리기로 옛 프로세스가 넘긴 상태 파일 (handover.go, 없으면 "")
func runDaemon(cfg daemonConfig, once bool, resume string) int {
	for _, d := range []string{cfg.CacheDir, cfg.OutDir, cfg.StateDir} {
		if err := os.MkdirAll(d, 0755); err != nil {
			log.Print(err)
			return 1
		}
	}
	usr2 := upgradeSignal()
	var hs *handoverState
	if resume != "" {
		var err error
		if hs, err = readHandover(resume); err != nil {
			// 못 읽으면 끝냄 -> systemd 가 다시 띄움 = 연결이 끊긴 재시작 (판 올리기 전과 같음)
			log.Printf("handover: %v : exiting (systemd restarts)", err)
			return 1
		}
	}
	// 잠금 : 같은 상태 폴더로 두 개 뜨지 않게. 판 올리기면 옛 프로세스가 쥔 fd 를 그대로 (새로 열면 flock 이 막힘)
	var lf *os.File
	if hs != nil {
		lf = hs.lockFile(filepath.Join(cfg.StateDir, "lock"))
	} else {
		var err error
		if lf, err = os.OpenFile(filepath.Join(cfg.StateDir, "lock"), os.O_CREATE|os.O_RDWR, 0600); err != nil {
			log.Print(err)
			return 1
		}
		if err := syscall.Flock(int(lf.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
			log.Printf("already running (lock %s)", lf.Name())
			return 1
		}
	}
	privateState(lf, cfg.StateDir)
	// TAL : 시작 때 한 번 확인하고 어느 것을 쓰는지 기록 (깨졌으면 시작하지 않음). 회차마다 다시 읽음
	tals, source, err := loadTALs(cfg.TALDir)
	if err != nil {
		log.Printf("TAL: %v", err)
		return 1
	}
	log.Printf("TAL (%s): %s", source, talSummary(tals))

	d := &daemon{cfg: cfg, st: &store{}, started: time.Now(), confPath: cfg.ConfPath, confAt: time.Now(), lockFile: lf,
		gate: make(chan struct{}, 1)}
	d.exe, _ = os.Executable()
	d.live.Store(&cfg)
	if d.fetch, err = newFetcher(cfg.CacheDir, cfg.FetchJobs); err != nil {
		log.Print(err)
		return 1
	}
	d.fetch.NoRsync = cfg.NoRsync
	d.loadState()
	if hs != nil {
		hs.restoreDaemon(d) // 시작 시각, 저장소 backoff 기록, 판 올리기 횟수
	}
	d.hist, d.histLines = loadHistory(cfg.StateDir)

	if once {
		// -t 시험 모드 : 한 번 돌고 끝 (RTR / HTTP 안 엶)
		d.cycle()
		return 0
	}

	d.rtr = &rtrServer{St: d.st, Refresh: cfg.RTRRefresh, Retry: cfg.RTRRetry, Expire: cfg.RTRExpire,
		MaxConns: cfg.RTRMaxConns, MaxPerIP: cfg.RTRMaxPerIP, TrustedMax: cfg.RTRTrustedMax, Logf: log.Printf}
	for _, a := range cfg.RTRAllow {
		p, err := parsePrefixOrAddr(a)
		if err != nil {
			log.Printf("rtr allow %q: %v", a, err)
			return 1
		}
		d.rtr.Allow = append(d.rtr.Allow, p)
	}
	trusted, err := parsePrefixes(cfg.RTRTrusted)
	if err != nil {
		log.Printf("rtr trusted %v", err)
		return 1
	}
	d.rtr.Trusted = trusted
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
		allow, err := parsePrefixes(cfg.HTTPAllow)
		if err != nil {
			log.Printf("http allow %v", err)
			return 1
		}
		pub, err := parsePrefixes(cfg.HTTPPublic)
		if err != nil {
			log.Printf("http public %v", err)
			return 1
		}
		d.httpAllow.Store(&allow)
		d.httpPub.Store(&pub)
		h := httpAccess(d.httpAllow.Load, d.httpPub.Load, d.apiHandler(), d.publicHandler())
		log.Printf("http allow %v public %v", cfg.HTTPAllow, cfg.HTTPPublic)
		d.httpHandler = h
		for _, addr := range strings.Split(cfg.HTTPAddr, ",") {
			addr = strings.TrimSpace(addr)
			if addr == "" {
				continue
			}
			ln := hs.httpListener(addr) // 판 올리기면 넘겨받은 소켓 (없으면 nil)
			if ln == nil {
				// 시작 때 바로 listen : 포트가 막혀 있으면 로그에 남김 (계속 돎, RTR 은 따로)
				if ln, err = net.Listen("tcp", addr); err != nil {
					log.Printf("http listen %s: %v", addr, err)
					continue
				}
			}
			d.serveHTTP(addr, ln)
		}
	}
	hs.closeUnusedHTTP() // 설정에서 빠진 HTTP 주소의 넘겨받은 소켓 (재시작 항목이지만 판 올리기는 새 설정을 따름)
	// 직전 VRP 로 이미 데이터가 있으면 RTR 바로
	d.st.mu.RLock()
	have := d.st.Cur != nil
	d.st.mu.RUnlock()
	if hs != nil {
		hs.resumeRTR(d, have) // 넘겨받은 듣기 소켓 / 라우터 연결 (집합이 없으면 닫음 = 재시작과 같음)
	}
	if have {
		d.openRTR()
	}
	go d.watchReload()      // systemctl reload haetae (SIGHUP) -> 설정 다시 읽음
	go d.watchTerm()        // systemctl stop / restart (SIGTERM) -> 정리하고 끝 (ops.go)
	go d.watchStale()       // 묵은 데이터 경보 / RTR 닫기
	go d.watchdog()         // systemd WatchdogSec
	go d.watchUpgrade(usr2) // 판 올리기 (SIGUSR2, handover.go)
	sdNotify("READY=1")     // Type=notify : 듣기 소켓을 연 뒤 (직전 집합이 있으면 RTR 도)
	if hs != nil {
		hs.resumed(d)
	}

	if hs != nil {
		// 판 올리기 직후 : 받기 전에 캐시만 검증해 조회 API 결과부터 (약 40 초). 그다음 평소 회차 (CA 에서 받음)
		d.gate <- struct{}{}
		d.buildView()
		<-d.gate
	}
	for {
		start := time.Now()
		d.gate <- struct{}{} // 판 올리기 중이면 기다림 (넘기면 이 프로세스는 exec 로 바뀜)
		d.cycle()
		<-d.gate
		if wait := d.c().Interval - time.Since(start); wait > 0 {
			time.Sleep(wait)
		}
	}
}

// httpConnState : 요청 처리 중인 연결 수 (판 올리기가 하던 요청을 마칠 때까지 기다림)
func (d *daemon) httpConnState(c net.Conn, st http.ConnState) {
	d.httpBusyMu.Lock()
	if d.httpBusy == nil {
		d.httpBusy = map[net.Conn]bool{}
	}
	if st == http.StateActive {
		d.httpBusy[c] = true
	} else {
		delete(d.httpBusy, c)
	}
	d.httpBusyMu.Unlock()
}

// httpTrusted : 내부 허용 목록 (-http-allow) 주소 = 연결 상한의 공개 쪽 제한을 받지 않음 (reload 로 바뀐 목록을 바로 씀)
func (d *daemon) httpTrusted(ip netip.Addr) bool { return prefixesContain(d.httpAllow.Load(), ip) }

// serveHTTP : 듣기 소켓 하나에 HTTP 서버 (시작 / 판 올리기를 그만둘 때)
func (d *daemon) serveHTTP(addr string, ln net.Listener) {
	// 시간 제한 : 요청 머리 10 초, 요청 전체 30 초, 쉬는 연결 2 분. 응답 쓰기는 전체 제한 없이 조각마다 60 초 (writeProgress)
	srv := &http.Server{Handler: writeProgress(d.httpHandler), ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 30 * time.Second,
		IdleTimeout: 2 * time.Minute, MaxHeaderBytes: 64 << 10, ConnState: d.httpConnState}
	d.mu.Lock()
	d.httpSrv = append(d.httpSrv, srv)
	d.httpLn = append(d.httpLn, httpListen{addr, ln})
	d.mu.Unlock()
	go func() {
		log.Printf("http listening %s", addr)
		if err := srv.Serve(newLimitListener(ln, maxHTTPConns, &d.httpHold, d.httpTrusted)); err != http.ErrServerClosed {
			log.Print(err)
		}
	}()
}

// loadState : 재시작 때 직전 상태로 시작 (C3, C4)
//
//	state/payload.gob (0.2.0) = RTR 에 준 집합 (SLURM 뒤) + session / serial + delta 기록, 한 파일이라 언제나 같은 회차
//	집합이 max-start-age 보다 오래되었거나 파일이 깨졌으면 새 session : 라우터가 전체를 새로 받음 (같은 serial 에 다른 내용 금지)
//	payload.gob 이 없으면 (처음 시작, 0.2.0 전 판) 도 새 session (0.3.0 에서 옛 방식 읽기를 지움)
func (d *daemon) loadState() {
	gp := filepath.Join(d.cfg.StateDir, "payload.gob")
	ss, p, err := loadSavedState(gp)
	if err == nil && time.Since(p.Built) > d.cfg.MaxStartAge {
		err = fmt.Errorf("too old (%s)", time.Since(p.Built).Round(time.Second))
	}
	if err != nil {
		var old uint16
		if ss != nil {
			old = ss.Session
		}
		d.st.Session = newSession(old)
		log.Printf("state: new session %d (payload.gob: %v)", d.st.Session, err)
		return
	}
	d.st.Session, d.st.Serial, d.st.History = ss.Session, ss.Serial, ss.History
	d.st.Cur, d.st.Updated = p, ss.Saved
	log.Printf("state: session %d serial %d, %d VRPs from %s, deltas %d (payload.gob saved %s)",
		ss.Session, ss.Serial, len(p.VRPs), p.Built.Format(time.RFC3339), len(ss.History), ss.Saved.Format(time.RFC3339))
}

// newSession : 옛 session 과 반드시 다른 새 값 (같으면 라우터가 옛 serial 로 이어 받으려 함) -> 0 이 아닌 난수와 XOR
func newSession(old uint16) uint16 {
	var b [2]byte
	for binary.BigEndian.Uint16(b[:]) == 0 {
		rand.Read(b[:])
	}
	return binary.BigEndian.Uint16(b[:]) ^ old
}

func (d *daemon) openRTR() {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.rtrOpen || d.rtr == nil || d.stopping {
		return
	}
	// 못 연 포트는 다음 반영 회차에 다시 (포트 충돌이 풀리면 열림). 모두 열었을 때만 rtrOpen = true (상태 API / metrics)
	// 평문 TCP 포트 : TCP-MD5 / TCP-AO 키는 여기 듣기 소켓에 (키 없는 주소는 그냥 TCP)
	if d.cfg.RTRAddr != "" && d.rtrListen == nil {
		ln, err := authListenConfig(d.rtr.Auth).Listen(context.Background(), "tcp", d.cfg.RTRAddr)
		if err != nil {
			log.Printf("rtr listen %s: %v (retry after next applied run)", d.cfg.RTRAddr, err)
		} else {
			d.rtrListen = ln
			log.Printf("rtr listening %s (allow %v, trusted %v, tcp auth keys %d)", d.cfg.RTRAddr, d.cfg.RTRAllow, d.cfg.RTRTrusted, len(d.rtr.Auth))
			go d.rtr.serve(ln)
		}
	}
	// TLS 포트 (허용 목록은 같음)
	wantTLS := d.cfg.RTRTLSAddr != "" && d.rtrTLS != nil
	if wantTLS && d.rtrTLSLn == nil {
		ln, err := authListenConfig(nil).Listen(context.Background(), "tcp", d.cfg.RTRTLSAddr)
		if err != nil {
			log.Printf("rtr tls listen %s: %v (retry after next applied run)", d.cfg.RTRTLSAddr, err)
		} else {
			d.rtrTLSLn = ln
			log.Printf("rtr tls listening %s (client cert %v)", d.cfg.RTRTLSAddr, d.cfg.RTRTLSCA != "")
			go d.rtr.serve(tls.NewListener(ln, d.rtrTLS))
		}
	}
	d.rtrOpen = (d.cfg.RTRAddr == "" || d.rtrListen != nil) && (!wantTLS || d.rtrTLSLn != nil)
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
	d.mu.Lock()
	d.cycleStart = ri.Start
	d.mu.Unlock()
	defer func() {
		d.mu.Lock()
		d.cycleStart = time.Time{}
		d.mu.Unlock()
	}()

	tals, _, err := loadTALs(c.TALDir)
	if err != nil {
		d.skipRun(ri, fmt.Sprintf("TAL: %v, keep previous", err))
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
			d.mu.Lock()
			d.slurmErr = err.Error()
			d.mu.Unlock()
			d.skipRun(ri, fmt.Sprintf("SLURM %s: %v, keep previous", c.SLURM, err))
			return
		}
	}
	d.mu.Lock()
	d.slurmErr = ""
	d.mu.Unlock()

	d.fetch.RunDeadline = c.FetchDeadline // reset 이 이 값으로 이번 회차 기한을 정함
	d.fetch.reset()
	d.fetch.NoRsync = c.NoRsync
	if cap(d.fetch.sem) != c.FetchJobs { // 회차 사이라 수집 중인 것 없음
		d.fetch.sem = make(chan struct{}, c.FetchJobs)
	}
	d.fetch.checkDisk()
	v := newValidator(d.cfg.CacheDir, time.Now(), c.Workers)
	v.Fetch = d.fetch
	v.ValidDir = filepath.Join(d.cfg.CacheDir, "valid") // 직전 정상 publication point (valid.go)
	v.run(tals)
	if n := d.fetch.late.Load(); n > 0 {
		log.Printf("WARNING run deadline %s: %d repositories not fetched (using previous data)", c.FetchDeadline, n)
	}
	if len(v.failedTA) == 0 {
		// 이번에 보지 않은 CA 의 저장본 / 오래 안 쓴 저장소 폴더 정리 (TA 가 하나라도 실패하면 못 본 CA 가 많으니 건너뜀)
		if n := cleanValid(v.ValidDir, v.validSeen); n > 0 {
			log.Printf("valid: removed %d stale publication points", n)
		}
		if n := d.fetch.cleanRepos(); n > 0 {
			log.Printf("cache: removed %d repositories unused for %s", n, repoKeepUnused)
		}
	}
	ps := newPayloadSet(v, slurm)

	ri.VRPs, ri.VAPs, ri.Keys = len(ps.VRPs), len(ps.ASPAs), len(ps.Keys)
	ri.FailedTA, ri.Counts = v.failedTA, v.count
	// TA 키 교체 예고 (TAK successor) : 놓치면 교체 뒤 그 RIR 전체가 빠지므로 회차마다 로그
	for _, ex := range v.warnEx[warnTAKSuccessor] {
		log.Printf("WARNING TA key rollover announced (TAK, update TAL): %s", ex)
	}
	ri.PerTA = map[string]int{}
	for _, k := range ps.Full {
		ri.PerTA[k.TA]++
	}
	repos := d.fetch.statuses()
	ri.Repos = map[string]int{}
	for _, r := range repos {
		ri.Repos[r.Type+" "+r.Result]++
	}
	ri.Bytes = d.fetch.bytes.Load()
	ri.MB = ri.Bytes >> 20
	var view *queryView

	// 반영할지
	d.st.mu.RLock()
	prev := d.st.Cur
	d.st.mu.RUnlock()
	apply := true
	switch {
	// TA 실패 / VRP 0 은 직전 결과가 없어도 (첫 회차) 반영하지 않음 : 반쪽 결과로 RTR 을 열지 않음 (C3). 다음 회차에 다시
	case len(v.failedTA) > 0:
		apply, ri.Reason = false, fmt.Sprintf("TA failed %v, keep previous", v.failedTA)
	case len(ps.VRPs) == 0:
		apply, ri.Reason = false, "no VRP, keep previous"
	case prev != nil && float64(len(ps.VRPs)) < float64(len(prev.VRPs))*(1-c.DropWarn):
		ri.Reason = fmt.Sprintf("WARNING VRP drop %d -> %d", len(prev.VRPs), len(ps.VRPs))
		if c.HoldOnDrop {
			apply = false
			ri.Reason += " (held)"
		}
	}
	if apply {
		d.applyMu.Lock() // SIGTERM 이 이 구간 (출력 + 집합 교체 + 저장) 이 끝나길 기다림
		defer d.applyMu.Unlock()
		// 1. 조회 결과와 출력 파일을 먼저 (아직 옛 집합을 주는 중, 몇 초)
		v.sortObjects()
		view = newQueryView(v, ps, repos)
		ri.Unsafe = len(view.Unsafe)
		if err := v.writeOutputs(d.cfg.OutDir, ri.Start); err != nil {
			log.Printf("output: %v", err)
		}
		writeRepoStatusQuiet(d.cfg.OutDir, repos)
		// 2. 집합 (RTR / json-delta / validity) 과 조회 결과 (objects / ca / as …) 를 한 잠금 안에서 같이 바꿈 :
		//    API 끼리 다른 회차를 보이는 틈이 없게 (11-02, 전에는 집합을 먼저 바꾸고 출력을 쓴 뒤 몇 초 늦게 view).
		//    잠금 순서 = d.mu -> st.mu (current 와 같음)
		d.mu.Lock()
		dl, _ := d.st.update(ps)
		d.view = view
		d.mu.Unlock()
		ri.Announced, ri.Withdrawn = len(dl.AnnVRP), len(dl.WdrVRP)
		// 재시작 복원용 : 집합 + session / serial + delta 를 한 파일에 (반영할 때마다, 집합의 시각이 max-start-age 판단에 쓰임)
		if err := saveState(filepath.Join(d.cfg.StateDir, "payload.gob"), d.st); err != nil {
			log.Printf("state save: %v", err)
		}
		// state.json : 사람이 보는 용도 (session / serial). 복원에는 쓰지 않음
		if err := saveRTRState(filepath.Join(d.cfg.StateDir, "state.json"), d.st); err != nil {
			log.Printf("state.json save: %v", err)
		}
	}
	ri.Applied = apply
	ri.Duration = time.Since(ri.Start).Round(time.Second).String()
	ri.DurationS = time.Since(ri.Start).Seconds()
	ri.MemMB = memRSS() >> 20

	d.mu.Lock()
	d.last, d.repos, d.tas = ri, repos, tas
	d.runs++
	d.countNotApplied(ri)
	if apply {
		d.lastOK = time.Now()
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
	// 오래 걸린 회차 : 어느 저장소가 느렸는지 남김 (11-03 10 분 회차의 원인을 못 찾음, 11-04)
	if time.Since(ri.Start) >= slowRun {
		log.Printf("slow run %s: slowest repos %s", ri.Duration, slowestRepos(repos, 5))
	}
}

// slowRun : 평소 회차는 1 분 안팎, 이보다 길면 느린 저장소를 로그에
const slowRun = 3 * time.Minute

// slowestRepos : 받는 데 오래 걸린 저장소 n 개 "uri type result 시간" (긴 순)
func slowestRepos(repos []repoStatus, n int) string {
	rs := append([]repoStatus(nil), repos...)
	sort.Slice(rs, func(i, j int) bool { return rs[i].Duration > rs[j].Duration })
	var parts []string
	for _, r := range rs {
		if len(parts) == n || r.Duration < time.Second {
			break
		}
		parts = append(parts, fmt.Sprintf("%s %s %s %s", r.URI, r.Type, r.Result, r.Duration.Round(time.Second)))
	}
	if len(parts) == 0 {
		return "(none over 1s, time spent in validation)"
	}
	return strings.Join(parts, ", ")
}

// buildView : 받지 않고 캐시만 검증해 조회 API 결과 (objects / ca / expiring / unsafe, VRP 출처) 를 만듦.
// 판 올리기 직후 첫 회차 (받기 + 검증, 1 ~ 5 분) 를 기다리지 않고 503 시간을 줄이려고. RTR 집합 / 출력 파일 / 이력은 건드리지 않음
// (unsafe 는 지금 주고 있는 집합 기준). 그 사이 회차가 결과를 만들었으면 덮지 않음
func (d *daemon) buildView() {
	defer func() {
		if p := recover(); p != nil {
			log.Printf("handover: lookup data panic: %v", p)
		}
	}()
	start := time.Now()
	c := d.c()
	d.st.mu.RLock()
	cur := d.st.Cur
	d.st.mu.RUnlock()
	tals, _, err := loadTALs(c.TALDir)
	if err != nil || cur == nil {
		log.Printf("handover: lookup data not rebuilt (TAL %v, set %v), waiting for the next run", err, cur != nil)
		return
	}
	d.fetch.reset()
	d.fetch.Offline = true
	defer func() {
		d.fetch.Offline = false
		d.fetch.reset()
	}()
	d.mu.Lock()
	d.cycleStart = start // watchdog : 회차와 같이 봄
	d.mu.Unlock()
	v := newValidator(d.cfg.CacheDir, time.Now(), c.Workers)
	v.Fetch = d.fetch
	v.ValidDir = filepath.Join(d.cfg.CacheDir, "valid")
	v.run(tals)
	v.sortObjects()
	d.mu.Lock()
	d.cycleStart = time.Time{}
	if d.view == nil {
		d.view = newQueryView(v, cur, d.repos)
	}
	d.mu.Unlock()
	log.Printf("handover: lookup data rebuilt from the cache in %s (%d objects), fetching next",
		time.Since(start).Round(time.Second), len(v.objects))
}

// countNotApplied : 반영하지 않은 회차를 이유별로 셈 (d.mu 안에서). 이유 = ta_failed / no_vrp / drop_held / tal / slurm
func (d *daemon) countNotApplied(ri *runInfo) {
	if ri.Applied {
		return
	}
	reason := "other"
	switch r := ri.Reason; {
	case strings.HasPrefix(r, "TA failed"):
		reason = "ta_failed"
	case strings.HasPrefix(r, "no VRP"):
		reason = "no_vrp"
	case strings.Contains(r, "(held)"):
		reason = "drop_held"
	case strings.HasPrefix(r, "TAL"):
		reason = "tal"
	case strings.HasPrefix(r, "SLURM"):
		reason = "slurm"
	}
	if d.notApplied == nil {
		d.notApplied = map[string]int{}
	}
	d.notApplied[reason]++
}

// skipRun : 검증을 시작하지 못한 회차 (TAL / SLURM 오류) 도 상태 / 이력 / 로그에 남김.
// 개수는 지금 주고 있는 집합 그대로 (그래프가 0 으로 떨어지지 않게), applied=false + 이유
func (d *daemon) skipRun(ri *runInfo, reason string) {
	d.st.mu.RLock()
	if cur := d.st.Cur; cur != nil {
		ri.VRPs, ri.VAPs, ri.Keys = len(cur.VRPs), len(cur.ASPAs), len(cur.Keys)
	}
	ser := d.st.Serial
	d.st.mu.RUnlock()
	ri.Applied, ri.Reason = false, reason
	ri.Duration = time.Since(ri.Start).Round(time.Second).String()
	ri.DurationS = time.Since(ri.Start).Seconds()
	ri.MemMB = memRSS() >> 20
	d.mu.Lock()
	d.last = ri
	d.runs++
	d.countNotApplied(ri)
	d.mu.Unlock()
	d.addHistory(newHistRun(ri, ser, nil))
	log.Printf("run skipped: %s (serial %d)", reason, ser)
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
