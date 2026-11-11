package main

// api_public.go : HTTP 접근 두 단계 (0.2.0, [http] public)
//
//   allow  (-http-allow)  : 내부. 모든 경로 (지금까지와 같음)
//   public (-http-public) : 공개. 조회 경로만, 상태는 내부 정보 (라우터 주소, 설정 경로, 메모리, SLURM) 를 뺀 판,
//                           큰 파일 (/json /csv) 은 주소마다 -delta-full-interval 에 한 번 (429 + Retry-After)
//   둘 다 아니면 403. 두 목록에 다 들면 allow (내부) 가 이김
//
// 공개 경로를 늘릴 때는 publicHandler 에 더하고 docs/api.md, docs/en/api.md 를 함께 고침

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"sync"
	"time"
)

// 듣기 소켓 하나의 동시 연결 상한 (넘으면 Accept 를 미룸 = 커널 backlog 에서 기다림)
const maxHTTPConns = 256

// 내부 허용 목록 (-http-allow) 밖 주소의 연결 상한 (11-05 검토 5) : 주소 (IPv6 /64) 하나 8 개, 모두 합쳐 224 개.
// 넘으면 바로 닫음. 남은 32 자리는 내부 몫 = 공개 쪽이 자리를 다 채워도 내부 조회는 됨
const (
	maxHTTPPerClient = 8
	httpReserved     = 32
)

// httpWriteIdle : 응답을 이 시간 동안 한 조각 (httpWriteChunk) 도 못 보내면 연결을 끊음.
// 응답 전체 시간 제한 (WriteTimeout) 은 큰 파일 / 느린 망에 안 맞아 조각마다 기한을 늘림 -> 읽지 않는 연결만 끊김
var httpWriteIdle = 60 * time.Second // 시험에서 줄임

const httpWriteChunk = 256 << 10

// httpAccess : 출발지 주소로 내부 / 공개 / 403 을 가름. 목록은 요청마다 불러 지금 값 (reload 로 바뀜)
func httpAccess(allow, public func() *[]netip.Prefix, full, pub http.Handler) http.Handler {
	in := func(get func() *[]netip.Prefix, ip netip.Addr) bool { return prefixesContain(get(), ip) }
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ap, err := netip.ParseAddrPort(r.RemoteAddr)
		if err == nil {
			ip := ap.Addr().Unmap()
			switch {
			case in(allow, ip):
				full.ServeHTTP(w, r)
				return
			case public != nil && in(public, ip):
				pub.ServeHTTP(w, r)
				return
			}
		}
		http.Error(w, "forbidden", http.StatusForbidden)
	})
}

// prefixesContain : 목록 (nil = 빈 목록) 에 ip 가 드는지
func prefixesContain(p *[]netip.Prefix, ip netip.Addr) bool {
	if p == nil {
		return false
	}
	for _, x := range *p {
		if x.Contains(ip) {
			return true
		}
	}
	return false
}

// writeProgress : 응답을 조각으로 나눠 쓰고 조각마다 쓰기 기한을 늘림 (httpWriteIdle)
func writeProgress(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		pw := &progressWriter{ResponseWriter: w, rc: http.NewResponseController(w)}
		pw.rc.SetWriteDeadline(time.Now().Add(httpWriteIdle)) // 머리만 쓰는 응답 (Write 없음) 도
		h.ServeHTTP(pw, r)
	})
}

type progressWriter struct {
	http.ResponseWriter
	rc *http.ResponseController
}

func (p *progressWriter) Write(b []byte) (int, error) {
	n := 0
	for len(b) > 0 {
		c := min(len(b), httpWriteChunk)
		p.rc.SetWriteDeadline(time.Now().Add(httpWriteIdle))
		m, err := p.ResponseWriter.Write(b[:c])
		n += m
		if err != nil {
			return n, err
		}
		b = b[c:]
	}
	return n, nil
}

// Unwrap : ResponseController (Flush, 기한) 가 원래 ResponseWriter 를 찾게
func (p *progressWriter) Unwrap() http.ResponseWriter { return p.ResponseWriter }

// publicHandler : 공개 쪽 경로. 여기 없는 경로는 403 (내부 전용)
func (d *daemon) publicHandler() http.Handler {
	mux := http.NewServeMux()
	for _, name := range []string{"json", "csv"} {
		name := name
		mux.HandleFunc("GET /"+name, func(w http.ResponseWriter, r *http.Request) {
			if d.tooSoon(w, r, "/"+name) {
				return
			}
			d.serveOut(w, r, name)
		})
	}
	mux.HandleFunc("GET /status", d.handleStatusTextPublic)
	mux.HandleFunc("GET /api/v1/status", d.handleStatusJSONPublic)
	mux.HandleFunc("GET /api/v1/validity/{as}/{prefix...}", d.handleValidity)
	mux.HandleFunc("GET /api/v1/vrps/delta", d.handleDelta)
	mux.HandleFunc("GET /api/v1/aspa/verify", d.handleASPAVerify)
	mux.HandleFunc("GET /api/v1/as/{as}", func(w http.ResponseWriter, r *http.Request) {
		// 결과가 클 수 있음 (AS 하나 VRP 수만 개) : 주소마다 publicQueryEvery 에 한 번 (11-05 검토 15). 내부는 제한 없음
		if d.tooSoonEvery(w, r, "/api/v1/as", publicQueryEvery) {
			return
		}
		d.handleAS(w, r)
	})
	mux.HandleFunc("GET /api/v1/prefix/{prefix...}", d.handlePrefix)
	mux.HandleFunc("GET /json-delta", d.handleJSONDelta) // 전체 (reset) 는 원래 주소마다 제한
	mux.HandleFunc("GET /healthz", d.handleHealthz)
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "not available on public access", http.StatusForbidden)
	})
	return mux
}

// publicQueryEvery : 공개 쪽 /api/v1/as 를 주소마다 이 간격에 한 번
const publicQueryEvery = time.Second

// tooSoon : 이 주소가 kind 를 간격 (-delta-full-interval) 안에 다시 받으려 하면 429 + Retry-After 를 쓰고 true
func (d *daemon) tooSoon(w http.ResponseWriter, r *http.Request, kind string) bool {
	return d.tooSoonEvery(w, r, kind, d.c().DeltaFullInterval)
}

// tooSoonEvery : tooSoon 을 간격 iv 로
func (d *daemon) tooSoonEvery(w http.ResponseWriter, r *http.Request, kind string, iv time.Duration) bool {
	wait := d.clientWaitEvery(kind, r.RemoteAddr, iv)
	if wait <= 0 {
		return false
	}
	sec := int((wait + time.Second - 1) / time.Second)
	w.Header().Set("Retry-After", strconv.Itoa(sec))
	http.Error(w, fmt.Sprintf("%s allowed once per %s per client, retry after %d s", kind, iv, sec),
		http.StatusTooManyRequests)
	return true
}

// clientKey : 주소별 제한의 열쇠. IPv6 는 /64 (한 가입자가 보통 /64 하나를 통째로 가짐)
func clientKey(remote string) string {
	ap, err := netip.ParseAddrPort(remote)
	if err != nil {
		return remote
	}
	ip := ap.Addr().Unmap()
	if ip.Is6() {
		p, _ := ip.Prefix(64)
		return p.String()
	}
	return ip.String()
}

// limitListener : 동시 연결을 n 개로 (golang.org/x/net/netutil 과 같은 일, 표준만 쓰려고 직접)
// + trusted 가 아닌 주소는 주소마다 maxHTTPPerClient, 모두 합쳐 n - httpReserved (trusted = nil 이면 모두 공개로 셈)
type limitListener struct {
	net.Listener
	sem     chan struct{}
	hold    *acceptHold // 판 올리기 동안 받기를 멈춤 (nil = 없음)
	trusted func(netip.Addr) bool

	mu     sync.Mutex
	pub    int            // trusted 가 아닌 연결 수
	perKey map[string]int // clientKey -> 연결 수 (trusted 가 아닌 것만)
}

func newLimitListener(l net.Listener, n int, hold *acceptHold, trusted func(netip.Addr) bool) net.Listener {
	return &limitListener{Listener: l, sem: make(chan struct{}, n), hold: hold, trusted: trusted, perKey: map[string]int{}}
}

func (l *limitListener) Accept() (net.Conn, error) {
	for {
		l.hold.wait()
		l.sem <- struct{}{}
		c, err := l.Listener.Accept()
		if err != nil {
			<-l.sem
			var ne net.Error
			if l.hold.held() && errors.As(err, &ne) && ne.Timeout() {
				continue // 판 올리기가 시간 제한을 지금으로 당김 : 풀릴 때까지 기다림 (새 연결은 커널이 줄 세움)
			}
			return nil, err
		}
		key, ok := l.admit(c.RemoteAddr().String())
		if !ok {
			c.Close() // 공개 쪽 상한 : 기다리게 하지 않고 바로 닫음 (자리를 쥐고 있지 않게)
			<-l.sem
			continue
		}
		return &limitConn{Conn: c, release: func() { l.leave(key); <-l.sem }}, nil
	}
}

// admit : 공개 쪽 상한 확인. key = 센 열쇠 ("" = trusted, 세지 않음)
func (l *limitListener) admit(remote string) (string, bool) {
	if ap, err := netip.ParseAddrPort(remote); err == nil && l.trusted != nil && l.trusted(ap.Addr().Unmap()) {
		return "", true
	}
	key := clientKey(remote)
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.pub >= cap(l.sem)-httpReserved || l.perKey[key] >= maxHTTPPerClient {
		return "", false
	}
	l.pub++
	l.perKey[key]++
	return key, true
}

func (l *limitListener) leave(key string) {
	if key == "" {
		return
	}
	l.mu.Lock()
	l.pub--
	if l.perKey[key]--; l.perKey[key] <= 0 {
		delete(l.perKey, key)
	}
	l.mu.Unlock()
}

// acceptHold : 판 올리기 동안 HTTP 받기를 멈추는 문 (handover.go). nil 이면 늘 열림
type acceptHold struct {
	mu sync.Mutex
	ch chan struct{} // nil = 열림
}

func (h *acceptHold) close() {
	h.mu.Lock()
	if h.ch == nil {
		h.ch = make(chan struct{})
	}
	h.mu.Unlock()
}

func (h *acceptHold) open() {
	h.mu.Lock()
	if h.ch != nil {
		close(h.ch)
		h.ch = nil
	}
	h.mu.Unlock()
}

func (h *acceptHold) held() bool {
	if h == nil {
		return false
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.ch != nil
}

func (h *acceptHold) wait() {
	if h == nil {
		return
	}
	h.mu.Lock()
	ch := h.ch
	h.mu.Unlock()
	if ch != nil {
		<-ch
	}
}

type limitConn struct {
	net.Conn
	release func()
	once    sync.Once // Close 가 여러 번 불려도 자리는 한 번만 돌려줌
}

func (c *limitConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(c.release)
	return err
}
