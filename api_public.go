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

// httpAccess : 출발지 주소로 내부 / 공개 / 403 을 가름. 목록은 요청마다 불러 지금 값 (reload 로 바뀜)
func httpAccess(allow, public func() *[]netip.Prefix, full, pub http.Handler) http.Handler {
	in := func(get func() *[]netip.Prefix, ip netip.Addr) bool {
		p := get()
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
	mux.HandleFunc("GET /api/v1/as/{as}", d.handleAS)
	mux.HandleFunc("GET /api/v1/prefix/{prefix...}", d.handlePrefix)
	mux.HandleFunc("GET /json-delta", d.handleJSONDelta) // 전체 (reset) 는 원래 주소마다 제한
	mux.HandleFunc("GET /healthz", d.handleHealthz)
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "not available on public access", http.StatusForbidden)
	})
	return mux
}

// tooSoon : 이 주소가 kind 를 간격 안에 다시 받으려 하면 429 + Retry-After 를 쓰고 true
func (d *daemon) tooSoon(w http.ResponseWriter, r *http.Request, kind string) bool {
	wait := d.clientWait(kind, r.RemoteAddr)
	if wait <= 0 {
		return false
	}
	sec := int((wait + time.Second - 1) / time.Second)
	w.Header().Set("Retry-After", strconv.Itoa(sec))
	http.Error(w, fmt.Sprintf("%s allowed once per %s per client, retry after %d s", kind, d.c().DeltaFullInterval, sec),
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
type limitListener struct {
	net.Listener
	sem  chan struct{}
	hold *acceptHold // 판 올리기 동안 받기를 멈춤 (nil = 없음)
}

func newLimitListener(l net.Listener, n int, hold *acceptHold) net.Listener {
	return &limitListener{l, make(chan struct{}, n), hold}
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
		return &limitConn{Conn: c, release: func() { <-l.sem }}, nil
	}
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
