package main

// rtr.go : RTR 서버 (RFC 8210 v1, RFC 6810 v0, draft-ietf-sidrops-8210bis v2 = ASPA)
//
// 라우터가 TCP 로 붙어서
//   Reset Query  -> Cache Response, 전체 (prefix / router key / ASPA), End of Data
//   Serial Query -> 그 serial 이후 바뀐 것만 (기록이 없으면 Cache Reset -> 라우터가 Reset Query)
// 새 serial 이 생기면 붙어 있는 라우터에 Serial Notify.
// 버전 : 라우터가 처음 보낸 PDU 의 버전으로 정함 (0, 1, 2). 그보다 높으면 Error 4 + 우리 최고 버전.
//   v0 : prefix 만, v1 : + router key, v2 : + ASPA
// 결정 C2 : TCP + 허용 IP 목록, C5 : refresh 600 / retry 300 / expire 7200, C6 : 포트 3323
//
// PDU 머리 (8 바이트) : version(1) type(1) session 또는 flags(2) length(4), 모두 빅엔디안

import (
	"bufio"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// PDU 종류
const (
	pduSerialNotify = 0
	pduSerialQuery  = 1
	pduResetQuery   = 2
	pduCacheResp    = 3
	pduIPv4Prefix   = 4
	pduIPv6Prefix   = 6
	pduEndOfData    = 7
	pduCacheReset   = 8
	pduRouterKey    = 9
	pduErrorReport  = 10
	pduASPA         = 11
)

// Error Report 코드
const (
	errCorruptData     = 0
	errInternal        = 1
	errNoData          = 2
	errInvalidRequest  = 3
	errUnsupportedVer  = 4
	errUnsupportedPDU  = 5
	errUnexpectedVer   = 8
	rtrMaxVersion      = 2
	rtrMaxPDUFromRoute = 64 * 1024
)

// 인터넷에 열 때를 위한 제한 (0.2.0)
const (
	rtrFirstQuery = 30 * time.Second // 붙은 뒤 첫 PDU 까지 (라우터는 바로 Reset / Serial Query 를 보냄)
	rtrIdle       = 2 * time.Hour    // 그 뒤 PDU 없이 이만큼이면 끊음 (라우터는 refresh 마다 Serial Query, 보통 10 분 ~ 1 시간)
	rtrFullEvery  = time.Minute      // 연결 하나가 전체 (Reset Query 응답, 약 100 만 VRP) 를 받는 최소 간격
)

type rtrServer struct {
	St      *store
	Allow   []netip.Prefix // 비어 있으면 아무도 못 붙음
	Auth    []rtrAuthKey   // TCP-MD5 / TCP-AO 키 (rtr_auth.go, 상태 표시용. 실제 적용은 듣기 소켓)
	Refresh uint32
	Retry   uint32
	Expire  uint32
	Logf    func(string, ...any)

	MaxConns int // 동시 연결 상한 (0 = 제한 없음, 시험용)
	MaxPerIP int // 주소 하나 (IPv6 는 /64) 의 동시 연결 상한 (0 = 제한 없음)

	cmu sync.RWMutex // Allow / Refresh / Retry / Expire / MaxConns / MaxPerIP 보호 (systemctl reload 로 바뀜, setLive)

	clients atomic.Int64
	mu      sync.Mutex
	active  map[*rtrConn]bool
	perIP   map[string]int // clientKey -> 연결 수 (Accept 때 더하고 run 이 끝날 때 뺌)
	total   int
	refused int // 상한으로 거절한 연결 수 (로그는 1 분에 한 번)
	refLog  time.Time

	// 판 올리기 (handover.go) : 연결마다 PDU 경계에서 읽기를 멈추고 (park) 기다림
	pausing  atomic.Bool
	pmu      sync.Mutex
	parked   map[*rtrConn]bool
	resumeCh chan struct{} // 판 올리기를 그만두면 닫음 (멈춘 연결이 이어 읽음)
}

// rtrConn : 라우터 연결 하나
type rtrConn struct {
	srv      *rtrServer
	c        net.Conn
	remote   string
	trans    string       // tcp / tcp-md5 / tcp-ao / tls
	key      string       // clientKey (연결 수 셈)
	lastFull time.Time    // 마지막 전체 전송 (rtrFullEvery)
	ver      atomic.Int32 // 협상된 버전, -1 = 아직 모름
	wmu      sync.Mutex
	w        *bufio.Writer
	since    time.Time
	lastQ    atomic.Int64 // 마지막 query 시각 (unix)
	sentSer  atomic.Uint32
	pending  []byte // 받았지만 아직 PDU 하나가 안 된 바이트 (판 올리기 때 새 판으로 넘김)
	rbuf     []byte
	resumed  bool // 판 올리기로 이어받은 연결
}

// errPaused : 판 올리기로 읽기를 멈춤 (readPDU)
var errPaused = errors.New("paused for handover")

// errBadLength : PDU 머리의 길이가 틀림 (8 미만 또는 rtrMaxPDUFromRoute 초과)
var errBadLength = errors.New("bad length")

// rtrClientInfo : 상태 API 용
type rtrClientInfo struct {
	Remote    string    `json:"remote"`
	Transport string    `json:"transport"`
	Version   int       `json:"version"`
	Since     time.Time `json:"since"`
	LastQuery time.Time `json:"last_query"`
	Serial    uint32    `json:"serial"`
}

func (s *rtrServer) clientsInfo() []rtrClientInfo {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []rtrClientInfo
	for c := range s.active {
		out = append(out, rtrClientInfo{c.remote, c.trans, int(c.ver.Load()), c.since, time.Unix(c.lastQ.Load(), 0), c.sentSer.Load()})
	}
	return out
}

func (s *rtrServer) allowed(addr net.Addr) bool {
	ta, ok := addr.(*net.TCPAddr)
	if !ok {
		return false
	}
	ip, ok := netip.AddrFromSlice(ta.IP)
	if !ok {
		return false
	}
	return s.allowedIP(ip.Unmap())
}

func (s *rtrServer) allowedIP(ip netip.Addr) bool {
	s.cmu.RLock()
	defer s.cmu.RUnlock()
	for _, p := range s.Allow {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}

// timers : End of Data 에 실을 refresh / retry / expire
func (s *rtrServer) timers() (uint32, uint32, uint32) {
	s.cmu.RLock()
	defer s.cmu.RUnlock()
	return s.Refresh, s.Retry, s.Expire
}

// setLive : reload 로 허용 목록 / 타이머를 바꿈. 새 목록에 없는 주소의 연결은 끊음 (돌려주는 값 = 끊은 수)
// 타이머는 다음 End of Data 부터 (이미 받은 라우터는 다음 Serial Query 응답 때 새 값을 받음)
func (s *rtrServer) setLive(allow []netip.Prefix, refresh, retry, expire uint32, maxConns, maxPerIP int) int {
	s.cmu.Lock()
	s.Allow, s.Refresh, s.Retry, s.Expire = allow, refresh, retry, expire
	s.MaxConns, s.MaxPerIP = maxConns, maxPerIP
	s.cmu.Unlock()
	s.mu.Lock()
	var drop []*rtrConn
	for c := range s.active {
		if a, ok := c.c.RemoteAddr().(*net.TCPAddr); ok {
			if ip, ok := netip.AddrFromSlice(a.IP); ok && s.allowedIP(ip.Unmap()) {
				continue
			}
		}
		drop = append(drop, c)
	}
	s.mu.Unlock()
	for _, c := range drop {
		s.Logf("rtr %s: not in allow list any more (reload), closed", c.remote)
		c.c.Close()
	}
	return len(drop)
}

// take : 연결 하나 자리를 잡음 (상한을 넘으면 false). 거절은 1 분에 한 번 로그
func (s *rtrServer) take(key string) bool {
	s.cmu.RLock()
	maxConns, maxPerIP := s.MaxConns, s.MaxPerIP
	s.cmu.RUnlock()
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.perIP == nil {
		s.perIP = map[string]int{}
	}
	if (maxConns > 0 && s.total >= maxConns) || (maxPerIP > 0 && s.perIP[key] >= maxPerIP) {
		s.refused++
		if time.Since(s.refLog) > time.Minute {
			s.Logf("rtr %s: connection limit (total %d / %d, this address %d / %d), refused %d since last log",
				key, s.total, maxConns, s.perIP[key], maxPerIP, s.refused)
			s.refLog, s.refused = time.Now(), 0
		}
		return false
	}
	s.total++
	s.perIP[key]++
	return true
}

func (s *rtrServer) release(key string) {
	s.mu.Lock()
	s.total--
	if s.perIP[key]--; s.perIP[key] <= 0 {
		delete(s.perIP, key)
	}
	s.mu.Unlock()
}

// closeAll : 붙어 있는 라우터 연결을 모두 끊음 (묵은 데이터 / 종료). 끊은 수
func (s *rtrServer) closeAll() int {
	s.mu.Lock()
	var all []*rtrConn
	for c := range s.active {
		all = append(all, c)
	}
	s.mu.Unlock()
	for _, c := range all {
		c.c.Close()
	}
	return len(all)
}

// serve : 연결을 받음 (닫힐 때까지)
func (s *rtrServer) serve(ln net.Listener) error {
	s.mu.Lock()
	if s.active == nil {
		s.active = map[*rtrConn]bool{}
	}
	s.mu.Unlock()
	for {
		c, err := ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			var ne net.Error
			if s.pausing.Load() && errors.As(err, &ne) && ne.Timeout() {
				s.waitResume() // 판 올리기 : 새 연결은 커널이 줄 세워 둠 (exec 되면 새 판이 받음)
				continue
			}
			s.Logf("rtr accept: %v", err)
			time.Sleep(time.Second)
			continue
		}
		if !s.allowed(c.RemoteAddr()) {
			s.Logf("rtr %s: not in allow list, closed", c.RemoteAddr())
			c.Close()
			continue
		}
		key := clientKey(c.RemoteAddr().String())
		if !s.take(key) {
			c.Close()
			continue
		}
		if tc, ok := c.(*net.TCPConn); ok {
			tc.SetKeepAlive(true)
			tc.SetKeepAlivePeriod(60 * time.Second)
		}
		rc := &rtrConn{srv: s, c: c, remote: c.RemoteAddr().String(), key: key, trans: s.transportOf(c),
			w: bufio.NewWriterSize(c, 64*1024), since: time.Now()}
		rc.ver.Store(-1)
		s.register(rc) // go 전에 : 판 올리기가 막 받은 연결도 기다려서 넘김
		go func() {
			// TLS : 인사 (handshake) 를 시간 제한 안에 먼저 끝냄 (받기 루프를 막지 않게 여기서)
			if tc, ok := c.(*tls.Conn); ok {
				tc.SetDeadline(time.Now().Add(15 * time.Second))
				if err := tc.Handshake(); err != nil {
					s.Logf("rtr %s: tls handshake: %v", rc.remote, err)
					c.Close()
					return
				}
				tc.SetDeadline(time.Time{})
			}
			rc.run()
		}()
	}
}

// register : 연결을 활성 목록에 (serve / 판 올리기로 이어받은 연결). 빼는 것은 run 이 끝날 때
func (s *rtrServer) register(rc *rtrConn) {
	s.mu.Lock()
	if s.active == nil {
		s.active = map[*rtrConn]bool{}
	}
	s.active[rc] = true
	s.mu.Unlock()
	s.clients.Add(1)
}

// run : 연결 하나를 끝날 때까지 (register 뒤에 부름)
func (rc *rtrConn) run() {
	s := rc.srv
	if rc.resumed {
		s.Logf("rtr %s: resumed (%s, v%d, connected %s)", rc.remote, rc.trans, rc.ver.Load(), rc.since.Format(time.RFC3339))
	} else {
		s.Logf("rtr %s: connected (%s)", rc.remote, rc.trans)
	}

	notify := s.St.subscribe()
	done := make(chan struct{})
	defer func() {
		close(done)
		s.St.unsubscribe(notify)
		rc.c.Close()
		s.mu.Lock()
		delete(s.active, rc)
		s.mu.Unlock()
		if rc.key != "" { // serve 를 거친 연결만 자리를 잡았음
			s.release(rc.key)
		}
		s.clients.Add(-1)
		if p := recover(); p != nil {
			s.Logf("rtr %s: panic: %v", rc.remote, p)
		}
	}()

	// 새 serial 이 생기면 Serial Notify (버전이 정해진 뒤에만)
	go func() {
		for {
			select {
			case <-done:
				return
			case <-notify:
				if rc.ver.Load() >= 0 {
					s.St.mu.RLock()
					ses, ser := s.St.Session, s.St.Serial
					s.St.mu.RUnlock()
					rc.send(func() { rc.putHeader(pduSerialNotify, ses, 12); rc.put32(ser) })
				}
			}
		}
	}()

	for {
		// 질의 없이 오래 붙어만 있는 연결은 끊음 (인터넷에 열 때 자리 차지 막기). 버전을 모르면 = 아직 첫 PDU 전
		if rc.ver.Load() < 0 {
			rc.c.SetReadDeadline(time.Now().Add(rtrFirstQuery))
		} else {
			rc.c.SetReadDeadline(time.Now().Add(rtrIdle))
		}
		pdu, err := rc.readPDU()
		if err == errPaused {
			rc.park() // 판 올리기 : exec 되면 돌아오지 않음, 그만두면 이어 읽음
			continue
		}
		if err == errBadLength {
			rc.sendError(errCorruptData, pdu, "bad length")
			return
		}
		if err != nil {
			if len(rc.pending) > 0 && err == io.EOF {
				err = io.ErrUnexpectedEOF // PDU 중간에 끊김
			}
			if err != io.EOF {
				s.Logf("rtr %s: read: %v", rc.remote, err)
			} else {
				s.Logf("rtr %s: closed", rc.remote)
			}
			return
		}
		hdr, body := pdu[:8], pdu[8:]
		ver, typ := int(hdr[0]), hdr[1]
		ln := uint32(len(pdu))

		// 버전 정하기 / 확인
		if rc.ver.Load() < 0 {
			if ver > rtrMaxVersion {
				// 우리가 아는 최고 버전으로 Error 4 -> 라우터가 낮춰서 다시 붙음
				rc.ver.Store(int32(rtrMaxVersion))
				rc.sendError(errUnsupportedVer, pdu, "unsupported version")
				return
			}
			rc.ver.Store(int32(ver))
		} else if int32(ver) != rc.ver.Load() {
			rc.sendError(errUnexpectedVer, pdu, "unexpected version")
			return
		}
		rc.lastQ.Store(time.Now().Unix())

		switch typ {
		case pduResetQuery:
			if ln != 8 {
				rc.sendError(errCorruptData, pdu, "bad Reset Query length")
				return
			}
			// 전체는 연결마다 1 분에 한 번 : 넘으면 No Data Available (치명적이 아님, 라우터는 retry 뒤 다시) = 대역 남용 막기
			if !rc.lastFull.IsZero() && time.Since(rc.lastFull) < rtrFullEvery {
				rc.sendError(errNoData, pdu, "full set at most once per minute per connection")
				continue
			}
			rc.lastFull = time.Now()
			rc.sendFull()
		case pduSerialQuery:
			if ln != 12 {
				rc.sendError(errCorruptData, pdu, "bad Serial Query length")
				return
			}
			ses := binary.BigEndian.Uint16(hdr[2:])
			ser := binary.BigEndian.Uint32(body)
			rc.sendSince(ses, ser)
		case pduErrorReport:
			s.Logf("rtr %s: error report from router: code %d%s", rc.remote, binary.BigEndian.Uint16(hdr[2:]), errorReportDetail(body))
			return
		default:
			rc.sendError(errUnsupportedPDU, pdu, "unsupported PDU type")
			return
		}
	}
}

// readPDU : PDU 하나 (머리 + 본문). 판 올리기로 멈추면 errPaused, 읽다 만 바이트는 rc.pending 에 남음
// (bufio + io.ReadFull 은 시간 제한으로 멈추면 읽은 바이트를 잃음 -> 직접 버퍼. 봉수대 msgReader 와 같은 생각)
func (rc *rtrConn) readPDU() ([]byte, error) {
	if rc.rbuf == nil {
		rc.rbuf = make([]byte, 4096)
	}
	for {
		if len(rc.pending) >= 8 {
			ln := binary.BigEndian.Uint32(rc.pending[4:8])
			if ln < 8 || ln > rtrMaxPDUFromRoute {
				return rc.pending[:8], errBadLength
			}
			if uint32(len(rc.pending)) >= ln {
				pdu := append([]byte(nil), rc.pending[:ln]...)
				rc.pending = append(rc.pending[:0], rc.pending[ln:]...)
				return pdu, nil
			}
		}
		// 다 받은 PDU 는 먼저 처리 (그 응답을 다 보낸 뒤 멈춤)
		if rc.srv.pausing.Load() {
			return nil, errPaused
		}
		n, err := rc.c.Read(rc.rbuf)
		rc.pending = append(rc.pending, rc.rbuf[:n]...)
		if err != nil {
			var ne net.Error
			if rc.srv.pausing.Load() && errors.As(err, &ne) && ne.Timeout() {
				continue // pauseAll 이 시간 제한을 지금으로 당김
			}
			return nil, err
		}
	}
}

// park : 판 올리기 동안 멈춤. 쓰기 잠금도 쥐어 Serial Notify 도 멈춤. 그만두면 (resumeAll) 돌아옴
func (rc *rtrConn) park() {
	s := rc.srv
	rc.wmu.Lock()
	s.pmu.Lock()
	ch := s.resumeCh
	if ch == nil { // 그 사이 판 올리기를 그만둠
		s.pmu.Unlock()
		rc.wmu.Unlock()
		return
	}
	s.parked[rc] = true
	s.pmu.Unlock()
	<-ch
	s.pmu.Lock()
	delete(s.parked, rc)
	s.pmu.Unlock()
	rc.wmu.Unlock()
}

// pauseAll : 모든 연결에 멈추라고 함 (읽기 시간 제한을 지금으로). 새 연결은 부르는 쪽이 듣기 소켓을 닫아 막음
func (s *rtrServer) pauseAll() {
	s.pmu.Lock()
	s.resumeCh = make(chan struct{})
	s.parked = map[*rtrConn]bool{}
	s.pmu.Unlock()
	s.pausing.Store(true)
	s.mu.Lock()
	for c := range s.active {
		c.c.SetReadDeadline(time.Now())
	}
	s.mu.Unlock()
}

// waitParked : 붙어 있는 연결이 모두 멈출 때까지 (하던 응답은 끝냄, 전체 전송 약 20 초). 멈춘 연결 목록
func (s *rtrServer) waitParked(limit time.Duration) ([]*rtrConn, error) {
	end := time.Now().Add(limit)
	for {
		s.mu.Lock()
		s.pmu.Lock()
		var list []*rtrConn
		busy := 0
		for c := range s.active {
			if s.parked[c] {
				list = append(list, c)
			} else {
				busy++
			}
		}
		s.pmu.Unlock()
		s.mu.Unlock()
		if busy == 0 {
			return list, nil
		}
		if time.Now().After(end) {
			return nil, fmt.Errorf("%d rtr connections still busy after %s", busy, limit)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// waitResume : 판 올리기 중이면 그만둘 때까지 기다림 (받기 루프)
func (s *rtrServer) waitResume() {
	s.pmu.Lock()
	ch := s.resumeCh
	s.pmu.Unlock()
	if ch != nil {
		<-ch
	}
}

// resumeAll : 판 올리기를 그만둠 -> 멈춘 연결이 이어 읽음
func (s *rtrServer) resumeAll() {
	s.pausing.Store(false)
	s.pmu.Lock()
	if s.resumeCh != nil {
		close(s.resumeCh)
		s.resumeCh = nil
	}
	s.pmu.Unlock()
}

// errorReportDetail : 라우터가 보낸 Error Report 본문 (RFC 8210 5.11) 을 로그용으로
//
//	본문 = 잘못된 PDU 길이 (4) + 그 PDU + 글 길이 (4) + 글 (UTF-8). 길이가 맞지 않으면 그만큼만
func errorReportDetail(body []byte) string {
	if len(body) < 4 {
		return ""
	}
	out := ""
	n := binary.BigEndian.Uint32(body)
	if uint64(n) > uint64(len(body)-4) {
		return " (bad encapsulated length)"
	}
	if n >= 2 {
		out += fmt.Sprintf(", PDU type %d (v%d)", body[5], body[4])
	}
	rest := body[4+n:]
	if len(rest) < 4 {
		return out
	}
	tl := binary.BigEndian.Uint32(rest)
	if uint64(tl) > uint64(len(rest)-4) {
		return out + " (bad text length)"
	}
	text := strings.Map(func(r rune) rune { // 로그 한 줄 : 제어 문자는 공백
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, string(rest[4:4+tl]))
	if len(text) > 200 {
		text = text[:200] + "..."
	}
	if text != "" {
		out += fmt.Sprintf(", text %q", text)
	}
	return out
}

// ---- 쓰기 도우미 (wmu 를 잡은 send 안에서만 부름) ----

func (rc *rtrConn) putHeader(typ uint8, field uint16, length uint32) {
	var b [8]byte
	b[0], b[1] = byte(rc.ver.Load()), typ
	binary.BigEndian.PutUint16(b[2:], field)
	binary.BigEndian.PutUint32(b[4:], length)
	rc.w.Write(b[:])
}

func (rc *rtrConn) put32(v uint32) {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], v)
	rc.w.Write(b[:])
}

// send : fn 이 쓰는 PDU 들을 한 번에 보냄 (쓰기 시간 제한 5 분 = 큰 전체 전송 포함)
func (rc *rtrConn) send(fn func()) error {
	rc.wmu.Lock()
	defer rc.wmu.Unlock()
	rc.c.SetWriteDeadline(time.Now().Add(5 * time.Minute))
	fn()
	err := rc.w.Flush()
	if err != nil {
		rc.c.Close()
	}
	return err
}

func (rc *rtrConn) sendError(code uint16, pdu []byte, text string) {
	if rc.ver.Load() < 0 {
		rc.ver.Store(int32(0))
	}
	rc.srv.Logf("rtr %s: error %d: %s", rc.remote, code, text)
	if len(pdu) > 1024 {
		pdu = pdu[:1024]
	}
	rc.send(func() {
		rc.putHeader(pduErrorReport, code, uint32(8+4+len(pdu)+4+len(text)))
		rc.put32(uint32(len(pdu)))
		rc.w.Write(pdu)
		rc.put32(uint32(len(text)))
		rc.w.WriteString(text)
	})
}

// putPrefix : IPv4 (20 바이트) / IPv6 (32 바이트) Prefix PDU
func (rc *rtrConn) putPrefix(v rtrVRP, announce bool) {
	flags := byte(0)
	if announce {
		flags = 1
	}
	a := v.Prefix.Addr()
	if a.Is4() {
		rc.putHeader(pduIPv4Prefix, 0, 20)
		rc.w.Write([]byte{flags, byte(v.Prefix.Bits()), v.MaxLength, 0})
		b := a.As4()
		rc.w.Write(b[:])
	} else {
		rc.putHeader(pduIPv6Prefix, 0, 32)
		rc.w.Write([]byte{flags, byte(v.Prefix.Bits()), v.MaxLength, 0})
		b := a.As16()
		rc.w.Write(b[:])
	}
	rc.put32(v.ASN)
}

// putRouterKey : Router Key PDU (v1+). 머리의 session 자리 = flags(1) + zero(1)
func (rc *rtrConn) putRouterKey(k rtrKey, announce bool) {
	flags := uint16(0)
	if announce {
		flags = 1 << 8
	}
	rc.putHeader(pduRouterKey, flags, uint32(8+20+4+len(k.SPKI)))
	rc.w.Write(k.SKI[:])
	rc.put32(k.ASN)
	rc.w.WriteString(k.SPKI)
}

// putASPA : ASPA PDU (v2, draft-ietf-sidrops-8210bis 최근판 : flags + customer + provider 목록)
// withdraw 는 provider 없이. rtrdump / 라우터로 확인 필요 (draft 가 바뀌어 왔음)
func (rc *rtrConn) putASPA(customer uint32, providers []uint32, announce bool) {
	flags := uint16(0)
	if announce {
		flags = 1 << 8
	} else {
		providers = nil
	}
	rc.putHeader(pduASPA, flags, uint32(8+4+4*len(providers)))
	rc.put32(customer)
	for _, p := range providers {
		rc.put32(p)
	}
}

func (rc *rtrConn) putEndOfData(ses uint16, ser uint32) {
	if rc.ver.Load() == 0 {
		rc.putHeader(pduEndOfData, ses, 12)
		rc.put32(ser)
		return
	}
	refresh, retry, expire := rc.srv.timers()
	rc.putHeader(pduEndOfData, ses, 24)
	rc.put32(ser)
	rc.put32(refresh)
	rc.put32(retry)
	rc.put32(expire)
}

// sendFull : Reset Query 응답 = 전체
func (rc *rtrConn) sendFull() {
	st := rc.srv.St
	st.mu.RLock()
	cur, ses, ser := st.Cur, st.Session, st.Serial
	st.mu.RUnlock()
	if cur == nil {
		rc.sendError(errNoData, nil, "no data available yet")
		return
	}
	rc.send(func() {
		rc.putHeader(pduCacheResp, ses, 8)
		for v := range cur.VRPs {
			rc.putPrefix(v, true)
		}
		if rc.ver.Load() >= 1 {
			for k := range cur.Keys {
				rc.putRouterKey(k, true)
			}
		}
		if rc.ver.Load() >= 2 {
			for c, ps := range cur.ASPAs {
				rc.putASPA(c, ps, true)
			}
		}
		rc.putEndOfData(ses, ser)
	})
	rc.sentSer.Store(ser)
}

// sendSince : Serial Query 응답 = 바뀐 것만, 못 하면 Cache Reset
func (rc *rtrConn) sendSince(clientSes uint16, clientSer uint32) {
	st := rc.srv.St
	st.mu.RLock()
	cur, ses, ser := st.Cur, st.Session, st.Serial
	if cur == nil {
		st.mu.RUnlock()
		rc.sendError(errNoData, nil, "no data available yet")
		return
	}
	if clientSes != ses {
		st.mu.RUnlock()
		rc.send(func() { rc.putHeader(pduCacheReset, 0, 8) })
		return
	}
	ann, wdr, kAnn, kWdr, aspaChg, ok := st.netDiff(clientSer)
	st.mu.RUnlock()
	if !ok {
		rc.send(func() { rc.putHeader(pduCacheReset, 0, 8) })
		return
	}
	rc.send(func() {
		rc.putHeader(pduCacheResp, ses, 8)
		// withdraw 먼저, 그다음 announce
		for _, v := range wdr {
			rc.putPrefix(v, false)
		}
		for _, v := range ann {
			rc.putPrefix(v, true)
		}
		if rc.ver.Load() >= 1 {
			for _, k := range kWdr {
				rc.putRouterKey(k, false)
			}
			for _, k := range kAnn {
				rc.putRouterKey(k, true)
			}
		}
		if rc.ver.Load() >= 2 {
			for _, c := range aspaChg {
				if ps, ok := cur.ASPAs[c]; ok {
					rc.putASPA(c, ps, true)
				} else {
					rc.putASPA(c, nil, false)
				}
			}
		}
		rc.putEndOfData(ses, ser)
	})
	rc.sentSer.Store(ser)
}

// String : 로그용
func (s *rtrServer) String() string {
	return fmt.Sprintf("rtr clients %d", s.clients.Load())
}
