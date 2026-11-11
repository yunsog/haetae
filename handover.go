package main

// handover.go : 무중단 판 올리기 (0.2.0, 11-02. 봉수대 handover.go 와 같은 방식, docs/manual.md 6.9)
//
// 새 실행 파일을 같은 자리에 깐 뒤 SIGUSR2 (sudo systemctl kill -s USR2 --kill-whom=main haetae) :
//
//	옛 판 (pid 그대로)                                        새 판 (같은 pid, -resume <상태 파일>)
//	 1. 새 실행 파일 확인 (-handover-check : 상태 형식 판, 설정 / TAL)
//	 2. 회차 자리 (gate) 를 잡음 = 돌던 회차 (수집 + 검증 + 반영) 가 끝나길 기다림
//	    -> payload.gob (집합 + session / serial + delta) 은 그 회차가 이미 저장함
//	 3. RTR / HTTP 새 연결 받기 멈춤 (커널이 줄 세워 둠), HTTP 는 하던 요청만 마침
//	 4. RTR 연결마다 하던 응답을 끝내고 PDU 경계에서 멈춤 (읽다 만 바이트 챙김, rtr.go park)
//	 5. fd 복사 (dup = CLOEXEC 없음 : exec 뒤에도 열림) : 잠금 파일, 듣기 소켓, 연결
//	    상태 파일 state/handover.gob : fd, 연결 상태 (버전, 마지막 전체 전송 …), 저장소 backoff
//	 6. syscall.Exec  ------------------------------------------>  7. payload.gob 으로 같은 session / serial
//	    (exec 전 어디서 실패해도 되돌리고 그대로 계속)                 8. 소켓 / 연결을 이어받아 이어 읽음 = 멈춤 끝
//	                                                                9. 회차 하나를 바로 (조회 API 결과를 다시 만듦)
//
// 같은 pid 라 systemd 는 모름 (재시작 아님, watchdog / Type=notify 그대로).
// TLS 연결은 암호 상태가 프로세스 메모리에 있어 넘길 수 없음 -> 끊김 (라우터가 다시 붙음). 듣기 소켓은 넘김.
// 새 판이 상태 파일을 못 읽으면 끝냄 -> systemd 가 다시 띄움 = 지금까지의 재시작과 같음 (더 나빠지지 않음)

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/gob"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

const (
	handoverVersion   = 1                // 상태 파일 형식 판. 다르면 판 올리기를 하지 않음 (그때는 재시작)
	handoverCycleWait = 15 * time.Minute // 돌던 회차를 기다리는 최대 (평소 1 ~ 3 분)
	handoverParkWait  = 2 * time.Minute  // RTR 연결이 하던 응답을 끝내길 기다리는 최대 (전체 전송 약 20 초)
	handoverHTTPWait  = 30 * time.Second // HTTP 하던 요청
	handoverCheckWait = 30 * time.Second // 새 실행 파일 확인
	handoverFile      = "handover.gob"   // 상태 폴더 안
)

// handoverState : 옛 판 -> 새 판 (gob)
type handoverState struct {
	Version  int
	From     string    // 옛 판 (version)
	PausedAt time.Time // RTR 을 멈춘 시각 (새 판이 멈춘 시간을 셈)
	Started  time.Time // 처음 시작한 시각 (판 올리기를 거듭해도 그대로)
	Count    int       // 이것이 몇 번째 판 올리기인지
	LockFd   int
	RTRFd    int // -1 = 없음
	RTRAddr  string
	TLSFd    int // RTR over TLS 듣기 소켓 (TCP, -1 = 없음)
	TLSAddr  string
	HTTP     []fdAddr
	Conns    []rtrConnState
	Health   map[string]repoHealthState

	used map[string]bool // 새 판 : 쓴 HTTP 주소
}

type fdAddr struct {
	Addr string
	Fd   int
}

// rtrConnState : RTR 연결 하나 (rtrConn 의 넘길 칸)
type rtrConnState struct {
	Fd       int
	Remote   string
	Trans    string
	Ver      int32
	Since    time.Time
	LastFull time.Time
	LastQ    int64
	SentSer  uint32
	Pending  []byte
}

// handoverInfo : 상태 API "handover" (d.mu)
type handoverInfo struct {
	Count       int       `json:"count"`                  // 이 pid 가 판을 올린 횟수
	LastAt      time.Time `json:"last_at,omitzero"`       // 마지막 판 올리기
	From        string    `json:"from,omitempty"`         // 그때 옛 판
	PauseMs     int64     `json:"pause_ms,omitempty"`     // 그때 RTR 이 멈춘 시간
	Conns       int       `json:"rtr_conns,omitempty"`    // 그때 이어받은 RTR 연결
	LastError   string    `json:"last_error,omitempty"`   // 마지막으로 그만둔 이유
	LastErrorAt time.Time `json:"last_error_at,omitzero"` // 그 시각
}

// ---- 옛 판 ----

// upgradeSignal : SIGUSR2 받기를 시작 직후에 등록 (등록 전 USR2 는 Go 기본 동작 = 프로세스 끝)
func upgradeSignal() chan os.Signal {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGUSR2)
	return ch
}

// watchUpgrade : SIGUSR2 = 판 올리기
func (d *daemon) watchUpgrade(ch chan os.Signal) {
	for range ch {
		d.upgrade()
	}
}

func (d *daemon) upgrade() {
	if !d.upBusy.CompareAndSwap(false, true) {
		log.Printf("handover: already in progress, ignored")
		return
	}
	defer d.upBusy.Store(false)
	log.Printf("handover: start (SIGUSR2), checking %s", d.exe)
	if err := d.checkNewBinary(); err != nil {
		d.handoverFail(err)
		return
	}
	d.handoverFail(d.handover())
}

// handoverFail : 판 올리기를 그만둠 (기록 + 상태 API). 옛 판이 그대로 계속
func (d *daemon) handoverFail(err error) {
	log.Printf("handover: aborted, old process keeps running : %v", err)
	d.mu.Lock()
	d.ho.LastError, d.ho.LastErrorAt = err.Error(), time.Now()
	d.mu.Unlock()
}

// checkNewBinary : 새 실행 파일이 같은 상태 형식을 알고, 지금 설정 / TAL 을 받아들이는지
func (d *daemon) checkNewBinary() error {
	if d.exe == "" {
		return errors.New("executable path unknown")
	}
	ctx, cancel := context.WithTimeout(context.Background(), handoverCheckWait)
	defer cancel()
	cmd := exec.CommandContext(ctx, d.exe, append(baseArgs(), "-handover-check")...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	want := fmt.Sprintf("handover state %d", handoverVersion)
	if got := strings.TrimSpace(string(out)); err != nil || got != want {
		return fmt.Errorf("%s -handover-check : %q %v %s (want %q : the new binary must know the same state format and accept the config)",
			d.exe, got, err, strings.TrimSpace(stderr.String()), want)
	}
	return nil
}

// handoverCheck : -handover-check (새 실행 파일 쪽). 설정은 main 이 이미 읽어 확인함
func handoverCheck(cfg daemonConfig) int {
	if _, _, err := loadTALs(cfg.TALDir); err != nil {
		fmt.Fprintln(os.Stderr, "TAL:", err)
		return 2
	}
	fmt.Printf("handover state %d\n", handoverVersion)
	return 0
}

// baseArgs : 이 프로세스의 명령줄 옵션에서 -resume 을 뺀 것 (판 올리기를 거듭해도 쌓이지 않게)
func baseArgs() []string {
	var out []string
	args := os.Args[1:]
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "-resume" || a == "--resume" {
			i++ // 값도 뺌
			continue
		}
		if strings.HasPrefix(a, "-resume=") || strings.HasPrefix(a, "--resume=") {
			continue
		}
		out = append(out, a)
	}
	return out
}

// deadliner : 듣기 소켓의 받기 시간 제한 (TCPListener)
type deadliner interface{ SetDeadline(time.Time) error }

func setAcceptDeadline(ln net.Listener, t time.Time) {
	if dl, ok := ln.(deadliner); ok {
		dl.SetDeadline(t)
	}
}

// handover : 2 ~ 6. 돌아오면 실패 (멈춘 것을 모두 되돌려 둠)
func (d *daemon) handover() (err error) {
	// 2. 회차 자리
	t0 := time.Now()
	select {
	case d.gate <- struct{}{}:
	case <-time.After(handoverCycleWait):
		return fmt.Errorf("cycle still running after %s", handoverCycleWait)
	}
	if w := time.Since(t0); w > time.Second {
		log.Printf("handover: waited %s for the running cycle", w.Round(time.Second))
	}
	d.mu.Lock()
	stopping, rtrLn, tlsLn := d.stopping, d.rtrListen, d.rtrTLSLn
	httpLns := append([]httpListen(nil), d.httpLn...)
	httpSrv := append(d.httpSrv[:0:0], d.httpSrv...)
	d.mu.Unlock()
	if stopping {
		<-d.gate
		return errors.New("stopping")
	}

	var fds []int
	path := filepath.Join(d.cfg.StateDir, handoverFile)
	defer func() { // 여기 오면 실패 : 되돌림
		for _, fd := range fds {
			syscall.Close(fd)
		}
		os.Remove(path)
		for _, ln := range []net.Listener{rtrLn, tlsLn} {
			if ln != nil {
				setAcceptDeadline(ln, time.Time{})
			}
		}
		for _, h := range httpLns {
			setAcceptDeadline(h.Ln, time.Time{})
		}
		for _, s := range httpSrv {
			s.SetKeepAlivesEnabled(true)
		}
		if d.rtr != nil {
			d.rtr.resumeAll()
		}
		d.httpHold.open()
		<-d.gate
	}()

	// 3. 새 연결 받기 멈춤 : 받기 루프가 시간 제한으로 깨어나 기다림 (rtr.go serve, api_public.go limitListener)
	tPause := time.Now()
	if d.rtr != nil {
		d.rtr.pauseAll() // 4 도 함께 : 연결마다 PDU 경계에서 멈춤
	}
	d.httpHold.close()
	for _, ln := range []net.Listener{rtrLn, tlsLn} {
		if ln != nil {
			setAcceptDeadline(ln, time.Now())
		}
	}
	for _, h := range httpLns {
		setAcceptDeadline(h.Ln, time.Now())
	}
	for _, s := range httpSrv {
		s.SetKeepAlivesEnabled(false) // 쉬는 연결은 닫음 (응답을 마친 연결부터)
	}
	// HTTP 하던 요청
	httpEnd := time.Now().Add(handoverHTTPWait)
	for {
		d.httpBusyMu.Lock()
		busy := len(d.httpBusy)
		d.httpBusyMu.Unlock()
		if busy == 0 {
			break
		}
		if time.Now().After(httpEnd) {
			log.Printf("handover: %d http requests still running after %s, they will be cut", busy, handoverHTTPWait)
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	// 4. RTR 연결
	var parked []*rtrConn
	if d.rtr != nil {
		if parked, err = d.rtr.waitParked(handoverParkWait); err != nil {
			return err
		}
	}
	tParked := time.Since(tPause)

	// 5. fd + 상태 파일
	hs := &handoverState{Version: handoverVersion, From: version, PausedAt: tPause, LockFd: -1, RTRFd: -1, TLSFd: -1,
		RTRAddr: d.cfg.RTRAddr, TLSAddr: d.cfg.RTRTLSAddr, Health: d.fetch.healthState()}
	d.mu.Lock()
	hs.Started, hs.Count = d.started, d.ho.Count+1
	d.mu.Unlock()
	dup := func(sc any) (int, error) {
		c, ok := sc.(syscall.Conn)
		if !ok {
			return -1, fmt.Errorf("%T has no fd", sc)
		}
		fd, err := dupFd(c)
		if err == nil {
			fds = append(fds, fd)
		}
		return fd, err
	}
	if hs.LockFd, err = dup(d.lockFile); err != nil {
		return fmt.Errorf("lock file fd : %w", err)
	}
	if rtrLn != nil {
		if hs.RTRFd, err = dup(rtrLn); err != nil {
			return fmt.Errorf("rtr listener fd : %w", err)
		}
	}
	if tlsLn != nil {
		if hs.TLSFd, err = dup(tlsLn); err != nil {
			return fmt.Errorf("rtr tls listener fd : %w", err)
		}
	}
	for _, h := range httpLns {
		fd, err := dup(h.Ln)
		if err != nil {
			return fmt.Errorf("http listener %s fd : %w", h.Addr, err)
		}
		hs.HTTP = append(hs.HTTP, fdAddr{h.Addr, fd})
	}
	tlsDropped := 0
	for _, rc := range parked {
		if _, isTLS := rc.c.(*tls.Conn); isTLS { // 암호 상태는 넘길 수 없음 : exec 로 닫힘 (라우터가 다시 붙음)
			tlsDropped++
			continue
		}
		fd, err := dup(rc.c)
		if err != nil { // 그 사이 닫힌 연결 : 넘기지 않음 = 라우터가 다시 붙음
			log.Printf("handover: rtr %s not passed (%v)", rc.remote, err)
			continue
		}
		hs.Conns = append(hs.Conns, rtrConnState{Fd: fd, Remote: rc.remote, Trans: rc.trans, Ver: rc.ver.Load(), Since: rc.since,
			LastFull: rc.lastFull, LastQ: rc.lastQ.Load(), SentSer: rc.sentSer.Load(), Pending: append([]byte(nil), rc.pending...)})
	}
	if err := writeHandover(path, hs); err != nil {
		return fmt.Errorf("state file %s : %w", path, err)
	}
	for _, fd := range fds { // 넘길 fd 만 exec 뒤에도 열림 (dup 은 CLOEXEC 없음, 나머지 fd 는 Go 가 CLOEXEC 로 엶)
		if err := clearCloexec(fd); err != nil {
			return fmt.Errorf("fd %d : %w", fd, err)
		}
	}
	log.Printf("handover: paused %d rtr connections (%d tls dropped) and %d http listeners in %s, state %s : exec %s",
		len(hs.Conns), tlsDropped, len(hs.HTTP), tParked.Round(time.Millisecond), path, d.exe)
	// 6. exec : 같은 pid, 같은 환경 (NOTIFY_SOCKET / WATCHDOG_USEC 그대로), 옵션 + -resume
	args := append([]string{os.Args[0]}, baseArgs()...)
	args = append(args, "-resume", path)
	err = syscall.Exec(d.exe, args, os.Environ())
	return fmt.Errorf("exec %s : %w", d.exe, err) // 여기 오면 exec 실패
}

// dupFd : 소켓 / 파일의 fd 복사 (dup 은 CLOEXEC 를 붙이지 않음). 원래 fd 는 Go 가 그대로 씀
func dupFd(sc syscall.Conn) (int, error) {
	rc, err := sc.SyscallConn()
	if err != nil {
		return -1, err
	}
	nfd, derr := -1, error(nil)
	if err := rc.Control(func(fd uintptr) { nfd, derr = syscall.Dup(int(fd)) }); err != nil {
		return -1, err
	}
	return nfd, derr
}

// clearCloexec : exec 뒤에도 열려 있게 (dup 은 이미 없지만 확실히)
func clearCloexec(fd int) error {
	_, _, e := syscall.Syscall(syscall.SYS_FCNTL, uintptr(fd), syscall.F_SETFD, 0)
	if e != 0 {
		return e
	}
	return nil
}

func writeHandover(path string, hs *handoverState) error {
	var b bytes.Buffer
	if err := gob.NewEncoder(&b).Encode(hs); err != nil {
		return err
	}
	return os.WriteFile(path, b.Bytes(), 0600)
}

// ---- 새 판 ----

// readHandover : -resume 의 상태 파일. 읽은 뒤 지움 (다음 재시작이 옛 파일을 보지 않게)
func readHandover(path string) (*handoverState, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	os.Remove(path)
	hs := &handoverState{}
	if err := gob.NewDecoder(bytes.NewReader(b)).Decode(hs); err != nil {
		return nil, fmt.Errorf("%s : %w", path, err)
	}
	if hs.Version != handoverVersion {
		return nil, fmt.Errorf("%s : state version %d, this binary knows %d", path, hs.Version, handoverVersion)
	}
	return hs, nil
}

// inherit : 이어받은 fd 하나. 다시 CLOEXEC (rsync 같은 자식 프로세스가 물려받지 않게)
func inherit(fd int, name string) *os.File {
	syscall.CloseOnExec(fd)
	return os.NewFile(uintptr(fd), name)
}

// lockFile : 옛 프로세스가 쥔 잠금 (flock 은 열린 파일에 걸림 -> 새로 열면 막힘)
func (hs *handoverState) lockFile(name string) *os.File {
	return inherit(hs.LockFd, name)
}

// restoreDaemon : 시작 시각, 저장소 backoff 기록, 판 올리기 횟수
func (hs *handoverState) restoreDaemon(d *daemon) {
	if !hs.Started.IsZero() {
		d.started = hs.Started
	}
	d.fetch.setHealth(hs.Health)
	d.ho.Count, d.ho.From = hs.Count, hs.From
}

// fileListener : 이어받은 듣기 소켓 (net.FileListener 가 다시 dup 하므로 받은 fd 는 닫음)
func fileListener(fd int, name string) (net.Listener, error) {
	f := inherit(fd, name)
	defer f.Close()
	return net.FileListener(f)
}

// httpListener : 이 주소의 이어받은 HTTP 듣기 소켓 (없으면 nil = 새로 엶)
func (hs *handoverState) httpListener(addr string) net.Listener {
	if hs == nil {
		return nil
	}
	for _, h := range hs.HTTP {
		if h.Addr != addr {
			continue
		}
		if hs.used == nil {
			hs.used = map[string]bool{}
		}
		hs.used[addr] = true
		ln, err := fileListener(h.Fd, "http "+addr)
		if err != nil {
			log.Printf("handover: http %s : %v (opening a new one)", addr, err)
			return nil
		}
		return ln
	}
	return nil
}

// closeUnusedHTTP : 설정에서 빠진 HTTP 주소의 이어받은 소켓을 닫음
func (hs *handoverState) closeUnusedHTTP() {
	if hs == nil {
		return
	}
	for _, h := range hs.HTTP {
		if !hs.used[h.Addr] {
			log.Printf("handover: http %s not in the config any more, closed", h.Addr)
			syscall.Close(h.Fd)
		}
	}
}

// resumeRTR : 이어받은 RTR 듣기 소켓과 라우터 연결. 집합이 없으면 (payload.gob 을 못 읽음) 모두 닫음 = 재시작과 같음
// 듣기 주소가 설정에서 바뀌었으면 이어받은 소켓을 그대로 씀 (주소를 바꾸려면 재시작, 기록 한 줄)
func (hs *handoverState) resumeRTR(d *daemon, have bool) {
	closeAll := func(why string) {
		for _, fd := range []int{hs.RTRFd, hs.TLSFd} {
			if fd >= 0 {
				syscall.Close(fd)
			}
		}
		for _, c := range hs.Conns {
			syscall.Close(c.Fd)
		}
		if len(hs.Conns) > 0 || hs.RTRFd >= 0 {
			log.Printf("handover: rtr sockets closed (%s), %d routers will reconnect", why, len(hs.Conns))
		}
		hs.Conns = nil
	}
	if !have {
		closeAll("no saved set")
		return
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if hs.RTRFd >= 0 {
		if d.cfg.RTRAddr == "" {
			syscall.Close(hs.RTRFd)
			log.Printf("handover: rtr listener %s closed (rtr off in the config)", hs.RTRAddr)
		} else if ln, err := fileListener(hs.RTRFd, "rtr "+hs.RTRAddr); err != nil {
			log.Printf("handover: rtr listener : %v (opening a new one)", err)
		} else {
			if d.cfg.RTRAddr != hs.RTRAddr {
				log.Printf("handover: rtr listen %s -> %s ignored, keeping the inherited socket (needs a restart)", hs.RTRAddr, d.cfg.RTRAddr)
			}
			d.rtrListen = ln
			go d.rtr.serve(ln)
		}
	}
	if hs.TLSFd >= 0 {
		if d.cfg.RTRTLSAddr == "" || d.rtrTLS == nil {
			syscall.Close(hs.TLSFd)
			log.Printf("handover: rtr tls listener %s closed (tls off in the config)", hs.TLSAddr)
		} else if ln, err := fileListener(hs.TLSFd, "rtr tls "+hs.TLSAddr); err != nil {
			log.Printf("handover: rtr tls listener : %v (opening a new one)", err)
		} else {
			if d.cfg.RTRTLSAddr != hs.TLSAddr {
				log.Printf("handover: rtr tls listen %s -> %s ignored, keeping the inherited socket (needs a restart)", hs.TLSAddr, d.cfg.RTRTLSAddr)
			}
			d.rtrTLSLn = ln
			go d.rtr.serve(tls.NewListener(ln, d.rtrTLS))
		}
	}
	if d.rtrListen == nil { // 평문 듣기 소켓이 없는데 연결만 이어받을 수는 없음 (보통 일어나지 않음)
		for _, c := range hs.Conns {
			syscall.Close(c.Fd)
		}
		hs.Conns = nil
		return
	}
	var live []rtrConnState
	for _, s := range hs.Conns {
		f := inherit(s.Fd, "rtr "+s.Remote)
		c, err := net.FileConn(f)
		f.Close()
		if err != nil {
			log.Printf("handover: rtr %s : %v", s.Remote, err)
			continue
		}
		slot, ok := d.rtr.take(s.Remote)
		if !ok { // 상한을 줄인 설정 (재시작과 같은 결과)
			c.Close()
			continue
		}
		rc := &rtrConn{srv: d.rtr, c: c, remote: s.Remote, slot: slot, trans: s.Trans, w: bufio.NewWriterSize(c, 64*1024),
			since: s.Since, lastFull: s.LastFull, pending: s.Pending, resumed: true}
		rc.ver.Store(s.Ver)
		rc.lastQ.Store(s.LastQ)
		rc.sentSer.Store(s.SentSer)
		d.rtr.register(rc)
		go rc.run()
		live = append(live, s)
	}
	hs.Conns = live
}

// resumed : 소켓 / 연결을 모두 이어받음 = 멈춤 끝 (기록 + 상태 API)
func (hs *handoverState) resumed(d *daemon) {
	pause := time.Since(hs.PausedAt)
	sdNotify("WATCHDOG=1")
	d.mu.Lock()
	d.ho.LastAt, d.ho.PauseMs, d.ho.Conns = time.Now(), pause.Milliseconds(), len(hs.Conns)
	d.mu.Unlock()
	log.Printf("handover: resumed from %s (#%d) : %d rtr connections, %d http listeners, paused %s",
		hs.From, hs.Count, len(hs.Conns), len(hs.HTTP), pause.Round(time.Millisecond))
}
