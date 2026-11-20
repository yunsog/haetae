// SPDX-License-Identifier: Apache-2.0

package main

// rtr_auth.go : RTR 전송 보안 (결정 C2, RFC 8210 7 절 / RFC 6810 7 절)
//
// 라우터마다 지원하는 방식이 달라 셋 다 둠 (모두 Go 표준만)
//   TCP-MD5 (RFC 2385) / TCP-AO (RFC 5925) : RTR 포트 (-rtr) 그대로, 리눅스 커널이 TCP 세그먼트마다 서명.
//     라우터 주소별 키를 듣기 소켓에 setsockopt (listen 전에). 키가 있는 주소에서 서명 없이 오면 커널이 버림.
//     키가 없는 주소는 지금처럼 그냥 TCP (허용 목록은 그대로 적용)
//   TLS : 따로 포트 (-rtr-tls), crypto/tls. -rtr-tls-ca 를 주면 라우터 인증서 필수
//   SSH : Go 표준에 SSH 서버가 없음 -> 시스템 sshd 의 "rpki-rtr" subsystem 이 haetae -rtr-stdio 를 실행해
//     표준 입출력을 RTR 포트 (127.0.0.1) 로 이어 줌 (runRTRStdio, 설정은 docs/manual.md)
//
// 키 파일 (-rtr-auth, 소유자만 읽기 0600 권장, 키를 명령줄에 두지 않으려고 파일로)
//   # 주소 또는 대역   방식   나머지
//   192.0.2.1          md5    <비밀번호>
//   192.0.2.0/24       ao     <알고리즘> <sendid> <recvid> <비밀번호>
//   알고리즘 : hmac(sha1) (RFC 5926 HMAC-SHA-1-96), cmac(aes128) (AES-128-CMAC-96), hmac(sha256)
//   sendid / recvid : 우리 쪽에서 본 값 (라우터 설정의 send-id / receive-id 와 엇갈림), MAC 길이 12 바이트

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

// 리눅스 <linux/tcp.h>
const (
	sysTCPMD5SigExt       = 32 // TCP_MD5SIG_EXT
	sysTCPMD5FlagPrefix   = 0x1
	sysTCPAOAddKey        = 38 // TCP_AO_ADD_KEY
	sysTCPKeyMax          = 80 // TCP_MD5SIG_MAXKEYLEN = TCP_AO_MAXKEYLEN
	sizeofSockaddrStorage = 128
	sizeofTCPMD5Sig       = 216 // struct tcp_md5sig
	sizeofTCPAOAdd        = 288 // struct tcp_ao_add (aligned 8)
	tcpAOMACLen           = 12
)

// rtrAuthKey : 키 파일 한 줄
type rtrAuthKey struct {
	Peer    netip.Prefix
	Method  string // md5 / ao
	Alg     string // ao 만
	SendID  uint8
	RecvID  uint8
	Key     []byte
	LineNum int
}

// loadRTRAuth : 키 파일 읽기. 다른 사람이 읽을 수 있으면 경고만
func loadRTRAuth(path string, logf func(string, ...any)) ([]rtrAuthKey, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	if st, err := f.Stat(); err == nil && st.Mode().Perm()&0o077 != 0 {
		logf("rtr auth: %s mode %o (0600 recommended, keys inside)", path, st.Mode().Perm())
	}
	var keys []rtrAuthKey
	sc := bufio.NewScanner(f)
	n := 0
	for sc.Scan() {
		n++
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, err := parseRTRAuthLine(line)
		if err != nil {
			return nil, fmt.Errorf("%s:%d: %w", path, n, err)
		}
		k.LineNum = n
		keys = append(keys, k)
	}
	return keys, sc.Err()
}

func parseRTRAuthLine(line string) (rtrAuthKey, error) {
	var k rtrAuthKey
	f := strings.Fields(line)
	if len(f) < 3 {
		return k, fmt.Errorf("want: <addr> md5 <key> | <addr> ao <alg> <sendid> <recvid> <key>")
	}
	p, err := parsePrefixOrAddr(f[0])
	if err != nil {
		return k, err
	}
	k.Peer, k.Method = p, f[1]
	switch k.Method {
	case "md5":
		if len(f) != 3 {
			return k, fmt.Errorf("md5: want <addr> md5 <key>")
		}
		k.Key = []byte(f[2])
	case "ao":
		if len(f) != 6 {
			return k, fmt.Errorf("ao: want <addr> ao <alg> <sendid> <recvid> <key>")
		}
		switch f[2] {
		case "hmac(sha1)", "cmac(aes128)", "hmac(sha256)":
		default:
			return k, fmt.Errorf("ao: unknown algorithm %q", f[2])
		}
		k.Alg = f[2]
		s, err1 := strconv.ParseUint(f[3], 10, 8)
		r, err2 := strconv.ParseUint(f[4], 10, 8)
		if err1 != nil || err2 != nil {
			return k, fmt.Errorf("ao: sendid / recvid 0..255")
		}
		k.SendID, k.RecvID, k.Key = uint8(s), uint8(r), []byte(f[5])
	default:
		return k, fmt.Errorf("unknown method %q (md5 / ao)", k.Method)
	}
	if len(k.Key) == 0 || len(k.Key) > sysTCPKeyMax {
		return k, fmt.Errorf("key length 1..%d", sysTCPKeyMax)
	}
	return k, nil
}

// putSockaddr : sockaddr_storage 자리에 주소를 씀. v6sock = IPv6 (이중 스택) 소켓이면 IPv4 를 ::ffff:a.b.c.d 로
// (커널이 IPv4 키로 바꿔 넣음, 대역 길이는 IPv4 기준 그대로)
func putSockaddr(b []byte, p netip.Prefix, v6sock bool) int {
	a := p.Addr()
	if a.Is4() && !v6sock {
		binary.NativeEndian.PutUint16(b[0:], syscall.AF_INET)
		a4 := a.As4()
		copy(b[4:8], a4[:])
		return p.Bits()
	}
	binary.NativeEndian.PutUint16(b[0:], syscall.AF_INET6)
	a16 := a.As16() // IPv4 면 ::ffff:a.b.c.d
	copy(b[8:24], a16[:])
	return p.Bits()
}

// md5Opt : struct tcp_md5sig (TCP_MD5SIG_EXT + 대역 길이)
func md5Opt(k rtrAuthKey, v6sock bool) []byte {
	b := make([]byte, sizeofTCPMD5Sig)
	plen := putSockaddr(b, k.Peer, v6sock)
	b[128] = sysTCPMD5FlagPrefix
	b[129] = byte(plen)
	binary.NativeEndian.PutUint16(b[130:], uint16(len(k.Key)))
	copy(b[136:], k.Key)
	return b
}

// aoOpt : struct tcp_ao_add. 처음 키를 current / rnext 로
func aoOpt(k rtrAuthKey, v6sock bool, first bool) []byte {
	b := make([]byte, sizeofTCPAOAdd)
	plen := putSockaddr(b, k.Peer, v6sock)
	copy(b[128:192], k.Alg)
	if first {
		binary.NativeEndian.PutUint32(b[196:], 0x3) // set_current | set_rnext (비트 필드, 아래 비트부터)
	}
	b[202] = byte(plen)
	b[203] = k.SendID
	b[204] = k.RecvID
	b[205] = tcpAOMACLen
	b[207] = byte(len(k.Key))
	copy(b[208:], k.Key)
	return b
}

func setsockoptBytes(fd uintptr, opt int, b []byte) error {
	_, _, e := syscall.Syscall6(syscall.SYS_SETSOCKOPT, fd, syscall.IPPROTO_TCP, uintptr(opt),
		uintptr(unsafe.Pointer(&b[0])), uintptr(len(b)), 0)
	if e != 0 {
		return e
	}
	return nil
}

// applyTCPAuth : 소켓에 키 전부 (듣기 소켓은 listen 전, 시험용 클라이언트는 connect 전)
func applyTCPAuth(fd uintptr, keys []rtrAuthKey, v6sock bool) error {
	firstAO := map[netip.Prefix]bool{}
	for _, k := range keys {
		if !v6sock && k.Peer.Addr().Is6() {
			continue // IPv4 전용 소켓에는 IPv6 키를 못 넣음
		}
		var err error
		switch k.Method {
		case "md5":
			err = setsockoptBytes(fd, sysTCPMD5SigExt, md5Opt(k, v6sock))
		case "ao":
			err = setsockoptBytes(fd, sysTCPAOAddKey, aoOpt(k, v6sock, !firstAO[k.Peer]))
			firstAO[k.Peer] = true
		}
		if err != nil {
			return fmt.Errorf("line %d (%s %s): %w", k.LineNum, k.Peer, k.Method, err)
		}
	}
	return nil
}

// authListenConfig : 키를 넣는 ListenConfig (키가 없으면 그냥 keepalive 만)
func authListenConfig(keys []rtrAuthKey) *net.ListenConfig {
	lc := &net.ListenConfig{KeepAlive: 60 * time.Second}
	if len(keys) == 0 {
		return lc
	}
	lc.Control = func(network, address string, c syscall.RawConn) error {
		var err error
		cerr := c.Control(func(fd uintptr) {
			err = applyTCPAuth(fd, keys, network == "tcp6")
		})
		if cerr != nil {
			return cerr
		}
		return err
	}
	return lc
}

// transportOf : 연결 하나의 전송 방식 (상태 API 의 transport)
func (s *rtrServer) transportOf(c net.Conn) string {
	if _, ok := c.(*tls.Conn); ok {
		return "tls"
	}
	ta, ok := c.RemoteAddr().(*net.TCPAddr)
	if !ok {
		return "tcp"
	}
	ip, _ := netip.AddrFromSlice(ta.IP)
	ip = ip.Unmap()
	// 커널은 가장 긴 대역의 키를 씀 -> 같게
	best, method := -1, "tcp"
	for _, k := range s.Auth {
		if k.Peer.Contains(ip) && k.Peer.Bits() > best {
			best, method = k.Peer.Bits(), "tcp-"+k.Method
		}
	}
	return method
}

// ---- TLS ----

// rtrTLSConfig : 서버 인증서 + (caFile 이 있으면) 라우터 인증서 필수
func rtrTLSConfig(certFile, keyFile, caFile string) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, err
	}
	cfg := &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13} // RFC 9852 (8210bis-29 9 장의 BCP 195)
	if caFile != "" {
		pem, err := os.ReadFile(caFile)
		if err != nil {
			return nil, err
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("%s: no PEM certificate", caFile)
		}
		cfg.ClientCAs, cfg.ClientAuth = pool, tls.RequireAndVerifyClientCert
	}
	return cfg, nil
}

// ---- SSH (sshd subsystem 에서 실행) ----

// runRTRStdio : 표준 입출력 <-> RTR 포트. sshd 가 라우터 하나마다 실행.
// 해태에게는 모든 SSH 라우터가 127.0.0.1 로 보이므로, 첫머리에 라우터의 실제 주소를 PROXY 한 줄로 알림 (B8)
func runRTRStdio(addr string) int {
	c, err := net.DialTimeout("tcp", addr, 10*time.Second)
	if err != nil {
		fmt.Fprintln(os.Stderr, "rtr-stdio:", err)
		return 1
	}
	if line := proxyLine(os.Getenv("SSH_CONNECTION")); line != "" {
		if _, err := io.WriteString(c, line); err != nil {
			fmt.Fprintln(os.Stderr, "rtr-stdio:", err)
			return 1
		}
	}
	relayStdio(c, os.Stdin, os.Stdout)
	return 0
}

// ---- PROXY protocol v1 한 줄 (HAProxy 문서 "proxy-protocol.txt" 2.1, 텍스트 판) ----
//
//	"PROXY TCP4 <라우터 IP> <서버 IP> <라우터 포트> <서버 포트>\r\n" (IPv6 는 TCP6), 최대 107 바이트
//
// -rtr-stdio 가 보내고, 해태는 loopback 평문 연결의 첫머리일 때만 받음 (proxyAllowed).
// 인터넷에서 온 연결이 보내면 지금처럼 잘못된 PDU (길이 틀림) 로 끊김 = 주소를 속일 수 없음.
// 같은 서버의 다른 계정은 속일 수 있음 (해태를 돌리는 서버에 아무나 로그인하지 않는다는 전제)

const proxyMaxLine = 107

// proxyLine : sshd 의 SSH_CONNECTION ("라우터IP 라우터포트 서버IP 서버포트") -> PROXY 한 줄 ("" = 못 만듦 = 보내지 않음)
func proxyLine(sshConn string) string {
	f := strings.Fields(sshConn)
	if len(f) != 4 {
		return ""
	}
	src, err1 := netip.ParseAddr(f[0])
	dst, err2 := netip.ParseAddr(f[2])
	_, err3 := strconv.ParseUint(f[1], 10, 16)
	_, err4 := strconv.ParseUint(f[3], 10, 16)
	if err1 != nil || err2 != nil || err3 != nil || err4 != nil {
		return ""
	}
	src, dst = src.Unmap(), dst.Unmap()
	proto := "TCP4"
	if src.Is6() || dst.Is6() {
		if src.Is4() || dst.Is4() {
			return ""
		}
		proto = "TCP6"
	}
	return fmt.Sprintf("PROXY %s %s %s %s %s\r\n", proto, src, dst, f[1], f[3])
}

// proxyAllowed : 이 연결이 첫머리에 PROXY 한 줄을 보내도 되는지 = loopback 에서 온 평문 TCP (-rtr-stdio)
func proxyAllowed(remote, trans string) bool {
	ap, err := netip.ParseAddrPort(remote)
	return err == nil && trans == "tcp" && ap.Addr().Unmap().IsLoopback()
}

// takeProxy : rc.pending 첫머리의 PROXY 한 줄을 읽어 연결의 주소를 라우터 주소로 바꿈 (readPDU 가 부름).
// done=false : 한 줄이 아직 덜 옴. 첫 바이트가 'P' 가 아니면 보통 RTR (PROXY 없음) -> loopback 주소로 자리를 잡고 done.
// PROXY 면 연결 자리 (상한 / trusted) 를 라우터 주소로 잡음 (판 올리기로 이어받아 loopback 자리가 있으면 돌려줌)
func (rc *rtrConn) takeProxy() (done bool, err error) {
	s := rc.srv
	if rc.pending[0] != 'P' {
		rc.proxyOK = false
		return rc.slotHere()
	}
	i := bytes.Index(rc.pending, []byte("\r\n"))
	if i < 0 {
		if len(rc.pending) > proxyMaxLine {
			return false, errors.New("bad PROXY line (too long)")
		}
		return false, nil
	}
	line := string(rc.pending[:i])
	rc.pending = append(rc.pending[:0], rc.pending[i+2:]...)
	rc.proxyOK = false
	f := strings.Fields(line)
	if len(f) == 2 && f[0] == "PROXY" && f[1] == "UNKNOWN" { // 주소를 모름 : loopback 그대로
		return rc.slotHere()
	}
	if len(f) != 6 || f[0] != "PROXY" || (f[1] != "TCP4" && f[1] != "TCP6") {
		return false, fmt.Errorf("bad PROXY line %q", line)
	}
	ip, err := netip.ParseAddr(f[2])
	port, perr := strconv.ParseUint(f[4], 10, 16)
	if err != nil || perr != nil {
		return false, fmt.Errorf("bad PROXY line %q", line)
	}
	remote := netip.AddrPortFrom(ip.Unmap(), uint16(port)).String()
	slot, ok := s.take(remote)
	if !ok {
		return false, fmt.Errorf("ssh %s: connection limit", remote)
	}
	s.Logf("rtr %s: ssh from %s", rc.remote, remote)
	s.mu.Lock() // remote / trans / slot 은 상태 API (clientsInfo) 가 읽음
	old := rc.slot
	rc.remote, rc.trans, rc.slot = remote, "ssh", slot
	s.mu.Unlock()
	s.release(old)
	return true, nil
}

// slotHere : PROXY 없는 loopback 연결 = 자기 주소로 자리를 잡음 (이미 있으면 그대로)
func (rc *rtrConn) slotHere() (bool, error) {
	if rc.slot.taken {
		return true, nil
	}
	slot, ok := rc.srv.take(rc.remote)
	if !ok {
		return false, errors.New("connection limit")
	}
	rc.srv.mu.Lock()
	rc.slot = slot
	rc.srv.mu.Unlock()
	return true, nil
}

// relayStdio : in -> c, c -> out 을 옮김. 끝은 RTR 쪽 (c -> out) 이 정함 (11-04 고침)
//   - 라우터가 보내기만 닫음 (in EOF) : RTR 쪽에도 보내기 끝 (CloseWrite) 만 알리고, 남은 응답은 끝까지 넘김
//     (전에는 여기서 바로 닫아 해태가 보내던 응답이 잘림)
//   - 라우터가 끊음 : sshd 가 in 을 닫음 -> 위와 같이 RTR 쪽에 알림 -> 해태가 연결을 닫음 -> 끝
//   - 해태가 끊음 (유휴 시간 등) : c -> out 이 끝남 -> 바로 끝 (in 을 기다리지 않음)
func relayStdio(c net.Conn, in io.Reader, out io.Writer) {
	go func() {
		io.Copy(c, in)
		if tc, ok := c.(*net.TCPConn); ok {
			tc.CloseWrite()
		}
	}()
	io.Copy(out, c)
	c.Close()
}
