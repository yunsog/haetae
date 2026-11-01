package main

// rtr_auth_test.go : TCP-MD5 / TCP-AO 키를 넣은 듣기 소켓에 같은 키 / 다른 키 / 키 없이 붙어 봄, TLS RTR

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"log"
	"math/big"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func mustKey(t *testing.T, line string) rtrAuthKey {
	t.Helper()
	k, err := parseRTRAuthLine(line)
	if err != nil {
		t.Fatalf("%q: %v", line, err)
	}
	return k
}

// echoOnce : 받은 연결마다 한 바이트 읽어 되돌려 줌
func echoOnce(ln net.Listener) {
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		go func() {
			defer c.Close()
			b := make([]byte, 1)
			c.SetDeadline(time.Now().Add(3 * time.Second))
			if _, err := c.Read(b); err == nil {
				c.Write(b)
			}
		}()
	}
}

// tryDial : 클라이언트 쪽 키 (nil = 키 없음) 로 붙어 한 바이트 주고받기
func tryDial(addr string, keys []rtrAuthKey) error {
	d := net.Dialer{Timeout: 800 * time.Millisecond}
	if len(keys) > 0 {
		d.Control = func(network, address string, c syscall.RawConn) error {
			var err error
			c.Control(func(fd uintptr) { err = applyTCPAuth(fd, keys, network == "tcp6") })
			return err
		}
	}
	c, err := d.Dial("tcp", addr)
	if err != nil {
		return err
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(800 * time.Millisecond))
	if _, err := c.Write([]byte{7}); err != nil {
		return err
	}
	b := make([]byte, 1)
	_, err = c.Read(b)
	return err
}

func TestRTRTCPAuth(t *testing.T) {
	cases := []struct {
		name   string
		server string // 서버 키 (peer = 클라이언트 127.0.0.1)
		good   string // 같은 키 (클라이언트 쪽, peer = 서버 127.0.0.1)
		bad    string // 다른 키
	}{
		{"md5", "127.0.0.1 md5 secret1", "127.0.0.1 md5 secret1", "127.0.0.1 md5 secret2"},
		{"ao-sha1", "127.0.0.0/8 ao hmac(sha1) 1 2 secret1", "127.0.0.1 ao hmac(sha1) 2 1 secret1", "127.0.0.1 ao hmac(sha1) 2 1 secret2"},
		{"ao-cmac", "127.0.0.1 ao cmac(aes128) 5 6 secret1", "127.0.0.1 ao cmac(aes128) 6 5 secret1", "127.0.0.1 ao cmac(aes128) 6 9 secret1"},
	}
	for _, c := range cases {
		// IPv4 소켓과 이중 스택 (IPv6) 소켓 둘 다 (운영은 ":3323" = 이중 스택)
		for _, laddr := range []string{"127.0.0.1:0", "[::]:0"} {
			ln, err := authListenConfig([]rtrAuthKey{mustKey(t, c.server)}).Listen(context.Background(), "tcp", laddr)
			if err != nil {
				t.Fatalf("%s %s listen: %v", c.name, laddr, err)
			}
			go echoOnce(ln)
			addr := netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), uint16(ln.Addr().(*net.TCPAddr).Port)).String()
			if err := tryDial(addr, []rtrAuthKey{mustKey(t, c.good)}); err != nil {
				t.Errorf("%s %s same key: %v", c.name, laddr, err)
			}
			if err := tryDial(addr, []rtrAuthKey{mustKey(t, c.bad)}); err == nil {
				t.Errorf("%s %s wrong key: connected", c.name, laddr)
			}
			if err := tryDial(addr, nil); err == nil {
				t.Errorf("%s %s no key: connected", c.name, laddr)
			}
			ln.Close()
		}
	}

	// 키 없는 주소는 그냥 TCP (다른 라우터용 키만 있음)
	ln, err := authListenConfig([]rtrAuthKey{mustKey(t, "192.0.2.1 md5 x")}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go echoOnce(ln)
	if err := tryDial(ln.Addr().String(), nil); err != nil {
		t.Errorf("unkeyed peer: %v", err)
	}
	ln.Close()

	for _, bad := range []string{"1.2.3.4 md5", "1.2.3.4 ao hmac(md5) 1 2 k", "1.2.3.4 ao hmac(sha1) 1 300 k", "x md5 k", "1.2.3.4 sha k"} {
		if _, err := parseRTRAuthLine(bad); err == nil {
			t.Errorf("%q: want error", bad)
		}
	}
}

// testCert : 시험용 자체 서명 인증서 (PEM 파일 두 개)
func testCert(t *testing.T, dir, name string) (certFile, keyFile string) {
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: name},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, IsCA: true, BasicConstraintsValid: true,
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	kb, _ := x509.MarshalECPrivateKey(k)
	certFile, keyFile = filepath.Join(dir, name+".pem"), filepath.Join(dir, name+".key")
	os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600)
	os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb}), 0600)
	return
}

func TestRTRTLS(t *testing.T) {
	dir := t.TempDir()
	sc, sk := testCert(t, dir, "server")
	cc, ck := testCert(t, dir, "router")
	cfg, err := rtrTLSConfig(sc, sk, cc) // 라우터 인증서 필수 (자체 서명이라 자기가 CA)
	if err != nil {
		t.Fatal(err)
	}
	st := &store{Session: 9}
	st.update(mkSet([]rtrVRP{vr("192.0.2.0/24", 24, 64500)}, nil))
	srv := &rtrServer{St: st, Allow: []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}, Logf: log.Printf}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go srv.serve(tls.NewListener(ln, cfg))

	pool := x509.NewCertPool()
	b, _ := os.ReadFile(sc)
	pool.AppendCertsFromPEM(b)
	cert, _ := tls.LoadX509KeyPair(cc, ck)

	// 라우터 인증서 있음 -> Reset Query 에 VRP 1 개
	c, err := tls.Dial("tcp", ln.Addr().String(), &tls.Config{RootCAs: pool, Certificates: []tls.Certificate{cert}})
	if err != nil {
		t.Fatal(err)
	}
	c.Write([]byte{1, pduResetQuery, 0, 0, 0, 0, 0, 8})
	n := readUntilEOD(t, c)
	if n[pduIPv4Prefix] != 1 || n[pduEndOfData] != 1 {
		t.Errorf("tls reset: %v", n)
	}
	time.Sleep(50 * time.Millisecond)
	if ci := srv.clientsInfo(); len(ci) != 1 || ci[0].Transport != "tls" {
		t.Errorf("clients: %+v", ci)
	}
	c.Close()

	// 라우터 인증서 없음 -> 인사 실패
	c2, err := tls.Dial("tcp", ln.Addr().String(), &tls.Config{RootCAs: pool})
	if err == nil {
		c2.Write([]byte{1, pduResetQuery, 0, 0, 0, 0, 0, 8})
		c2.SetReadDeadline(time.Now().Add(2 * time.Second))
		if _, err = c2.Read(make([]byte, 8)); err == nil {
			t.Errorf("tls without client cert: got data")
		}
		c2.Close()
	}
}
