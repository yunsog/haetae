package main

// reload_test.go : systemctl reload (설정 다시 읽기)

import (
	"encoding/binary"
	"errors"
	"io"
	"log"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"
)

// reloadDaemon : 지금 설정 base 로 도는 것처럼 꾸민 daemon. next 가 reload 때 읽힐 새 설정
func reloadDaemon(base daemonConfig, next func() (daemonConfig, string, error)) *daemon {
	base.Reload = next
	d := &daemon{cfg: base, st: &store{Session: 7}}
	d.live.Store(&base)
	allow, _ := parsePrefixes(base.HTTPAllow)
	d.httpAllow.Store(&allow)
	rtrAllow, _ := parsePrefixes(base.RTRAllow)
	d.rtr = &rtrServer{St: d.st, Allow: rtrAllow, Refresh: base.RTRRefresh, Retry: base.RTRRetry, Expire: base.RTRExpire, Logf: log.Printf}
	return d
}

func baseConf() daemonConfig {
	return daemonConfig{CacheDir: "/c", OutDir: "/o", StateDir: "/s", Interval: 10 * time.Minute, Workers: 4, FetchJobs: 32,
		RTRAddr: ":3323", RTRAllow: []string{"127.0.0.1"}, RTRRefresh: 600, RTRRetry: 300, RTRExpire: 7200,
		HTTPAddr: "127.0.0.1:8323", HTTPAllow: []string{"127.0.0.1"}, DeltaFullInterval: time.Minute, DropWarn: 0.1}
}

// 바로 바뀌는 항목은 바뀌고, 재시작 항목은 지금 값 그대로
func TestReloadApply(t *testing.T) {
	next := baseConf()
	next.RTRAllow = []string{"127.0.0.1", "10.0.0.1"}
	next.RTRRetry = 120
	next.HTTPAllow = []string{"127.0.0.1", "198.51.100.0/24"}
	next.JSONExt, next.HoldOnDrop, next.DropWarn, next.Interval = true, true, 0.05, 5*time.Minute
	next.HTTPAddr, next.CacheDir, next.RTRAddr = "0.0.0.0:9999", "/other", ":9999" // 재시작 항목
	d := reloadDaemon(baseConf(), func() (daemonConfig, string, error) { return next, "/etc/haetae/haetae.conf", nil })

	if err := d.reload(); err != nil {
		t.Fatal(err)
	}
	c := d.c()
	if !c.JSONExt || !c.HoldOnDrop || c.DropWarn != 0.05 || c.Interval != 5*time.Minute || c.RTRRetry != 120 {
		t.Errorf("바로 바뀌는 항목 : %+v", c)
	}
	if c.HTTPAddr != "127.0.0.1:8323" || c.CacheDir != "/c" || c.RTRAddr != ":3323" {
		t.Errorf("재시작 항목이 바뀜 : http %s cache %s rtr %s", c.HTTPAddr, c.CacheDir, c.RTRAddr)
	}
	if !d.rtr.allowedIP(netip.MustParseAddr("10.0.0.1")) {
		t.Error("RTR 허용 목록이 안 바뀜")
	}
	if _, retry, _ := d.rtr.timers(); retry != 120 {
		t.Errorf("RTR retry %d", retry)
	}
	if len(*d.httpAllow.Load()) != 2 || d.confPath != "/etc/haetae/haetae.conf" || d.confAt.IsZero() {
		t.Errorf("http allow %v, 설정 %q %v", *d.httpAllow.Load(), d.confPath, d.confAt)
	}
	if d.c().Reload == nil {
		t.Error("다음 reload 를 위해 Reload 가 남아 있어야 함")
	}
}

// 새 설정이 틀리면 아무것도 안 바꿈 (지금 값으로 계속)
func TestReloadRejectKeepsOld(t *testing.T) {
	for name, next := range map[string]func() (daemonConfig, string, error){
		"읽기 실패": func() (daemonConfig, string, error) { return daemonConfig{}, "", errors.New("3 줄 : 모르는 키") },
		"rtr allow 틀림": func() (daemonConfig, string, error) {
			c := baseConf()
			c.RTRAllow, c.JSONExt = []string{"not-an-ip"}, true
			return c, "x", nil
		},
		"http allow 틀림": func() (daemonConfig, string, error) {
			c := baseConf()
			c.HTTPAllow, c.JSONExt = []string{"1.2.3.4/99"}, true
			return c, "x", nil
		},
	} {
		d := reloadDaemon(baseConf(), next)
		before := d.c()
		if err := d.reload(); err == nil {
			t.Errorf("%s : 오류여야 함", name)
		}
		if d.c() != before || d.c().JSONExt || !d.rtr.allowedIP(netip.MustParseAddr("127.0.0.1")) {
			t.Errorf("%s : 설정이 바뀌었음", name)
		}
	}
}

// 허용 목록에서 빠진 주소의 RTR 연결은 reload 때 끊김
func TestReloadDropsRTRConn(t *testing.T) {
	d := reloadDaemon(baseConf(), func() (daemonConfig, string, error) {
		c := baseConf()
		c.RTRAllow = []string{"10.0.0.0/8"} // 127.0.0.1 빠짐
		return c, "x", nil
	})
	d.st.update(mkSet([]rtrVRP{vr("10.0.0.0/8", 24, 65001)}, nil))
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go d.rtr.serve(ln)
	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.Write(query(1, pduResetQuery, 0, nil))
	readUntilEOD(t, c) // 붙어서 받는 중

	if err := d.reload(); err != nil {
		t.Fatal(err)
	}
	c.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := io.ReadFull(c, make([]byte, 8)); err == nil || strings.Contains(err.Error(), "timeout") {
		t.Errorf("연결이 끊겨야 함 : %v", err)
	}
}

// RTR 타이머는 다음 End of Data 부터 새 값
func TestReloadRTRTimers(t *testing.T) {
	d := reloadDaemon(baseConf(), func() (daemonConfig, string, error) {
		c := baseConf()
		c.RTRRefresh, c.RTRRetry, c.RTRExpire = 900, 120, 3600
		return c, "x", nil
	})
	d.st.update(mkSet([]rtrVRP{vr("10.0.0.0/8", 24, 65001)}, nil))
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go d.rtr.serve(ln)
	if err := d.reload(); err != nil {
		t.Fatal(err)
	}
	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.Write(query(1, pduResetQuery, 0, nil))
	for {
		p := readPDU(t, c)
		if p.typ != pduEndOfData {
			continue
		}
		// v1 End of Data 본문 : serial, refresh, retry, expire
		if r, y, e := binary.BigEndian.Uint32(p.body[4:]), binary.BigEndian.Uint32(p.body[8:]), binary.BigEndian.Uint32(p.body[12:]); r != 900 || y != 120 || e != 3600 {
			t.Errorf("End of Data 타이머 %d / %d / %d", r, y, e)
		}
		return
	}
}
