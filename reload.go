package main

// reload.go : systemctl reload haetae (= SIGHUP) 때 설정을 다시 읽음 (재시작 아님, RTR 세션 / VRP / 회차 그대로)
//
// 순서
//   1. 명령줄 + 설정 파일을 시작 때와 같은 규칙으로 다시 읽음 (명령줄이 우선, main.go 의 cfg.Reload)
//   2. 새 값을 모두 먼저 확인 (허용 목록, TLS 인증서). 하나라도 틀리면 아무것도 안 바꿈 = 지금 값으로 계속
//   3. 재시작해야 바뀌는 항목 (듣는 주소, 폴더 등) 은 지금 값을 유지하고 경고만
//   4. 나머지를 한 번에 바꿈 (설정 묶음 포인터 교체). 로그에 바뀐 항목만 "키 옛값 -> 새값"
//
// 언제부터 적용 : 허용 목록 = 다음 연결 / 요청부터 (RTR 은 목록에서 빠진 연결을 바로 끊음),
//   RTR 타이머 = 다음 End of Data, 회차 설정 (주기, 동시 수, SLURM, TAL, 급감) = 다음 회차, TLS 인증서 = 다음 TLS 연결

import (
	"crypto/tls"
	"fmt"
	"log"
	"net/netip"
	"os"
	"os/signal"
	"strings"
	"sync/atomic"
	"syscall"
	"time"
)

// confField : 설정 항목 하나 (로그 / 비교용). restart = 재시작해야 바뀜
type confField struct {
	key     string
	restart bool
	get     func(*daemonConfig) string
}

func str(v any) string { return fmt.Sprint(v) }

var confFields = []confField{
	{"paths.cache", true, func(c *daemonConfig) string { return c.CacheDir }},
	{"paths.out", true, func(c *daemonConfig) string { return c.OutDir }},
	{"paths.state", true, func(c *daemonConfig) string { return c.StateDir }},
	{"paths.tal", false, func(c *daemonConfig) string { return c.TALDir }},
	{"paths.slurm", false, func(c *daemonConfig) string { return c.SLURM }},
	{"fetch.interval", false, func(c *daemonConfig) string { return str(c.Interval) }},
	{"fetch.jobs", false, func(c *daemonConfig) string { return str(c.FetchJobs) }},
	{"fetch.rsync", false, func(c *daemonConfig) string { return str(!c.NoRsync) }},
	{"validation.workers", false, func(c *daemonConfig) string { return str(c.Workers) }},
	{"validation.drop-warn", false, func(c *daemonConfig) string { return str(c.DropWarn) }},
	{"validation.hold-drop", false, func(c *daemonConfig) string { return str(c.HoldOnDrop) }},
	{"validation.max-start-age", true, func(c *daemonConfig) string { return str(c.MaxStartAge) }},
	{"rtr.listen", true, func(c *daemonConfig) string { return c.RTRAddr }},
	{"rtr.allow", false, func(c *daemonConfig) string { return strings.Join(c.RTRAllow, ",") }},
	{"rtr.auth", true, func(c *daemonConfig) string { return c.RTRAuth }},
	{"rtr.refresh", false, func(c *daemonConfig) string { return str(c.RTRRefresh) }},
	{"rtr.retry", false, func(c *daemonConfig) string { return str(c.RTRRetry) }},
	{"rtr.expire", false, func(c *daemonConfig) string { return str(c.RTRExpire) }},
	{"rtr-tls.listen", true, func(c *daemonConfig) string { return c.RTRTLSAddr }},
	{"rtr-tls.cert", false, func(c *daemonConfig) string { return c.RTRTLSCert }},
	{"rtr-tls.key", false, func(c *daemonConfig) string { return c.RTRTLSKey }},
	{"rtr-tls.ca", false, func(c *daemonConfig) string { return c.RTRTLSCA }},
	{"http.listen", true, func(c *daemonConfig) string { return c.HTTPAddr }},
	{"http.allow", false, func(c *daemonConfig) string { return strings.Join(c.HTTPAllow, ",") }},
	{"http.jsonext", false, func(c *daemonConfig) string { return str(c.JSONExt) }},
	{"http.delta-full-interval", false, func(c *daemonConfig) string { return str(c.DeltaFullInterval) }},
}

// keepRestartFields : 재시작 항목은 지금 값 그대로 (돌고 있는 소켓 / 폴더와 맞아야 함)
func keepRestartFields(nc, old *daemonConfig) {
	nc.CacheDir, nc.OutDir, nc.StateDir = old.CacheDir, old.OutDir, old.StateDir
	nc.MaxStartAge = old.MaxStartAge
	nc.RTRAddr, nc.RTRAuth, nc.RTRTLSAddr = old.RTRAddr, old.RTRAuth, old.RTRTLSAddr
	nc.HTTPAddr = old.HTTPAddr
}

func parsePrefixes(list []string) ([]netip.Prefix, error) {
	var out []netip.Prefix
	for _, a := range list {
		p, err := parsePrefixOrAddr(a)
		if err != nil {
			return nil, fmt.Errorf("%q: %v", a, err)
		}
		out = append(out, p)
	}
	return out, nil
}

// tlsLive : TLS 듣기 소켓용 설정. 연결마다 cur 의 지금 설정을 씀 -> reload 로 인증서를 바꾸면 다음 연결부터
func tlsLive(cur *atomic.Pointer[tls.Config], first *tls.Config) *tls.Config {
	cur.Store(first)
	return &tls.Config{
		MinVersion: tls.VersionTLS12,
		GetConfigForClient: func(*tls.ClientHelloInfo) (*tls.Config, error) {
			return cur.Load(), nil
		},
	}
}

// watchReload : SIGHUP 을 기다렸다가 reload (systemd ExecReload = kill -HUP $MAINPID)
func (d *daemon) watchReload() {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGHUP)
	for range ch {
		d.reload()
	}
}

// reload : 설정을 다시 읽어 바꿀 수 있는 것만 바꿈. 실패하면 아무것도 안 바꾸고 오류를 돌려줌
func (d *daemon) reload() error {
	if d.cfg.Reload == nil {
		log.Printf("설정 다시 읽기 : 지원 안 함 (Reload 없음)")
		return fmt.Errorf("no reload")
	}
	nc, path, err := d.cfg.Reload()
	if err != nil {
		return reloadFail(err)
	}
	old := d.c()

	// 새 값을 바꾸기 전에 모두 확인
	rtrAllow, err := parsePrefixes(nc.RTRAllow)
	if err != nil {
		return reloadFail(fmt.Errorf("rtr.allow %v", err))
	}
	httpAllow, err := parsePrefixes(nc.HTTPAllow)
	if err != nil {
		return reloadFail(fmt.Errorf("http.allow %v", err))
	}
	var newTLS *tls.Config // TLS 포트가 열려 있고 인증서가 바뀌었을 때만 새로 읽음
	if d.rtrTLS != nil && (nc.RTRTLSCert != old.RTRTLSCert || nc.RTRTLSKey != old.RTRTLSKey || nc.RTRTLSCA != old.RTRTLSCA) {
		if newTLS, err = rtrTLSConfig(nc.RTRTLSCert, nc.RTRTLSKey, nc.RTRTLSCA); err != nil {
			return reloadFail(fmt.Errorf("rtr-tls %v", err))
		}
	}
	d.applyReload(&nc, old, path, rtrAllow, httpAllow, newTLS)
	return nil
}

func reloadFail(err error) error {
	log.Printf("설정 다시 읽기 실패, 지금 값 유지 : %v", err)
	return err
}

// applyReload : 확인이 끝난 새 설정을 적용하고 로그를 남김
func (d *daemon) applyReload(nc, old *daemonConfig, path string, rtrAllow, httpAllow []netip.Prefix, newTLS *tls.Config) {
	var changed, restart []string
	for _, f := range confFields {
		a, b := f.get(old), f.get(nc)
		if a == b {
			continue
		}
		if f.restart {
			restart = append(restart, fmt.Sprintf("%s (지금 %q, 파일 %q)", f.key, a, b))
		} else {
			changed = append(changed, fmt.Sprintf("%s %q -> %q", f.key, a, b))
		}
	}
	keepRestartFields(nc, old)
	nc.Reload, nc.ConfPath = d.cfg.Reload, path

	d.live.Store(nc)
	d.httpAllow.Store(&httpAllow)
	if newTLS != nil {
		d.rtrTLSCur.Store(newTLS)
	}
	dropped := 0
	if d.rtr != nil {
		dropped = d.rtr.setLive(rtrAllow, nc.RTRRefresh, nc.RTRRetry, nc.RTRExpire)
	}
	d.mu.Lock()
	d.confPath, d.confAt = path, time.Now()
	d.mu.Unlock()

	if len(changed) == 0 {
		log.Printf("설정 다시 읽음 (%s) : 바뀐 것 없음", path)
	} else {
		log.Printf("설정 다시 읽음 (%s) : %s", path, strings.Join(changed, ", "))
	}
	if dropped > 0 {
		log.Printf("설정 다시 읽음 : 허용 목록에서 빠진 RTR 연결 %d 개 끊음", dropped)
	}
	if len(restart) > 0 {
		log.Printf("설정 다시 읽음 : 재시작해야 바뀌는 항목 (지금 값 유지) : %s", strings.Join(restart, ", "))
	}
}
