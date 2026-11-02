package main

// ops.go : 운영 안정 (0.2.0)
//
//   묵은 데이터   1 분마다 지금 집합의 나이 (검증 시각부터) 를 봄. -stale-warn 넘으면 경고 로그 / 상태 stale,
//                 -stale-close (0 = 끔) 넘으면 RTR 을 닫음 -> 라우터가 다른 RP 로 넘어감. 새 집합이 반영되면 다시 엶 (openRTR)
//   /healthz      정상 200 / 아니면 503 + 이유 (감시 시스템용, 공개 쪽에서도 됨)
//   watchdog      systemd Type=notify + WatchdogSec. 내부 잠금이 응답하고 회차가 maxCycle 안이면 WATCHDOG=1.
//                 멈추면 (교착 / 끝나지 않는 회차) 알리지 않음 -> systemd 가 죽이고 다시 띄움 (Restart=on-failure)
//   SIGTERM       STOPPING=1 -> RTR / HTTP 닫음 -> 반영 저장 중이면 끝날 때까지 (최대 60 초) -> 끝
//
// sd_notify 는 NOTIFY_SOCKET (unix datagram) 에 글자 한 줄 (libsystemd 없이 표준만). 환경 변수가 없으면 아무것도 안 함

import (
	"context"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"
)

const maxCycle = time.Hour // 회차가 이보다 오래 걸리면 멈춘 것으로 봄 (평소 2 분, 저장소당 5 분 제한)

// sdNotify : systemd 에 상태 한 줄 (READY=1, WATCHDOG=1, STOPPING=1). systemd 밖이면 아무것도 안 함
func sdNotify(state string) {
	addr := os.Getenv("NOTIFY_SOCKET")
	if addr == "" {
		return
	}
	if addr[0] == '@' { // 추상 소켓
		addr = "\x00" + addr[1:]
	}
	c, err := net.DialUnix("unixgram", nil, &net.UnixAddr{Name: addr, Net: "unixgram"})
	if err != nil {
		log.Printf("sd_notify: %v", err)
		return
	}
	defer c.Close()
	c.Write([]byte(state))
}

// dataAge : 지금 집합을 만든 (검증한) 뒤 지난 시간. 집합이 없으면 -1
func (d *daemon) dataAge() time.Duration {
	d.st.mu.RLock()
	defer d.st.mu.RUnlock()
	if d.st.Cur == nil {
		return -1
	}
	return time.Since(d.st.Cur.Built)
}

// watchStale : 1 분마다 데이터 나이 확인 (회차가 멈춰도 돌도록 따로)
func (d *daemon) watchStale() {
	var warned time.Time
	for range time.Tick(time.Minute) {
		d.checkStale(&warned)
	}
}

func (d *daemon) checkStale(warned *time.Time) {
	c := d.c()
	age := d.dataAge()
	if age < 0 {
		return
	}
	stale := c.StaleWarn > 0 && age > c.StaleWarn
	d.mu.Lock()
	was := d.stale
	d.stale = stale
	d.mu.Unlock()
	switch {
	case stale && (!was || time.Since(*warned) > 30*time.Minute): // 바뀔 때 + 30 분마다
		log.Printf("WARNING stale data: set built %s ago (stale-warn %s)", age.Round(time.Second), c.StaleWarn)
		*warned = time.Now()
	case !stale && was:
		log.Printf("stale data cleared (set built %s ago)", age.Round(time.Second))
	}
	if c.StaleClose > 0 && age > c.StaleClose {
		d.closeRTR("set built " + age.Round(time.Second).String() + " ago, over stale-close " + c.StaleClose.String())
	}
}

// closeRTR : RTR 듣기 소켓과 연결을 모두 닫음 (라우터는 다른 RP 로). 새 집합이 반영되면 openRTR 이 다시 엶
func (d *daemon) closeRTR(why string) {
	d.mu.Lock()
	if d.rtr == nil || (d.rtrListen == nil && d.rtrTLSLn == nil) {
		d.mu.Unlock()
		return
	}
	for _, ln := range []net.Listener{d.rtrListen, d.rtrTLSLn} {
		if ln != nil {
			ln.Close()
		}
	}
	d.rtrListen, d.rtrTLSLn, d.rtrOpen = nil, nil, false
	d.mu.Unlock()
	n := d.rtr.closeAll()
	log.Printf("rtr closed (%s), %d connections dropped", why, n)
}

// health : /healthz 판단. ok = 데이터 있음 + 묵지 않음 + (RTR 을 쓰면) RTR 열림
func (d *daemon) health() (ok bool, m map[string]any) {
	age := d.dataAge()
	d.mu.Lock()
	rtrOpen, last, stale := d.rtrOpen, d.last, d.stale
	d.mu.Unlock()
	d.st.mu.RLock()
	ser := d.st.Serial
	d.st.mu.RUnlock()
	status := "ok"
	switch {
	case age < 0:
		status = "starting" // 첫 검증 전 (직전 집합도 못 씀)
	case stale:
		status = "stale"
	case d.cfg.RTRAddr != "" && !rtrOpen:
		status = "rtr-closed"
	}
	m = map[string]any{"status": status, "serial": ser, "rtr_open": rtrOpen}
	if age >= 0 {
		m["data_age_s"] = int(age.Seconds())
	}
	if last != nil {
		m["last_run"] = map[string]any{"start": last.Start, "applied": last.Applied, "reason": last.Reason}
	}
	return status == "ok", m
}

func (d *daemon) handleHealthz(w http.ResponseWriter, r *http.Request) {
	ok, m := d.health()
	if !ok {
		w.WriteHeader(http.StatusServiceUnavailable) // writeJSON 이 머리를 쓰기 전에
	}
	writeJSON(w, m)
}

// alive : watchdog 용. 잠금이 10 초 안에 잡히고 회차가 maxCycle 안이면 true
func (d *daemon) alive() bool {
	done := make(chan bool, 1)
	go func() {
		d.st.mu.RLock()
		d.st.mu.RUnlock()
		d.mu.Lock()
		running := d.cycleStart
		d.mu.Unlock()
		done <- running.IsZero() || time.Since(running) < maxCycle
	}()
	select {
	case ok := <-done:
		return ok
	case <-time.After(10 * time.Second):
		return false
	}
}

// watchdog : WATCHDOG_USEC 의 1/3 마다 살아 있으면 알림. 멈추면 알리지 않음 (로그 한 번)
func (d *daemon) watchdog() {
	us, err := strconv.ParseInt(os.Getenv("WATCHDOG_USEC"), 10, 64)
	if err != nil || us <= 0 {
		return
	}
	every := time.Duration(us) * time.Microsecond / 3
	logged := false
	for range time.Tick(every) {
		if d.alive() {
			sdNotify("WATCHDOG=1")
			logged = false
		} else if !logged {
			log.Printf("watchdog: not alive (lock held or cycle over %s), systemd will restart", maxCycle)
			logged = true
		}
	}
}

// watchTerm : SIGTERM / SIGINT 이면 정리하고 끝냄
func (d *daemon) watchTerm() {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGTERM, syscall.SIGINT)
	sig := <-ch
	log.Printf("%v: stopping", sig)
	sdNotify("STOPPING=1")
	d.mu.Lock()
	d.stopping = true
	d.mu.Unlock()
	d.closeRTR("stopping")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	for _, s := range d.httpSrv {
		s.Shutdown(ctx) // 받은 요청은 마치고 (최대 5 초)
	}
	cancel()
	// 반영 / 저장 중이면 끝날 때까지 (payload.gob, 출력 파일이 다 써진 뒤). 받기 / 검증 중이면 바로
	got := make(chan struct{})
	go func() {
		d.applyMu.Lock()
		close(got)
	}()
	select {
	case <-got:
	case <-time.After(60 * time.Second):
		log.Printf("stop: apply still running after 60 s, exiting anyway (payload.gob is written atomically)")
	}
	log.Printf("stopped")
	os.Exit(0)
}
