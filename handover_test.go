package main

// handover_test.go : 무중단 판 올리기 (handover.go)
//   TestRTRPauseResume : 멈춤 -> 그만둠 (되돌리기) 뒤에도 연결이 그대로 이어 읽음 (반만 받은 PDU 포함)
//   TestHandoverExec   : 실제 실행 파일을 띄우고 RTR 연결 셋이 붙은 채 SIGUSR2 를 거듭 -> 끊김 0, 같은 pid / session / serial,
//                        반만 보낸 PDU 가 새 판에서 이어짐, 조회 API 결과를 캐시로 먼저 만듦, HTTP 상태의 handover.count,
//                        새 실행 파일이 틀리면 그만두고 그대로
//                        (go test -short 면 건너뜀. HAETAE_SHOWLOG=1 이면 데몬 기록을 보임)

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestRTRPauseResume(t *testing.T) {
	d := testDaemon(t)
	s := &rtrServer{St: d.st, Allow: []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}, Refresh: 600, Retry: 300, Expire: 7200, Logf: t.Logf}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go s.serve(ln)
	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.Write(query(1, pduResetQuery, 0, nil))
	readUntilEOD(t, c)

	// 반만 보낸 Serial Query 가 있는 채로 멈춤
	ser := d.st.Serial
	q := query(1, pduSerialQuery, d.st.Session, &ser)
	c.Write(q[:5])
	time.Sleep(50 * time.Millisecond)
	s.pauseAll()
	setAcceptDeadline(ln, time.Now())
	parked, err := s.waitParked(5 * time.Second)
	if err != nil || len(parked) != 1 {
		t.Fatalf("parked %d %v", len(parked), err)
	}
	if got := len(parked[0].pending); got != 5 {
		t.Errorf("pending %d bytes, want 5", got)
	}
	// 멈춘 동안 붙은 연결은 커널이 줄 세움 (받기는 그만둔 뒤)
	c2, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c2.Close()

	// 그만둠 : 나머지를 보내면 응답
	setAcceptDeadline(ln, time.Time{})
	s.resumeAll()
	c.Write(q[5:])
	if n := readUntilEOD(t, c); n[pduEndOfData] != 1 {
		t.Errorf("after resume: %v", n)
	}
	c2.Write(query(1, pduResetQuery, 0, nil))
	if n := readUntilEOD(t, c2); n[pduEndOfData] != 1 {
		t.Errorf("queued conn: %v", n)
	}
}

func TestHandoverExec(t *testing.T) {
	if testing.Short() {
		t.Skip("builds and runs the binary")
	}
	dir := t.TempDir()
	bin := filepath.Join(dir, "haetae")
	if out, err := exec.Command("go", "build", "-o", bin, ".").CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}
	// 직전 집합 (payload.gob) : 시작하자마자 RTR 을 엶
	state := filepath.Join(dir, "state")
	os.MkdirAll(state, 0755)
	d := testDaemon(t)
	d.st.Cur.Built = time.Now()
	if err := saveState(filepath.Join(state, "payload.gob"), d.st); err != nil {
		t.Fatal(err)
	}
	// TAL : 키는 진짜, 주소는 닿지 않는 곳 (회차는 TA 실패 = 반영 안 함, 집합은 그대로)
	talDir := filepath.Join(dir, "tals")
	os.MkdirAll(talDir, 0755)
	ripe, err := os.ReadFile("tals/ripe.tal")
	if err != nil {
		t.Fatal(err)
	}
	key := string(ripe[strings.Index(string(ripe), "\n\n")+2:])
	os.WriteFile(filepath.Join(talDir, "test.tal"), []byte("https://127.0.0.1:1/ta.cer\n\n"+key), 0644)
	conf := filepath.Join(dir, "haetae.conf")
	os.WriteFile(conf, nil, 0644)
	rtrAddr, httpAddr := freeAddr(t), freeAddr(t)
	logPath := filepath.Join(dir, "log")
	logf, _ := os.Create(logPath)
	defer logf.Close()
	cmd := exec.Command(bin, "-c", conf, "-cache", filepath.Join(dir, "cache"), "-o", filepath.Join(dir, "out"), "-state", state,
		"-tal", talDir, "-norsync", "-interval", "1h", "-rtr", rtrAddr, "-rtr-allow", "127.0.0.1", "-http", httpAddr, "-http-allow", "127.0.0.1")
	cmd.Stdout, cmd.Stderr = logf, logf
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		cmd.Process.Signal(syscall.SIGTERM)
		cmd.Wait()
		if t.Failed() || os.Getenv("HAETAE_SHOWLOG") != "" {
			b, _ := os.ReadFile(logPath)
			t.Logf("log:\n%s", b)
		}
	}()
	waitFor(t, 10*time.Second, func() bool {
		c, err := net.Dial("tcp", rtrAddr)
		if err == nil {
			c.Close()
		}
		return err == nil
	})

	// 라우터 셋 : 전체를 받아 둠
	var cs []net.Conn
	for i := 0; i < 3; i++ {
		c, err := net.Dial("tcp", rtrAddr)
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		c.Write(query(1, pduResetQuery, 0, nil))
		if n := readUntilEOD(t, c); n[pduEndOfData] != 1 {
			t.Fatalf("reset query: %v", n)
		}
		cs = append(cs, c)
	}
	ses, ser := d.st.Session, d.st.Serial
	pid := cmd.Process.Pid
	for round := 1; round <= 3; round++ {
		q := query(1, pduSerialQuery, ses, &ser)
		cs[0].Write(q[:5]) // 반만 보낸 채로 판 올리기
		time.Sleep(50 * time.Millisecond)
		cmd.Process.Signal(syscall.SIGUSR2)
		want := fmt.Sprintf("resumed from %s (#%d)", version, round)
		waitFor(t, 30*time.Second, func() bool { b, _ := os.ReadFile(logPath); return strings.Contains(string(b), want) })
		if err := syscall.Kill(pid, 0); err != nil {
			t.Fatalf("round %d: process gone: %v", round, err)
		}
		cs[0].Write(q[5:])
		for i, c := range cs {
			if i > 0 {
				c.Write(q)
			}
			p := readPDU(t, c)
			for p.typ != pduEndOfData {
				if p.typ == pduCacheReset || p.typ == pduErrorReport {
					t.Fatalf("round %d conn %d: pdu %d", round, i, p.typ)
				}
				p = readPDU(t, c)
			}
			if p.field != ses || beUint32(p.body[:4]) != ser {
				t.Errorf("round %d conn %d: session %d serial %d, want %d %d", round, i, p.field, beUint32(p.body[:4]), ses, ser)
			}
		}
		// 조회 API 결과는 받기 전에 캐시만 검증해 다시 만듦 (이 시험의 회차는 TA 실패 = 반영 안 함 -> 이 단계가 아니면 계속 503)
		waitFor(t, 30*time.Second, func() bool {
			b, _ := os.ReadFile(logPath)
			return strings.Count(string(b), "lookup data rebuilt") >= round
		})
		if resp, err := http.Get("http://" + httpAddr + "/api/v1/objects?limit=1"); err != nil || resp.StatusCode != 200 {
			t.Errorf("round %d: objects after handover: %v %v", round, err, resp)
		} else {
			resp.Body.Close()
		}
		// HTTP 상태 : 판 올리기 횟수, 같은 serial
		resp, err := http.Get("http://" + httpAddr + "/api/v1/status")
		if err != nil {
			t.Fatalf("round %d: http: %v", round, err)
		}
		var st struct {
			Serial   uint32       `json:"serial"`
			Handover handoverInfo `json:"handover"`
			Clients  []any        `json:"rtr_clients"`
		}
		json.NewDecoder(resp.Body).Decode(&st)
		resp.Body.Close()
		if st.Handover.Count != round || st.Serial != ser || st.Handover.Conns != 3 || len(st.Clients) != 3 {
			t.Errorf("round %d: status %+v", round, st)
		}
	}
	// 새 실행 파일이 틀리면 (확인 실패) 그만두고 옛 판이 그대로 : 연결도 그대로 질의에 답함
	os.Rename(bin, bin+".good")
	os.WriteFile(bin, []byte("#!/bin/sh\nexit 1\n"), 0755)
	cmd.Process.Signal(syscall.SIGUSR2)
	waitFor(t, 30*time.Second, func() bool { b, _ := os.ReadFile(logPath); return strings.Contains(string(b), "handover: aborted") })
	q := query(1, pduSerialQuery, ses, &ser)
	for i, c := range cs {
		c.Write(q)
		if n := readUntilEOD(t, c); n[pduEndOfData] != 1 {
			t.Errorf("after abort conn %d: %v", i, n)
		}
	}
	b, _ := os.ReadFile(logPath)
	if n := strings.Count(string(b), ": connected ("); n != 4 { // 처음 확인 1 + 라우터 3, 판 올리기 뒤 새로 붙은 것 없음
		t.Errorf("connected %d times, want 4 (no reconnects)", n)
	}
}

func freeAddr(t *testing.T) string {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return ln.Addr().String()
}

func waitFor(t *testing.T, limit time.Duration, ok func() bool) {
	t.Helper()
	end := time.Now().Add(limit)
	for !ok() {
		if time.Now().After(end) {
			t.Fatalf("timeout after %s", limit)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func beUint32(b []byte) uint32 {
	return uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
}
