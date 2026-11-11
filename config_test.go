package main

// config_test.go : 설정 파일 읽기 (deploy/haetae.conf.example, 운영 deploy/haetae.conf 가 실제 옵션에 다 맞는지 포함)

import (
	"flag"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"strings"
	"testing"
)

// 설정 파일 하나를 읽어 모든 키가 옵션에 들어가는지 (예시 / 운영 파일은 모든 키를 채움)
func loadAllKeys(t *testing.T, name string) *options {
	f := flag.NewFlagSet("t", flag.ContinueOnError)
	o := defineFlags(f)
	path, applied, err := loadConfig(name, f)
	if err != nil {
		t.Fatal(err)
	}
	if path == "" || len(applied) != len(confKeys) {
		t.Errorf("%s : 항목 %d 개, 설정 키는 %d 개", name, len(applied), len(confKeys))
	}
	if err := checkRTRTimers(*o.rtrRefresh, *o.rtrRetry, *o.rtrExpire); err != nil {
		t.Error(err)
	}
	return o
}

// 예시 설정 파일 : 값이 원하는 대로 되는지
func TestExampleConfig(t *testing.T) {
	o := loadAllKeys(t, "deploy/haetae.conf.example")
	if *o.httpAddr != "127.0.0.1:8323,0.0.0.0:8324" || *o.httpAllow != "127.0.0.1,::1,198.51.100.0/24" {
		t.Errorf("http %q allow %q", *o.httpAddr, *o.httpAllow)
	}
	if *o.rtrAllow != "127.0.0.1,::1,192.0.2.1" || *o.rtrRetry != 300 || *o.noRsync || *o.talDir != "" {
		t.Errorf("rtr allow %q retry %d norsync %v tal %q", *o.rtrAllow, *o.rtrRetry, *o.noRsync, *o.talDir)
	}
}

// 운영 설정 파일 (있을 때만) : 모든 키가 맞는지
func TestDeployConfig(t *testing.T) {
	if _, err := os.Stat("deploy/haetae.conf"); err != nil {
		t.Skip("deploy/haetae.conf 없음")
	}
	loadAllKeys(t, "deploy/haetae.conf")
}

// 명령줄에 준 옵션은 설정 파일이 덮지 않음, rsync = false -> -norsync
func TestConfigCommandLineWins(t *testing.T) {
	f := flag.NewFlagSet("t", flag.ContinueOnError)
	o := defineFlags(f)
	f.Parse([]string{"-rtr-allow", "10.0.0.1"})
	e, err := parseConf(strings.NewReader("[rtr]\nallow = 1.1.1.1\n[fetch]\nrsync = false\n"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := applyConf(e, f); err != nil {
		t.Fatal(err)
	}
	if *o.rtrAllow != "10.0.0.1" || !*o.noRsync {
		t.Errorf("allow %q norsync %v", *o.rtrAllow, *o.noRsync)
	}
}

// 잘못된 설정은 오류 (시작하지 않음)
func TestConfigErrors(t *testing.T) {
	bad := map[string]string{
		"모르는 키":       "[rtr]\nallw = 1.1.1.1\n",
		"구역 없음":       "listen = :3323\n",
		"같은 키 두 번":    "[rtr]\nretry = 1\nretry = 2\n",
		"쉼표 뒤 끝":      "[rtr]\nallow = 1.1.1.1,\n",
		"쉼표 뒤 다음 키":   "[rtr]\nallow = 1.1.1.1,\nretry = 1\n",
		"키 = 값 아님":    "[rtr]\nallow\n",
		"숫자 아님":       "[rtr]\nretry = abc\n",
		"bool 아님":     "[fetch]\nrsync = yes please\n",
		"구역 이름 깨짐":    "[rtr\nretry = 1\n",
		"duration 아님": "[fetch]\ninterval = 10\n",
		"따옴표 안 닫힘":    "[paths]\nslurm = \"/etc/a.json\n",
		"따옴표 가운데":     "[paths]\nslurm = /etc/\"a\".json\n",
		"따옴표 뒤 글자":    "[paths]\nslurm = \"/etc/a\".json\n",
	}
	for name, text := range bad {
		f := flag.NewFlagSet("t", flag.ContinueOnError)
		defineFlags(f)
		e, err := parseConf(strings.NewReader(text))
		if err == nil {
			_, err = applyConf(e, f)
		}
		if err == nil {
			t.Errorf("%s : 오류여야 함", name)
		}
	}
}

func TestRTRTimers(t *testing.T) {
	if checkRTRTimers(600, 300, 7200) != nil {
		t.Error("기본값")
	}
	for _, c := range [][3]uint{{0, 300, 7200}, {600, 0, 7200}, {600, 300, 500}, {3600, 300, 3600}, {600, 8000, 9000}} {
		if checkRTRTimers(c[0], c[1], c[2]) == nil {
			t.Errorf("%v : 오류여야 함", c)
		}
	}
}

// HTTP 허용 목록 : 밖이면 403, IPv4-mapped 도 같은 주소
func TestHTTPAllow(t *testing.T) {
	allow := []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32"), netip.MustParsePrefix("198.51.100.0/24")}
	ok := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})
	h := httpAccess(func() *[]netip.Prefix { return &allow }, nil, ok, ok)
	for addr, want := range map[string]int{
		"127.0.0.1:5000":          200,
		"198.51.100.20:5000":      200,
		"[::ffff:198.51.100.9]:1": 200,
		"198.51.101.1:5000":       403,
		"[2001:db8::1]:5000":      403,
		"bad":                     403,
	} {
		req := httptest.NewRequest("GET", "/status", nil)
		req.RemoteAddr = addr
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != want {
			t.Errorf("%s : %d, want %d", addr, rec.Code, want)
		}
	}
}

// 따옴표 : 안의 # / 쉼표는 글자, 감싼 따옴표는 뗌, 따옴표 밖 # 은 주석 (11-04)
func TestConfigQuotes(t *testing.T) {
	text := `[paths]
slurm = "/etc/haetae/slurm#2.json"   # 주석
tal   = /etc/haetae/tals              # 따옴표 없음 그대로
[rtr]
allow = "127.0.0.1", ::1,
        "192.0.2.0/24"
[rtr-tls]
cert  = ""
`
	e, err := parseConf(strings.NewReader(text))
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{
		"paths.slurm":  "/etc/haetae/slurm#2.json",
		"paths.tal":    "/etc/haetae/tals",
		"rtr.allow":    "127.0.0.1,::1,192.0.2.0/24",
		"rtr-tls.cert": "",
	}
	if len(e) != len(want) {
		t.Fatalf("entries %v", e)
	}
	for _, x := range e {
		if want[x.Key] != x.Val {
			t.Errorf("%s = %q, want %q", x.Key, x.Val, want[x.Key])
		}
	}
}
