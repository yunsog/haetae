package main

// config.go : 설정 파일 (기본 /etc/haetae/haetae.conf, 상주 모드만)
//
// 모양
//   # 주석 (줄 어디서나 # 뒤는 무시)
//   [rtr]                         구역
//   listen = :3323                키 = 값
//   allow  = 127.0.0.1, ::1,      값이 쉼표로 끝나면 다음 줄에 이어짐 (목록을 여러 줄로)
//            192.0.2.1
//
// 구역.키 를 명령줄 옵션 이름으로 바꿔 flag.Set 으로 넣음 (confKeys 표).
// 명령줄에 준 옵션은 건드리지 않음 (명령줄이 우선). 모르는 키 / 같은 키 두 번 / 잘못된 값 = 오류 -> 시작하지 않음.

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
)

const defConfig = "/etc/haetae/haetae.conf"

// confKeys : 설정 파일 "구역.키" -> 옵션 이름. "!" 로 시작하면 bool 을 뒤집어 넣음 (rsync = true -> -norsync=false)
var confKeys = map[string]string{
	"paths.cache": "cache",
	"paths.out":   "o",
	"paths.state": "state",
	"paths.tal":   "tal",
	"paths.slurm": "slurm",

	"fetch.interval": "interval",
	"fetch.jobs":     "fetch-j",
	"fetch.rsync":    "!norsync",

	"validation.workers":       "j",
	"validation.drop-warn":     "drop-warn",
	"validation.hold-drop":     "hold-drop",
	"validation.max-start-age": "max-start-age",

	"rtr.listen":  "rtr",
	"rtr.allow":   "rtr-allow",
	"rtr.auth":    "rtr-auth",
	"rtr.refresh": "rtr-refresh",
	"rtr.retry":   "rtr-retry",
	"rtr.expire":  "rtr-expire",

	"rtr-tls.listen": "rtr-tls",
	"rtr-tls.cert":   "rtr-tls-cert",
	"rtr-tls.key":    "rtr-tls-key",
	"rtr-tls.ca":     "rtr-tls-ca",

	"http.listen":              "http",
	"http.allow":               "http-allow",
	"http.jsonext":             "jsonext",
	"http.delta-full-interval": "delta-full-interval",
}

// confEntry : 설정 파일 한 항목 (줄 번호는 오류 표시용)
type confEntry struct {
	Key  string // 구역.키
	Val  string // 목록이면 "a,b,c" (공백 뺌)
	Line int
}

// parseConf : 설정 파일 글자 -> 항목 목록
func parseConf(r io.Reader) ([]confEntry, error) {
	var out []confEntry
	seen := map[string]int{}
	section := ""
	sc := bufio.NewScanner(r)
	n := 0
	var cur *confEntry // 쉼표로 끝나 다음 줄을 기다리는 항목
	for sc.Scan() {
		n++
		line := sc.Text()
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = line[:i]
		}
		line = strings.TrimSpace(line)
		if cur != nil { // 앞 줄이 쉼표로 끝남 -> 이어 붙임
			if line == "" {
				continue
			}
			if strings.HasPrefix(line, "[") || strings.Contains(line, "=") {
				return nil, fmt.Errorf("%d 줄 : %s 의 목록이 쉼표로 끝났는데 다음 값이 없음", cur.Line, cur.Key)
			}
			cur.Val += line
			if !strings.HasSuffix(line, ",") {
				out = append(out, *cur)
				cur = nil
			}
			continue
		}
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "[") {
			if !strings.HasSuffix(line, "]") {
				return nil, fmt.Errorf("%d 줄 : 구역 이름 %q", n, line)
			}
			section = strings.TrimSpace(line[1 : len(line)-1])
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			return nil, fmt.Errorf("%d 줄 : \"키 = 값\" 이 아님 : %q", n, line)
		}
		key := section + "." + strings.TrimSpace(k)
		if _, ok := confKeys[key]; !ok {
			return nil, fmt.Errorf("%d 줄 : 모르는 키 [%s] %s", n, section, strings.TrimSpace(k))
		}
		if prev, dup := seen[key]; dup {
			return nil, fmt.Errorf("%d 줄 : %s 가 %d 줄에도 있음", n, key, prev)
		}
		seen[key] = n
		e := confEntry{Key: key, Val: strings.TrimSpace(v), Line: n}
		if strings.HasSuffix(e.Val, ",") {
			cur = &e
			continue
		}
		out = append(out, e)
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if cur != nil {
		return nil, fmt.Errorf("%d 줄 : %s 의 목록이 쉼표로 끝났는데 파일이 끝남", cur.Line, cur.Key)
	}
	for i := range out {
		out[i].Val = strings.Join(splitList(out[i].Val), ",") // "a, b ,c" -> "a,b,c" (목록 아닌 값은 그대로)
	}
	return out, nil
}

// applyConf : 항목을 옵션에 넣음. 명령줄에 준 옵션은 건너뜀. 돌려주는 것 = 로그용 "키=값" 목록
func applyConf(entries []confEntry, f *flag.FlagSet) ([]string, error) {
	given := map[string]bool{}
	f.Visit(func(fl *flag.Flag) { given[fl.Name] = true })
	var applied []string
	for _, e := range entries {
		name, val := confKeys[e.Key], e.Val
		if inv, ok := strings.CutPrefix(name, "!"); ok {
			b, err := strconv.ParseBool(val)
			if err != nil {
				return nil, fmt.Errorf("%d 줄 : %s = %q : true / false", e.Line, e.Key, val)
			}
			name, val = inv, strconv.FormatBool(!b)
		}
		if given[name] {
			applied = append(applied, e.Key+"=(명령줄 -"+name+")")
			continue
		}
		if err := f.Set(name, val); err != nil {
			return nil, fmt.Errorf("%d 줄 : %s = %q : %v", e.Line, e.Key, e.Val, err)
		}
		applied = append(applied, e.Key+"="+e.Val)
	}
	return applied, nil
}

// loadConfig : path 가 비었으면 기본 파일이 있을 때만 읽음. 읽은 파일 이름 (없으면 "") 과 넣은 항목
func loadConfig(path string, f *flag.FlagSet) (string, []string, error) {
	if path == "" {
		if _, err := os.Stat(defConfig); errors.Is(err, os.ErrNotExist) {
			return "", nil, nil
		}
		path = defConfig
	}
	fh, err := os.Open(path)
	if err != nil {
		return "", nil, err
	}
	defer fh.Close()
	entries, err := parseConf(fh)
	if err != nil {
		return "", nil, fmt.Errorf("%s %w", path, err)
	}
	applied, err := applyConf(entries, f)
	if err != nil {
		return "", nil, fmt.Errorf("%s %w", path, err)
	}
	return path, applied, nil
}
