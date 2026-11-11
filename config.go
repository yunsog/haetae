package main

// config.go : 설정 파일 (기본 /etc/haetae/haetae.conf, 상주 모드만)
//
// 모양
//   # 주석 (줄 어디서나 # 뒤는 무시, 따옴표 안의 # 은 글자)
//   cert = "/etc/haetae/a#1.pem"   값을 따옴표로 감싸도 됨 (따옴표는 뗌, 11-04)
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
	"fetch.deadline": "fetch-deadline",
	"fetch.rsync":    "!norsync",

	"validation.workers":       "j",
	"validation.drop-warn":     "drop-warn",
	"validation.hold-drop":     "hold-drop",
	"validation.max-start-age": "max-start-age",
	"validation.stale-warn":    "stale-warn",
	"rtr.stale-close":          "stale-close",
	"rtr.max-conns":            "rtr-max-conns",
	"rtr.max-per-ip":           "rtr-max-per-ip",
	"rtr.trusted":              "rtr-trusted",
	"rtr.trusted-max-conns":    "rtr-trusted-max-conns",

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
	"http.public":              "http-public",
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
		line, err := stripComment(sc.Text())
		if err != nil {
			return nil, fmt.Errorf("%d 줄 : %v", n, err)
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
		v, err := confValue(out[i].Val) // "a, b ,c" -> "a,b,c", 감싼 따옴표 뗌 (목록 아닌 값은 항목 하나)
		if err != nil {
			return nil, fmt.Errorf("%d 줄 : %s : %v", out[i].Line, out[i].Key, err)
		}
		out[i].Val = v
	}
	return out, nil
}

// stripComment : 따옴표 밖의 # 부터 줄 끝까지 지움 (따옴표 안의 # 은 글자, 11-04). 닫히지 않은 따옴표 = 오류
func stripComment(line string) (string, error) {
	in := false
	for i := 0; i < len(line); i++ {
		switch line[i] {
		case '"':
			in = !in
		case '#':
			if !in {
				return line[:i], nil
			}
		}
	}
	if in {
		return "", errors.New("따옴표가 닫히지 않음")
	}
	return line, nil
}

// confValue : 값을 따옴표 밖의 쉼표로 나눠 항목마다 앞뒤 공백과 감싼 따옴표를 뗀 뒤 쉼표로 다시 이음.
// 따옴표는 항목 전체를 감쌀 때만 ("/a#b" 는 됨, ab"c 나 "a"b 는 오류 = 뜻이 모호한 값으로 시작하지 않음)
func confValue(v string) (string, error) {
	var items []string
	var b strings.Builder
	in := false
	flush := func() error {
		s := strings.TrimSpace(b.String())
		b.Reset()
		if strings.Contains(s, `"`) {
			if len(s) < 2 || s[0] != '"' || s[len(s)-1] != '"' || strings.Contains(s[1:len(s)-1], `"`) {
				return fmt.Errorf("따옴표는 값 전체를 감쌀 때만 : %s", s)
			}
			s = s[1 : len(s)-1]
		}
		if s != "" {
			items = append(items, s)
		}
		return nil
	}
	for i := 0; i < len(v); i++ {
		switch c := v[i]; {
		case c == '"':
			in = !in
			b.WriteByte(c)
		case c == ',' && !in:
			if err := flush(); err != nil {
				return "", err
			}
		default:
			b.WriteByte(c)
		}
	}
	if err := flush(); err != nil {
		return "", err
	}
	return strings.Join(items, ","), nil
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
