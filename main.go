package main

// main.go : 옵션과 모드
//
//   haetae -parse <파일|폴더>   1 단계 : 객체 파일을 하나씩 파싱 / 검사, 실패 목록과 개수
//   haetae -validate -cache <캐시> -tal <TAL 폴더> -o <출력 폴더> [-P <epoch>]
//                                2 단계 : TAL 부터 검증 트리, VRP / ASPA / 라우터 키 / 전체 객체 목록
//   haetae -rsc <x.sig> [-cache <캐시> -tal <TAL 폴더> [-P <epoch>]] [파일 ...]
//                                RSC (RFC 9323) 하나 확인 + 나열한 파일의 해시 확인 (rsc.go)
//   haetae -rtr-stdio <주소>     표준 입출력 <-> RTR (sshd 의 rpki-rtr subsystem 에서 실행, rtr_auth.go)
//   haetae [-c 설정] [-t] [옵션] 4 단계 : 상주 (수집 + 검증 주기, RTR, HTTP API). -t = 한 번 돌고 끝
//                                설정 파일 = config.go (/etc/haetae/haetae.conf, 명령줄이 우선)

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"sort"
	"strings"
	"sync"
	"time"
)

// 상주 모드 폴더 기본값 (10-31, 운영 = 전용 계정 haetae). 개발 때는 -cache data/cache -o data/out -state data/state 처럼 직접 줌.
// -validate 는 기본값을 쓰지 않음 (-cache / -o 필수) : 시험 검증이 운영 캐시를 건드리지 않게
const (
	defCache = "/var/lib/haetae/cache"
	defOut   = "/var/lib/haetae/out"
	defState = "/var/lib/haetae/state"
)

// options : 명령줄 옵션 (설정 파일 config.go 도 같은 이름으로 채움)
type options struct {
	parse, rscFile, failOut, cacheDir, talDir, outDir                      *string
	workers, fetchJobs                                                     *int
	validate, fetch, noRsync, once                                         *bool
	evalTime                                                               *int64
	stateDir, slurmPath, rtrAddr, rtrAllow, rtrAuth                        *string
	rtrTLS, rtrTLSCert, rtrTLSKey, rtrTLSCA, rtrStdio, httpAddr, httpAllow *string
	rtrRefresh, rtrRetry, rtrExpire                                        *uint
	interval, deltaFull, maxStartAge                                       *time.Duration
	jsonExt, holdDrop                                                      *bool
	dropWarn                                                               *float64
	config                                                                 *string
}

// defineFlags : 옵션 정의 (main 과 시험이 같이 씀)
func defineFlags(f *flag.FlagSet) *options {
	o := &options{}
	o.parse = f.String("parse", "", "파일 또는 폴더의 객체를 파싱만 함 (1 단계 시험)")
	o.rscFile = f.String("rsc", "", "RSC (.sig) 하나 확인, 뒤에 확인할 파일들 (-cache 를 주면 체인까지)")
	o.workers = f.Int("j", runtime.NumCPU(), "동시 작업 수")
	o.failOut = f.String("fail", "", "실패 목록을 쓸 파일 (경로<TAB>이유)")
	o.validate = f.Bool("validate", false, "검증 트리 (2 단계 시험)")
	o.cacheDir = f.String("cache", "", "캐시 폴더 (rsync URI 모양 파일 트리, ta/<TAL>/ 에 TA 인증서). 상주 기본 "+defCache)
	o.talDir = f.String("tal", "", "TAL 폴더 (*.tal). 빈 값 = 실행 파일 안의 TAL (저장소 tals/, 5 RIR)")
	o.outDir = f.String("o", "", "출력 폴더. 상주 기본 "+defOut)
	o.evalTime = f.Int64("P", 0, "검증 시각 (unix 초, 0 = 지금). rpki-client -P 와 같음")
	o.fetch = f.Bool("fetch", false, "-validate 전에 저장소에서 받음 (RRDP / rsync, -cache 는 이 RP 의 캐시)")
	o.fetchJobs = f.Int("fetch-j", 32, "동시 수집 저장소 수")
	o.noRsync = f.Bool("norsync", false, "rsync 대체 안 함")

	// 상주 모드
	o.config = f.String("c", "", "설정 파일 (상주 모드만). 빈 값 = "+defConfig+" 가 있으면 그것. 명령줄 옵션이 설정 파일보다 우선")
	o.once = f.Bool("t", false, "상주 모드를 한 회차만 (시험)")
	o.stateDir = f.String("state", defState, "상태 폴더 (잠금, session / serial, delta, 이력)")
	o.slurmPath = f.String("slurm", "", "SLURM 파일 (RFC 8416)")
	o.interval = f.Duration("interval", 10*time.Minute, "수집 + 검증 주기")
	o.rtrAddr = f.String("rtr", ":3323", "RTR 주소 (빈 값 = 안 엶)")
	o.rtrAllow = f.String("rtr-allow", "127.0.0.1,::1", "RTR 허용 주소 / 대역 (쉼표)")
	o.rtrAuth = f.String("rtr-auth", "", "RTR TCP-MD5 / TCP-AO 키 파일 (줄마다 <주소> md5 <키> | <주소> ao <알고리즘> <sendid> <recvid> <키>)")
	o.rtrRefresh = f.Uint("rtr-refresh", 600, "RTR refresh (초, 1~86400) : 라우터가 Notify 없이도 묻는 간격 (v1 / v2)")
	o.rtrRetry = f.Uint("rtr-retry", 300, "RTR retry (초, 1~7200) : 끊겼을 때 라우터가 다시 붙는 간격")
	o.rtrExpire = f.Uint("rtr-expire", 7200, "RTR expire (초, 600~172800, refresh / retry 보다 커야 함) : 이 시간 못 받으면 라우터가 VRP 를 버림")
	o.rtrTLS = f.String("rtr-tls", "", "RTR over TLS 주소 (빈 값 = 안 엶, 예 :3324)")
	o.rtrTLSCert = f.String("rtr-tls-cert", "", "RTR TLS 서버 인증서 (PEM)")
	o.rtrTLSKey = f.String("rtr-tls-key", "", "RTR TLS 서버 키 (PEM)")
	o.rtrTLSCA = f.String("rtr-tls-ca", "", "라우터 인증서를 확인할 CA (PEM, 주면 라우터 인증서 필수)")
	o.rtrStdio = f.String("rtr-stdio", "", "표준 입출력을 이 RTR 주소로 이음 (sshd rpki-rtr subsystem 용, 예 127.0.0.1:3323)")
	o.httpAddr = f.String("http", "127.0.0.1:8323", "HTTP API 주소, 여러 개는 쉼표 (빈 값 = 안 엶, 예 127.0.0.1:8323,0.0.0.0:5002)")
	o.httpAllow = f.String("http-allow", "127.0.0.1,::1", "HTTP API 허용 주소 / 대역 (쉼표, 모든 -http 주소에 적용, 밖이면 403)")
	o.jsonExt = f.Bool("jsonext", false, "HTTP /jsonext 엶 (Routinator 모양, 약 470 MB, 부를 때마다 약 5 초 계산. 차이 조사 때만)")
	o.deltaFull = f.Duration("delta-full-interval", time.Minute, "/json-delta 전체 (reset) 를 받는 쪽 주소마다 이 간격에 한 번, 그 안이면 429 (0 = 제한 없음)")
	o.maxStartAge = f.Duration("max-start-age", 2*time.Hour, "시작 때 직전 VRP 를 쓸 최대 나이")
	o.dropWarn = f.Float64("drop-warn", 0.1, "VRP 가 이 비율 넘게 줄면 경고")
	o.holdDrop = f.Bool("hold-drop", false, "VRP 급감이면 반영 보류 (D1 보류 옵션)")
	return o
}

// splitList : "a, b,c" -> [a b c] (빈 것 뺌)
func splitList(s string) []string {
	var out []string
	for _, a := range strings.Split(s, ",") {
		if a = strings.TrimSpace(a); a != "" {
			out = append(out, a)
		}
	}
	return out
}

func main() {
	o := defineFlags(flag.CommandLine)
	flag.Parse()

	switch {
	case *o.parse != "":
		os.Exit(runParse(*o.parse, *o.workers, *o.failOut))
	case *o.rtrStdio != "":
		os.Exit(runRTRStdio(*o.rtrStdio))
	case *o.rscFile != "":
		os.Exit(runRSC(*o.rscFile, flag.Args(), *o.cacheDir, *o.talDir, *o.evalTime, *o.workers))
	case *o.validate:
		os.Exit(runValidate(*o.cacheDir, *o.talDir, *o.outDir, *o.evalTime, *o.workers, *o.fetch, *o.fetchJobs, *o.noRsync))
	default:
		// 상주 : 설정 파일 (있으면) -> 명령줄에 없는 옵션만 채움
		path, applied, err := loadConfig(*o.config, flag.CommandLine)
		if err != nil {
			fmt.Fprintln(os.Stderr, "설정:", err)
			os.Exit(2)
		}
		if path != "" {
			log.Printf("설정 %s : %s", path, strings.Join(applied, " "))
		}
		cfg, err := buildDaemonConfig(o)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
		cfg.ConfPath = path
		cfg.Reload = func() (daemonConfig, string, error) { return reloadConfig(path) }
		os.Exit(runDaemon(cfg, *o.once))
	}
}

// buildDaemonConfig : 옵션 값 -> 상주 설정 (시작 / reload 가 같이 씀)
func buildDaemonConfig(o *options) (daemonConfig, error) {
	if *o.cacheDir == "" {
		*o.cacheDir = defCache
	}
	if *o.outDir == "" {
		*o.outDir = defOut
	}
	if err := checkRTRTimers(*o.rtrRefresh, *o.rtrRetry, *o.rtrExpire); err != nil {
		return daemonConfig{}, err
	}
	return daemonConfig{
		CacheDir: *o.cacheDir, TALDir: *o.talDir, OutDir: *o.outDir, StateDir: *o.stateDir, SLURM: *o.slurmPath,
		Interval: *o.interval, Workers: *o.workers, FetchJobs: *o.fetchJobs, NoRsync: *o.noRsync,
		RTRAddr: *o.rtrAddr, RTRAllow: splitList(*o.rtrAllow), RTRAuth: *o.rtrAuth,
		RTRRefresh: uint32(*o.rtrRefresh), RTRRetry: uint32(*o.rtrRetry), RTRExpire: uint32(*o.rtrExpire),
		RTRTLSAddr: *o.rtrTLS, RTRTLSCert: *o.rtrTLSCert, RTRTLSKey: *o.rtrTLSKey, RTRTLSCA: *o.rtrTLSCA,
		HTTPAddr: *o.httpAddr, HTTPAllow: splitList(*o.httpAllow), JSONExt: *o.jsonExt, DeltaFullInterval: *o.deltaFull,
		MaxStartAge: *o.maxStartAge, DropWarn: *o.dropWarn, HoldOnDrop: *o.holdDrop,
	}, nil
}

// reloadConfig : systemctl reload 때. 시작 때의 명령줄 (os.Args) 을 새로 읽고, 시작 때 읽은 설정 파일을 다시 읽음
// (명령줄이 여전히 우선). 시작 때 설정 파일이 있었는데 지금 없으면 오류 = 지금 값 유지 (파일을 지워서 기본값으로 돌아가는 사고 방지)
func reloadConfig(startPath string) (daemonConfig, string, error) {
	f := flag.NewFlagSet(os.Args[0], flag.ContinueOnError)
	f.SetOutput(io.Discard)
	o := defineFlags(f)
	if err := f.Parse(os.Args[1:]); err != nil {
		return daemonConfig{}, "", err
	}
	path := *o.config
	if path == "" {
		path = startPath // 시작 때 기본 파일을 읽었으면 그 파일 (없어졌으면 loadConfig 가 오류)
	}
	path, _, err := loadConfig(path, f)
	if err != nil {
		return daemonConfig{}, "", err
	}
	cfg, err := buildDaemonConfig(o)
	return cfg, path, err
}

// checkRTRTimers : RFC 8210 6 장의 범위 (expire 는 refresh / retry 보다 커야 함)
func checkRTRTimers(refresh, retry, expire uint) error {
	switch {
	case refresh < 1 || refresh > 86400:
		return fmt.Errorf("rtr-refresh %d : 1~86400", refresh)
	case retry < 1 || retry > 7200:
		return fmt.Errorf("rtr-retry %d : 1~7200", retry)
	case expire < 600 || expire > 172800:
		return fmt.Errorf("rtr-expire %d : 600~172800", expire)
	case expire <= refresh || expire <= retry:
		return fmt.Errorf("rtr-expire %d 는 refresh %d / retry %d 보다 커야 함", expire, refresh, retry)
	}
	return nil
}

// runValidate : 2 단계 오프라인 검증
func runValidate(cacheDir, talDir, outDir string, evalTime int64, workers int, fetch bool, fetchJobs int, noRsync bool) int {
	if cacheDir == "" || outDir == "" {
		fmt.Fprintln(os.Stderr, "-validate 에는 -cache 와 -o 가 필요")
		return 2
	}
	started := time.Now()
	now := started
	if evalTime != 0 {
		now = time.Unix(evalTime, 0)
	}

	tals, source, err := loadTALs(talDir)
	if err != nil {
		fmt.Fprintln(os.Stderr, "TAL:", err)
		return 1
	}
	fmt.Fprintf(os.Stderr, "TAL (%s): %s\n", source, talSummary(tals))

	v := newValidator(cacheDir, now, workers)
	if fetch {
		f, err := newFetcher(cacheDir, fetchJobs)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		f.NoRsync = noRsync
		v.Fetch = f
	}
	v.run(tals)
	if v.Fetch != nil {
		writeRepoStatus(outDir, v.Fetch)
	}
	if err := v.writeOutputs(outDir, started); err != nil {
		fmt.Fprintln(os.Stderr, "출력:", err)
		return 1
	}
	b, _ := os.ReadFile(filepath.Join(outDir, "summary.txt"))
	os.Stdout.Write(b)
	return 0
}

// writeRepoStatus : 저장소별 수집 결과 (repos.json) + 화면 요약
func writeRepoStatus(outDir string, f *fetcher) {
	st := f.statuses()
	cnt := map[string]int{}
	for _, s := range st {
		cnt[s.Type+" "+s.Result]++
	}
	os.MkdirAll(outDir, 0755)
	b, _ := json.MarshalIndent(st, "", " ")
	os.WriteFile(filepath.Join(outDir, "repos.json"), b, 0644)
	fmt.Printf("repos %v, downloaded %d MB, rsync runs %d\n", cnt, f.bytes.Load()>>20, f.rsyncs.Load())
}

// parseResult : 파일 하나의 결과
type parseResult struct {
	Path string
	Type string // 확장자 (cer, roa, ...)
	Kind string // 성공 시 세부 종류 (CA, router 등)
	Err  error
}

// parseFile : 파일 하나 파싱. panic 은 그 파일만 실패 (입력은 믿을 수 없는 저장소)
func parseFile(path string) (r parseResult) {
	r.Path = path
	r.Type = strings.TrimPrefix(filepath.Ext(path), ".")
	defer func() {
		if p := recover(); p != nil {
			r.Err = fmt.Errorf("panic: %v\n%s", p, debug.Stack())
		}
	}()

	st, err := os.Stat(path)
	if err != nil {
		r.Err = err
		return
	}
	if st.Size() > maxObjectSize {
		r.Err = fmt.Errorf("file too large (%d)", st.Size())
		return
	}
	b, err := os.ReadFile(path)
	if err != nil {
		r.Err = err
		return
	}

	switch r.Type {
	case "cer":
		c, err := parseCert(b, false)
		if err != nil {
			r.Err = err
			return
		}
		r.Kind = c.Kind.String()
		if c.SelfSigned && c.Kind == kindCA {
			r.Kind = "TA"
		}
		if c.Kind == kindRouter {
			_, r.Err = c.routerKeys()
		}
	case "crl":
		_, r.Err = parseCRL(b)
		r.Kind = "ok"
	case "mft":
		_, r.Err = parseManifest(b)
		r.Kind = "ok"
	case "roa":
		_, r.Err = parseROA(b)
		r.Kind = "ok"
	case "asa":
		_, r.Err = parseASPA(b)
		r.Kind = "ok"
	case "gbr":
		_, r.Err = parseGBR(b)
		r.Kind = "ok"
	case "spl":
		_, r.Err = parseSPL(b)
		r.Kind = "ok"
	case "tak":
		_, r.Err = parseTAK(b)
		r.Kind = "ok"
	case "sig":
		_, r.Err = parseRSC(b)
		r.Kind = "ok"
	default:
		r.Kind = "unknown" // 표준 아닌 확장자 (사설 / 시험 객체) : 오류 아님
	}
	return
}

// runParse : 폴더를 돌며 객체 파일을 동시에 파싱, 종류별 개수와 실패 목록
func runParse(root string, workers int, failOut string) int {
	paths := make(chan string, 1024)
	results := make(chan parseResult, 1024)

	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for p := range paths {
				results <- parseFile(p)
			}
		}()
	}

	// 폴더 순회 : 일반 파일만, 숨김 폴더 (.rrdp, .rsync 상태 등) 는 건너뜀
	go func() {
		filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				fmt.Fprintln(os.Stderr, "walk:", err)
				return nil
			}
			if d.IsDir() {
				if p != root && strings.HasPrefix(d.Name(), ".") {
					return filepath.SkipDir
				}
				return nil
			}
			if d.Type().IsRegular() {
				paths <- p
			}
			return nil
		})
		close(paths)
		wg.Wait()
		close(results)
	}()

	ok := map[string]int{}   // "cer/CA" 같은 키
	fail := map[string]int{} // 확장자별 실패 수
	var fails []parseResult
	for r := range results {
		if r.Err != nil {
			fail[r.Type]++
			fails = append(fails, r)
			continue
		}
		ok[r.Type+"/"+r.Kind]++
	}

	// 화면 : 종류별 성공 / 실패 개수
	var keys []string
	for k := range ok {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	fmt.Println("# 성공")
	for _, k := range keys {
		fmt.Printf("  %-14s %8d\n", k, ok[k])
	}
	keys = keys[:0]
	for k := range fail {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	fmt.Println("# 실패")
	for _, k := range keys {
		fmt.Printf("  %-14s %8d\n", k, fail[k])
	}

	// 실패 이유별 개수 (이유 문자열 앞부분으로 묶음)
	reasons := map[string]int{}
	for _, f := range fails {
		reasons[f.Type+": "+shortReason(f.Err)]++
	}
	keys = keys[:0]
	for k := range reasons {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return reasons[keys[i]] > reasons[keys[j]] })
	fmt.Println("# 실패 이유")
	for _, k := range keys {
		fmt.Printf("  %6d  %s\n", reasons[k], k)
	}

	if failOut != "" {
		sort.Slice(fails, func(i, j int) bool { return fails[i].Path < fails[j].Path })
		var sb strings.Builder
		for _, f := range fails {
			fmt.Fprintf(&sb, "%s\t%s\n", f.Path, strings.ReplaceAll(f.Err.Error(), "\n", " | "))
		}
		if err := os.WriteFile(failOut, []byte(sb.String()), 0644); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
	}
	return 0
}

// shortReason : 묶어 세기 위한 이유 (숫자 / 따옴표 안 값이 달라도 같은 이유로)
func shortReason(err error) string {
	s := err.Error()
	if i := strings.IndexAny(s, "\"0123456789"); i > 0 {
		s = s[:i]
	}
	if len(s) > 80 {
		s = s[:80]
	}
	return strings.TrimSpace(s)
}
