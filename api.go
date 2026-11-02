package main

// api.go : HTTP API (net/http)
//
//   /status, /api/v1/status         상태 (text / JSON) : serial, 회차 결과, TA 별 개수, RTR 클라이언트, 저장소 (E3)
//   /json /csv /objects.jsonl /rejects.txt /repos.json   마지막 출력 파일 그대로 (E1, E6)
//   /api/v1/validity/<AS>/<prefix>  경로 검증 (RFC 6811, Routinator 호환 모양, E2)
//   /api/v1/vrps/delta?serial=N[&session=S]  N 이후 바뀐 VRP (받아 가는 시스템용, E5). 기록 없거나 session 이 다르면 reset=true
//   나머지 조회 API 는 api_query.go, /api/v1/history /metrics 는 history.go
// 형식은 docs/api.md 와 같게 유지 (바꾸면 문서 먼저). 쓰기 기능 없음 (모두 GET, 조회만)

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

func parsePrefixOrAddr(s string) (netip.Prefix, error) {
	if strings.Contains(s, "/") {
		p, err := netip.ParsePrefix(s)
		return p.Masked(), err
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Prefix{}, err
	}
	return netip.PrefixFrom(a, a.BitLen()), nil
}

// writeRepoStatusQuiet : repos.json
func writeRepoStatusQuiet(outDir string, st []repoStatus) {
	b, _ := json.MarshalIndent(st, "", " ")
	tmp := filepath.Join(outDir, ".repos.json.tmp")
	if os.WriteFile(tmp, b, 0644) == nil {
		os.Rename(tmp, filepath.Join(outDir, "repos.json"))
	}
}

func (d *daemon) apiHandler() http.Handler {
	mux := http.NewServeMux()
	for _, name := range []string{"json", "csv", "objects.jsonl", "rejects.txt", "repos.json"} {
		name := name
		mux.HandleFunc("GET /"+name, func(w http.ResponseWriter, r *http.Request) {
			d.serveOut(w, r, name)
		})
	}
	mux.HandleFunc("GET /status", d.handleStatusText)
	mux.HandleFunc("GET /api/v1/status", d.handleStatusJSON)
	mux.HandleFunc("GET /api/v1/validity/{as}/{prefix...}", d.handleValidity)
	mux.HandleFunc("GET /api/v1/vrps/delta", d.handleDelta)
	mux.HandleFunc("GET /api/v1/aspa/verify", d.handleASPAVerify)
	mux.HandleFunc("GET /api/v1/as/{as}", d.handleAS)
	mux.HandleFunc("GET /api/v1/prefix/{prefix...}", d.handlePrefix)
	mux.HandleFunc("GET /json-delta", d.handleJSONDelta)
	mux.HandleFunc("GET /jsonext", d.handleJSONExt) // 무거운 조사용 : -jsonext 로 켤 때만, 끄면 404 (reload 로 바뀜)
	mux.HandleFunc("GET /api/v1/objects", d.handleObjects)
	mux.HandleFunc("GET /api/v1/expiring", d.handleExpiring)
	mux.HandleFunc("GET /api/v1/ca", d.handleCA)
	mux.HandleFunc("GET /api/v1/unsafe", d.handleUnsafe)
	mux.HandleFunc("GET /api/v1/slurm", d.handleSLURM)
	mux.HandleFunc("GET /api/v1/history", d.handleHistory)
	mux.HandleFunc("GET /metrics", d.handleMetrics)
	mux.HandleFunc("GET /healthz", d.handleHealthz)
	return mux
}

// outTypes : 출력 파일의 Content-Type (파일 이름에 확장자가 없어 ServeFile 이 맞히지 못함)
var outTypes = map[string]string{
	"json":          "application/json",
	"csv":           "text/csv; charset=utf-8",
	"objects.jsonl": "application/jsonl",
	"rejects.txt":   "text/plain; charset=utf-8",
	"repos.json":    "application/json",
}

// serveOut : 출력 폴더의 파일 하나 (Range / If-Modified-Since 는 ServeFile 이 처리)
func (d *daemon) serveOut(w http.ResponseWriter, r *http.Request, name string) {
	if t := outTypes[name]; t != "" {
		w.Header().Set("Content-Type", t)
	}
	http.ServeFile(w, r, filepath.Join(d.cfg.OutDir, name))
}

// statusData : 상태 한 덩어리. public = 공개 쪽 (라우터 주소, 설정 / SLURM 파일, 메모리 뺌)
func (d *daemon) statusData(public bool) map[string]any {
	d.st.mu.RLock()
	ses, ser, cur, upd := d.st.Session, d.st.Serial, d.st.Cur, d.st.Updated
	hist := len(d.st.History)
	d.st.mu.RUnlock()
	d.mu.Lock()
	defer d.mu.Unlock()
	m := map[string]any{
		"version":        "haetae " + version,
		"started":        d.started,
		"config":         map[string]any{"file": d.confPath, "loaded": d.confAt}, // 설정 파일과 마지막으로 읽은 시각 (시작 / reload)
		"session":        ses,
		"serial":         ser,
		"deltas_kept":    hist,
		"set_updated":    upd,
		"last_applied":   d.lastOK,
		"runs":           d.runs,
		"last_run":       d.last,
		"rtr_open":       d.rtrOpen,
		"stale":          d.stale, // 집합이 stale-warn 보다 오래됨 (ops.go)
		"repos_problems": problemRepos(d.repos),
		"tas":            d.tas,
		"mem_mb":         memRSS() >> 20,
		"handover":       d.ho, // 무중단 판 올리기 (handover.go)
	}
	if d.view != nil {
		m["unsafe_vrps"] = len(d.view.Unsafe)
	}
	if slurmFile := d.c().SLURM; slurmFile != "" {
		sl := map[string]any{"file": slurmFile, "loaded": d.slurmAt}
		if d.slurmErr != "" {
			sl["error"] = d.slurmErr // 이 동안 회차는 반영하지 않음 (직전 집합 유지)
		}
		if cur != nil {
			sl["filtered"] = cur.Filtered
		}
		if d.slurm != nil {
			sl["added"] = slurmCounts{len(d.slurm.Asserts.Prefix), len(d.slurm.Asserts.BGPsec), len(d.slurm.Asserts.ASPA)}
		}
		m["slurm"] = sl
	}
	if cur != nil {
		m["vrps"], m["vaps"], m["router_keys"] = len(cur.VRPs), len(cur.ASPAs), len(cur.Keys)
		m["data_time"] = cur.Built
	}
	if d.rtr != nil {
		m["rtr_clients"] = d.rtr.clientsInfo()
	}
	if public {
		for _, k := range []string{"rtr_clients", "config", "slurm", "mem_mb", "started", "handover"} {
			delete(m, k)
		}
		if ri, ok := m["last_run"].(*runInfo); ok && ri != nil {
			c := *ri
			c.MemMB = 0
			m["last_run"] = &c
		}
	}
	return m
}

func problemRepos(rs []repoStatus) []repoStatus {
	var out []repoStatus
	for _, r := range rs {
		if r.Result != "ok" {
			out = append(out, r)
		}
	}
	return out
}

func (d *daemon) handleStatusJSON(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, d.statusData(false))
}

func (d *daemon) handleStatusJSONPublic(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, d.statusData(true))
}

func (d *daemon) handleStatusText(w http.ResponseWriter, r *http.Request) {
	writeStatusText(w, d.statusData(false))
}

func (d *daemon) handleStatusTextPublic(w http.ResponseWriter, r *http.Request) {
	writeStatusText(w, d.statusData(true))
}

func writeStatusText(w http.ResponseWriter, m map[string]any) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	keys := []string{"version", "started", "session", "serial", "data_time", "set_updated", "last_applied", "runs", "vrps", "vaps", "router_keys", "unsafe_vrps", "rtr_open", "mem_mb"}
	for _, k := range keys {
		if v, ok := m[k]; ok {
			if t, ok := v.(time.Time); ok {
				v = t.UTC().Format(time.RFC3339)
			}
			fmt.Fprintf(w, "%-14s %v\n", k+":", v)
		}
	}
	if ri, ok := m["last_run"].(*runInfo); ok && ri != nil {
		fmt.Fprintf(w, "last-run:      %s %s applied=%v %s\n", ri.Start.UTC().Format(time.RFC3339), ri.Duration, ri.Applied, ri.Reason)
		tas := make([]string, 0, len(ri.PerTA))
		for t := range ri.PerTA {
			tas = append(tas, t)
		}
		sort.Strings(tas)
		fmt.Fprint(w, "vrps-per-ta:  ")
		for _, t := range tas {
			fmt.Fprintf(w, " %s=%d", t, ri.PerTA[t])
		}
		fmt.Fprintf(w, "\nrepos:         %v\n", ri.Repos)
	}
	if cl, ok := m["rtr_clients"].([]rtrClientInfo); ok {
		for _, c := range cl {
			fmt.Fprintf(w, "rtr-client:    %s v%d since %s serial %d\n", c.Remote, c.Version, c.Since.UTC().Format(time.RFC3339), c.Serial)
		}
	}
	if pr, ok := m["repos_problems"].([]repoStatus); ok {
		for _, rp := range pr {
			fmt.Fprintf(w, "repo-problem:  %s %s %s\n", rp.Type, rp.Result, rp.URI)
		}
	}
}

// ---- 경로 검증 (RFC 6811) ----

type valVRP struct {
	ASN       string `json:"asn"`
	Prefix    string `json:"prefix"`
	MaxLength int    `json:"max_length"`
}

// coveringVRPs : route 를 덮는 (같거나 짧은 prefix) VRP 전부. prefix 길이마다 map 을 한 번씩 봄
func coveringVRPs(cur *payloadSet, route netip.Prefix) []rtrVRP {
	idx := cur.index()
	var out []rtrVRP
	for l := 0; l <= route.Bits(); l++ {
		p, _ := route.Addr().Prefix(l)
		out = append(out, idx[p]...)
	}
	return out
}

func (d *daemon) handleValidity(w http.ResponseWriter, r *http.Request) {
	asStr := strings.TrimPrefix(strings.ToUpper(r.PathValue("as")), "AS")
	asn, err := strconv.ParseUint(asStr, 10, 32)
	if err != nil {
		http.Error(w, "bad AS", 400)
		return
	}
	route, err := netip.ParsePrefix(r.PathValue("prefix"))
	if err != nil || route != route.Masked() {
		http.Error(w, "bad prefix", 400)
		return
	}
	d.st.mu.RLock()
	cur := d.st.Cur
	d.st.mu.RUnlock()
	if cur == nil {
		http.Error(w, "no data yet", 503)
		return
	}

	state, reason, m1, m2, m3 := rov(cur, uint32(asn), route)
	conv := func(vs []rtrVRP) []valVRP {
		out := make([]valVRP, 0, len(vs))
		for _, v := range vs {
			out = append(out, valVRP{fmt.Sprintf("AS%d", v.ASN), v.Prefix.String(), int(v.MaxLength)})
		}
		return out
	}
	matched, badAS, badLen := conv(m1), conv(m2), conv(m3)
	desc := map[string]string{
		"valid":     "At least one VRP Matches the Route Prefix",
		"invalid":   "",
		"not-found": "No VRP Covers the Route Prefix",
	}[state]
	switch reason {
	case "length":
		desc = "At least one VRP Covers the Route Prefix, but the Route Prefix length is greater than the maximum length allowed by VRP(s) matching this route origin ASN"
	case "as":
		desc = "At least one VRP Covers the Route Prefix, but no VRP ASN matches the route origin ASN"
	}
	nz := func(x []valVRP) []valVRP {
		if x == nil {
			return []valVRP{}
		}
		return x
	}
	validity := map[string]any{"state": state, "description": desc,
		"VRPs": map[string]any{"matched": nz(matched), "unmatched_as": nz(badAS), "unmatched_length": nz(badLen)}}
	if reason != "" {
		validity["reason"] = reason
	}
	out := map[string]any{
		"validated_route": map[string]any{
			"route":    map[string]any{"origin_asn": fmt.Sprintf("AS%d", asn), "prefix": route.String()},
			"validity": validity,
		},
		"generatedTime": cur.Built.UTC().Format(time.RFC3339),
	}
	writeJSON(w, out)
}

// ---- 바뀐 것 (E5) ----

func (d *daemon) handleDelta(w http.ResponseWriter, r *http.Request) {
	from, err := strconv.ParseUint(r.URL.Query().Get("serial"), 10, 32)
	if err != nil {
		http.Error(w, "serial=N required", 400)
		return
	}
	d.st.mu.RLock()
	ses, ser := d.st.Session, d.st.Serial
	ann, wdr, _, _, _, ok := d.st.netDiff(uint32(from))
	d.st.mu.RUnlock()
	// session 을 주면 확인 : 다르면 (재시작으로 새 session) 같은 serial 이라도 다른 집합 -> reset
	if s := r.URL.Query().Get("session"); s != "" && s != strconv.Itoa(int(ses)) {
		ok = false
	}

	conv := func(vs []rtrVRP) []valVRP {
		out := make([]valVRP, 0, len(vs))
		for _, v := range vs {
			out = append(out, valVRP{fmt.Sprintf("AS%d", v.ASN), v.Prefix.String(), int(v.MaxLength)})
		}
		return out
	}
	res := map[string]any{"session": ses, "serial": ser, "from": from, "reset": !ok}
	if ok {
		res["announced"], res["withdrawn"] = conv(ann), conv(wdr)
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(res)
}
