package main

// api_query.go : 조회 API (docs/api.md 와 같게 유지)
//
//   GET  /api/v1/as/<AS>            AS 의 VRP (+ 출처 ROA), ASPA, provider 로 등록된 곳, 라우터 키
//   GET  /api/v1/prefix/<prefix>    덮는 VRP + 안쪽 VRP
//   GET  /json-delta                Routinator 모양 전체 / 바뀐 것 (routeOrigin, routerKey, aspa)
//   GET  /jsonext                   Routinator jsonext 모양 (VRP 마다 출처 ROA)
//   GET  /api/v1/objects            객체 조건 검색
//   GET  /api/v1/expiring           곧 만료되는 객체
//   GET  /api/v1/ca?uri=            CA 하나 (자원, 하위 객체)
//   GET  /api/v1/unsafe             unsafe VRP (A4)
//   GET  /api/v1/slurm              SLURM 적용 현황

import (
	"bufio"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	maxMoreSpecific  = 10000
	maxObjectsLimit  = 10000
	maxCAChildren    = 10000
	defaultObjLimit  = 1000
	maxExpiringDays  = 90
	defaultExpiryDay = 7
)

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	enc.SetIndent("", " ")
	enc.Encode(v)
}

// parseASN : "13335" 또는 "AS13335"
func parseASN(s string) (uint32, error) {
	s = strings.TrimPrefix(strings.ToUpper(s), "AS")
	n, err := strconv.ParseUint(s, 10, 32)
	return uint32(n), err
}

// current : 지금 집합과 조회용 결과 (언제나 같은 회차 : cycle 이 d.mu 안에서 둘을 같이 바꿈). 잠금 순서 d.mu -> st.mu
func (d *daemon) current() (*payloadSet, *queryView) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.st.mu.RLock()
	defer d.st.mu.RUnlock()
	return d.st.Cur, d.view
}

func noData(w http.ResponseWriter) {
	http.Error(w, "no data yet (wait for first validation)", 503)
}

// ---- 경로 판정 (RFC 6811) ----

// rov : 경로 하나 판정. state = valid / invalid / not-found, reason = as / length (invalid 일 때)
func rov(cur *payloadSet, asn uint32, route netip.Prefix) (state, reason string, matched, badAS, badLen []rtrVRP) {
	for _, v := range coveringVRPs(cur, route) {
		switch {
		case v.ASN == asn && v.ASN != 0 && route.Bits() <= int(v.MaxLength):
			matched = append(matched, v)
		case v.ASN == asn:
			badLen = append(badLen, v)
		default:
			badAS = append(badAS, v)
		}
	}
	switch {
	case len(matched) > 0:
		return "valid", "", matched, badAS, badLen
	case len(badLen) > 0:
		return "invalid", "length", matched, badAS, badLen
	case len(badAS) > 0:
		return "invalid", "as", matched, badAS, badLen
	}
	return "not-found", "", matched, badAS, badLen
}

// ---- AS / prefix 조회 ----

type vrpOut struct {
	ASN       uint32       `json:"asn"`
	Prefix    netip.Prefix `json:"prefix"`
	MaxLength int          `json:"maxLength"`
	TA        string       `json:"ta"`
	Expires   int64        `json:"expires"`
	ROAs      []string     `json:"roas"`
}

func newVRPOut(cur *payloadSet, view *queryView, k vrpKey) vrpOut {
	o := vrpOut{k.ASN, k.Prefix, k.MaxLength, k.TA, cur.FullExp[k].Unix(), []string{}}
	if view != nil {
		for _, s := range view.VRPSrc[k] {
			o.ROAs = append(o.ROAs, s.URI)
		}
	}
	return o
}

type srcOut struct {
	URI      string    `json:"uri"`
	TA       string    `json:"ta"`
	NotAfter time.Time `json:"notAfter"`
	Expires  int64     `json:"expires"`
}

// GET /api/v1/as/<AS>
func (d *daemon) handleAS(w http.ResponseWriter, r *http.Request) {
	asn, err := parseASN(r.PathValue("as"))
	if err != nil {
		http.Error(w, "bad AS", 400)
		return
	}
	cur, view := d.current()
	if cur == nil {
		noData(w)
		return
	}
	vrps := []vrpOut{}
	for _, k := range cur.Full {
		if k.ASN == asn {
			vrps = append(vrps, newVRPOut(cur, view, k))
		}
	}

	var aspa any // 없으면 null
	if ps, ok := cur.ASPAs[asn]; ok {
		srcs := []srcOut{}
		if view != nil {
			for i := range view.Objects {
				o := &view.Objects[i]
				if o.Type != "asa" || o.Status != "valid" {
					continue
				}
				if as := objASNs(o); len(as) == 1 && as[0] == asn {
					exp := int64(0)
					if a := view.ASPAs[aspaKey{asn, o.TA}]; a != nil {
						exp = a.Expires.Unix()
					}
					srcs = append(srcs, srcOut{o.URI, o.TA, o.NotAfter, exp})
				}
			}
		}
		aspa = map[string]any{"providers": ps, "sources": srcs}
	}

	providerOf := []uint32{}
	for c, ps := range cur.ASPAs {
		i := sort.Search(len(ps), func(i int) bool { return ps[i] >= asn })
		if i < len(ps) && ps[i] == asn {
			providerOf = append(providerOf, c)
		}
	}
	sort.Slice(providerOf, func(i, j int) bool { return providerOf[i] < providerOf[j] })

	keys := []map[string]any{}
	for k := range cur.Keys {
		if k.ASN != asn {
			continue
		}
		m := map[string]any{"ski": fmt.Sprintf("%X", k.SKI), "pubkey": base64.StdEncoding.EncodeToString([]byte(k.SPKI))}
		if view != nil {
			for _, rk := range view.RKeys {
				if rk.ASN == asn && string(rk.SKI) == string(k.SKI[:]) {
					m["ta"], m["expires"], m["uri"] = rk.TA, rk.Expires.Unix(), rk.URI
					break
				}
			}
		}
		keys = append(keys, m)
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i]["ski"].(string) < keys[j]["ski"].(string) })

	writeJSON(w, map[string]any{
		"asn": asn, "generatedTime": cur.Built.UTC().Format(time.RFC3339),
		"vrps": vrps, "aspa": aspa, "provider_of": providerOf, "router_keys": keys,
	})
}

// cmpPrefix : 주소, 길이 순 (payloadSet.Full 정렬과 같음)
func cmpPrefix(a, b netip.Prefix) int {
	if c := a.Addr().Compare(b.Addr()); c != 0 {
		return c
	}
	return a.Bits() - b.Bits()
}

// fullLower : Full 에서 prefix 가 p 이상인 첫 위치
func fullLower(full []vrpKey, p netip.Prefix) int {
	return sort.Search(len(full), func(i int) bool { return cmpPrefix(full[i].Prefix, p) >= 0 })
}

// GET /api/v1/prefix/<prefix>
func (d *daemon) handlePrefix(w http.ResponseWriter, r *http.Request) {
	p, err := netip.ParsePrefix(r.PathValue("prefix"))
	if err != nil || p != p.Masked() {
		http.Error(w, "bad prefix", 400)
		return
	}
	cur, view := d.current()
	if cur == nil {
		noData(w)
		return
	}
	covering, more := []vrpOut{}, []vrpOut{}
	// 덮는 것 : 길이 0..p.Bits() 의 상위 prefix 마다 정확히 같은 것
	for l := 0; l <= p.Bits(); l++ {
		up, _ := p.Addr().Prefix(l)
		for i := fullLower(cur.Full, up); i < len(cur.Full) && cur.Full[i].Prefix == up; i++ {
			covering = append(covering, newVRPOut(cur, view, cur.Full[i]))
		}
	}
	// 안쪽 : 같은 주소부터 p 안에 있는 동안, 길이가 p 보다 긴 것
	truncated := false
	for i := fullLower(cur.Full, p); i < len(cur.Full); i++ {
		k := cur.Full[i]
		if k.Prefix.Addr().Is4() != p.Addr().Is4() || !p.Contains(k.Prefix.Addr()) {
			break
		}
		if k.Prefix.Bits() <= p.Bits() {
			continue
		}
		if len(more) >= maxMoreSpecific {
			truncated = true
			break
		}
		more = append(more, newVRPOut(cur, view, k))
	}
	writeJSON(w, map[string]any{
		"prefix": p.String(), "generatedTime": cur.Built.UTC().Format(time.RFC3339),
		"covering": covering, "more_specific": more, "more_specific_truncated": truncated,
	})
}

// ---- /json-delta (Routinator 모양) ----

func jsonDeltaVRP(bw *bufio.Writer, v rtrVRP) {
	fmt.Fprintf(bw, `{"type":"routeOrigin","asn":"AS%d","prefix":"%s","maxLength":%d}`, v.ASN, v.Prefix, v.MaxLength)
}

func jsonDeltaKey(bw *bufio.Writer, k rtrKey) {
	fmt.Fprintf(bw, `{"type":"routerKey","asn":"AS%d","SKI":"%X","routerPublicKey":"%s"}`,
		k.ASN, k.SKI, base64.StdEncoding.EncodeToString([]byte(k.SPKI)))
}

func jsonDeltaASPA(bw *bufio.Writer, customer uint32, providers []uint32) {
	ps := make([]string, len(providers))
	for i, p := range providers {
		ps[i] = fmt.Sprintf(`"AS%d"`, p)
	}
	fmt.Fprintf(bw, `{"type":"aspa","customer":"AS%d","providers":[%s]}`, customer, strings.Join(ps, ","))
}

// GET /json-delta?session=S&serial=N[&to=M] : 인자가 없거나 맞지 않으면 reset (전체, Routinator 와 같음)
// 전체 (85 MB, CPU 약 1 초) 는 받는 쪽 주소마다 -delta-full-interval (기본 60 초) 에 한 번.
// 그 안에 다시 오면 429 + Retry-After (받는 쪽은 실패로 보고 가진 목록을 그대로 둠 -> VRP 를 지우는 일 없음)
// to 를 주면 serial N 뒤 ~ M 까지만 (회차 하나 = serial=M-1&to=M). to 까지의 기록이 없으면 404 (reset 아님)
func (d *daemon) handleJSONDelta(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	d.st.mu.RLock()
	cur, ses, ser := d.st.Cur, d.st.Session, d.st.Serial
	if cur == nil {
		d.st.mu.RUnlock()
		noData(w)
		return
	}
	to := ser
	if s := q.Get("to"); s != "" {
		n, err := strconv.ParseUint(s, 10, 32)
		if err != nil || uint32(n) > ser {
			d.st.mu.RUnlock()
			http.Error(w, "bad to (must be <= current serial)", 400)
			return
		}
		to = uint32(n)
	}
	var ann, wdr []rtrVRP
	var kAnn, kWdr []rtrKey
	var aspaChg []uint32
	aspaTo := map[uint32][]uint32{} // to 시점의 provider (비었으면 없음)
	ok := false
	from, err := strconv.ParseUint(q.Get("serial"), 10, 32)
	if err == nil && q.Get("session") == strconv.Itoa(int(ses)) && uint32(from) <= to {
		ann, wdr, kAnn, kWdr, aspaChg, ok = d.st.netDiffTo(uint32(from), to)
		for _, c := range aspaChg {
			aspaTo[c] = d.st.aspaAt(c, to)
		}
	}
	d.st.mu.RUnlock()
	if !ok && to != ser {
		http.Error(w, "serial range not in delta history (use json-delta without to for full set)", 404)
		return
	}
	if !ok {
		if wait := d.clientWait("/json-delta full", r.RemoteAddr); wait > 0 {
			sec := int((wait + time.Second - 1) / time.Second)
			w.Header().Set("Retry-After", strconv.Itoa(sec))
			http.Error(w, fmt.Sprintf("full set (reset) allowed once per %s per client, retry after %d s",
				d.c().DeltaFullInterval, sec), http.StatusTooManyRequests)
			return
		}
	}

	w.Header().Set("Content-Type", "application/json")
	bw := bufio.NewWriterSize(w, 1<<20)
	defer bw.Flush()
	fmt.Fprintf(bw, `{"reset":%v,"session":"%d","serial":%d,`, !ok, ses, to)
	if ok {
		fmt.Fprintf(bw, `"fromSerial":%d,`, from)
	}
	fmt.Fprintf(bw, `"generated":%d,"generatedTime":"%s",`, cur.Built.Unix(), cur.Built.UTC().Format(time.RFC3339))

	n := 0
	sep := func() {
		if n > 0 {
			bw.WriteString(",\n")
		} else {
			bw.WriteString("\n")
		}
		n++
	}
	bw.WriteString(`"announced":[`)
	if !ok {
		// 전체
		for _, v := range cur.sortedVRPs() {
			sep()
			jsonDeltaVRP(bw, v)
		}
		for k := range cur.Keys {
			sep()
			jsonDeltaKey(bw, k)
		}
		for _, c := range sortedASPACustomers(cur) {
			sep()
			jsonDeltaASPA(bw, c, cur.ASPAs[c])
		}
	} else {
		sortRTRVRPs(ann)
		for _, v := range ann {
			sep()
			jsonDeltaVRP(bw, v)
		}
		for _, k := range kAnn {
			sep()
			jsonDeltaKey(bw, k)
		}
		for _, c := range aspaChg {
			if ps := aspaTo[c]; len(ps) > 0 {
				sep()
				jsonDeltaASPA(bw, c, ps)
			}
		}
	}
	bw.WriteString("],\n\"withdrawn\":[")
	n = 0
	if ok {
		sortRTRVRPs(wdr)
		for _, v := range wdr {
			sep()
			jsonDeltaVRP(bw, v)
		}
		for _, k := range kWdr {
			sep()
			jsonDeltaKey(bw, k)
		}
		for _, c := range aspaChg {
			if len(aspaTo[c]) == 0 {
				sep()
				jsonDeltaASPA(bw, c, nil)
			}
		}
	}
	bw.WriteString("]}\n")
}

// clientWait : 이 주소가 kind (/json-delta 전체, 공개 쪽 /json 등) 를 받아도 되면 0 (그리고 지금 시각을 기록), 아니면 남은 시간
// 간격 = -delta-full-interval, 0 = 제한 없음. 주소 = clientKey (IPv6 는 /64). 표가 커지면 지난 것만 지움 (주소 수 상한 대신)
func (d *daemon) clientWait(kind, remote string) time.Duration {
	iv := d.c().DeltaFullInterval
	if iv <= 0 {
		return 0
	}
	host := kind + " " + clientKey(remote)
	now := time.Now()
	d.fullMu.Lock()
	defer d.fullMu.Unlock()
	if d.fullLast == nil {
		d.fullLast = map[string]time.Time{}
	}
	if t, ok := d.fullLast[host]; ok && now.Sub(t) < iv {
		return iv - now.Sub(t)
	}
	if len(d.fullLast) >= 1000 {
		for h, t := range d.fullLast {
			if now.Sub(t) >= iv {
				delete(d.fullLast, h)
			}
		}
	}
	d.fullLast[host] = now
	return 0
}

func sortedASPACustomers(p *payloadSet) []uint32 {
	cs := make([]uint32, 0, len(p.ASPAs))
	for c := range p.ASPAs {
		cs = append(cs, c)
	}
	sort.Slice(cs, func(i, j int) bool { return cs[i] < cs[j] })
	return cs
}

// ---- /jsonext (Routinator 모양) ----

func rfc3339(epoch int64) string { return time.Unix(epoch, 0).UTC().Format(time.RFC3339) }

func jsonextSource(bw *bufio.Writer, s vrpSource) {
	fmt.Fprintf(bw, `{"type":"roa","uri":%q,"tal":%q,"validity":{"notBefore":"%s","notAfter":"%s"},`+
		`"chainValidity":{"notBefore":"%s","notAfter":"%s"},"stale":"%s"}`,
		s.URI, s.TA, rfc3339(s.NB), rfc3339(s.NA), rfc3339(s.ChainNB), rfc3339(s.ChainNA), rfc3339(s.Stale))
}

// GET /jsonext : VRP 마다 출처 ROA. (asn, prefix, maxLength) 가 같으면 TA 가 달라도 한 항목 (source 여러 개)
func (d *daemon) handleJSONExt(w http.ResponseWriter, r *http.Request) {
	if !d.c().JSONExt {
		http.NotFound(w, r)
		return
	}
	cur, view := d.current()
	if cur == nil || view == nil {
		noData(w)
		return
	}
	d.mu.Lock()
	slurmPath := d.c().SLURM
	d.mu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	bw := bufio.NewWriterSize(w, 1<<20)
	defer bw.Flush()
	fmt.Fprintf(bw, "{\n  \"metadata\": {\"generated\": %d, \"generatedTime\": \"%s\"},\n  \"roas\": [",
		cur.Built.Unix(), cur.Built.UTC().Format(time.RFC3339))
	full := cur.Full
	first := true
	for i := 0; i < len(full); {
		k := full[i]
		j := i
		for j < len(full) && full[j].ASN == k.ASN && full[j].Prefix == k.Prefix && full[j].MaxLength == k.MaxLength {
			j++
		}
		// Full 은 (주소, 길이, maxLength, ASN, TA) 순이라 같은 VRP 의 TA 들이 붙어 있음
		if !first {
			bw.WriteString(",")
		}
		first = false
		fmt.Fprintf(bw, "\n    {\"asn\": \"AS%d\", \"prefix\": \"%s\", \"maxLength\": %d, \"source\": [", k.ASN, k.Prefix, k.MaxLength)
		ns := 0
		for _, kk := range full[i:j] {
			srcs := view.VRPSrc[kk]
			if kk.TA == "slurm" || len(srcs) == 0 {
				if ns > 0 {
					bw.WriteString(", ")
				}
				fmt.Fprintf(bw, `{"type":"exception","path":%q}`, slurmPath)
				ns++
				continue
			}
			for _, s := range srcs {
				if ns > 0 {
					bw.WriteString(", ")
				}
				jsonextSource(bw, s)
				ns++
			}
		}
		bw.WriteString("]}")
		i = j
	}
	bw.WriteString("\n  ],\n  \"routerKeys\": [")
	for i, rk := range view.RKeys {
		if i > 0 {
			bw.WriteString(",")
		}
		fmt.Fprintf(bw, "\n    {\"asn\": \"AS%d\", \"SKI\": \"%X\", \"routerPublicKey\": \"%s\", \"source\": [{\"type\":\"cer\",\"uri\":%q,\"tal\":%q,\"expires\":%d}]}",
			rk.ASN, rk.SKI, base64.StdEncoding.EncodeToString(rk.SPKI), rk.URI, rk.TA, rk.Expires.Unix())
	}
	bw.WriteString("\n  ],\n  \"aspas\": [")
	for i, c := range sortedASPACustomers(cur) {
		if i > 0 {
			bw.WriteString(",")
		}
		ps := make([]string, len(cur.ASPAs[c]))
		for x, p := range cur.ASPAs[c] {
			ps[x] = fmt.Sprintf(`"AS%d"`, p)
		}
		fmt.Fprintf(bw, "\n    {\"customer\": \"AS%d\", \"providers\": [%s]}", c, strings.Join(ps, ", "))
	}
	bw.WriteString("\n  ]\n}\n")
}

// ---- 객체 ----

// queryInt : 정수 인자 (없으면 def, 범위 밖이면 오류)
func queryInt(r *http.Request, name string, def, lo, hi int) (int, error) {
	s := r.URL.Query().Get(name)
	if s == "" {
		return def, nil
	}
	n, err := strconv.Atoi(s)
	if err != nil || n < lo || n > hi {
		return 0, fmt.Errorf("%s = %d..%d", name, lo, hi)
	}
	return n, nil
}

// parseObjFilter : type kind ta status uri as prefix
func parseObjFilter(r *http.Request) (*objFilter, error) {
	q := r.URL.Query()
	f := &objFilter{Type: q.Get("type"), Kind: q.Get("kind"), TA: q.Get("ta"), Status: q.Get("status"), URIPrefix: q.Get("uri")}
	switch f.Kind {
	case "", "TA", "CA", "router":
	default:
		return nil, fmt.Errorf("kind = TA / CA / router")
	}
	if s := q.Get("as"); s != "" {
		a, err := parseASN(s)
		if err != nil {
			return nil, fmt.Errorf("bad as")
		}
		f.ASN = &a
	}
	if s := q.Get("prefix"); s != "" {
		p, err := parsePrefixOrAddr(s)
		if err != nil {
			return nil, fmt.Errorf("bad prefix")
		}
		f.Prefix = &p
	}
	return f, nil
}

// GET /api/v1/objects?type=&kind=&ta=&as=&prefix=&uri=&status=&limit=&offset=
func (d *daemon) handleObjects(w http.ResponseWriter, r *http.Request) {
	_, view := d.current()
	if view == nil {
		noData(w)
		return
	}
	f, err := parseObjFilter(r)
	if err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	limit, err := queryInt(r, "limit", defaultObjLimit, 1, maxObjectsLimit)
	if err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	offset, err := queryInt(r, "offset", 0, 0, 1<<30)
	if err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	total, out := 0, []*objInfo{}
	for i := range view.Objects {
		o := &view.Objects[i]
		if !f.match(o) {
			continue
		}
		if total >= offset && len(out) < limit {
			out = append(out, o)
		}
		total++
	}
	writeJSON(w, map[string]any{"total": total, "offset": offset, "objects": out})
}

// GET /api/v1/expiring?days=7&type=&as=&ta=&limit=
// 객체 자체 인증서의 notAfter 기준. manifest / CRL (매일 갱신) 은 뺌
func (d *daemon) handleExpiring(w http.ResponseWriter, r *http.Request) {
	_, view := d.current()
	if view == nil {
		noData(w)
		return
	}
	f, err := parseObjFilter(r)
	if err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	days, err := queryInt(r, "days", defaultExpiryDay, 1, maxExpiringDays)
	if err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	limit, err := queryInt(r, "limit", maxObjectsLimit, 1, maxObjectsLimit)
	if err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	if f.Type == "mft" || f.Type == "crl" {
		http.Error(w, "type mft / crl not supported (nextUpdate changes daily)", 400)
		return
	}
	f.Status = "valid"
	f.ExpireBefore = time.Now().Add(time.Duration(days) * 24 * time.Hour)
	var out []*objInfo
	for i := range view.Objects {
		o := &view.Objects[i]
		if o.Type != "mft" && o.Type != "crl" && f.match(o) {
			out = append(out, o)
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].NotAfter.Before(out[j].NotAfter) })
	total := len(out)
	if len(out) > limit {
		out = out[:limit]
	}
	if out == nil {
		out = []*objInfo{}
	}
	writeJSON(w, map[string]any{"days": days, "total": total, "objects": out})
}

// GET /api/v1/ca?uri=<CA 인증서 rsync URI>
func (d *daemon) handleCA(w http.ResponseWriter, r *http.Request) {
	_, view := d.current()
	if view == nil {
		noData(w)
		return
	}
	uri := r.URL.Query().Get("uri")
	o := view.object(uri)
	if o == nil || o.Type != "cer" {
		http.Error(w, "no such CA certificate", 404)
		return
	}
	m, _ := o.Summary.(map[string]any)
	if m != nil && m["kind"] == "router" {
		http.Error(w, "router certificate, not CA", 404)
		return
	}
	res := map[string]any{"uri": o.URI, "ta": o.TA, "parent": o.Parent, "status": o.Status,
		"notBefore": o.NotBefore, "notAfter": o.NotAfter, "sha256": o.SHA256}
	if o.Reason != "" {
		res["reason"] = o.Reason
	}
	if m != nil {
		res["kind"] = m["kind"]
		res["resources"] = m["resources"]
		repo, _ := m["repository"].(string)
		notify, _ := m["notify"].(string)
		res["repository"], res["notify"] = repo, notify
		res["repo_result"] = view.repoOf(notify, repo)
	}
	children := []map[string]any{}
	counts := map[string]int{}
	truncated := false
	for i := range view.Objects {
		c := &view.Objects[i]
		if c.Parent != o.URI {
			continue
		}
		counts[c.Type+" "+c.Status]++
		if len(children) >= maxCAChildren {
			truncated = true
			continue
		}
		ch := map[string]any{"uri": c.URI, "type": c.Type, "status": c.Status}
		if cm, ok := c.Summary.(map[string]any); ok && c.Type == "cer" {
			ch["kind"] = cm["kind"]
		}
		children = append(children, ch)
	}
	res["children"], res["children_truncated"], res["counts"] = children, truncated, counts
	writeJSON(w, res)
}

// GET /api/v1/unsafe
func (d *daemon) handleUnsafe(w http.ResponseWriter, r *http.Request) {
	_, view := d.current()
	if view == nil {
		noData(w)
		return
	}
	out := view.Unsafe
	if out == nil {
		out = []unsafeVRP{}
	}
	writeJSON(w, map[string]any{"generatedTime": view.Built.UTC().Format(time.RFC3339), "total": len(out), "vrps": out})
}

// GET /api/v1/slurm
func (d *daemon) handleSLURM(w http.ResponseWriter, r *http.Request) {
	cur, _ := d.current()
	d.mu.Lock()
	s, at, path := d.slurm, d.slurmAt, d.c().SLURM
	d.mu.Unlock()
	res := map[string]any{"file": path}
	if s == nil {
		res["loaded"] = nil
		writeJSON(w, res)
		return
	}
	res["loaded"] = at
	res["filters"] = s.Filters
	res["assertions"] = s.Asserts
	res["added"] = slurmCounts{len(s.Asserts.Prefix), len(s.Asserts.BGPsec), len(s.Asserts.ASPA)}
	if cur != nil {
		res["filtered"] = cur.Filtered
	}
	writeJSON(w, res)
}
