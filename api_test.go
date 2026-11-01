package main

// api_test.go : 조회 API (AS / prefix / 대량 판정 / json-delta / unsafe / 객체 / 이력)

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"
)

// testSet : VRP 목록 (asn, prefix, maxLength, ta) 으로 payloadSet
func testSet(vs []vrpKey, aspas map[uint32][]uint32) *payloadSet {
	p := &payloadSet{VRPs: map[rtrVRP]bool{}, Keys: map[rtrKey]bool{}, ASPAs: map[uint32][]uint32{},
		FullExp: map[vrpKey]time.Time{}, Built: time.Unix(1793285077, 0)}
	for _, k := range vs {
		p.Full = append(p.Full, k)
		p.FullExp[k] = p.Built.Add(time.Hour)
		p.VRPs[rtrVRP{k.Prefix, uint8(k.MaxLength), k.ASN}] = true
	}
	for c, ps := range aspas {
		p.ASPAs[c] = ps
	}
	return p
}

func vk(asn uint32, pfx string, ml int, ta string) vrpKey {
	return vrpKey{asn, netip.MustParsePrefix(pfx), ml, ta}
}

func testDaemon(t *testing.T) *daemon {
	d := &daemon{cfg: daemonConfig{StateDir: t.TempDir()}, st: &store{Session: 7}}
	full := []vrpKey{
		vk(13335, "1.1.1.0/24", 24, "apnic"),
		vk(13335, "1.0.0.0/8", 16, "apnic"),
		vk(64500, "1.1.0.0/16", 24, "ripe"),
		vk(64500, "1.1.0.0/16", 24, "arin"), // 같은 VRP, 다른 TA
		vk(64501, "2001:db8::/32", 48, "ripe"),
	}
	ps := testSet(full, map[uint32][]uint32{64500: {174, 13335}})
	ps2 := testSet(append(full[:5:5], vk(64502, "10.0.0.0/8", 8, "ripe")), map[uint32][]uint32{64500: {174}})
	sortFull := func(p *payloadSet) {
		for i := range p.Full {
			for j := i + 1; j < len(p.Full); j++ {
				if lessVRPKey(p.Full[j], p.Full[i]) {
					p.Full[i], p.Full[j] = p.Full[j], p.Full[i]
				}
			}
		}
	}
	sortFull(ps)
	sortFull(ps2)
	d.st.update(ps)  // 처음 : serial 0
	d.st.update(ps2) // serial 1 : +10.0.0.0/8, ASPA 64500 바뀜
	roa := objInfo{Type: "roa", URI: "rsync://x/a.roa", TA: "apnic", Status: "valid", NotAfter: time.Now().Add(48 * time.Hour),
		Summary: map[string]any{"asn": uint32(13335), "prefixes": []roaPrefixOut{{netip.MustParsePrefix("1.1.1.0/24"), 24}}}}
	asa := objInfo{Type: "asa", URI: "rsync://x/b.asa", TA: "ripe", Status: "valid", NotAfter: time.Now().Add(100 * 24 * time.Hour),
		Summary: map[string]any{"customer": uint32(64500), "providers": []uint32{174}}}
	d.view = &queryView{
		Objects: []objInfo{roa, asa},
		VRPSrc:  map[vrpKey][]vrpSource{full[0]: {{URI: roa.URI, TA: "apnic"}}},
		ASPAs:   map[aspaKey]*aspaOut{},
	}
	return d
}

func get(t *testing.T, h http.Handler, method, url, body string) (int, map[string]any) {
	t.Helper()
	req := httptest.NewRequest(method, url, strings.NewReader(body))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	var m map[string]any
	if rec.Code == 200 {
		if err := json.Unmarshal(rec.Body.Bytes(), &m); err != nil {
			t.Fatalf("%s: %v\n%s", url, err, rec.Body.String())
		}
	}
	return rec.Code, m
}

func TestAPIAsPrefix(t *testing.T) {
	h := testDaemon(t).apiHandler()

	_, m := get(t, h, "GET", "/api/v1/as/AS13335", "")
	if n := len(m["vrps"].([]any)); n != 2 {
		t.Errorf("AS13335 vrps %d", n)
	}
	_, m = get(t, h, "GET", "/api/v1/as/174", "")
	if po := m["provider_of"].([]any); len(po) != 1 || po[0].(float64) != 64500 {
		t.Errorf("provider_of %v", po)
	}
	_, m = get(t, h, "GET", "/api/v1/as/64500", "")
	if a := m["aspa"].(map[string]any); len(a["sources"].([]any)) != 1 {
		t.Errorf("aspa %v", a)
	}

	_, m = get(t, h, "GET", "/api/v1/prefix/1.1.0.0/16", "")
	cov, more := m["covering"].([]any), m["more_specific"].([]any)
	// 덮는 것 : 1.0.0.0/8, 1.1.0.0/16 (TA 2 개) / 안쪽 : 1.1.1.0/24
	if len(cov) != 3 || len(more) != 1 {
		t.Errorf("prefix covering %d more %d", len(cov), len(more))
	}
	if r := more[0].(map[string]any)["roas"].([]any); len(r) != 1 {
		t.Errorf("roas %v", r)
	}
	if code, _ := get(t, h, "GET", "/api/v1/prefix/1.1.1.1/16", ""); code != 400 {
		t.Errorf("host bits code %d", code)
	}
}

// /jsonext : -jsonext 로 켤 때만 (기본 끔 = 404)
func TestAPIJSONExtOption(t *testing.T) {
	d := testDaemon(t)
	if code, _ := get(t, d.apiHandler(), "GET", "/jsonext", ""); code != 404 {
		t.Errorf("off: code %d, want 404", code)
	}
	d.cfg.JSONExt = true
	if code, _ := get(t, d.apiHandler(), "GET", "/jsonext", ""); code == 404 {
		t.Errorf("on: code %d", code)
	}
}

// POST 대량 판정은 10-31 지움 (부르는 곳 없음) -> 열려 있지 않아야 함
func TestAPINoBulkPOST(t *testing.T) {
	h := testDaemon(t).apiHandler()
	for _, p := range []string{"/api/v1/validity", "/api/v1/aspa/verify"} {
		if code, _ := get(t, h, "POST", p, `{}`); code == 200 {
			t.Errorf("POST %s code %d", p, code)
		}
	}
}

func TestAPIJSONDelta(t *testing.T) {
	h := testDaemon(t).apiHandler()
	_, m := get(t, h, "GET", "/json-delta", "")
	if m["reset"] != true || len(m["announced"].([]any)) != 6 { // VRP 5 (TA 합침) + ASPA 1
		t.Errorf("reset: %v %d", m["reset"], len(m["announced"].([]any)))
	}
	_, m = get(t, h, "GET", "/json-delta?session=7&serial=0", "")
	ann := m["announced"].([]any)
	if m["reset"] != false || m["fromSerial"].(float64) != 0 || len(ann) != 2 || len(m["withdrawn"].([]any)) != 0 {
		t.Errorf("delta: %v", m)
	}
	_, m = get(t, h, "GET", "/json-delta?session=8&serial=0", "")
	if m["reset"] != true || len(m["announced"].([]any)) != 6 {
		t.Error("other session must reset (full)")
	}
}

// 전체 (reset) 는 주소마다 간격에 한 번, 그 안이면 429 + Retry-After. 바뀐 것만은 제한 없음
func TestAPIJSONDeltaFullLimit(t *testing.T) {
	d := testDaemon(t)
	d.cfg.DeltaFullInterval = time.Minute
	h := d.apiHandler()
	call := func(addr, url string) *httptest.ResponseRecorder {
		req := httptest.NewRequest("GET", url, nil)
		req.RemoteAddr = addr
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}
	if rec := call("192.0.2.1:1000", "/json-delta"); rec.Code != 200 {
		t.Fatalf("first full: %d", rec.Code)
	}
	rec := call("192.0.2.1:2000", "/json-delta?session=8&serial=0") // 같은 주소, 다른 포트, reset
	if rec.Code != 429 || rec.Header().Get("Retry-After") == "" {
		t.Errorf("second full: %d retry %q", rec.Code, rec.Header().Get("Retry-After"))
	}
	if rec := call("192.0.2.1:2000", "/json-delta?session=7&serial=0"); rec.Code != 200 {
		t.Errorf("delta must not be limited: %d", rec.Code)
	}
	if rec := call("[::ffff:192.0.2.2]:1000", "/json-delta"); rec.Code != 200 {
		t.Errorf("other client: %d", rec.Code)
	}
	if rec := call("192.0.2.2:1000", "/json-delta"); rec.Code != 429 { // v4-mapped = 같은 주소
		t.Errorf("mapped same client: %d", rec.Code)
	}
	d.cfg.DeltaFullInterval = 0 // 제한 없음
	if rec := call("192.0.2.1:1000", "/json-delta"); rec.Code != 200 {
		t.Errorf("no limit: %d", rec.Code)
	}
}

func TestAPIObjects(t *testing.T) {
	h := testDaemon(t).apiHandler()
	_, m := get(t, h, "GET", "/api/v1/objects?prefix=1.1.0.0/16", "")
	if m["total"].(float64) != 1 {
		t.Errorf("objects prefix total %v", m["total"])
	}
	_, m = get(t, h, "GET", "/api/v1/objects?as=64500", "")
	if m["total"].(float64) != 1 {
		t.Errorf("objects as total %v", m["total"])
	}
	_, m = get(t, h, "GET", "/api/v1/expiring?days=7", "")
	if m["total"].(float64) != 1 {
		t.Errorf("expiring total %v", m["total"])
	}
}

func TestUnsafe(t *testing.T) {
	rs := []unsafeRange{
		{"rsync://ca/bad.cer", true, prefixRange(netip.MustParsePrefix("1.1.1.0/24"))},
		{"rsync://ca/bad6.cer", false, prefixRange(netip.MustParsePrefix("2001:db8:1::/48"))},
	}
	vs := []vrpKey{
		vk(1, "1.0.0.0/8", 24, "apnic"),      // 넓은 것 : 겹침
		vk(2, "1.1.1.128/25", 25, "apnic"),   // 안쪽 : 겹침
		vk(3, "1.1.2.0/24", 24, "apnic"),     // 옆 : 안 겹침
		vk(4, "2001:db8::/32", 48, "ripe"),   // 겹침
		vk(5, "2001:db8:2::/48", 48, "ripe"), // 안 겹침
	}
	got := computeUnsafe(vs, rs)
	if len(got) != 3 {
		t.Fatalf("unsafe %v", got)
	}
	for _, u := range got {
		if u.ASN == 3 || u.ASN == 5 {
			t.Errorf("not overlapping but unsafe: %v", u)
		}
	}
}

func TestRangeString(t *testing.T) {
	cases := []struct {
		pfx  string
		want string
	}{{"10.0.0.0/8", "10.0.0.0/8"}, {"2001:db8::/32", "2001:db8::/32"}, {"0.0.0.0/0", "0.0.0.0/0"}}
	for _, c := range cases {
		p := netip.MustParsePrefix(c.pfx)
		if got := rangeString(prefixRange(p), p.Addr().Is4()); got != c.want {
			t.Errorf("%s -> %s", c.pfx, got)
		}
	}
	r := ipRange{}
	copy(r.Min[:], []byte{10, 0, 0, 1})
	copy(r.Max[:], []byte{10, 0, 0, 5})
	if got := rangeString(r, true); got != "10.0.0.1-10.0.0.5" {
		t.Errorf("range -> %s", got)
	}
}

func TestHistory(t *testing.T) {
	d := testDaemon(t)
	for i := 0; i < 30; i++ {
		d.addHistory(histRun{Start: time.Now().Add(time.Duration(i-30) * time.Minute), VRPs: i})
	}
	hist, lines := loadHistory(d.cfg.StateDir)
	if len(hist) != 30 || lines > 30 {
		t.Errorf("loaded %d lines %d", len(hist), lines)
	}
	_, m := get(t, d.apiHandler(), "GET", "/api/v1/history?hours=1", "")
	if n := len(m["runs"].([]any)); n != 30 {
		t.Errorf("history runs %d", n)
	}
	rec := httptest.NewRecorder()
	d.apiHandler().ServeHTTP(rec, httptest.NewRequest("GET", "/metrics", nil))
	if !strings.Contains(rec.Body.String(), "haetae_vrps 5") {
		t.Errorf("metrics:\n%s", rec.Body.String())
	}
}

func TestJSONDeltaTo(t *testing.T) {
	d := testDaemon(t) // serial 1 : +10.0.0.0/8, ASPA 64500 {174 13335} -> {174}
	ps3 := testSet([]vrpKey{vk(13335, "1.1.1.0/24", 24, "apnic")}, nil)
	d.st.update(ps3) // serial 2 : 많이 빠지고 ASPA 64500 없어짐
	h := d.apiHandler()

	// serial 0 -> 1 만 : 10/8 추가, ASPA 는 1 시점 값 {174}
	_, m := get(t, h, "GET", "/json-delta?session=7&serial=0&to=1", "")
	if m["serial"].(float64) != 1 || m["reset"] != false {
		t.Fatalf("to=1: %v", m)
	}
	var aspa map[string]any
	for _, x := range m["announced"].([]any) {
		if e := x.(map[string]any); e["type"] == "aspa" {
			aspa = e
		}
	}
	if aspa == nil || len(aspa["providers"].([]any)) != 1 {
		t.Errorf("aspa at 1: %v", aspa)
	}
	// 1 -> 2 : ASPA 64500 withdrawn
	_, m = get(t, h, "GET", "/json-delta?session=7&serial=1&to=2", "")
	found := false
	for _, x := range m["withdrawn"].([]any) {
		if e := x.(map[string]any); e["type"] == "aspa" {
			found = true
		}
	}
	if !found {
		t.Errorf("aspa withdraw missing: %v", m["withdrawn"])
	}
	if code, _ := get(t, h, "GET", "/json-delta?session=7&serial=5&to=1", ""); code != 404 {
		t.Errorf("bad range code %d", code)
	}
	if code, _ := get(t, h, "GET", "/json-delta?to=9", ""); code != 400 {
		t.Errorf("to > serial code %d", code)
	}
}

func TestSaveLoadDeltas(t *testing.T) {
	d := testDaemon(t)
	p := d.cfg.StateDir + "/deltas.gob"
	if err := saveDeltas(p, d.st); err != nil {
		t.Fatal(err)
	}
	hist, err := loadDeltas(p, 7, 1)
	if err != nil || len(hist) != 1 || len(hist[0].AnnVRP) != 1 {
		t.Fatalf("load: %v %v", hist, err)
	}
	if _, err := loadDeltas(p, 8, 1); err == nil {
		t.Error("other session accepted")
	}
}
