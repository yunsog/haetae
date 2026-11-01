package main

// aspa_verify_test.go : ASPA 경로 검증 (오르막 / 내리막, 앞 단계, API)

import (
	"testing"
)

func TestASPAVerify(t *testing.T) {
	// 64501 -> 64502 -> 64503 (고객 -> provider), 64520 은 64502 의 고객, 64503 은 provider 없음 (AS 0)
	aspas := map[uint32][]uint32{
		64501: {64502},
		64502: {64503},
		64520: {64502},
		64503: {0},
	}
	cases := []struct {
		path     string
		neighbor uint32
		up, down string
	}{
		{"64503 64502 64501", 64503, "valid", "valid"},         // 올라가기만
		{"64503 64503 64502 64501 64501", 0, "valid", "valid"}, // prepend 합침
		{"64502 64501 64504", 0, "unknown", "unknown"},         // origin 64504 ASPA 없음
		{"64503 64501 64502", 0, "invalid", "invalid"},         // 64502 가 64501 을 provider 로 (leak)
		{"64510 64502 64501", 64510, "invalid", "valid"},       // provider 64510 에게서 받음 (꼭대기 peer)
		{"64503 64520 64502 64501", 0, "invalid", "invalid"},   // 계곡 : 내려갔다 다시 올라감
		{"64502 64501", 64999, "invalid", "invalid"},           // 이웃 불일치
		{"64502 {1 2} 64501", 0, "invalid", "invalid"},         // AS_SET
		{"", 0, "invalid", "invalid"},                          // 빈 경로
		{"64501", 64501, "valid", "valid"},                     // origin 하나
		{"64520 64502 64501", 0, "invalid", "valid"},           // 64502 -> 고객 64520 으로 내려옴
	}
	for _, c := range cases {
		path, set, err := parseASPath(c.path)
		if err != nil {
			t.Fatalf("%q: %v", c.path, err)
		}
		v := aspaVerify(aspas, path, set, c.neighbor)
		if v.Upstream.State != c.up || v.Downstream.State != c.down {
			t.Errorf("%q: up %s (%s) down %s (%s), want %s / %s  ramps %d %d %d %d",
				c.path, v.Upstream.State, v.Upstream.Reason, v.Downstream.State, v.Downstream.Reason, c.up, c.down,
				v.MaxUpRamp, v.MinUpRamp, v.MaxDownRamp, v.MinDownRamp)
		}
	}
	for _, bad := range []string{"64500 {1", "64500 }", "{1 {2}}", "AS-1", "4294967296"} {
		if _, _, err := parseASPath(bad); err == nil {
			t.Errorf("%q: want error", bad)
		}
	}
}

func TestASPAVerifyAPI(t *testing.T) {
	d := testDaemon(t) // 지금 집합 : 64500 -> {174}
	h := d.apiHandler()
	code, m := get(t, h, "GET", "/api/v1/aspa/verify?path=174+64500&neighbor=AS174", "")
	if code != 200 {
		t.Fatalf("code %d", code)
	}
	res := m["result"].(map[string]any)
	if res["upstream"].(map[string]any)["state"] != "valid" {
		t.Errorf("upstream: %v", res)
	}
}
