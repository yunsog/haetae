// SPDX-License-Identifier: Apache-2.0

package main

// slurm_test.go : SLURM 빼기 / 더하기

import (
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestSLURM(t *testing.T) {
	p := filepath.Join(t.TempDir(), "slurm.json")
	os.WriteFile(p, []byte(`{
 "slurmVersion": 2,
 "validationOutputFilters": {
  "prefixFilters": [ {"prefix": "10.0.0.0/8", "comment": "10/8 아래 전부"}, {"asn": 64496} ],
  "bgpsecFilters": [],
  "aspaFilters": [ {"customerAsn": 64499} ]
 },
 "locallyAddedAssertions": {
  "prefixAssertions": [ {"asn": 64500, "prefix": "198.51.100.0/24", "maxPrefixLength": 24} ],
  "bgpsecAssertions": [],
  "aspaAssertions": [ {"customerAsn": 64500, "providerAsns": [64501]} ]
 }
}`), 0644)
	s, err := loadSLURM(p)
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		asn  uint32
		pfx  string
		drop bool
	}{
		{1, "10.1.0.0/16", true}, // 10/8 안
		{1, "10.0.0.0/8", true},  // 같음
		{1, "8.0.0.0/6", false},  // 10/8 보다 넓음 -> 해당 안 됨
		{64496, "192.0.2.0/24", true},
		{2, "192.0.2.0/24", false},
	}
	for _, c := range cases {
		if got := s.filterVRP(c.asn, netip.MustParsePrefix(c.pfx)); got != c.drop {
			t.Errorf("filter AS%d %s = %v", c.asn, c.pfx, got)
		}
	}
	ps := &payloadSet{VRPs: map[rtrVRP]bool{}, Keys: map[rtrKey]bool{}, ASPAs: map[uint32][]uint32{},
		FullExp: map[vrpKey]time.Time{}, Built: time.Now()}
	s.addAssertions(ps)
	if !ps.VRPs[rtrVRP{netip.MustParsePrefix("198.51.100.0/24"), 24, 64500}] {
		t.Error("assertion not added")
	}
	if got := ps.ASPAs[64500]; len(got) != 1 || got[0] != 64501 {
		t.Errorf("aspa assertion %v", got)
	}
	if !s.filterASPA(64499) || s.filterASPA(64500) {
		t.Error("aspa filter")
	}
}

// aspa-slurm-04 : 판과 aspa* 키, providerAsns 규칙
func TestSLURMASPAVersion(t *testing.T) {
	const empty = `"prefixFilters": [], "bgpsecFilters": []`
	const emptyA = `"prefixAssertions": [], "bgpsecAssertions": []`
	cases := []struct {
		name, body string
		ok         bool
	}{
		{"v1 plain", `{"slurmVersion": 1, "validationOutputFilters": {` + empty + `}, "locallyAddedAssertions": {` + emptyA + `}}`, true},
		{"v1 with aspa", `{"slurmVersion": 1, "validationOutputFilters": {` + empty + `, "aspaFilters": []}, "locallyAddedAssertions": {` + emptyA + `}}`, false},
		{"v2 empty aspa", `{"slurmVersion": 2, "validationOutputFilters": {` + empty + `, "aspaFilters": []}, "locallyAddedAssertions": {` + emptyA + `, "aspaAssertions": []}}`, true},
		{"v2 missing aspa", `{"slurmVersion": 2, "validationOutputFilters": {` + empty + `}, "locallyAddedAssertions": {` + emptyA + `}}`, false},
		{"v2 customer in providers", `{"slurmVersion": 2, "validationOutputFilters": {` + empty + `, "aspaFilters": []}, "locallyAddedAssertions": {` + emptyA + `, "aspaAssertions": [{"customerAsn": 1, "providerAsns": [1, 2]}]}}`, false},
		{"v2 not ascending", `{"slurmVersion": 2, "validationOutputFilters": {` + empty + `, "aspaFilters": []}, "locallyAddedAssertions": {` + emptyA + `, "aspaAssertions": [{"customerAsn": 1, "providerAsns": [3, 2]}]}}`, false},
		{"v2 old key names", `{"slurmVersion": 2, "validationOutputFilters": {` + empty + `, "aspaFilters": [{"customer_asid": 1}]}, "locallyAddedAssertions": {` + emptyA + `, "aspaAssertions": []}}`, false},
		{"v3", `{"slurmVersion": 3, "validationOutputFilters": {` + empty + `}, "locallyAddedAssertions": {` + emptyA + `}}`, false},
	}
	for _, c := range cases {
		p := filepath.Join(t.TempDir(), "s.json")
		os.WriteFile(p, []byte(c.body), 0644)
		if _, err := loadSLURM(p); (err == nil) != c.ok {
			t.Errorf("%s: err %v", c.name, err)
		}
	}
}
