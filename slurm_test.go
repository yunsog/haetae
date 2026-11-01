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
 "slurmVersion": 1,
 "validationOutputFilters": {
  "prefixFilters": [ {"prefix": "10.0.0.0/8", "comment": "10/8 아래 전부"}, {"asn": 64496} ],
  "bgpsecFilters": []
 },
 "locallyAddedAssertions": {
  "prefixAssertions": [ {"asn": 64500, "prefix": "198.51.100.0/24", "maxPrefixLength": 24} ],
  "bgpsecAssertions": [],
  "aspaAssertions": [ {"customer_asid": 64500, "provider_set": [64501, 64500]} ]
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
		t.Errorf("aspa assertion %v (customer 자신은 빠져야 함)", got)
	}
}
