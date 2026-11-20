// SPDX-License-Identifier: Apache-2.0

package main

// constraints_test.go : TA constraints 파일 읽기 / 검사 (go test). 실제 파일과의 대조는 스냅샷 (docs/manual.md 7 장)

import (
	"strings"
	"testing"
)

const consSample = `# draft-ietf-sidrops-constraining-rpki-trust-anchors-02 4 절 예
allow 10.0.0.0/8      # comments may follow entries
allow 192.168.0.0/16
deny 192.168.1.0/24
allow 100.64.0.0 - 100.127.255.254
allow 3fff::/20
deny 3fff::/48
allow 64496 - 64511
deny 64500
allow 65536
`

// eeOf : 시험용 EE (적힌 자원만)
func eeOf(t *testing.T, prefixes []string, ases ...asRange) *rpkiCert {
	c := &rpkiCert{}
	for _, p := range prefixes {
		r := rangeOf(t, p)
		if strings.Contains(p, ":") {
			c.IPs.V6.Present = true
			c.IPs.V6.Ranges = append(c.IPs.V6.Ranges, r)
		} else {
			c.IPs.V4.Present = true
			c.IPs.V4.Ranges = append(c.IPs.V4.Ranges, r)
		}
	}
	if len(ases) > 0 {
		c.ASs = asResources{Present: true, Ranges: ases}
	}
	return c
}

func TestConstraintsCheck(t *testing.T) {
	c, err := parseConstraints([]byte(consSample))
	if err != nil {
		t.Fatal(err)
	}
	c.File = "x.constraints"
	cases := []struct {
		name string
		ee   *rpkiCert
		ok   bool
	}{
		{"inside allow", eeOf(t, []string{"10.1.0.0/16"}), true},
		{"outside allow", eeOf(t, []string{"11.0.0.0/16"}), false},
		{"inside deny hole", eeOf(t, []string{"192.168.1.0/25"}), false},
		{"overlaps deny", eeOf(t, []string{"192.168.0.0/23"}), false},
		{"beside deny", eeOf(t, []string{"192.168.2.0/24"}), true},
		{"range end", eeOf(t, []string{"100.127.255.0/25"}), true},
		{"past range end", eeOf(t, []string{"100.127.255.0/24"}), false},
		{"ipv6 ok", eeOf(t, []string{"3fff:0:1::/48"}), true},
		{"ipv6 deny", eeOf(t, []string{"3fff::/56"}), false},
		{"as ok", eeOf(t, nil, asRange{64496, 64499}), true},
		{"as deny", eeOf(t, nil, asRange{64500, 64500}), false},
		{"as range over deny", eeOf(t, nil, asRange{64496, 64511}), false},
		{"as single", eeOf(t, nil, asRange{65536, 65536}), true},
		{"as outside", eeOf(t, nil, asRange{65537, 65537}), false},
	}
	for _, x := range cases {
		err := c.check(x.ee)
		if (err == nil) != x.ok {
			t.Errorf("%s: err = %v, want ok %v", x.name, err, x.ok)
		}
	}
	// inherit 는 검사 안 함
	in := &rpkiCert{}
	in.IPs.V4 = ipFamily{Present: true, Inherit: true}
	in.ASs = asResources{Present: true, Inherit: true}
	if err := c.check(in); err != nil {
		t.Errorf("inherit: %v", err)
	}
	// 끔 (nil) = 늘 통과
	var off *taConstraints
	if err := off.check(eeOf(t, []string{"11.0.0.0/8"})); err != nil {
		t.Errorf("nil constraints: %v", err)
	}
}

func TestConstraintsAllowMissing(t *testing.T) {
	// allow 가 IP 만 있으면 AS 는 deny 만 봄, IPv6 allow 가 없으면 IPv6 는 거부 (암묵적 deny)
	c, err := parseConstraints([]byte("allow 10.0.0.0/8\ndeny 64500\n"))
	if err != nil {
		t.Fatal(err)
	}
	if err := c.check(eeOf(t, nil, asRange{65000, 65000})); err != nil {
		t.Errorf("AS without allow list: %v", err)
	}
	if err := c.check(eeOf(t, nil, asRange{64500, 64500})); err == nil {
		t.Errorf("AS in deny accepted")
	}
	if err := c.check(eeOf(t, []string{"2001:db8::/32"})); err == nil {
		t.Errorf("IPv6 without IPv6 allow accepted")
	}
}

func TestConstraintsMerge(t *testing.T) {
	// 붙은 allow 두 개를 합쳐 둘에 걸친 자원도 통과 (rpki-client 의 canonize 와 같음)
	c, err := parseConstraints([]byte("allow 10.0.0.0/9\nallow 10.128.0.0/9\nallow 64496 - 64499\nallow 64500 - 64511\n"))
	if err != nil {
		t.Fatal(err)
	}
	if err := c.check(eeOf(t, []string{"10.0.0.0/8"}, asRange{64496, 64511})); err != nil {
		t.Errorf("adjacent entries: %v", err)
	}
}

func TestConstraintsBadFile(t *testing.T) {
	bad := map[string]string{
		"keyword":      "permit 10.0.0.0/8\n",
		"no resource":  "allow\n",
		"host bits":    "allow 10.0.0.1/8\n",
		"reverse":      "allow 10.0.0.9 - 10.0.0.1\n",
		"mixed family": "allow 10.0.0.1 - 2001:db8::1\n",
		"bad AS":       "allow AS64500\n",
		"AS reverse":   "allow 64511 - 64496\n",
		"overlap":      "allow 10.0.0.0/8\nallow 10.1.0.0/16\n",
		"deny overlap": "deny 64496 - 64500\ndeny 64500\n",
		"v6 overlap":   "allow 2001:db8::/32\nallow 2001:db8:1::/48\n",
	}
	for name, s := range bad {
		if _, err := parseConstraints([]byte(s)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// IPv6 끝이 0 인 주소를 IPv4 처럼 셈하지 않음 (붙은 판정)
	if _, err := parseConstraints([]byte("allow 2001:db8::/48\nallow 2001:db8:1::/48\n")); err != nil {
		t.Errorf("ipv6 adjacent: %v", err)
	}
}
