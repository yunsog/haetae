// SPDX-License-Identifier: Apache-2.0

package main

// constraints.go : TA constraints (draft-ietf-sidrops-constraining-rpki-trust-anchors-02, 0.4.0)
//
// 설정 paths.constraints (옵션 -constraints) = 폴더. 빈 값 = 끔 (기본).
// 폴더의 <TAL 이름>.constraints (예 apnic.constraints) 가 그 TA 아래 EE 인증서의 자원을 좁힘. 파일이 없는 TA 는 검사 안 함.
// OpenBSD (rpki-client) 가 배포하는 파일을 그대로 쓸 수 있음. 파일은 할당이 바뀌면 따라 고쳐야 함 (오래된 파일 = 정상 객체 거부)
//
// 파일 모양 (한 줄에 하나, # 뒤는 주석)
//   allow 2001:200::/23            prefix
//   allow 27648 - 28671            AS 범위 (양 끝 포함, 작은 것 먼저)
//   deny  192.0.2.0 - 192.0.2.127  주소 범위
//   deny  64500                    AS 하나
//
// 검사 (rpki-client 9.9 constraints.c 와 같게)
//   - 대상 = ROA / ASPA / SPL 의 EE 인증서, BGPsec 라우터 인증서. EE 에 적힌 자원만 (inherit 는 검사 안 함)
//   - deny 와 조금이라도 겹치면 거부
//   - allow 가 하나라도 있으면 (IP 와 AS 따로) allow 하나 (붙거나 겹친 항목은 합친 것) 안에 다 들어가야 함
//     = allow 에 없는 주소 체계 / AS 는 거부 (draft 의 암묵적 deny). allow 가 하나도 없으면 deny 만 봄
//   - 파일에 틀린 줄이 있으면 그 파일 전체를 쓰지 않음 (draft 4 절, 경고). rpki-client 는 이때 프로그램을 멈춤

import (
	"bufio"
	"bytes"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// maxConstraintLines : 파일 하나의 줄 수 상한 (지금 OpenBSD 파일 = 가장 큰 것 약 1,000 줄)
const maxConstraintLines = 100000

// taConstraints : TA 하나의 constraints (범위는 정렬 + 붙은 것 합침)
type taConstraints struct {
	File                     string
	AllowV4, AllowV6         []ipRange
	DenyV4, DenyV6           []ipRange
	AllowAS, DenyAS          []asRange
	HaveAllowIP, HaveAllowAS bool
}

// loadConstraints : 폴더에서 TAL 마다 <이름>.constraints 를 읽음. dir 빈 값 = 끔 (nil)
// 돌려주는 것 : TA 이름 -> constraints, 쓰지 못한 파일의 오류 목록 (그 TA 는 검사 안 함)
// 폴더 자체를 못 읽으면 err (설정 오류)
func loadConstraints(dir string, tals []*tal) (map[string]*taConstraints, []error, error) {
	if dir == "" {
		return nil, nil, nil
	}
	if st, err := os.Stat(dir); err != nil {
		return nil, nil, err
	} else if !st.IsDir() {
		return nil, nil, fmt.Errorf("%s: not a directory", dir)
	}
	out := map[string]*taConstraints{}
	var bad []error
	for _, t := range tals {
		p := filepath.Join(dir, t.Name+".constraints")
		data, err := os.ReadFile(p)
		if os.IsNotExist(err) {
			continue
		}
		if err == nil {
			var c *taConstraints
			if c, err = parseConstraints(data); err == nil {
				c.File = filepath.Base(p)
				out[t.Name] = c
				continue
			}
		}
		bad = append(bad, fmt.Errorf("%s: %v", p, err))
	}
	return out, bad, nil
}

// parseConstraints : 파일 내용 -> constraints. 틀린 줄이 하나라도 있으면 오류 (줄 번호)
func parseConstraints(data []byte) (*taConstraints, error) {
	c := &taConstraints{}
	sc := bufio.NewScanner(bytes.NewReader(data))
	n := 0
	for sc.Scan() {
		n++
		if n > maxConstraintLines {
			return nil, fmt.Errorf("more than %d lines", maxConstraintLines)
		}
		line := sc.Text()
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = line[:i]
		}
		f := strings.Fields(line)
		if len(f) == 0 {
			continue
		}
		if err := c.addLine(f[0], strings.Join(f[1:], " ")); err != nil {
			return nil, fmt.Errorf("line %d: %v", n, err)
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	// 같은 쪽 (allow 끼리, deny 끼리) 겹침 = 오류 (draft 4 절), 붙은 것은 합침
	var err error
	for _, x := range []struct {
		rs *[]ipRange
		v4 bool
	}{{&c.AllowV4, true}, {&c.AllowV6, false}, {&c.DenyV4, true}, {&c.DenyV6, false}} {
		if *x.rs, err = mergeIPRanges(*x.rs, x.v4); err != nil {
			return nil, err
		}
	}
	for _, rs := range []*[]asRange{&c.AllowAS, &c.DenyAS} {
		if *rs, err = mergeASRanges(*rs); err != nil {
			return nil, err
		}
	}
	return c, nil
}

// addLine : "allow" / "deny" + 자원 하나. 자원 종류 = '.' 있으면 IPv4, ':' 있으면 IPv6, 아니면 AS (rpki-client 와 같은 판정)
func (c *taConstraints) addLine(kw, res string) error {
	if kw != "allow" && kw != "deny" {
		return fmt.Errorf("unknown keyword %q", kw)
	}
	if res == "" {
		return fmt.Errorf("%s without resource", kw)
	}
	allow := kw == "allow"
	switch {
	case strings.ContainsAny(res, ".:"):
		r, v4, err := parseIPResource(res)
		if err != nil {
			return err
		}
		switch {
		case allow && v4:
			c.AllowV4 = append(c.AllowV4, r)
		case allow:
			c.AllowV6 = append(c.AllowV6, r)
		case v4:
			c.DenyV4 = append(c.DenyV4, r)
		default:
			c.DenyV6 = append(c.DenyV6, r)
		}
		if allow {
			c.HaveAllowIP = true
		}
	default:
		r, err := parseASResource(res)
		if err != nil {
			return err
		}
		if allow {
			c.AllowAS = append(c.AllowAS, r)
			c.HaveAllowAS = true
		} else {
			c.DenyAS = append(c.DenyAS, r)
		}
	}
	return nil
}

// splitRange : "a - b" -> a, b (하이픈 둘레 공백은 있어도 없어도 됨). 하이픈이 없으면 ok = false
func splitRange(s string) (a, b string, ok bool) {
	i := strings.IndexByte(s, '-')
	if i < 0 {
		return s, "", false
	}
	return strings.TrimSpace(s[:i]), strings.TrimSpace(s[i+1:]), true
}

// parseIPResource : prefix 또는 주소 범위 -> ipRange (IPv4 는 앞 4 바이트, rfc3779.go 와 같은 모양)
func parseIPResource(s string) (ipRange, bool, error) {
	v4 := strings.Contains(s, ".")
	a, b, isRange := splitRange(s)
	if !isRange {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return ipRange{}, false, err
		}
		if p.Addr().Is4() != v4 || p.Addr().Zone() != "" {
			return ipRange{}, false, fmt.Errorf("bad prefix %q", s)
		}
		if p != p.Masked() {
			return ipRange{}, false, fmt.Errorf("prefix %q has host bits set", s)
		}
		return prefixRange(p), v4, nil
	}
	lo, err1 := netip.ParseAddr(a)
	hi, err2 := netip.ParseAddr(b)
	if err1 != nil || err2 != nil || lo.Is4() != v4 || hi.Is4() != v4 || lo.Zone() != "" || hi.Zone() != "" {
		return ipRange{}, false, fmt.Errorf("bad address range %q", s)
	}
	if hi.Less(lo) {
		return ipRange{}, false, fmt.Errorf("range %q: lower end point must come first", s)
	}
	var r ipRange
	copy(r.Min[:], lo.AsSlice())
	copy(r.Max[:], hi.AsSlice())
	return r, v4, nil
}

// parseASResource : AS 하나 또는 범위 (숫자만, "AS" 글자 없음)
func parseASResource(s string) (asRange, error) {
	a, b, isRange := splitRange(s)
	lo, err := strconv.ParseUint(a, 10, 32)
	if err != nil {
		return asRange{}, fmt.Errorf("bad AS %q", a)
	}
	hi := lo
	if isRange {
		if hi, err = strconv.ParseUint(b, 10, 32); err != nil {
			return asRange{}, fmt.Errorf("bad AS %q", b)
		}
		if hi < lo {
			return asRange{}, fmt.Errorf("AS range %q: lower end point must come first", s)
		}
	}
	return asRange{uint32(lo), uint32(hi)}, nil
}

// nextAddr : 범위 끝 다음 주소. n = 주소 바이트 수 (IPv4 4, IPv6 16, 앞 n 바이트만 셈). 끝 주소면 ok = false
func nextAddr(a [16]byte, n int) ([16]byte, bool) {
	for i := n - 1; i >= 0; i-- {
		a[i]++
		if a[i] != 0 {
			return a, true
		}
	}
	return a, false
}

// mergeIPRanges : 정렬하고 붙은 범위는 합침. 겹치면 오류 (ipCovered 는 정렬 + 겹침 없는 목록을 받음)
func mergeIPRanges(rs []ipRange, v4 bool) ([]ipRange, error) {
	n := 16
	if v4 {
		n = 4
	}
	sort.Slice(rs, func(i, j int) bool { return bytes.Compare(rs[i].Min[:], rs[j].Min[:]) < 0 })
	var out []ipRange
	for _, r := range rs {
		if len(out) > 0 {
			last := &out[len(out)-1]
			if bytes.Compare(r.Min[:], last.Max[:]) <= 0 {
				return nil, fmt.Errorf("overlapping entries %s and %s", rangeString(*last, v4), rangeString(r, v4))
			}
			if nx, ok := nextAddr(last.Max, n); ok && nx == r.Min {
				last.Max = r.Max
				continue
			}
		}
		out = append(out, r)
	}
	return out, nil
}

// mergeASRanges : 정렬하고 붙은 범위는 합침. 겹치면 오류
func mergeASRanges(rs []asRange) ([]asRange, error) {
	sort.Slice(rs, func(i, j int) bool { return rs[i].Min < rs[j].Min })
	var out []asRange
	for _, r := range rs {
		if len(out) > 0 {
			last := &out[len(out)-1]
			if r.Min <= last.Max {
				return nil, fmt.Errorf("overlapping entries %s and %s", asRangeString(*last), asRangeString(r))
			}
			if last.Max != ^uint32(0) && last.Max+1 == r.Min {
				last.Max = r.Max
				continue
			}
		}
		out = append(out, r)
	}
	return out, nil
}

// ipOverlaps : r 이 rs (정렬, 겹침 없음) 중 하나와 조금이라도 겹치는지
func ipOverlaps(rs []ipRange, r ipRange) bool {
	// Max 가 r.Min 이상인 첫 범위만 보면 됨
	i := sort.Search(len(rs), func(i int) bool { return bytes.Compare(rs[i].Max[:], r.Min[:]) >= 0 })
	return i < len(rs) && bytes.Compare(rs[i].Min[:], r.Max[:]) <= 0
}

// asOverlaps : r 이 rs 중 하나와 겹치는지
func asOverlaps(rs []asRange, r asRange) bool {
	i := sort.Search(len(rs), func(i int) bool { return rs[i].Max >= r.Min })
	return i < len(rs) && rs[i].Min <= r.Max
}

// check : EE 인증서 (또는 라우터 인증서) 에 적힌 자원이 constraints 안인지. nil 이면 검사 안 함
// 오류 메시지에 파일 이름을 넣어 rejects.txt 에서 원인을 바로 알게 함
func (c *taConstraints) check(ee *rpkiCert) error {
	if c == nil {
		return nil
	}
	as := ee.ASs
	if as.Present && !as.Inherit {
		for _, r := range as.Ranges {
			if asOverlaps(c.DenyAS, r) || (c.HaveAllowAS && !asCovered(c.AllowAS, r)) {
				return fmt.Errorf("resource violates %s: %s", c.File, asRangeString(r))
			}
		}
	}
	for _, f := range []struct {
		fam         ipFamily
		allow, deny []ipRange
		v4          bool
	}{{ee.IPs.V4, c.AllowV4, c.DenyV4, true}, {ee.IPs.V6, c.AllowV6, c.DenyV6, false}} {
		if !f.fam.Present || f.fam.Inherit {
			continue
		}
		for _, r := range f.fam.Ranges {
			if ipOverlaps(f.deny, r) || (c.HaveAllowIP && !ipCovered(f.allow, r)) {
				return fmt.Errorf("resource violates %s: %s", c.File, rangeString(r, f.v4))
			}
		}
	}
	return nil
}

// useConstraints : 회차 / -validate 시작 때 constraints 를 읽어 v 에 넣음. 쓰지 못한 파일은 경고 (그 TA 는 검사 안 함).
// 폴더를 못 읽으면 오류 (부르는 쪽이 회차를 건너뛰거나 멈춤)
func (v *validator) useConstraints(dir string, tals []*tal) error {
	cs, bad, err := loadConstraints(dir, tals)
	if err != nil {
		return fmt.Errorf("constraints: %v", err)
	}
	v.Constraints = cs
	for _, e := range bad {
		v.warn("constraints file rejected (not used)", e.Error())
	}
	return nil
}

// constraintsSummary : 로그용 "apnic.constraints, ripe.constraints" (끔이면 "off")
func constraintsSummary(cs map[string]*taConstraints) string {
	if cs == nil {
		return "off"
	}
	var names []string
	for _, c := range cs {
		names = append(names, c.File)
	}
	sort.Strings(names)
	if len(names) == 0 {
		return "on, no files"
	}
	return strings.Join(names, ", ")
}

// asRangeString : "AS64500" 또는 "AS64496-AS64511"
func asRangeString(r asRange) string {
	if r.Min == r.Max {
		return fmt.Sprintf("AS%d", r.Min)
	}
	return fmt.Sprintf("AS%d-AS%d", r.Min, r.Max)
}
