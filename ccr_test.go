// SPDX-License-Identifier: Apache-2.0

package main

// ccr_test.go : CCR 의 DER 쓰기 (go test). 전체 모양은 스냅샷에서 rpki-client 9.9 의 rpki.ccr 와 cmp (docs/manual.md 7 장)

import (
	"bytes"
	"math/big"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"
)

func TestDerWrite(t *testing.T) {
	cases := map[string]struct{ got, want []byte }{
		"int 0":       {derInteger(big.NewInt(0)), []byte{0x02, 0x01, 0x00}},
		"int 128":     {derInteger(big.NewInt(128)), []byte{0x02, 0x02, 0x00, 0x80}},
		"uint32 max":  {derUint32(4294967295), []byte{0x02, 0x05, 0x00, 0xff, 0xff, 0xff, 0xff}},
		"prefix /0":   {derPrefixBits(netip.MustParsePrefix("0.0.0.0/0")), []byte{0x03, 0x01, 0x00}},
		"prefix /20":  {derPrefixBits(netip.MustParsePrefix("10.16.0.0/20")), []byte{0x03, 0x04, 0x04, 10, 16, 0}},
		"prefix /24":  {derPrefixBits(netip.MustParsePrefix("192.0.2.0/24")), []byte{0x03, 0x04, 0x00, 192, 0, 2}},
		"gentime":     {derGenTime(time.Unix(1793285077, 0)), append([]byte{0x18, 15}, "20261029144437Z"...)},
		"long length": {derOctet(make([]byte, 200))[:3], []byte{0x04, 0x81, 200}},
	}
	for name, c := range cases {
		if !bytes.Equal(c.got, c.want) {
			t.Errorf("%s: % x, want % x", name, c.got, c.want)
		}
	}
}

// TestCCRRead : 만든 CCR 을 der.go 로 다시 읽어 모양과 칸별 해시를 확인
func TestCCRRead(t *testing.T) {
	v := newValidator("", time.Unix(1793285077, 0), 1)
	v.vrps[vrpKey{64496, netip.MustParsePrefix("192.0.2.0/24"), 24, "a"}] = time.Now()
	v.vrps[vrpKey{64496, netip.MustParsePrefix("192.0.2.0/24"), 24, "b"}] = time.Now() // TA 만 다름 = 하나
	v.vrps[vrpKey{64496, netip.MustParsePrefix("2001:db8::/32"), 48, "a"}] = time.Now()
	v.aspas[aspaKey{64496, "a"}] = &aspaOut{Providers: map[uint32]bool{64511: true, 64500: true}}
	der, hs := v.buildCCR()

	ci, err := derOne(der)
	if err != nil {
		t.Fatal(err)
	}
	top, err := derSeq(ci, 2, 2)
	if err != nil {
		t.Fatal(err)
	}
	if o, _ := derOIDOf(top[0]); !o.Equal(oidCTCCR) {
		t.Fatalf("content type %v", o)
	}
	inner, _ := derChildren(top[1], 1)
	f, err := derSeq(inner[0], 7, 7) // hashAlg, producedAt, [1]..[5] (version 은 뺌)
	if err != nil {
		t.Fatal(err)
	}
	if !f[2].isCtx(1) || !f[6].isCtx(5) {
		t.Errorf("state tags")
	}
	// [2] vrps : AS 하나, 주소 체계 둘 (IPv4 의 maxLength 는 뺌, IPv6 은 48)
	st, _ := derChildren(f[3], 1)
	vs, _ := derSeq(st[0], 2, 2)
	sets, _ := derChildren(vs[0], 10)
	if len(sets) != 1 {
		t.Fatalf("ROAPayloadSet %d", len(sets))
	}
	if hs.VRPs == "" || hs.Mfts == "" || hs.RKs == "" {
		t.Errorf("hashes %+v", hs)
	}
	// 같은 입력 = 같은 결과
	der2, _ := v.buildCCR()
	if !bytes.Equal(der, der2) {
		t.Errorf("not deterministic")
	}
}

// TestMergedProviders : AS 0 은 다른 provider 와 함께면 빠짐 (aspa-profile-31 5.2, 실제 예 AS59182)
func TestMergedProviders(t *testing.T) {
	cases := []struct {
		in   []uint32
		want []uint32
	}{
		{[]uint32{0}, []uint32{0}},
		{[]uint32{0, 9885, 55824}, []uint32{9885, 55824}},
		{[]uint32{55824, 9885}, []uint32{9885, 55824}},
	}
	for _, c := range cases {
		m := map[uint32]bool{}
		for _, x := range c.in {
			m[x] = true
		}
		if got := mergedProviders(m); !slices.Equal(got, c.want) {
			t.Errorf("%v -> %v, want %v", c.in, got, c.want)
		}
	}
}

// TestArchiveCCR : daily 는 하루 하나, hourly 는 한 시간 하나, cycle 은 매번, keep 지난 것은 지움
func TestArchiveCCR(t *testing.T) {
	der := []byte{0x30, 0x00}
	count := func(dir string) int {
		n := 0
		days, _ := os.ReadDir(dir)
		for _, d := range days {
			fs, _ := os.ReadDir(filepath.Join(dir, d.Name()))
			n += len(fs)
		}
		return n
	}
	base := time.Date(2026, 11, 18, 1, 0, 0, 0, time.UTC)
	for _, c := range []struct {
		mode string
		want int // 01:00, 01:10, 02:00, 다음 날 01:00 에 네 번 부른 뒤 (keep 없음)
	}{{"daily", 2}, {"hourly", 3}, {"cycle", 4}, {"latest", 0}, {"off", 0}} {
		dir := t.TempDir()
		for _, at := range []time.Duration{0, 10 * time.Minute, time.Hour, 24 * time.Hour} {
			if err := archiveCCR(dir, der, c.mode, 0, base.Add(at)); err != nil {
				t.Fatal(err)
			}
		}
		if n := count(dir); n != c.want {
			t.Errorf("%s: %d files, want %d", c.mode, n, c.want)
		}
	}
	// keep 1 일 : 3 일 전 것은 지워지고 빈 날짜 폴더도 없어짐
	dir := t.TempDir()
	archiveCCR(dir, der, "cycle", 0, base.Add(-72*time.Hour))
	archiveCCR(dir, der, "cycle", 24*time.Hour, base)
	if n := count(dir); n != 1 {
		t.Errorf("keep: %d files, want 1", n)
	}
	if _, err := os.Stat(filepath.Join(dir, base.Add(-72*time.Hour).Format("20060102"))); !os.IsNotExist(err) {
		t.Errorf("old day dir left: %v", err)
	}
	if !validCCRMode("hourly") || validCCRMode("weekly") {
		t.Errorf("validCCRMode")
	}
}
