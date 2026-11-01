package main

// der_test.go : 잘못된 DER 을 거부하는지 (go test)

import (
	"net/netip"
	"testing"
)

func TestDerReject(t *testing.T) {
	bad := map[string][]byte{
		"short":            {0x30},
		"indefinite":       {0x30, 0x80, 0x00, 0x00},
		"non-minimal len":  {0x04, 0x81, 0x01, 0xaa},
		"len leading zero": {0x04, 0x82, 0x00, 0x80},
		"len too big":      {0x04, 0x05, 0x01},
		"multi-byte tag":   {0x1f, 0x81, 0x01, 0x00},
		"trailing":         {0x05, 0x00, 0x00},
	}
	for name, b := range bad {
		if _, err := derOne(b); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestDerInt(t *testing.T) {
	ok := map[string]struct {
		b []byte
		v uint64
	}{
		"zero":  {[]byte{0x02, 0x01, 0x00}, 0},
		"128":   {[]byte{0x02, 0x02, 0x00, 0x80}, 128},
		"65537": {[]byte{0x02, 0x03, 0x01, 0x00, 0x01}, 65537},
	}
	for name, c := range ok {
		n, err := derOne(c.b)
		if err != nil {
			t.Fatal(name, err)
		}
		v, err := derUint(n, 1<<32)
		if err != nil || v != c.v {
			t.Errorf("%s: got %d %v", name, v, err)
		}
	}
	bad := map[string][]byte{
		"non-minimal": {0x02, 0x02, 0x00, 0x01},
		"negative":    {0x02, 0x01, 0xff},
		"empty":       {0x02, 0x00},
	}
	for name, b := range bad {
		n, err := derOne(b)
		if err != nil {
			continue
		}
		if _, err := derUint(n, 1<<32); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestDerBits(t *testing.T) {
	// 10.0.0.0/8 = 03 02 00 0a,  10.0.0.0/7 의 잘못된 padding = 03 02 01 0b
	n, _ := derOne([]byte{0x03, 0x02, 0x00, 0x0a})
	if b, u, err := derBits(n); err != nil || u != 0 || len(b) != 1 {
		t.Errorf("good bits: %v %d %v", b, u, err)
	}
	n, _ = derOne([]byte{0x03, 0x02, 0x01, 0x0b})
	if _, _, err := derBits(n); err == nil {
		t.Errorf("non-zero padding accepted")
	}
}

func TestPrefixRangeCovered(t *testing.T) {
	// 부모 10.0.0.0/8 이 자식 10.1.0.0/16 을 포함, 11.0.0.0/8 은 불포함
	parent := []ipRange{rangeOf(t, "10.0.0.0/8")}
	if !ipCovered(parent, rangeOf(t, "10.1.0.0/16")) {
		t.Error("10.1.0.0/16 not covered")
	}
	if ipCovered(parent, rangeOf(t, "11.0.0.0/8")) {
		t.Error("11.0.0.0/8 covered")
	}
}

func rangeOf(t *testing.T, s string) ipRange {
	p, err := netip.ParsePrefix(s)
	if err != nil {
		t.Fatal(err)
	}
	return prefixRange(p)
}
