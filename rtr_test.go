package main

// rtr_test.go : RTR 서버를 띄우고 작은 클라이언트로 주고받기 확인

import (
	"encoding/binary"
	"io"
	"log"
	"net"
	"net/netip"
	"testing"
	"time"
)

func mkSet(vrps []rtrVRP, aspa map[uint32][]uint32) *payloadSet {
	p := &payloadSet{VRPs: map[rtrVRP]bool{}, Keys: map[rtrKey]bool{}, ASPAs: map[uint32][]uint32{}}
	for _, v := range vrps {
		p.VRPs[v] = true
	}
	for c, ps := range aspa {
		p.ASPAs[c] = ps
	}
	return p
}

func vr(s string, ml uint8, asn uint32) rtrVRP {
	return rtrVRP{netip.MustParsePrefix(s), ml, asn}
}

// pdu : 받은 PDU 하나
type pdu struct {
	ver, typ uint8
	field    uint16
	body     []byte
}

func readPDU(t *testing.T, c net.Conn) pdu {
	t.Helper()
	c.SetReadDeadline(time.Now().Add(3 * time.Second))
	h := make([]byte, 8)
	if _, err := io.ReadFull(c, h); err != nil {
		t.Fatalf("read: %v", err)
	}
	b := make([]byte, binary.BigEndian.Uint32(h[4:])-8)
	if _, err := io.ReadFull(c, b); err != nil {
		t.Fatalf("read body: %v", err)
	}
	return pdu{h[0], h[1], binary.BigEndian.Uint16(h[2:]), b}
}

// readUntilEOD : Cache Response ~ End of Data 사이의 PDU 를 종류별로 셈
func readUntilEOD(t *testing.T, c net.Conn) map[uint8]int {
	t.Helper()
	n := map[uint8]int{}
	for {
		p := readPDU(t, c)
		n[p.typ]++
		if p.typ == pduEndOfData || p.typ == pduCacheReset || p.typ == pduErrorReport {
			return n
		}
	}
}

func query(ver, typ uint8, ses uint16, serial *uint32) []byte {
	l := 8
	if serial != nil {
		l = 12
	}
	b := make([]byte, l)
	b[0], b[1] = ver, typ
	binary.BigEndian.PutUint16(b[2:], ses)
	binary.BigEndian.PutUint32(b[4:], uint32(l))
	if serial != nil {
		binary.BigEndian.PutUint32(b[8:], *serial)
	}
	return b
}

func TestRTR(t *testing.T) {
	st := &store{Session: 77}
	st.update(mkSet([]rtrVRP{vr("10.0.0.0/8", 24, 65001), vr("2001:db8::/32", 48, 65002)},
		map[uint32][]uint32{65001: {174, 3356}}))

	srv := &rtrServer{St: st, Refresh: 600, Retry: 300, Expire: 7200, Logf: log.Printf,
		Allow: []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go srv.serve(ln)

	// v2 Reset Query : prefix 2 + ASPA 1
	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.Write(query(2, pduResetQuery, 0, nil))
	n := readUntilEOD(t, c)
	if n[pduCacheResp] != 1 || n[pduIPv4Prefix] != 1 || n[pduIPv6Prefix] != 1 || n[pduASPA] != 1 || n[pduEndOfData] != 1 {
		t.Fatalf("reset: %v", n)
	}

	// 바뀜 : 10/8 빠지고 192.0.2.0/24 들어옴, ASPA provider 바뀜 -> Notify
	st.update(mkSet([]rtrVRP{vr("192.0.2.0/24", 24, 65003), vr("2001:db8::/32", 48, 65002)},
		map[uint32][]uint32{65001: {174}}))
	p := readPDU(t, c)
	if p.typ != pduSerialNotify || binary.BigEndian.Uint32(p.body) != 1 {
		t.Fatalf("notify: %+v", p)
	}
	ser := uint32(0)
	c.Write(query(2, pduSerialQuery, 77, &ser))
	n = readUntilEOD(t, c)
	if n[pduIPv4Prefix] != 2 || n[pduIPv6Prefix] != 0 || n[pduASPA] != 1 {
		t.Fatalf("serial query: %v", n)
	}

	// 모르는 serial -> Cache Reset
	old := uint32(12345)
	c.Write(query(2, pduSerialQuery, 77, &old))
	if n = readUntilEOD(t, c); n[pduCacheReset] != 1 {
		t.Fatalf("unknown serial: %v", n)
	}

	// 버전 3 -> Error 4 (우리 최고 버전 2 로)
	c2, _ := net.Dial("tcp", ln.Addr().String())
	defer c2.Close()
	c2.Write(query(3, pduResetQuery, 0, nil))
	p = readPDU(t, c2)
	if p.typ != pduErrorReport || p.field != errUnsupportedVer || p.ver != 2 {
		t.Fatalf("version 3: %+v", p)
	}

	// v0 : prefix 만, End of Data 12 바이트
	c3, _ := net.Dial("tcp", ln.Addr().String())
	defer c3.Close()
	c3.Write(query(0, pduResetQuery, 0, nil))
	n = readUntilEOD(t, c3)
	if n[pduASPA] != 0 || n[pduIPv4Prefix] != 1 || n[pduIPv6Prefix] != 1 {
		t.Fatalf("v0: %v", n)
	}
}

func TestNetDiff(t *testing.T) {
	st := &store{}
	a, b := vr("10.0.0.0/8", 8, 1), vr("11.0.0.0/8", 8, 2)
	st.update(mkSet([]rtrVRP{a}, nil))    // 처음 (serial 0)
	st.update(mkSet([]rtrVRP{a, b}, nil)) // 1 : +b
	st.update(mkSet([]rtrVRP{a}, nil))    // 2 : -b
	ann, wdr, _, _, _, ok := st.netDiff(0)
	if !ok || len(ann) != 0 || len(wdr) != 0 {
		t.Fatalf("0->2 should be empty: %v %v %v", ann, wdr, ok)
	}
	ann, wdr, _, _, _, ok = st.netDiff(1)
	if !ok || len(ann) != 0 || len(wdr) != 1 {
		t.Fatalf("1->2: %v %v", ann, wdr)
	}
}
