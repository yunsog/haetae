package main

// tak_test.go : TAK (RFC 9691) 경고. 저장소에 실제 TAK 가 없어 확인을 통과한 TAK 모양만 만들어 checkTAK 를 봄
// (CA 도우미 testCA / ipBlocks 는 rsc_test.go)

import (
	"strings"
	"testing"
	"time"
)

// TAK 경고 : TA 가 낸 TAK 의 successor = 예고 경고, TA 아닌 곳 / 다른 키 = 무시 경고
func TestCheckTAK(t *testing.T) {
	ca, _ := testCA(t, ipBlocks(192, 0, 2))
	next := taKey{URIs: []string{"rsync://x/next.cer"}, SKI: []byte{1, 2}}
	v := newValidator("", time.Now(), 1)
	ta := &caCtx{Cert: ca, TA: "test"}
	v.checkTAK(ta, &rpkiTAK{Current: taKey{SKI: ca.SKI}}, "rsync://x/a.tak")
	if len(v.count) != 0 {
		t.Errorf("no successor: %v", v.count)
	}
	v.checkTAK(ta, &rpkiTAK{Current: taKey{SKI: ca.SKI}, Successor: &next}, "rsync://x/a.tak")
	if v.count["warn: "+warnTAKSuccessor] != 1 || !strings.Contains(v.warnEx[warnTAKSuccessor][0], "test: successor SKI 0102, certificate rsync://x/next.cer") {
		t.Errorf("successor: %v %v", v.count, v.warnEx)
	}
	v.checkTAK(&caCtx{Cert: ca, TA: "test", Depth: 1}, &rpkiTAK{Current: taKey{SKI: ca.SKI}, Successor: &next}, "rsync://x/b.tak")
	v.checkTAK(ta, &rpkiTAK{Current: next, Successor: &next}, "rsync://x/c.tak")
	if v.count["warn: "+warnTAKNotTA] != 2 || v.count["warn: "+warnTAKSuccessor] != 1 {
		t.Errorf("not TA: %v", v.count)
	}
}
