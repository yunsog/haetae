package main

// aspa_verify.go : ASPA 경로 검증 (draft-ietf-sidrops-aspa-verification-29, 2026-10, 5.3 ~ 5.6 절)
//
// 라우터가 할 일을 RP 쪽에서 미리 해 보는 조회용 (사람이 경로 하나를 넣어 보는 화면, 라우터 결과와 비교).
//   GET  /api/v1/aspa/verify?path=<AS_PATH>[&neighbor=<AS>]   경로 하나, 쌍마다 판정까지
// 두 방향 (upstream = 고객 / peer / RS 에서 받은 경로, downstream = provider 에서 받은 경로) 을 모두 돌려줌.
// 어느 쪽을 쓸지는 받은 세션의 관계 (BGP Role, RFC 9234) 로 부르는 쪽이 고름.
//
// 경로 표기 : AS_PATH 를 보이는 그대로 (왼쪽 = 이웃 = 가장 나중에 붙은 AS, 오른쪽 끝 = origin).
//   "64500 64501 64502", 쉼표도 됨, AS 접두어 됨, "{1 2}" = AS_SET (있으면 invalid)
// 초안의 번호는 반대 : A(1) = origin ... A(N) = 이웃. 아래 코드의 a[] 도 초안 순서 (a[0] = origin)
//
// authorized(x, y) : x 의 ASPA (모든 TA 합집합, SLURM 반영) 가 없으면 "No Attestation",
//   y 가 들어 있으면 "Provider+", 아니면 "Not Provider+"
// 오르막 (up-ramp) : origin 에서 고객 -> provider 로 올라가는 쌍이 이어지는 구간
// 내리막 (down-ramp) : 이웃 쪽에서 provider -> 고객 으로 내려오는 구간 (반대 방향에서 보면 오르막)
//   max_up_ramp  = (A(I), A(I+1)) 이 Not Provider+ 인 가장 작은 I, 없으면 N
//   min_up_ramp  = No Attestation 또는 Not Provider+ 인 가장 작은 I, 없으면 N
//   max_down_ramp = N - J + 1 (J = (A(J), A(J-1)) 이 Not Provider+ 인 가장 큰 J), 없으면 N. min 도 같은 방식
// upstream   : max_up < N -> invalid, min_up < N -> unknown, 아니면 valid (내리막 없어야 함)
// downstream : max_up + max_down < N -> invalid, min_up + min_down < N -> unknown, 아니면 valid

import (
	"fmt"
	"net/http"
	"slices"
	"strings"
	"time"
)

// 경로 길이 상한 (실제 경로는 수십 개 안쪽, 쓸데없이 큰 입력 차단)
const maxASPathLen = 1024

// authorized() 의 세 결과
const (
	aspaProviderPlus = "provider+"
	aspaNotProvider  = "not-provider+"
	aspaNoAttest     = "no-attestation"
)

// aspaHop : 이웃한 두 AS (origin 쪽 From, 이웃 쪽 To) 의 판정
//
//	Up   = authorized(From, To) : To 가 From 의 provider 인가 (오르막 쪽)
//	Down = authorized(To, From) : From 이 To 의 provider 인가 (내리막 쪽)
type aspaHop struct {
	From uint32 `json:"from"`
	To   uint32 `json:"to"`
	Up   string `json:"up"`
	Down string `json:"down"`
}

// aspaDirResult : 한 방향의 결과
type aspaDirResult struct {
	State  string `json:"state"`            // valid / invalid / unknown
	Reason string `json:"reason,omitempty"` // empty / neighbor / as_set / not-provider / no-attestation
}

// aspaVerdict : 경로 하나의 결과 (GET 응답)
type aspaVerdict struct {
	Path        []uint32      `json:"path"`       // 받은 그대로 (이웃 -> origin), AS_SET 은 빠짐
	Compressed  []uint32      `json:"compressed"` // 연속 중복 (prepend) 을 합친 것, 같은 순서
	HasSet      bool          `json:"as_set"`
	Neighbor    uint32        `json:"neighbor,omitempty"`
	Upstream    aspaDirResult `json:"upstream"`
	Downstream  aspaDirResult `json:"downstream"`
	MaxUpRamp   int           `json:"max_up_ramp"`
	MinUpRamp   int           `json:"min_up_ramp"`
	MaxDownRamp int           `json:"max_down_ramp"`
	MinDownRamp int           `json:"min_down_ramp"`
	Hops        []aspaHop     `json:"hops"` // origin -> 이웃 순서
}

// parseASPath : "64500 64501 {1 2} 64502" -> AS 목록 (AS_SET 안의 AS 는 빼고 hasSet = true)
func parseASPath(s string) (path []uint32, hasSet bool, err error) {
	s = strings.NewReplacer("{", " { ", "}", " } ", ",", " ").Replace(s)
	inSet := false
	for _, tok := range strings.Fields(s) {
		switch tok {
		case "{":
			if inSet {
				return nil, false, fmt.Errorf("nested AS_SET")
			}
			inSet, hasSet = true, true
			continue
		case "}":
			if !inSet {
				return nil, false, fmt.Errorf("unbalanced }")
			}
			inSet = false
			continue
		}
		n, err := parseASN(tok)
		if err != nil {
			return nil, false, fmt.Errorf("bad AS %q", tok)
		}
		if !inSet {
			path = append(path, n)
		}
		if len(path) > maxASPathLen {
			return nil, false, fmt.Errorf("AS_PATH too long (max %d)", maxASPathLen)
		}
	}
	if inSet {
		return nil, false, fmt.Errorf("unbalanced {")
	}
	return path, hasSet, nil
}

// aspaAuthorized : 초안 5.3 절 authorized(x, y). aspas = customer -> providers (오름차순)
// AS 0 은 "provider 없음" 표시라 provider 로 치지 않음 (U-SPAS 에서 AS 0 은 다른 AS 와 함께면 빠짐)
func aspaAuthorized(aspas map[uint32][]uint32, x, y uint32) string {
	ps, ok := aspas[x]
	if !ok {
		return aspaNoAttest
	}
	if y != 0 {
		if _, found := slices.BinarySearch(ps, y); found {
			return aspaProviderPlus
		}
	}
	return aspaNotProvider
}

// aspaVerify : 경로 하나를 두 방향으로 판정. neighbor = 0 이면 이웃 확인을 안 함 (RS-client 등)
func aspaVerify(aspas map[uint32][]uint32, path []uint32, hasSet bool, neighbor uint32) aspaVerdict {
	v := aspaVerdict{Path: path, HasSet: hasSet, Neighbor: neighbor, Hops: []aspaHop{}}
	for _, as := range path {
		if len(v.Compressed) == 0 || v.Compressed[len(v.Compressed)-1] != as {
			v.Compressed = append(v.Compressed, as)
		}
	}
	if v.Path == nil {
		v.Path, v.Compressed = []uint32{}, []uint32{}
	}
	n := len(v.Compressed)

	// 초안 순서로 뒤집음 : a[0] = A(1) = origin, a[n-1] = A(N) = 이웃
	a := make([]uint32, n)
	for i, as := range v.Compressed {
		a[n-1-i] = as
	}
	for i := 0; i+1 < n; i++ {
		v.Hops = append(v.Hops, aspaHop{From: a[i], To: a[i+1],
			Up: aspaAuthorized(aspas, a[i], a[i+1]), Down: aspaAuthorized(aspas, a[i+1], a[i])})
	}

	// 오르막 : origin 쪽부터 처음으로 막히는 곳 (I 는 1 부터)
	v.MaxUpRamp, v.MinUpRamp = n, n
	for i, h := range v.Hops {
		if h.Up != aspaProviderPlus && v.MinUpRamp == n {
			v.MinUpRamp = i + 1
		}
		if h.Up == aspaNotProvider {
			v.MaxUpRamp = i + 1
			break
		}
	}
	// 내리막 : 이웃 쪽부터 처음으로 막히는 곳. Hops[i] 의 Down = authorized(A(i+2), A(i+1)) -> J = i + 2
	v.MaxDownRamp, v.MinDownRamp = n, n
	for i := len(v.Hops) - 1; i >= 0; i-- {
		h := v.Hops[i]
		j := i + 2
		if h.Down != aspaProviderPlus && v.MinDownRamp == n {
			v.MinDownRamp = n - j + 1
		}
		if h.Down == aspaNotProvider {
			v.MaxDownRamp = n - j + 1
			break
		}
	}

	// 공통 앞 단계 (5.5 / 5.6 의 1 ~ 3)
	var pre string
	switch {
	case n == 0:
		pre = "empty"
	case neighbor != 0 && v.Compressed[0] != neighbor:
		pre = "neighbor"
	case hasSet:
		pre = "as_set"
	}
	if pre != "" {
		v.Upstream = aspaDirResult{"invalid", pre}
		v.Downstream = aspaDirResult{"invalid", pre}
		return v
	}
	v.Upstream = aspaRampResult(v.MaxUpRamp, v.MinUpRamp, 0, 0, n)
	v.Downstream = aspaRampResult(v.MaxUpRamp, v.MinUpRamp, v.MaxDownRamp, v.MinDownRamp, n)
	return v
}

// aspaRampResult : 5.4 절 마지막 문단 (upstream 은 내리막 = 0)
func aspaRampResult(maxUp, minUp, maxDown, minDown, n int) aspaDirResult {
	switch {
	case maxUp+maxDown < n:
		return aspaDirResult{"invalid", "not-provider"}
	case minUp+minDown < n:
		return aspaDirResult{"unknown", "no-attestation"}
	}
	return aspaDirResult{State: "valid"}
}

// ---- HTTP ----

// GET /api/v1/aspa/verify?path=64500+64501+64502[&neighbor=64500]
func (d *daemon) handleASPAVerify(w http.ResponseWriter, r *http.Request) {
	cur, _ := d.current()
	if cur == nil {
		noData(w)
		return
	}
	q := r.URL.Query()
	path, hasSet, err := parseASPath(q.Get("path"))
	if err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	var nb uint32
	if s := q.Get("neighbor"); s != "" {
		if nb, err = parseASN(s); err != nil {
			http.Error(w, "bad neighbor", 400)
			return
		}
	}
	d.st.mu.RLock()
	ser := d.st.Serial
	d.st.mu.RUnlock()
	writeJSON(w, map[string]any{"generatedTime": cur.Built.UTC().Format(time.RFC3339), "serial": ser,
		"result": aspaVerify(cur.ASPAs, path, hasSet, nb)})
}
