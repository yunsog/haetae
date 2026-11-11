package main

// vrp.go : 라우터 / API 에 주는 데이터 집합과 serial, 변경분 (delta)
//
// 한 회차 검증이 끝나면 payloadSet (VRP + 라우터 키 + ASPA) 을 새로 만들고
// 직전 집합과 비교해 바뀐 것 (announce / withdraw) 을 delta 로 보관 -> serial + 1.
// RTR Serial Query, VRP API "바뀐 것" (E5) 이 이 delta 를 씀.
// RTR 에는 TA 구분이 없으므로 (prefix, maxLength, ASN) 이 같으면 하나로 침.

import (
	"bufio"
	"bytes"
	"encoding/gob"
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"sort"
	"sync"
	"time"
)

// 보관할 delta 수 (10 분 주기면 약 하루 + 여유)
const maxDeltaHistory = 200

// rtrVRP : RTR 단위 VRP (TA 없음)
type rtrVRP struct {
	Prefix    netip.Prefix
	MaxLength uint8
	ASN       uint32
}

// rtrKey : 라우터 키
type rtrKey struct {
	SKI  [20]byte
	ASN  uint32
	SPKI string // DER (map key 로 쓰려고 string)
}

// payloadSet : 한 시점의 전체 (불변, 만든 뒤 바꾸지 않음)
type payloadSet struct {
	VRPs  map[rtrVRP]bool
	Keys  map[rtrKey]bool
	ASPAs map[uint32][]uint32 // customer -> providers (오름차순, TA 합침)

	// API / JSON 용 (TA 포함 원본)
	Full     []vrpKey
	FullExp  map[vrpKey]time.Time
	Built    time.Time // 검증 시각
	TAs      []string
	FailedTA []string

	Filtered slurmCounts // SLURM 으로 뺀 수

	idxOnce sync.Once
	idx     map[netip.Prefix][]rtrVRP // prefix -> VRP (경로 검증 조회용, 처음 쓸 때 만듦)

	sortOnce sync.Once
	sorted   []rtrVRP // 정렬된 VRP (json-delta 전체, 처음 쓸 때 만듦)

	asnOnce sync.Once
	asnIdx  map[uint32][]int32 // ASN -> Full 의 위치 (Full 순서 그대로, /api/v1/as 조회용, 처음 쓸 때 만듦)
}

// slurmCounts : SLURM 적용 수
type slurmCounts struct {
	VRPs       int `json:"vrps"`
	RouterKeys int `json:"router_keys"`
	ASPAs      int `json:"aspas"`
}

// sortedVRPs : 주소, prefix 길이, maxLength, ASN 순
func (p *payloadSet) sortedVRPs() []rtrVRP {
	p.sortOnce.Do(func() {
		p.sorted = make([]rtrVRP, 0, len(p.VRPs))
		for v := range p.VRPs {
			p.sorted = append(p.sorted, v)
		}
		sortRTRVRPs(p.sorted)
	})
	return p.sorted
}

func sortRTRVRPs(vs []rtrVRP) {
	sort.Slice(vs, func(i, j int) bool {
		a, b := vs[i], vs[j]
		if c := a.Prefix.Addr().Compare(b.Prefix.Addr()); c != 0 {
			return c < 0
		}
		if a.Prefix.Bits() != b.Prefix.Bits() {
			return a.Prefix.Bits() < b.Prefix.Bits()
		}
		if a.MaxLength != b.MaxLength {
			return a.MaxLength < b.MaxLength
		}
		return a.ASN < b.ASN
	})
}

// sortRTRKeys : 라우터 키를 ASN, SKI, SPKI 순으로
func sortRTRKeys(ks []rtrKey) {
	sort.Slice(ks, func(i, j int) bool {
		a, b := ks[i], ks[j]
		if a.ASN != b.ASN {
			return a.ASN < b.ASN
		}
		if c := bytes.Compare(a.SKI[:], b.SKI[:]); c != 0 {
			return c < 0
		}
		return a.SPKI < b.SPKI
	})
}

// sortedKeys : 라우터 키 정렬 목록 (수 개라 부를 때마다 만듦)
func (p *payloadSet) sortedKeys() []rtrKey {
	ks := make([]rtrKey, 0, len(p.Keys))
	for k := range p.Keys {
		ks = append(ks, k)
	}
	sortRTRKeys(ks)
	return ks
}

// index : 같은 prefix 의 VRP 묶음 (조회 때 prefix 길이마다 한 번씩 찾음)
func (p *payloadSet) index() map[netip.Prefix][]rtrVRP {
	p.idxOnce.Do(func() {
		p.idx = make(map[netip.Prefix][]rtrVRP, len(p.VRPs))
		for v := range p.VRPs {
			p.idx[v.Prefix] = append(p.idx[v.Prefix], v)
		}
	})
	return p.idx
}

// byASN : 이 ASN 의 VRP (Full 순서). 전에는 요청마다 Full (약 100 만) 을 다 훑음 (11-05 검토 15)
func (p *payloadSet) byASN(asn uint32) []vrpKey {
	p.asnOnce.Do(func() {
		p.asnIdx = map[uint32][]int32{}
		for i, k := range p.Full {
			p.asnIdx[k.ASN] = append(p.asnIdx[k.ASN], int32(i))
		}
	})
	out := make([]vrpKey, 0, len(p.asnIdx[asn]))
	for _, i := range p.asnIdx[asn] {
		out = append(out, p.Full[i])
	}
	return out
}

// delta : serial 하나만큼의 변화
type delta struct {
	Serial    uint32
	AnnVRP    []rtrVRP
	WdrVRP    []rtrVRP
	AnnKey    []rtrKey
	WdrKey    []rtrKey
	ASPAChg   []uint32 // 바뀐 customer (지금 값은 새 집합에서, 없으면 withdraw)
	Time      time.Time
	OldASPAOf map[uint32][]uint32
}

// store : 지금 집합 + session + serial + delta 기록 (RTR / API 가 같이 읽음)
type store struct {
	mu      sync.RWMutex
	Session uint16
	Serial  uint32
	Cur     *payloadSet
	History []delta // 오래된 것부터
	Updated time.Time

	listeners []chan struct{} // 바뀌면 알림 (RTR Serial Notify)
}

// newPayloadSet : 검증 결과 -> payloadSet
func newPayloadSet(v *validator, slurm *slurmFile) *payloadSet {
	p := &payloadSet{
		VRPs:     map[rtrVRP]bool{},
		Keys:     map[rtrKey]bool{},
		ASPAs:    map[uint32][]uint32{},
		FullExp:  map[vrpKey]time.Time{},
		Built:    v.Now,
		FailedTA: v.failedTA,
	}
	for k, exp := range v.vrps {
		if slurm.filterVRP(k.ASN, k.Prefix) {
			p.Filtered.VRPs++
			continue
		}
		p.Full = append(p.Full, k)
		p.FullExp[k] = exp
		p.VRPs[rtrVRP{k.Prefix, uint8(k.MaxLength), k.ASN}] = true
	}
	for _, r := range v.rkeys {
		if slurm.filterKey(r.ASN, r.SKI) {
			p.Filtered.RouterKeys++
			continue
		}
		var k rtrKey
		copy(k.SKI[:], r.SKI)
		k.ASN, k.SPKI = r.ASN, string(r.SPKI)
		p.Keys[k] = true
	}
	merged := map[uint32]map[uint32]bool{}
	for k, a := range v.aspas {
		if slurm.filterASPA(k.Customer) {
			p.Filtered.ASPAs++
			continue
		}
		if merged[k.Customer] == nil {
			merged[k.Customer] = map[uint32]bool{}
		}
		for pr := range a.Providers {
			merged[k.Customer][pr] = true
		}
	}
	for c, ps := range merged {
		p.ASPAs[c] = sortedASNs(ps)
	}
	slurm.addAssertions(p)
	sort.Slice(p.Full, func(i, j int) bool { return lessVRPKey(p.Full[i], p.Full[j]) })
	return p
}

func sortedASNs(m map[uint32]bool) []uint32 {
	out := make([]uint32, 0, len(m))
	for a := range m {
		out = append(out, a)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

func lessVRPKey(a, b vrpKey) bool {
	if c := a.Prefix.Addr().Compare(b.Prefix.Addr()); c != 0 {
		return c < 0
	}
	if a.Prefix.Bits() != b.Prefix.Bits() {
		return a.Prefix.Bits() < b.Prefix.Bits()
	}
	if a.MaxLength != b.MaxLength {
		return a.MaxLength < b.MaxLength
	}
	if a.ASN != b.ASN {
		return a.ASN < b.ASN
	}
	return a.TA < b.TA
}

func equalASNs(a, b []uint32) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// diffSets : old -> new 변화 (old 가 nil 이면 전부 announce)
func diffSets(old, nw *payloadSet) delta {
	var d delta
	if old == nil {
		old = &payloadSet{VRPs: map[rtrVRP]bool{}, Keys: map[rtrKey]bool{}, ASPAs: map[uint32][]uint32{}}
	}
	for k := range nw.VRPs {
		if !old.VRPs[k] {
			d.AnnVRP = append(d.AnnVRP, k)
		}
	}
	for k := range old.VRPs {
		if !nw.VRPs[k] {
			d.WdrVRP = append(d.WdrVRP, k)
		}
	}
	for k := range nw.Keys {
		if !old.Keys[k] {
			d.AnnKey = append(d.AnnKey, k)
		}
	}
	for k := range old.Keys {
		if !nw.Keys[k] {
			d.WdrKey = append(d.WdrKey, k)
		}
	}
	d.OldASPAOf = map[uint32][]uint32{}
	for c, ps := range nw.ASPAs {
		if op, ok := old.ASPAs[c]; !ok || !equalASNs(op, ps) {
			d.ASPAChg = append(d.ASPAChg, c)
			d.OldASPAOf[c] = op
		}
	}
	for c, op := range old.ASPAs {
		if _, ok := nw.ASPAs[c]; !ok {
			d.ASPAChg = append(d.ASPAChg, c)
			d.OldASPAOf[c] = op
		}
	}
	sort.Slice(d.ASPAChg, func(i, j int) bool { return d.ASPAChg[i] < d.ASPAChg[j] })
	return d
}

func (d *delta) empty() bool {
	return len(d.AnnVRP)+len(d.WdrVRP)+len(d.AnnKey)+len(d.WdrKey)+len(d.ASPAChg) == 0
}

// update : 새 집합으로 바꿈. 바뀐 것이 있으면 serial + 1, delta 보관, 알림
func (s *store) update(nw *payloadSet) (delta, bool) {
	s.mu.Lock()
	d := diffSets(s.Cur, nw)
	first := s.Cur == nil
	s.Cur = nw
	s.Updated = time.Now()
	changed := !d.empty() && !first
	if changed {
		s.Serial++ // uint32 이므로 넘치면 0 (RFC 1982 serial 산술)
		d.Serial = s.Serial
		d.Time = time.Now()
		s.History = append(s.History, d)
		if len(s.History) > maxDeltaHistory {
			s.History = s.History[len(s.History)-maxDeltaHistory:]
		}
	}
	ls := append([]chan struct{}(nil), s.listeners...)
	s.mu.Unlock()
	if changed {
		for _, l := range ls {
			select {
			case l <- struct{}{}:
			default:
			}
		}
	}
	return d, changed
}

func (s *store) subscribe() chan struct{} {
	ch := make(chan struct{}, 1)
	s.mu.Lock()
	s.listeners = append(s.listeners, ch)
	s.mu.Unlock()
	return ch
}

func (s *store) unsubscribe(ch chan struct{}) {
	s.mu.Lock()
	for i, l := range s.listeners {
		if l == ch {
			s.listeners = append(s.listeners[:i], s.listeners[i+1:]...)
			break
		}
	}
	s.mu.Unlock()
}

// netDiff : from (클라이언트가 가진 serial) 이후 지금까지 합친 변화. 기록이 없으면 ok=false (Cache Reset)
// 호출하는 쪽이 RLock 을 잡고 있어야 함
func (s *store) netDiff(from uint32) (ann, wdr []rtrVRP, kAnn, kWdr []rtrKey, aspaChg []uint32, ok bool) {
	return s.netDiffTo(from, s.Serial)
}

// netDiffTo : from 이후 to 까지 합친 변화 (to = 지금이면 netDiff). to 까지의 기록이 없으면 ok=false
func (s *store) netDiffTo(from, to uint32) (ann, wdr []rtrVRP, kAnn, kWdr []rtrKey, aspaChg []uint32, ok bool) {
	if from == to && to == s.Serial {
		return nil, nil, nil, nil, nil, true
	}
	start, end := -1, -1
	for i, d := range s.History {
		if d.Serial == from+1 {
			start = i
		}
		if d.Serial == to {
			end = i
		}
	}
	if start < 0 || end < start {
		return nil, nil, nil, nil, nil, false
	}
	// 순서대로 겹쳐서 최종 상태만 남김 (announce 뒤 withdraw = 없던 일)
	vs := map[rtrVRP]bool{} // true = announce, false = withdraw
	ks := map[rtrKey]bool{}
	as := map[uint32]bool{}
	for _, d := range s.History[start : end+1] {
		for _, k := range d.AnnVRP {
			if a, seen := vs[k]; seen && !a {
				delete(vs, k)
			} else {
				vs[k] = true
			}
		}
		for _, k := range d.WdrVRP {
			if a, seen := vs[k]; seen && a {
				delete(vs, k)
			} else {
				vs[k] = false
			}
		}
		for _, k := range d.AnnKey {
			if a, seen := ks[k]; seen && !a {
				delete(ks, k)
			} else {
				ks[k] = true
			}
		}
		for _, k := range d.WdrKey {
			if a, seen := ks[k]; seen && a {
				delete(ks, k)
			} else {
				ks[k] = false
			}
		}
		for _, c := range d.ASPAChg {
			as[c] = true
		}
	}
	for k, a := range vs {
		if a {
			ann = append(ann, k)
		} else {
			wdr = append(wdr, k)
		}
	}
	for k, a := range ks {
		if a {
			kAnn = append(kAnn, k)
		} else {
			kWdr = append(kWdr, k)
		}
	}
	for c := range as {
		aspaChg = append(aspaChg, c)
	}
	// 순서를 고정 (map 순서는 매번 다름 -> 같은 delta 가 매번 다른 순서였음, 11-04). RTR / json-delta / vrps/delta 모두 여기를 지남
	sortRTRVRPs(ann)
	sortRTRVRPs(wdr)
	sortRTRKeys(kAnn)
	sortRTRKeys(kWdr)
	sort.Slice(aspaChg, func(i, j int) bool { return aspaChg[i] < aspaChg[j] })
	return ann, wdr, kAnn, kWdr, aspaChg, true
}

// aspaAt : serial to 시점의 customer c 의 provider 목록 (nil = 없음). RLock 필요
// to 뒤에 c 를 처음 바꾼 delta 의 "바뀌기 전" 값, 그런 delta 가 없으면 지금 값
func (s *store) aspaAt(c, to uint32) []uint32 {
	for _, d := range s.History {
		if d.Serial <= to {
			continue
		}
		if old, ok := d.OldASPAOf[c]; ok {
			return old
		}
	}
	return s.Cur.ASPAs[c]
}

// ---- 재시작 대비 저장 (C4, B5) ----

// savedState : 재시작 복원용 한 파일 (state/payload.gob, 0.2.0). RTR 에 준 집합 (SLURM 뒤) + session / serial + delta 기록을
// 같은 순간에 한 번에 씀 -> 셋이 언제나 같은 회차 (전에는 state.json / out/json / deltas.gob 을 따로 써서 어긋날 수 있었음)
type savedState struct {
	Session  uint16
	Serial   uint32
	Saved    time.Time
	Built    time.Time
	VRPs     []rtrVRP
	Keys     []rtrKey
	ASPAs    map[uint32][]uint32
	Full     []vrpKey
	FullExp  []int64 // Full 과 같은 순서, Unix 초
	TAs      []string
	FailedTA []string
	Filtered slurmCounts
	History  []delta
}

// saveState : 지금 store 를 path 에 원자적으로 (임시 파일 + fsync + rename). 잠금은 꺼낼 때만 (집합은 바뀌지 않는 값)
func saveState(path string, s *store) error {
	s.mu.RLock()
	ss := savedState{Session: s.Session, Serial: s.Serial, Saved: time.Now(), History: s.History}
	cur := s.Cur
	s.mu.RUnlock()
	if cur == nil {
		return fmt.Errorf("no set")
	}
	ss.Built, ss.ASPAs, ss.TAs, ss.FailedTA, ss.Filtered = cur.Built, cur.ASPAs, cur.TAs, cur.FailedTA, cur.Filtered
	ss.VRPs = make([]rtrVRP, 0, len(cur.VRPs))
	for v := range cur.VRPs {
		ss.VRPs = append(ss.VRPs, v)
	}
	ss.Keys = make([]rtrKey, 0, len(cur.Keys))
	for k := range cur.Keys {
		ss.Keys = append(ss.Keys, k)
	}
	ss.Full = cur.Full
	ss.FullExp = make([]int64, len(cur.Full))
	for i, k := range cur.Full {
		ss.FullExp[i] = cur.FullExp[k].Unix()
	}

	tmp := path + ".tmp"
	f, err := os.Create(tmp)
	if err != nil {
		return err
	}
	bw := bufio.NewWriterSize(f, 1<<20)
	err = gob.NewEncoder(bw).Encode(&ss)
	if err == nil {
		err = bw.Flush()
	}
	if err == nil {
		err = f.Sync() // rename 뒤 정전이 나도 내용이 디스크에
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, path)
}

// loadSavedState : saveState 로 쓴 파일 -> session, serial, 집합, delta 기록
func loadSavedState(path string) (*savedState, *payloadSet, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, nil, err
	}
	defer f.Close()
	var ss savedState
	if err := gob.NewDecoder(bufio.NewReaderSize(f, 1<<20)).Decode(&ss); err != nil {
		return nil, nil, fmt.Errorf("%s: %w", path, err)
	}
	if len(ss.FullExp) != len(ss.Full) {
		return nil, nil, fmt.Errorf("%s: broken (full %d / exp %d)", path, len(ss.Full), len(ss.FullExp))
	}
	p := &payloadSet{VRPs: make(map[rtrVRP]bool, len(ss.VRPs)), Keys: make(map[rtrKey]bool, len(ss.Keys)), ASPAs: ss.ASPAs,
		Full: ss.Full, FullExp: make(map[vrpKey]time.Time, len(ss.Full)), Built: ss.Built, TAs: ss.TAs, FailedTA: ss.FailedTA,
		Filtered: ss.Filtered}
	if p.ASPAs == nil {
		p.ASPAs = map[uint32][]uint32{}
	}
	for _, v := range ss.VRPs {
		p.VRPs[v] = true
	}
	for _, k := range ss.Keys {
		p.Keys[k] = true
	}
	for i, k := range ss.Full {
		p.FullExp[k] = time.Unix(ss.FullExp[i], 0)
	}
	return &ss, p, nil
}

// rtrState : session / serial (state.json)
type rtrState struct {
	Session uint16    `json:"session"`
	Serial  uint32    `json:"serial"`
	Saved   time.Time `json:"saved"`
}

func saveRTRState(path string, s *store) error {
	s.mu.RLock()
	st := rtrState{s.Session, s.Serial, time.Now()}
	s.mu.RUnlock()
	b, _ := json.MarshalIndent(st, "", " ")
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
