package main

// validate.go : 검증 트리 (2 단계)
//
// TAL -> TA 인증서 -> (CA 마다) manifest -> CRL + 나열된 파일 -> 자식 CA 는 같은 일을 반복
//
// CA 하나 (publication point) 처리 순서
//   1. manifest 읽기 / 파싱, EE 서명 (CA 키), 시각 (thisUpdate <= now <= nextUpdate)
//   2. manifest 의 CRL (정확히 1 개) : 해시, 서명, 시각
//   3. 나열된 파일 전부 해시 확인 -> 하나라도 없거나 다르면 CA 전체 버림 (RFC 9286, 결정 A1)
//   4. 파일마다 : 서명 (CA 키), AKI, 폐기 여부, 유효기간, 자원 포함 (inherit 풀어서 부모 ⊆)
//      .cer = 자식 CA (다시 1 부터) 또는 라우터 키, .roa .asa .spl .gbr .tak = 서명 객체
// 실패는 그 객체 (또는 그 CA) 만. panic 도 그 CA 만 실패.
// 확신 없는 규칙 (AIA / signedObject 위치 일치 등) 은 우선 경고로 세고 rpki-client 와 비교해서 정함.

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"fmt"
	"net/netip"
	"os"
	"path"
	"path/filepath"
	"runtime/debug"
	"slices"
	"strings"
	"sync"
	"time"
)

// CA 깊이 상한 (B3). 실제 최대는 10 안쪽
const maxCADepth = 32

// caCtx : 처리할 CA 하나와 위에서 물려받은 것
type caCtx struct {
	Cert    *rpkiCert
	URI     string // 이 인증서 위치 (rsync)
	Base    string // 이 CA 의 객체를 읽을 기준 폴더 (그 아래 <host>/<path>)
	TA      string
	Depth   int
	IPs     ipResources // inherit 를 푼 실제 자원
	ASs     asResources
	Expires time.Time // 위 체인에서 가장 이른 만료
	NotBef  time.Time // 위 체인에서 가장 늦은 시작 (인증서 notBefore, manifest / CRL thisUpdate)
	Stale   time.Time // 위 체인의 manifest / CRL nextUpdate 중 가장 이른 것
}

// chainTimes : CA 하나 아래 객체에 물려주는 체인 시각 (jsonext 의 chainValidity / stale)
type chainTimes struct {
	NB, Exp, Stale time.Time
}

// vrpSource : VRP 하나가 나온 ROA (jsonext, AS / prefix 조회). 메모리 때문에 시각은 epoch 초
type vrpSource struct {
	URI     string
	TA      string
	NB, NA  int64 // ROA EE 유효기간
	ChainNB int64
	ChainNA int64
	Stale   int64
}

// unsafeRange : 거부된 CA 의 IP 자원 (A4 unsafe VRP 계산)
type unsafeRange struct {
	CA string
	V4 bool
	R  ipRange
}

type vrpKey struct {
	ASN       uint32
	Prefix    netip.Prefix
	MaxLength int
	TA        string
}

type aspaKey struct {
	Customer uint32
	TA       string
}

type aspaOut struct {
	Providers map[uint32]bool
	Expires   time.Time
}

type routerKeyOut struct {
	routerKey
	TA      string
	Expires time.Time
	URI     string
}

// objInfo : 전체 객체 목록 (E6) 한 줄
type objInfo struct {
	Type      string    `json:"type"`
	URI       string    `json:"uri"`
	SHA256    string    `json:"sha256,omitempty"`
	TA        string    `json:"ta"`
	Parent    string    `json:"parent,omitempty"` // 발행 CA 인증서 URI
	NotBefore time.Time `json:"notBefore,omitzero"`
	NotAfter  time.Time `json:"notAfter,omitzero"`
	Status    string    `json:"status"` // valid / rejected
	Reason    string    `json:"reason,omitempty"`
	Summary   any       `json:"summary,omitempty"`
}

// validator : 검증 한 번의 설정과 결과
type validator struct {
	CacheDir string
	Now      time.Time
	Workers  int
	Fetch    *fetcher // nil = 오프라인 (CacheDir 를 그대로 읽음, rpki-client 캐시 모양)
	KeepCAs  bool     // 검증된 CA 를 SKI 로 모음 (RSC 체인 확인, rsc.go). 메모리 때문에 평소에는 끔
	ValidDir string   // 직전 정상 publication point 저장 폴더 (valid.go). "" = 끔 (-validate 오프라인 비교)

	sem chan struct{}
	wg  sync.WaitGroup

	mu        sync.Mutex
	vrps      map[vrpKey]time.Time
	vrpSrc    map[vrpKey][]vrpSource
	unsafe    []unsafeRange
	aspas     map[aspaKey]*aspaOut
	rkeys     []routerKeyOut
	objects   []objInfo
	seenCA    map[string]bool        // CA 인증서 DER 의 sha256 -> 이미 처리 (같은 인증서 두 번 / 순환 방지)
	validSeen map[string]bool        // 이번 회차에 본 직전 정상본 폴더 (나머지는 cleanValid 가 지움)
	validLock map[string]*sync.Mutex // 직전 정상본 폴더마다 하나씩 (같은 폴더를 두 CA 가 동시에 쓰지 않게)
	count     map[string]int         // 통계 (종류별 valid / rejected, 경고)
	warnEx    map[string][]string    // 경고마다 예시 몇 개 (원인 확인용)
	failedTA  []string
	caBySKI   map[string][]*caRecord     // KeepCAs 일 때만
	taRepos   map[string]map[string]bool // TA -> 이번 회차에 쓴 저장소 열쇠 (maxReposPerTA, repo_guard.go)

	ppBudget *byteBudget // 동시에 메모리에 올린 publication point 바이트 (maxPPInFlight)
}

// publication point 하나 (manifest + 나열된 파일) 의 바이트 상한과, 동시에 메모리에 올리는 합 (11-05 검토 12).
// 나열된 파일은 해시 확인 뒤 CA 처리가 끝날 때까지 메모리에 있음 -> CA 하나 상한만으로는 동시 처리 (Workers) 만큼 곱해짐.
// 2026-11 운영 최대 = ARIN 한 곳 109 MB (파일 48,934 개). 합이 차면 다음 CA 는 앞의 것이 끝날 때까지 기다림
const (
	maxPPBytes    = 512 << 20
	maxPPInFlight = 2 << 30
)

// byteBudget : 바이트 단위 세마포어 (acquire 는 남은 양이 될 때까지 기다림). n 은 전체보다 크면 안 됨
type byteBudget struct {
	mu   sync.Mutex
	cond *sync.Cond
	left int64
}

func newByteBudget(n int64) *byteBudget {
	b := &byteBudget{left: n}
	b.cond = sync.NewCond(&b.mu)
	return b
}

func (b *byteBudget) acquire(n int64) {
	b.mu.Lock()
	for b.left < n {
		b.cond.Wait()
	}
	b.left -= n
	b.mu.Unlock()
}

func (b *byteBudget) release(n int64) {
	b.mu.Lock()
	b.left += n
	b.mu.Unlock()
	b.cond.Broadcast()
}

func newValidator(cacheDir string, now time.Time, workers int) *validator {
	return &validator{
		CacheDir:  cacheDir,
		Now:       now,
		Workers:   workers,
		sem:       make(chan struct{}, workers),
		vrps:      map[vrpKey]time.Time{},
		vrpSrc:    map[vrpKey][]vrpSource{},
		aspas:     map[aspaKey]*aspaOut{},
		seenCA:    map[string]bool{},
		validSeen: map[string]bool{},
		validLock: map[string]*sync.Mutex{},
		taRepos:   map[string]map[string]bool{},
		ppBudget:  newByteBudget(maxPPInFlight),
		count:     map[string]int{},
		warnEx:    map[string][]string{},
	}
}

// run : TAL 마다 TA 를 읽고 트리 전체를 처리, 끝날 때까지 기다림
func (v *validator) run(tals []*tal) {
	for _, t := range tals {
		if v.Fetch != nil {
			if err := v.Fetch.fetchTA(t); err != nil {
				v.Fetch.logf("TA %s: fetch failed, using cached copy: %v", t.Name, err)
			}
		}
		ta, err := t.loadTA(v.CacheDir)
		if err == nil {
			err = v.checkValidity(ta.X509.NotBefore, ta.X509.NotAfter)
		}
		uri := t.rsyncURI()
		if err != nil {
			v.rejectCert(uri, t.Name, "", err, nil, "TA")
			v.mu.Lock()
			v.failedTA = append(v.failedTA, t.Name)
			v.mu.Unlock()
			continue
		}
		v.warnSKI(ta, uri)
		v.valid("cer", uri, t.Name, "", ta.X509.Raw, ta.X509.NotBefore, ta.X509.NotAfter,
			map[string]any{"kind": "TA", "repository": ta.CARepository, "notify": ta.Notify, "resources": newResSummary(ta.IPs, ta.ASs)})
		v.spawn(caCtx{Cert: ta, URI: uri, TA: t.Name, IPs: ta.IPs, ASs: ta.ASs,
			Expires: ta.X509.NotAfter, NotBef: ta.X509.NotBefore, Stale: ta.X509.NotAfter})
	}
	v.wg.Wait()
}

// spawn : CA 하나를 동시 처리 (동시 수는 sem 으로 Workers 개까지)
func (v *validator) spawn(ctx caCtx) {
	v.wg.Add(1)
	go func() {
		defer v.wg.Done()
		// 저장소 수집은 검증 동시 수 (sem) 밖에서 (기다리는 동안 다른 CA 검증이 돌게)
		ctx.Base = v.CacheDir
		if v.Fetch != nil {
			if err := v.repoAllowed(&ctx); err != nil {
				v.reject("mft", ctx.Cert.Manifest, ctx.TA, ctx.URI, err)
				v.addUnsafe(ctx.URI, ctx.IPs)
				return
			}
			if ctx.Base = v.Fetch.ensure(ctx.Cert); ctx.Base == "" {
				// 받은 데이터가 전혀 없음 (rsync 끔 + RRDP 실패, 수집 중 panic). 빈 기준 = 현재 폴더 기준 상대 경로가 되므로 실패로
				v.reject("mft", ctx.Cert.Manifest, ctx.TA, ctx.URI, fmt.Errorf("no repository data"))
				v.addUnsafe(ctx.URI, ctx.IPs)
				return
			}
		}
		v.sem <- struct{}{}
		defer func() {
			if p := recover(); p != nil {
				v.reject("mft", ctx.Cert.Manifest, ctx.TA, ctx.URI, fmt.Errorf("panic: %v %s", p, debug.Stack()))
				v.addUnsafe(ctx.URI, ctx.IPs)
			}
			<-v.sem
		}()
		v.processCA(ctx)
	}()
}

// repoAllowed : 받기 전에 저장소 주소 확인 (11-05 검토 10)
//   - notify 정규화 (canonicalNotify). query / fragment 등이 있으면 notify 를 쓰지 않고 rsync 로 (경고)
//   - TA 하나 아래 서로 다른 저장소가 maxReposPerTA 를 넘으면 그 CA 실패
func (v *validator) repoAllowed(ctx *caCtx) error {
	c := ctx.Cert
	if c.Notify != "" {
		n, err := canonicalNotify(c.Notify)
		if err != nil {
			v.warn("rpkiNotify not usable, using rsync", c.Notify+": "+err.Error())
			n = ""
		}
		c.Notify = n // 직전 정상본 폴더 (validPPDir) 도 이 값으로
	}
	key := "rrdp " + c.Notify
	if c.Notify == "" {
		key = "rsync " + rsyncModule(c.CARepository)
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	set := v.taRepos[ctx.TA]
	if set == nil {
		set = map[string]bool{}
		v.taRepos[ctx.TA] = set
	}
	if !set[key] {
		if len(set) >= maxReposPerTA {
			return fmt.Errorf("too many repositories under TA %s (max %d)", ctx.TA, maxReposPerTA)
		}
		set[key] = true
	}
	return nil
}

// ---- 기록 도우미 ----

func (v *validator) inc(key string) {
	v.mu.Lock()
	v.count[key]++
	v.mu.Unlock()
}

// warn : 경고 개수 + 앞의 5 개는 예시 (detail) 로 남김 (summary.txt)
func (v *validator) warn(what, detail string) {
	v.mu.Lock()
	v.count["warn: "+what]++
	if ex := v.warnEx[what]; len(ex) < 5 && !slices.Contains(ex, detail) {
		v.warnEx[what] = append(ex, detail)
	}
	v.mu.Unlock()
}

// warnSKI : 확인을 통과한 인증서의 SKI 가 키 해시가 아니면 경고 (거부는 보류, 11-02 사용자 : 적용하고 지켜봄)
func (v *validator) warnSKI(c *rpkiCert, uri string) {
	if c.SKIBad {
		v.warn("SKI is not SHA-1 of public key", uri)
	}
}

func (v *validator) reject(typ, uri, ta, parent string, err error) {
	v.rejectSum(typ, uri, ta, parent, err, nil)
}

// rejectCert : 거부된 인증서. 종류 (TA / CA / router) 를 알면 summary.kind 로 남김 (objects 의 kind 조건)
// 파싱부터 실패하면 c = nil -> 종류 모름 (summary 없음)
func (v *validator) rejectCert(uri, ta, parent string, err error, c *rpkiCert, kind string) {
	var sum any
	if kind == "" && c != nil {
		kind = c.Kind.String()
	}
	if kind != "" {
		sum = map[string]any{"kind": kind}
	}
	v.rejectSum("cer", uri, ta, parent, err, sum)
}

func (v *validator) rejectSum(typ, uri, ta, parent string, err error, sum any) {
	v.mu.Lock()
	v.count[typ+" rejected"]++
	v.objects = append(v.objects, objInfo{Type: typ, URI: uri, TA: ta, Parent: parent, Status: "rejected", Reason: err.Error(), Summary: sum})
	v.mu.Unlock()
}

func (v *validator) valid(typ, uri, ta, parent string, raw []byte, nb, na time.Time, summary any) {
	sum := ""
	if raw != nil {
		sum = fmt.Sprintf("%x", sha256.Sum256(raw))
	}
	v.mu.Lock()
	v.count[typ+" valid"]++
	v.objects = append(v.objects, objInfo{Type: typ, URI: uri, SHA256: sum, TA: ta, Parent: parent,
		NotBefore: nb, NotAfter: na, Status: "valid", Summary: summary})
	v.mu.Unlock()
}

// ---- 공통 검사 ----

func (v *validator) checkValidity(nb, na time.Time) error {
	if v.Now.Before(nb) {
		return fmt.Errorf("certificate is not yet valid")
	}
	if v.Now.After(na) {
		return fmt.Errorf("certificate has expired")
	}
	return nil
}

// uriPath : rsync URI -> base 아래 파일 경로 (validURI 가 .. 을 이미 막음)
func uriPath(base, uri string) (string, error) {
	if !validURI(uri, "rsync://") {
		return "", fmt.Errorf("bad URI %q", uri)
	}
	return filepath.Join(base, filepath.FromSlash(strings.TrimPrefix(uri, "rsync://"))), nil
}

// checkIssued : 인증서 c 가 CA ca 가 낸 것이 맞는지 (서명, AKI, 폐기, 유효기간, CRLDP)
func (v *validator) checkIssued(ctx *caCtx, crl *rpkiCRL, crlURI string, c *rpkiCert) error {
	if !bytes.Equal(c.AKI, ctx.Cert.SKI) {
		return fmt.Errorf("AKI does not match issuer SKI")
	}
	if err := c.X509.CheckSignatureFrom(ctx.Cert.X509); err != nil {
		return fmt.Errorf("signature: %w", err)
	}
	if crl != nil && crl.Revoked[c.X509.SerialNumber.String()] {
		return fmt.Errorf("certificate is revoked")
	}
	if err := v.checkValidity(c.X509.NotBefore, c.X509.NotAfter); err != nil {
		return err
	}
	if c.CRLDP != crlURI {
		return fmt.Errorf("CRLDP %s does not match issuer CRL %s", c.CRLDP, crlURI)
	}
	if c.CAIssuers != ctx.URI {
		v.warn("AIA does not match issuer location", "aia "+c.CAIssuers+" issuer "+ctx.URI)
	}
	return nil
}

// resolveResources : inherit 를 부모 자원으로 바꾸고, 부모 자원 안에 있는지 확인
func resolveResources(c *rpkiCert, parent *caCtx) (ipResources, asResources, error) {
	var ips ipResources
	fams := []struct {
		child, par ipFamily
		out        *ipFamily
		name       string
	}{
		{c.IPs.V4, parent.IPs.V4, &ips.V4, "IPv4"},
		{c.IPs.V6, parent.IPs.V6, &ips.V6, "IPv6"},
	}
	for _, f := range fams {
		switch {
		case !f.child.Present:
		case f.child.Inherit:
			// 부모에 없는 체계를 inherit = 빈 자원 (rpki-client 와 같음, GBR EE 에 실제로 있음)
			*f.out = f.par
		default:
			for _, r := range f.child.Ranges {
				if !f.par.Present || !ipCovered(f.par.Ranges, r) {
					return ips, asResources{}, fmt.Errorf("%s resources not covered by issuer", f.name)
				}
			}
			*f.out = f.child
		}
	}
	var as asResources
	switch {
	case !c.ASs.Present:
	case c.ASs.Inherit:
		as = parent.ASs // 부모에 없으면 빈 자원
	default:
		for _, r := range c.ASs.Ranges {
			if !parent.ASs.Present || !asCovered(parent.ASs.Ranges, r) {
				return ips, as, fmt.Errorf("AS resources not covered by issuer")
			}
		}
		as = c.ASs
	}
	return ips, as, nil
}

func minTime(a, b time.Time) time.Time {
	if b.Before(a) {
		return b
	}
	return a
}

func maxTime(a, b time.Time) time.Time {
	if b.After(a) {
		return b
	}
	return a
}

// addUnsafe : 거부된 CA 의 IP 자원을 기록 (그 자원과 겹치는 다른 VRP = unsafe, A4)
func (v *validator) addUnsafe(caURI string, ips ipResources) {
	v.mu.Lock()
	for _, r := range ips.V4.Ranges {
		v.unsafe = append(v.unsafe, unsafeRange{caURI, true, r})
	}
	for _, r := range ips.V6.Ranges {
		v.unsafe = append(v.unsafe, unsafeRange{caURI, false, r})
	}
	v.mu.Unlock()
}

// ownIPs : 거부된 인증서의 IP 자원 (inherit 는 부모 것으로)
func ownIPs(c *rpkiCert, parent *caCtx) ipResources {
	ips := c.IPs
	if ips.V4.Inherit {
		ips.V4 = parent.IPs.V4
	}
	if ips.V6.Inherit {
		ips.V6 = parent.IPs.V6
	}
	return ips
}

// ---- CA 하나 ----

// mftEntry : manifest 에 나열되고 해시가 맞은 파일
type mftEntry struct {
	Name string
	URI  string
	Data []byte
}

func (v *validator) processCA(ctx caCtx) {
	c := ctx.Cert
	if ctx.Depth > maxCADepth {
		v.reject("mft", c.Manifest, ctx.TA, ctx.URI, fmt.Errorf("CA depth over %d", maxCADepth))
		v.addUnsafe(ctx.URI, ctx.IPs)
		return
	}
	// 같은 CA 판정은 인증서 자체로 : manifest URI 로 하면 아무 CA 가 남의 manifest URI 를 쓴 자식 CA 를 먼저 내세워
	// 진짜 CA 를 "duplicate" 로 빠뜨릴 수 있음 (11-05 검토 3). 순환은 같은 인증서 파일이 다시 나오는 것으로 끊김 (+ 깊이 상한)
	sum := sha256.Sum256(c.X509.Raw)
	v.mu.Lock()
	dup := v.seenCA[string(sum[:])]
	v.seenCA[string(sum[:])] = true
	v.mu.Unlock()
	if dup {
		v.warn("duplicate CA (same certificate)", ctx.URI)
		return
	}

	pp, fallback, err := v.publicationPoint(&ctx)
	if err != nil {
		v.reject("mft", c.Manifest, ctx.TA, ctx.URI, fmt.Errorf("no valid manifest available: %w", err))
		v.addUnsafe(ctx.URI, ctx.IPs)
		return
	}
	defer pp.done() // 나열된 파일을 다 쓴 뒤 바이트 예산을 돌려줌
	mft, crl, crlURI, files := pp.mft, pp.crl, pp.crlURI, pp.files
	if v.KeepCAs {
		v.mu.Lock()
		if v.caBySKI == nil {
			v.caBySKI = map[string][]*caRecord{}
		}
		v.caBySKI[string(c.SKI)] = append(v.caBySKI[string(c.SKI)], &caRecord{ctx, crl, crlURI})
		v.mu.Unlock()
	}
	mftSum := map[string]any{"number": mft.Number.String(), "files": len(mft.Files)}
	if fallback {
		mftSum["fallback"] = true // 새것이 틀려 직전 정상본으로 검증
	}
	v.valid("mft", c.Manifest, ctx.TA, ctx.URI, nil, mft.ThisUpdate, mft.NextUpdate, mftSum)
	v.valid("crl", crlURI, ctx.TA, ctx.URI, crl.X509.Raw, crl.ThisUpdate, crl.NextUpdate,
		map[string]any{"revoked": len(crl.Revoked)})

	// 이 CA 아래 객체의 만료 = 체인, manifest, CRL 중 가장 이른 것
	ch := chainTimes{
		NB:    maxTime(maxTime(ctx.NotBef, mft.ThisUpdate), crl.ThisUpdate),
		Exp:   minTime(minTime(ctx.Expires, mft.NextUpdate), crl.NextUpdate),
		Stale: minTime(minTime(ctx.Stale, mft.NextUpdate), crl.NextUpdate),
	}

	for _, f := range files {
		ext := strings.TrimPrefix(filepath.Ext(f.Name), ".")
		v.safeFile(&ctx, f, ext, func() {
			switch ext {
			case "crl":
				// 위에서 처리
			case "cer":
				v.processCert(&ctx, crl, crlURI, f, ch)
			case "roa", "asa", "spl", "gbr", "tak":
				v.processSigned(&ctx, crl, crlURI, f, ext, ch)
			default:
				v.inc("unknown file type " + ext)
			}
		})
	}
}

// safeFile : 나열된 파일 하나를 처리. panic 이면 그 파일만 거부하고 다음 파일로 (11-05 검토 13).
// 전에는 CA 전체를 거부로 적으면서도 그 전에 넣은 VRP / 띄운 자식 CA 는 그대로 나가 기록과 출력이 어긋났음.
// 결과를 넣는 곳은 v.mu 를 defer 로 풀어야 함 (panic 때 잠금이 남으면 아래 reject 가 멈춤)
func (v *validator) safeFile(ctx *caCtx, f mftEntry, ext string, fn func()) {
	defer func() {
		if p := recover(); p != nil {
			v.reject(ext, f.URI, ctx.TA, ctx.URI, fmt.Errorf("panic: %v %s", p, debug.Stack()))
		}
	}()
	fn()
}

// publicationPoint : 받은 캐시의 publication point. 틀리면 직전 정상본 (ValidDir, valid.go) 으로 다시. fallback = 직전 정상본을 씀
func (v *validator) publicationPoint(ctx *caCtx) (*pubPoint, bool, error) {
	c := ctx.Cert
	pp, err := v.loadPublicationPoint(ctx, func(uri string) (string, error) { return uriPath(ctx.Base, uri) }, v.ppBudget)
	if v.ValidDir == "" {
		return pp, false, err
	}
	dir := validPPDir(v.ValidDir, c)
	return v.withValid(dir, c.Manifest, pp, err, func() (*pubPoint, error) { return v.loadPublicationPoint(ctx, validAt(dir), nil) })
}

// withValid : 새로 받은 것 (pp, err) 과 저장본 (dir, loadOld 로 다시 검증) 중 쓸 것을 고르고, 새것이 맞으면 저장
//   - 저장본 없음 : 새것 그대로 (맞으면 저장)
//   - 새것이 맞고 번호가 같거나 큼 : 새것 (저장)
//   - 새것이 틀림, 또는 번호가 작아짐 : 저장본이 지금도 유효하면 저장본 (fallback)
//   - 번호가 작아졌는데 저장본이 이미 유효하지 않음 : 되돌릴 대상이 없으니 새것을 받음 (CA 를 다시 만듦 등, 11-05 검토 4)
func (v *validator) withValid(dir, mftURI string, pp *pubPoint, err error, loadOld func() (*pubPoint, error)) (*pubPoint, bool, error) {
	v.mu.Lock()
	v.validSeen[dir] = true
	lk := v.validLock[dir]
	if lk == nil {
		lk = &sync.Mutex{}
		v.validLock[dir] = lk
	}
	v.mu.Unlock()
	lk.Lock()
	defer lk.Unlock()

	store := func() {
		if serr := storeValid(dir, path.Base(mftURI), pp); serr != nil {
			v.warn("cannot store valid publication point", mftURI+": "+serr.Error())
		}
	}
	prev := storedNumber(dir)
	if prev == nil {
		if err == nil {
			store()
		}
		return pp, false, err
	}
	back := err == nil && pp.mft.Number.Cmp(prev) < 0
	if err == nil && !back {
		store()
		return pp, false, nil
	}
	old, oerr := loadOld()
	if back {
		if oerr != nil {
			v.warn("manifest number went back, previous copy no longer valid: accepted",
				fmt.Sprintf("%s: %s < %s", mftURI, pp.mft.Number, prev))
			store()
			return pp, false, nil
		}
		err = fmt.Errorf("manifest number %s lower than previous %s", pp.mft.Number, prev)
	}
	if oerr != nil {
		return nil, false, fmt.Errorf("%w (previous valid copy: %v)", err, oerr)
	}
	v.warn("manifest failed, using previous valid publication point", mftURI+": "+err.Error())
	pp.done() // 번호가 작아진 새것 (틀린 새것은 이미 nil)
	return old, true, nil
}

// pubPoint : 확인을 마친 publication point (manifest + CRL + 나열된 파일)
type pubPoint struct {
	mft    *rpkiManifest
	mftDER []byte
	crl    *rpkiCRL
	crlURI string
	files  []mftEntry
	paths  map[string]string // 파일 이름 -> 읽은 곳 (직전 정상본 저장 때 hard link 원본)

	budget *byteBudget // 잡은 바이트를 돌려줄 곳 (nil = 안 잡음)
	held   int64
}

// done : 나열된 파일을 다 쓴 뒤 잡은 바이트를 돌려줌 (여러 번 불러도 한 번만, nil 이어도 됨)
func (pp *pubPoint) done() {
	if pp != nil && pp.budget != nil {
		pp.budget.release(pp.held)
		pp.budget, pp.held = nil, 0
	}
}

// loadPublicationPoint : manifest + CRL + 나열된 파일 전부 (하나라도 틀리면 오류 = CA 전체 버림)
// at : 객체 URI -> 읽을 파일 (받은 캐시 = uriPath(ctx.Base, uri), 직전 정상본 = 그 폴더의 파일 이름)
// budget : 나열된 파일을 읽기 전에 그 크기만큼 잡음 (nil = 안 잡음 : 직전 정상본으로 다시 읽을 때, 드문 길이라 기다리다 서로 막히지 않게)
func (v *validator) loadPublicationPoint(ctx *caCtx, at func(uri string) (string, error), budget *byteBudget) (_ *pubPoint, err error) {
	c := ctx.Cert
	paths := map[string]string{}
	mp, err := at(c.Manifest)
	if err != nil {
		return nil, err
	}
	paths[path.Base(c.Manifest)] = mp
	der, err := readObject(mp)
	if err != nil {
		return nil, err
	}
	mft, err := parseManifest(der)
	if err != nil {
		return nil, err
	}
	ee := mft.EE
	if !bytes.Equal(ee.AKI, c.SKI) {
		return nil, fmt.Errorf("manifest EE AKI does not match CA SKI")
	}
	if err := ee.X509.CheckSignatureFrom(c.X509); err != nil {
		return nil, fmt.Errorf("manifest EE signature: %w", err)
	}
	if err := v.checkValidity(ee.X509.NotBefore, ee.X509.NotAfter); err != nil {
		return nil, fmt.Errorf("manifest EE: %w", err)
	}
	if v.Now.Before(mft.ThisUpdate) {
		return nil, fmt.Errorf("manifest thisUpdate in the future")
	}
	if v.Now.After(mft.NextUpdate) {
		return nil, fmt.Errorf("manifest is stale (nextUpdate %s)", mft.NextUpdate.Format(time.RFC3339))
	}
	if ee.SignedObject != c.Manifest {
		v.warn("manifest EE signedObject does not match location", c.Manifest)
	}
	v.warnSKI(ee, c.Manifest)

	// 나열된 파일 : 같은 폴더 (manifest 위치 기준), 해시 확인.
	// 먼저 크기만 더해 상한 확인 + 그만큼 잡음 (maxPPBytes / maxPPInFlight). 읽은 양이 잰 것보다 크면 (그 사이 바뀜) 오류
	base := c.Manifest[:strings.LastIndexByte(c.Manifest, '/')+1]
	total := int64(len(der))
	for _, mf := range mft.Files {
		p, err := at(base + mf.Name)
		if err != nil {
			return nil, err
		}
		paths[mf.Name] = p
		st, err := os.Stat(p)
		if err != nil {
			return nil, fmt.Errorf("listed file %s: %w", mf.Name, err)
		}
		if total += st.Size(); total > maxPPBytes {
			return nil, fmt.Errorf("publication point larger than %d MB", maxPPBytes>>20)
		}
	}
	pp := &pubPoint{mft: mft, mftDER: der, paths: paths}
	if budget != nil {
		budget.acquire(total)
		pp.budget, pp.held = budget, total
		defer func() {
			if err != nil {
				pp.done()
			}
		}()
	}
	read := int64(len(der))
	var files []mftEntry
	var crlEntry *mftEntry
	for _, mf := range mft.Files {
		uri := base + mf.Name
		data, err := readObject(paths[mf.Name])
		if err != nil {
			return nil, fmt.Errorf("listed file %s: %w", mf.Name, err)
		}
		if read += int64(len(data)); read > total {
			return nil, fmt.Errorf("listed file %s: changed while reading", mf.Name)
		}
		if sha256.Sum256(data) != mf.Hash {
			return nil, fmt.Errorf("listed file %s: hash mismatch", mf.Name)
		}
		files = append(files, mftEntry{mf.Name, uri, data})
		if strings.HasSuffix(mf.Name, ".crl") {
			if crlEntry != nil {
				return nil, fmt.Errorf("more than one CRL")
			}
			crlEntry = &files[len(files)-1]
		}
	}
	if crlEntry == nil {
		return nil, fmt.Errorf("no CRL in manifest")
	}
	crlURI := crlEntry.URI
	crl, err := parseCRL(crlEntry.Data)
	if err != nil {
		return nil, fmt.Errorf("CRL: %w", err)
	}
	if !bytes.Equal(crl.AKI, c.SKI) {
		return nil, fmt.Errorf("CRL AKI does not match CA SKI")
	}
	if err := crl.X509.CheckSignatureFrom(c.X509); err != nil {
		return nil, fmt.Errorf("CRL signature: %w", err)
	}
	if v.Now.Before(crl.ThisUpdate) {
		return nil, fmt.Errorf("CRL thisUpdate in the future")
	}
	if v.Now.After(crl.NextUpdate) {
		return nil, fmt.Errorf("CRL has expired")
	}
	if crl.Revoked[ee.X509.SerialNumber.String()] {
		return nil, fmt.Errorf("manifest EE is revoked")
	}
	pp.crl, pp.crlURI, pp.files = crl, crlURI, files
	return pp, nil
}

// readObject : 크기 상한을 지키며 파일 읽기
func readObject(p string) ([]byte, error) {
	st, err := os.Stat(p)
	if err != nil {
		return nil, err
	}
	if !st.Mode().IsRegular() || st.Size() > maxObjectSize {
		return nil, fmt.Errorf("not a regular file or too large")
	}
	return os.ReadFile(p)
}

// ---- 자식 인증서 (.cer) ----

func (v *validator) processCert(ctx *caCtx, crl *rpkiCRL, crlURI string, f mftEntry, ch chainTimes) {
	c, err := parseCert(f.Data, false)
	if err == nil {
		err = v.checkIssued(ctx, crl, crlURI, c)
	}
	var ips ipResources
	var as asResources
	if err == nil {
		ips, as, err = resolveResources(c, ctx)
	}
	if err != nil {
		v.rejectCert(f.URI, ctx.TA, ctx.URI, err, c, "")
		if c != nil && c.Kind == kindCA {
			v.addUnsafe(f.URI, ownIPs(c, ctx))
		}
		return
	}
	v.warnSKI(c, f.URI)
	exp := minTime(ch.Exp, c.X509.NotAfter)

	switch c.Kind {
	case kindCA:
		if c.SelfSigned {
			v.rejectCert(f.URI, ctx.TA, ctx.URI, fmt.Errorf("self-signed certificate below TA"), c, "")
			return
		}
		v.valid("cer", f.URI, ctx.TA, ctx.URI, f.Data, c.X509.NotBefore, c.X509.NotAfter,
			map[string]any{"kind": "CA", "repository": c.CARepository, "notify": c.Notify, "resources": newResSummary(ips, as)})
		v.spawn(caCtx{Cert: c, URI: f.URI, TA: ctx.TA, Depth: ctx.Depth + 1, IPs: ips, ASs: as,
			Expires: exp, NotBef: maxTime(ch.NB, c.X509.NotBefore), Stale: ch.Stale})
	case kindRouter:
		keys, err := c.routerKeys()
		if err != nil {
			v.rejectCert(f.URI, ctx.TA, ctx.URI, err, c, "")
			return
		}
		var asns []uint32
		v.mu.Lock()
		for _, k := range keys {
			v.rkeys = append(v.rkeys, routerKeyOut{k, ctx.TA, exp, f.URI})
			asns = append(asns, k.ASN)
		}
		v.mu.Unlock()
		v.valid("cer", f.URI, ctx.TA, ctx.URI, f.Data, c.X509.NotBefore, c.X509.NotAfter,
			map[string]any{"kind": "router", "asns": asns, "ski": fmt.Sprintf("%X", c.SKI)})
	}
}

// ---- 서명 객체 ----

func (v *validator) processSigned(ctx *caCtx, crl *rpkiCRL, crlURI string, f mftEntry, ext string, ch chainTimes) {
	var so *signedObject
	var summary any
	var err error
	var roa *rpkiROA
	var aspa *rpkiASPA
	var tak *rpkiTAK

	switch ext {
	case "roa":
		if roa, err = parseROA(f.Data); err == nil {
			so = roa.signedObject
		}
	case "asa":
		if aspa, err = parseASPA(f.Data); err == nil {
			so = aspa.signedObject
			summary = map[string]any{"customer": aspa.Customer, "providers": aspa.Providers}
		}
	case "spl":
		var s *rpkiSPL
		if s, err = parseSPL(f.Data); err == nil {
			so = s.signedObject
			summary = map[string]any{"asn": s.ASN, "prefixes": s.Prefixes}
		}
	case "gbr":
		var g *rpkiGBR
		if g, err = parseGBR(f.Data); err == nil {
			so = g.signedObject
			summary = map[string]any{"vcard": g.Props, "warnings": g.Warn}
		}
	case "tak":
		if tak, err = parseTAK(f.Data); err == nil {
			so = tak.signedObject
			s := map[string]any{"current": fmt.Sprintf("%X", tak.Current.SKI)}
			if tak.Predecessor != nil {
				s["predecessor"] = fmt.Sprintf("%X", tak.Predecessor.SKI)
			}
			if tak.Successor != nil {
				s["successor"] = fmt.Sprintf("%X", tak.Successor.SKI)
			}
			summary = s
		}
	}

	// EE 인증서 = CA 가 낸 것인지, 자원
	var ips ipResources
	if err == nil {
		err = v.checkIssued(ctx, crl, crlURI, so.EE)
	}
	if err == nil {
		ips, _, err = resolveResources(so.EE, ctx)
	}
	if err == nil && roa != nil {
		err = roaCovered(roa, ips)
	}
	if err != nil {
		v.reject(ext, f.URI, ctx.TA, ctx.URI, err)
		return
	}
	if so.EE.SignedObject != f.URI {
		v.warn("EE signedObject does not match location", f.URI)
	}
	v.warnSKI(so.EE, f.URI)
	if tak != nil {
		v.checkTAK(ctx, tak, f.URI)
	}
	ee := so.EE.X509
	exp := minTime(ch.Exp, ee.NotAfter)

	v.addSigned(ctx, f, roa, aspa, ee, exp, ch, &summary)
	v.valid(ext, f.URI, ctx.TA, ctx.URI, f.Data, ee.NotBefore, ee.NotAfter, summary)
}

// addSigned : ROA 의 VRP / ASPA 의 provider 를 결과에 넣음 (검사가 다 끝난 뒤 한 번에, 잠금은 defer 로 = panic 이어도 풀림)
func (v *validator) addSigned(ctx *caCtx, f mftEntry, roa *rpkiROA, aspa *rpkiASPA, ee *x509.Certificate, exp time.Time, ch chainTimes, summary *any) {
	v.mu.Lock()
	defer v.mu.Unlock()
	switch {
	case roa != nil:
		src := vrpSource{URI: f.URI, TA: ctx.TA, NB: ee.NotBefore.Unix(), NA: ee.NotAfter.Unix(),
			ChainNB: maxTime(ch.NB, ee.NotBefore).Unix(), ChainNA: exp.Unix(), Stale: ch.Stale.Unix()}
		pfx := make([]roaPrefixOut, 0, len(roa.VRPs))
		for _, r := range roa.VRPs {
			k := vrpKey{r.ASN, r.Prefix, r.MaxLength, ctx.TA}
			// 같은 VRP 가 여러 ROA 에 있으면 늦게 만료되는 것
			if old, ok := v.vrps[k]; !ok || exp.After(old) {
				v.vrps[k] = exp
			}
			v.vrpSrc[k] = append(v.vrpSrc[k], src)
			pfx = append(pfx, roaPrefixOut{r.Prefix, r.MaxLength})
		}
		*summary = map[string]any{"asn": roa.ASN, "vrps": len(roa.VRPs), "prefixes": pfx}
	case aspa != nil:
		k := aspaKey{aspa.Customer, ctx.TA}
		a := v.aspas[k]
		if a == nil {
			a = &aspaOut{Providers: map[uint32]bool{}, Expires: exp}
			v.aspas[k] = a
		}
		for _, p := range aspa.Providers {
			a.Providers[p] = true
		}
		if exp.After(a.Expires) {
			a.Expires = exp
		}
	}
}

// roaCovered : ROA 의 prefix 가 모두 EE 의 (inherit 푼) IP 자원 안에 있는지
func roaCovered(roa *rpkiROA, ips ipResources) error {
	for _, r := range roa.VRPs {
		fam := ips.V6
		if r.Prefix.Addr().Is4() {
			fam = ips.V4
		}
		if !fam.Present || !ipCovered(fam.Ranges, prefixRange(r.Prefix)) {
			return fmt.Errorf("ROA prefix %s not covered by EE resources", r.Prefix)
		}
	}
	return nil
}
