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
	"fmt"
	"net/netip"
	"os"
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

	sem chan struct{}
	wg  sync.WaitGroup

	mu       sync.Mutex
	vrps     map[vrpKey]time.Time
	vrpSrc   map[vrpKey][]vrpSource
	unsafe   []unsafeRange
	aspas    map[aspaKey]*aspaOut
	rkeys    []routerKeyOut
	objects  []objInfo
	seenCA   map[string]bool     // manifest URI -> 이미 처리 (같은 CA 두 번 방지)
	count    map[string]int      // 통계 (종류별 valid / rejected, 경고)
	warnEx   map[string][]string // 경고마다 예시 몇 개 (원인 확인용)
	failedTA []string
	caBySKI  map[string][]*caRecord // KeepCAs 일 때만
}

func newValidator(cacheDir string, now time.Time, workers int) *validator {
	return &validator{
		CacheDir: cacheDir,
		Now:      now,
		Workers:  workers,
		sem:      make(chan struct{}, workers),
		vrps:     map[vrpKey]time.Time{},
		vrpSrc:   map[vrpKey][]vrpSource{},
		aspas:    map[aspaKey]*aspaOut{},
		seenCA:   map[string]bool{},
		count:    map[string]int{},
		warnEx:   map[string][]string{},
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
			v.reject("cer", uri, t.Name, "", err)
			v.mu.Lock()
			v.failedTA = append(v.failedTA, t.Name)
			v.mu.Unlock()
			continue
		}
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
		// 저장소 수집은 검증 동시 수 (sem) 밖에서 (기다리는 동안 다른 CA 검증이 돌게)
		ctx.Base = v.CacheDir
		if v.Fetch != nil {
			ctx.Base = v.Fetch.ensure(ctx.Cert)
		}
		v.sem <- struct{}{}
		defer func() {
			if p := recover(); p != nil {
				v.reject("mft", ctx.Cert.Manifest, ctx.TA, ctx.URI, fmt.Errorf("panic: %v %s", p, debug.Stack()))
				v.addUnsafe(ctx.URI, ctx.IPs)
			}
			<-v.sem
			v.wg.Done()
		}()
		v.processCA(ctx)
	}()
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

func (v *validator) reject(typ, uri, ta, parent string, err error) {
	v.mu.Lock()
	v.count[typ+" rejected"]++
	v.objects = append(v.objects, objInfo{Type: typ, URI: uri, TA: ta, Parent: parent, Status: "rejected", Reason: err.Error()})
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
	v.mu.Lock()
	dup := v.seenCA[c.Manifest]
	v.seenCA[c.Manifest] = true
	v.mu.Unlock()
	if dup {
		v.warn("duplicate CA (same manifest URI)", c.Manifest)
		return
	}

	mft, crl, crlURI, files, err := v.loadPublicationPoint(&ctx)
	if err != nil {
		v.reject("mft", c.Manifest, ctx.TA, ctx.URI, fmt.Errorf("no valid manifest available: %w", err))
		v.addUnsafe(ctx.URI, ctx.IPs)
		return
	}
	if v.KeepCAs {
		v.mu.Lock()
		if v.caBySKI == nil {
			v.caBySKI = map[string][]*caRecord{}
		}
		v.caBySKI[string(c.SKI)] = append(v.caBySKI[string(c.SKI)], &caRecord{ctx, crl, crlURI})
		v.mu.Unlock()
	}
	v.valid("mft", c.Manifest, ctx.TA, ctx.URI, nil, mft.ThisUpdate, mft.NextUpdate,
		map[string]any{"number": mft.Number.String(), "files": len(mft.Files)})
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
	}
}

// loadPublicationPoint : manifest + CRL + 나열된 파일 전부 (하나라도 틀리면 오류 = CA 전체 버림)
func (v *validator) loadPublicationPoint(ctx *caCtx) (*rpkiManifest, *rpkiCRL, string, []mftEntry, error) {
	c := ctx.Cert
	mp, err := uriPath(ctx.Base, c.Manifest)
	if err != nil {
		return nil, nil, "", nil, err
	}
	der, err := readObject(mp)
	if err != nil {
		return nil, nil, "", nil, err
	}
	mft, err := parseManifest(der)
	if err != nil {
		return nil, nil, "", nil, err
	}
	ee := mft.EE
	if !bytes.Equal(ee.AKI, c.SKI) {
		return nil, nil, "", nil, fmt.Errorf("manifest EE AKI does not match CA SKI")
	}
	if err := ee.X509.CheckSignatureFrom(c.X509); err != nil {
		return nil, nil, "", nil, fmt.Errorf("manifest EE signature: %w", err)
	}
	if err := v.checkValidity(ee.X509.NotBefore, ee.X509.NotAfter); err != nil {
		return nil, nil, "", nil, fmt.Errorf("manifest EE: %w", err)
	}
	if v.Now.Before(mft.ThisUpdate) {
		return nil, nil, "", nil, fmt.Errorf("manifest thisUpdate in the future")
	}
	if v.Now.After(mft.NextUpdate) {
		return nil, nil, "", nil, fmt.Errorf("manifest is stale (nextUpdate %s)", mft.NextUpdate.Format(time.RFC3339))
	}
	if ee.SignedObject != c.Manifest {
		v.warn("manifest EE signedObject does not match location", c.Manifest)
	}

	// 나열된 파일 : 같은 폴더 (manifest 위치 기준), 해시 확인
	base := c.Manifest[:strings.LastIndexByte(c.Manifest, '/')+1]
	var files []mftEntry
	var crlEntry *mftEntry
	for _, mf := range mft.Files {
		uri := base + mf.Name
		p, err := uriPath(ctx.Base, uri)
		if err != nil {
			return nil, nil, "", nil, err
		}
		data, err := readObject(p)
		if err != nil {
			return nil, nil, "", nil, fmt.Errorf("listed file %s: %w", mf.Name, err)
		}
		if sha256.Sum256(data) != mf.Hash {
			return nil, nil, "", nil, fmt.Errorf("listed file %s: hash mismatch", mf.Name)
		}
		files = append(files, mftEntry{mf.Name, uri, data})
		if strings.HasSuffix(mf.Name, ".crl") {
			if crlEntry != nil {
				return nil, nil, "", nil, fmt.Errorf("more than one CRL")
			}
			crlEntry = &files[len(files)-1]
		}
	}
	if crlEntry == nil {
		return nil, nil, "", nil, fmt.Errorf("no CRL in manifest")
	}
	crlURI := crlEntry.URI
	crl, err := parseCRL(crlEntry.Data)
	if err != nil {
		return nil, nil, "", nil, fmt.Errorf("CRL: %w", err)
	}
	if !bytes.Equal(crl.AKI, c.SKI) {
		return nil, nil, "", nil, fmt.Errorf("CRL AKI does not match CA SKI")
	}
	if err := crl.X509.CheckSignatureFrom(c.X509); err != nil {
		return nil, nil, "", nil, fmt.Errorf("CRL signature: %w", err)
	}
	if v.Now.Before(crl.ThisUpdate) {
		return nil, nil, "", nil, fmt.Errorf("CRL thisUpdate in the future")
	}
	if v.Now.After(crl.NextUpdate) {
		return nil, nil, "", nil, fmt.Errorf("CRL has expired")
	}
	if crl.Revoked[ee.X509.SerialNumber.String()] {
		return nil, nil, "", nil, fmt.Errorf("manifest EE is revoked")
	}
	return mft, crl, crlURI, files, nil
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
		v.reject("cer", f.URI, ctx.TA, ctx.URI, err)
		if c != nil && c.Kind == kindCA {
			v.addUnsafe(f.URI, ownIPs(c, ctx))
		}
		return
	}
	exp := minTime(ch.Exp, c.X509.NotAfter)

	switch c.Kind {
	case kindCA:
		if c.SelfSigned {
			v.reject("cer", f.URI, ctx.TA, ctx.URI, fmt.Errorf("self-signed certificate below TA"))
			return
		}
		v.valid("cer", f.URI, ctx.TA, ctx.URI, f.Data, c.X509.NotBefore, c.X509.NotAfter,
			map[string]any{"kind": "CA", "repository": c.CARepository, "notify": c.Notify, "resources": newResSummary(ips, as)})
		v.spawn(caCtx{Cert: c, URI: f.URI, TA: ctx.TA, Depth: ctx.Depth + 1, IPs: ips, ASs: as,
			Expires: exp, NotBef: maxTime(ch.NB, c.X509.NotBefore), Stale: ch.Stale})
	case kindRouter:
		keys, err := c.routerKeys()
		if err != nil {
			v.reject("cer", f.URI, ctx.TA, ctx.URI, err)
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
		var t *rpkiTAK
		if t, err = parseTAK(f.Data); err == nil {
			so = t.signedObject
			s := map[string]any{"current": fmt.Sprintf("%X", t.Current.SKI)}
			if t.Predecessor != nil {
				s["predecessor"] = fmt.Sprintf("%X", t.Predecessor.SKI)
			}
			if t.Successor != nil {
				s["successor"] = fmt.Sprintf("%X", t.Successor.SKI)
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
	ee := so.EE.X509
	exp := minTime(ch.Exp, ee.NotAfter)

	v.mu.Lock()
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
		summary = map[string]any{"asn": roa.ASN, "vrps": len(roa.VRPs), "prefixes": pfx}
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
	v.mu.Unlock()
	v.valid(ext, f.URI, ctx.TA, ctx.URI, f.Data, ee.NotBefore, ee.NotAfter, summary)
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
