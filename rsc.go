package main

// rsc.go : RPKI Signed Checklist (RFC 9323, .sig)
//
// "이 파일들 (해시 목록) 은 이 IP / AS 자원의 주인이 서명했다" 는 서명 객체.
// 저장소에 게시하지 않고 파일로 주고받음 (예 : 상대 회사에 보내는 LOA 문서 + .sig).
// 그래서 검증 트리를 돌 때가 아니라 단일 파일 확인 모드로 확인함
//   haetae -rsc <x.sig> [-cache <캐시> -tal <TAL 폴더> [-P <epoch>]] [확인할 파일 ...]
//   -cache 가 있으면 검증 트리를 한 번 돌아 EE 를 낸 CA (AKI = CA SKI) 를 찾고 체인까지 확인
//
//   RpkiSignedChecklist ::= SEQUENCE {          (EXPLICIT TAGS)
//     version [0] INTEGER DEFAULT 0,
//     resources ResourceBlock,
//     digestAlgorithm AlgorithmIdentifier,       (sha256)
//     checkList SEQUENCE (1..MAX) OF FileNameAndHash }
//   FileNameAndHash ::= SEQUENCE { fileName IA5String OPTIONAL, hash OCTET STRING }
//   ResourceBlock ::= SEQUENCE { asID [0] ConstrainedASIdentifiers OPTIONAL,
//                                ipAddrBlocks [1] ConstrainedIPAddrBlocks OPTIONAL }  (하나는 있어야 함)
//   Constrained* = RFC 3779 와 같은 모양에서 inherit 와 SAFI 를 뺀 것
// EE 인증서 : SIA 없음 (게시 안 하므로), 자원 확장에 inherit 금지, RSC 자원 ⊆ EE 자원
//
// 파일 확인 (6 절) : 파일의 SHA-256 이 checkList 에 있어야 하고,
//   파일 이름을 아는 경우 해시가 맞는 항목 중 정확히 하나의 fileName 이 그 파일 이름이어야 함.
//   "-" (표준 입력) 은 이름을 모르는 경우 -> fileName 없는 항목과 맞아야 함

import (
	"bytes"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

var oidCTRSC = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 1, 48}

// checkList 항목 수 상한 (rpki-client 와 같은 크기)
const maxRSCEntries = 100000

// 표준 입력으로 받는 파일 크기 상한
const maxRSCFileSize = 1 << 30

type rscEntry struct {
	Name string // 없으면 ""
	Hash []byte // SHA-256 (32 바이트)
}

type rpkiRSC struct {
	*signedObject
	IPs     ipResources // inherit 없음
	ASs     asResources
	Entries []rscEntry
}

func parseRSC(der []byte) (*rpkiRSC, error) {
	so, err := parseSignedObjectOpt(der, oidCTRSC, true)
	if err != nil {
		return nil, err
	}
	r := &rpkiRSC{signedObject: so}

	top, err := derOne(so.Content)
	if err != nil {
		return nil, err
	}
	f, err := derSeq(top, 3, 4)
	if err != nil {
		return nil, fmt.Errorf("RSC: %w", err)
	}
	if len(f) == 4 {
		// version 은 0 만 있고 DEFAULT 0 이라 DER 에서는 빠져야 함
		return nil, fmt.Errorf("RSC version present (only v0)")
	}
	if err := r.parseResources(f[0]); err != nil {
		return nil, err
	}
	if oid, err := algID(f[1]); err != nil || !oid.Equal(oidSHA256) {
		return nil, fmt.Errorf("RSC digestAlgorithm not sha256")
	}
	if err := r.parseCheckList(f[2]); err != nil {
		return nil, err
	}

	// EE : 자원 확장에 inherit 금지 (5 절 2, 3), RSC 자원 ⊆ EE 자원
	ee := so.EE
	if ee.IPs.V4.Inherit || ee.IPs.V6.Inherit || ee.ASs.Inherit {
		return nil, fmt.Errorf("RSC EE resources with inherit")
	}
	for _, x := range r.ASs.Ranges {
		if !ee.ASs.Present || !asCovered(ee.ASs.Ranges, x) {
			return nil, fmt.Errorf("RSC AS resources not covered by EE")
		}
	}
	fams := []struct {
		rsc, ee ipFamily
		name    string
	}{{r.IPs.V4, ee.IPs.V4, "IPv4"}, {r.IPs.V6, ee.IPs.V6, "IPv6"}}
	for _, fm := range fams {
		for _, x := range fm.rsc.Ranges {
			if !fm.ee.Present || !ipCovered(fm.ee.Ranges, x) {
				return nil, fmt.Errorf("RSC %s resources not covered by EE", fm.name)
			}
		}
	}
	return r, nil
}

// parseResources : ResourceBlock. 두 [n] 은 EXPLICIT 이라 안쪽은 RFC 3779 확장 값과 같은 DER
func (r *rpkiRSC) parseResources(n derNode) error {
	parts, err := derSeq(n, 1, 2)
	if err != nil {
		return fmt.Errorf("RSC ResourceBlock: %w", err)
	}
	last := -1
	for _, p := range parts {
		if p.Class != classContext || !p.Constructed || p.Tag <= last || p.Tag > 1 {
			return fmt.Errorf("RSC ResourceBlock: unexpected element")
		}
		last = p.Tag
		inner, err := explicit(p, p.Tag)
		if err != nil {
			return err
		}
		if p.Tag == 0 {
			if r.ASs, err = parseASIdentifiers(inner.Full); err != nil {
				return fmt.Errorf("RSC asID: %w", err)
			}
			if r.ASs.Inherit || len(r.ASs.Ranges) == 0 {
				return fmt.Errorf("RSC asID inherit or empty")
			}
			continue
		}
		if err := checkAFIOrder(inner); err != nil {
			return err
		}
		if r.IPs, err = parseIPAddrBlocks(inner.Full); err != nil {
			return fmt.Errorf("RSC ipAddrBlocks: %w", err)
		}
		if r.IPs.V4.Inherit || r.IPs.V6.Inherit {
			return fmt.Errorf("RSC ipAddrBlocks inherit")
		}
	}
	return nil
}

// checkAFIOrder : ConstrainedIPAddrBlocks 는 AFI 오름차순 (IPv4 먼저, 4.2.2 절)
func checkAFIOrder(n derNode) error {
	fams, err := derSeq(n, 1, 2)
	if err != nil {
		return fmt.Errorf("RSC ipAddrBlocks: %w", err)
	}
	prev := ""
	for _, f := range fams {
		fc, err := derSeq(f, 2, 2)
		if err != nil {
			return fmt.Errorf("RSC IPAddressFamily: %w", err)
		}
		afi, err := derOctets(fc[0])
		if err != nil {
			return err
		}
		if string(afi) <= prev {
			return fmt.Errorf("RSC ipAddrBlocks not in AFI order")
		}
		prev = string(afi)
	}
	return nil
}

// parseCheckList : 이름은 Portable Filename 글자만, 이름 있는 항목끼리 이름이 겹치면 안 되고,
// 이름 없는 항목끼리 해시가 겹치면 안 됨 (4.4.1 절)
func (r *rpkiRSC) parseCheckList(n derNode) error {
	items, err := derSeq(n, 1, maxRSCEntries)
	if err != nil {
		return fmt.Errorf("RSC checkList: %w", err)
	}
	names := map[string]bool{}
	hashes := map[string]bool{}
	for _, it := range items {
		fe, err := derSeq(it, 1, 2)
		if err != nil {
			return fmt.Errorf("RSC FileNameAndHash: %w", err)
		}
		var e rscEntry
		if len(fe) == 2 {
			if !fe[0].is(tagIA5String) || fe[0].Constructed || !portableFilename(string(fe[0].Body)) {
				return fmt.Errorf("RSC FileNameAndHash: bad filename")
			}
			e.Name = string(fe[0].Body)
			if names[e.Name] {
				return fmt.Errorf("RSC checkList: duplicate filename %q", e.Name)
			}
			names[e.Name] = true
		}
		if e.Hash, err = derOctets(fe[len(fe)-1]); err != nil {
			return fmt.Errorf("RSC hash: %w", err)
		}
		if len(e.Hash) != sha256.Size {
			return fmt.Errorf("RSC hash: invalid SHA256 length %d", len(e.Hash))
		}
		if e.Name == "" {
			if hashes[string(e.Hash)] {
				return fmt.Errorf("RSC checkList: duplicate hash without filename")
			}
			hashes[string(e.Hash)] = true
		}
		r.Entries = append(r.Entries, e)
	}
	return nil
}

// portableFilename : a-z A-Z 0-9 . _ - 만 (POSIX Portable Filename Character Set)
func portableFilename(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '.', c == '_', c == '-':
		default:
			return false
		}
	}
	return true
}

// checkFile : 파일 하나 확인 (6 절, filename-aware). 맞으면 nil
func (r *rpkiRSC) checkFile(name string, data []byte) error {
	h := sha256.Sum256(data)
	matched, named := 0, 0
	for _, e := range r.Entries {
		if !bytes.Equal(e.Hash, h[:]) {
			continue
		}
		matched++
		if e.Name == name {
			named++
		}
	}
	switch {
	case matched == 0:
		return fmt.Errorf("hash %s not in checkList", hex.EncodeToString(h[:8]))
	case named != 1:
		return fmt.Errorf("hash matches but no checkList entry named %q", name)
	}
	return nil
}

// ---- 체인 확인 (검증 트리에서 찾은 CA) ----

// caRecord : 검증을 통과한 CA 하나 (validator.KeepCAs 일 때만 모음)
type caRecord struct {
	Ctx    caCtx
	CRL    *rpkiCRL
	CRLURI string
}

// checkChain : EE 를 낸 CA 를 찾아 서명 / 폐기 / 유효기간 / CRLDP / 자원 확인. 맞은 CA 를 돌려줌
func (r *rpkiRSC) checkChain(v *validator) (*caRecord, error) {
	recs := v.caBySKI[string(r.EE.AKI)]
	if len(recs) == 0 {
		return nil, fmt.Errorf("issuer CA (SKI %X) not found among validated CAs", r.EE.AKI)
	}
	var lastErr error
	for _, rec := range recs {
		err := v.checkIssued(&rec.Ctx, rec.CRL, rec.CRLURI, r.EE)
		if err == nil {
			_, _, err = resolveResources(r.EE, &rec.Ctx)
		}
		if err == nil {
			// 체인 위쪽의 가장 이른 만료 (manifest / CRL nextUpdate 포함) 도 지나지 않았는지
			if v.Now.After(rec.Ctx.Expires) {
				err = fmt.Errorf("issuer chain expired %s", rec.Ctx.Expires.Format(time.RFC3339))
			}
		}
		if err == nil {
			return rec, nil
		}
		lastErr = err
	}
	return nil, lastErr
}

// ---- 단일 파일 확인 모드 ----

func runRSC(rscPath string, files []string, cacheDir, talDir string, evalTime int64, workers int) int {
	der, err := readObject(rscPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	now := time.Now()
	if evalTime != 0 {
		now = time.Unix(evalTime, 0)
	}
	fail := false
	r, err := parseRSC(der)
	if err != nil {
		fmt.Printf("RSC        : %s\n결과       : 실패 (%v)\n", rscPath, err)
		return 1
	}
	ee := r.EE.X509
	fmt.Printf("RSC        : %s\n", rscPath)
	fmt.Printf("EE SKI     : %X\n", r.EE.SKI)
	fmt.Printf("EE AKI     : %X\n", r.EE.AKI)
	fmt.Printf("EE 유효기간 : %s ~ %s\n", ee.NotBefore.UTC().Format(time.RFC3339), ee.NotAfter.UTC().Format(time.RFC3339))
	if !r.SigningTime.IsZero() {
		fmt.Printf("signingTime: %s\n", r.SigningTime.UTC().Format(time.RFC3339))
	}
	res := newResSummary(r.IPs, r.ASs)
	fmt.Printf("자원       : AS %s / IPv4 %s / IPv6 %s\n", listOrDash(res.ASN), listOrDash(res.IPv4), listOrDash(res.IPv6))
	fmt.Printf("checkList  : %d 개\n", len(r.Entries))
	for _, e := range r.Entries {
		n := e.Name
		if n == "" {
			n = "(이름 없음)"
		}
		fmt.Printf("  %s  %s\n", hex.EncodeToString(e.Hash), n)
	}

	// EE 유효기간 (체인을 안 볼 때도)
	if now.Before(ee.NotBefore) || now.After(ee.NotAfter) {
		fmt.Printf("시각       : 실패 (EE 유효기간 밖, 기준 %s)\n", now.UTC().Format(time.RFC3339))
		fail = true
	}

	// 체인
	if cacheDir == "" {
		fmt.Println("체인       : 확인 안 함 (-cache 없음 -> CMS 서명과 자원 포함만 확인)")
	} else if err := rscChain(r, cacheDir, talDir, now, workers); err != nil {
		fmt.Printf("체인       : 실패 (%v)\n", err)
		fail = true
	}

	// 파일
	used := 0
	for _, p := range files {
		// "-" = 표준 입력 (이름 모름 -> fileName 없는 항목과 맞춤, 6 절 filename-unaware)
		var b []byte
		var err error
		name := ""
		if p == "-" {
			b, err = io.ReadAll(io.LimitReader(os.Stdin, maxRSCFileSize))
		} else {
			name = filepath.Base(p)
			b, err = os.ReadFile(p)
		}
		if err == nil {
			err = r.checkFile(name, b)
		}
		if err != nil {
			fmt.Printf("파일       : %s 실패 (%v)\n", p, err)
			fail = true
			continue
		}
		used++
		fmt.Printf("파일       : %s ok\n", p)
	}
	if len(files) > 0 && used < len(r.Entries) {
		// 6 절 : 오류는 아니지만 알림
		fmt.Printf("경고       : checkList %d 개 중 %d 개만 확인함\n", len(r.Entries), used)
	}
	if fail {
		fmt.Println("결과       : 실패")
		return 1
	}
	fmt.Println("결과       : ok")
	return 0
}

// rscChain : 검증 트리를 한 번 돌아 CA 를 모으고 EE 체인 확인 (출력 파일은 쓰지 않음)
func rscChain(r *rpkiRSC, cacheDir, talDir string, now time.Time, workers int) error {
	tals, _, err := loadTALs(talDir)
	if err != nil {
		return err
	}
	started := time.Now()
	v := newValidator(cacheDir, now, workers)
	v.KeepCAs = true
	v.run(tals)
	fmt.Printf("검증 트리   : CA %d 개, %.0f 초\n", len(v.caBySKI), time.Since(started).Seconds())
	rec, err := r.checkChain(v)
	if err != nil {
		return err
	}
	fmt.Printf("체인       : ok (TA %s, 발행 CA %s)\n", rec.Ctx.TA, rec.Ctx.URI)
	if r.EE.CAIssuers != rec.Ctx.URI {
		fmt.Printf("경고       : EE AIA %s != 발행 CA 위치\n", r.EE.CAIssuers)
	}
	return nil
}

func listOrDash(s []string) string {
	if len(s) == 0 {
		return "-"
	}
	return strings.Join(s, ",")
}
