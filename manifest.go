package main

// manifest.go : Manifest (RFC 9286)
//
// CA 의 publication point 에 있어야 할 파일 목록 + 각 파일 SHA-256.
//   Manifest ::= SEQUENCE {
//     version [0] INTEGER DEFAULT 0,   (DER 이므로 0 이면 생략되어야 함)
//     manifestNumber INTEGER,          (0 이상, 20 바이트 이하)
//     thisUpdate GeneralizedTime, nextUpdate GeneralizedTime,
//     fileHashAlg OID (sha256),
//     fileList SEQUENCE OF FileAndHash { file IA5String, hash BIT STRING } }
// 파일이 목록과 맞는지, 시각, 번호 증가는 validate.go (2 단계).

import (
	"fmt"
	"math/big"
	"time"
)

// 파일 수 상한 (큰 CA 도 수만 개 정도)
const maxManifestFiles = 200000

type mftFile struct {
	Name string
	Hash [32]byte
}

type rpkiManifest struct {
	*signedObject
	Number     *big.Int
	ThisUpdate time.Time
	NextUpdate time.Time
	Files      []mftFile
}

func parseManifest(der []byte) (*rpkiManifest, error) {
	so, err := parseSignedObject(der, oidCTManifest)
	if err != nil {
		return nil, err
	}
	m := &rpkiManifest{signedObject: so}
	// RFC 9286 5.1 : manifest EE 자원은 inherit
	if !eeInherits(so.EE) {
		return nil, fmt.Errorf("manifest EE resources not inherit")
	}

	top, err := derOne(so.Content)
	if err != nil {
		return nil, err
	}
	f, err := derSeq(top, 5, 6)
	if err != nil {
		return nil, fmt.Errorf("Manifest: %w", err)
	}
	if len(f) == 6 {
		// version 이 있음 = 0 이 아님 (DEFAULT 0 은 생략) -> 지원 안 함
		return nil, fmt.Errorf("Manifest version present (only v0)")
	}

	if m.Number, err = derBigInt(f[0]); err != nil {
		return nil, err
	}
	if m.Number.Sign() < 0 || len(f[0].Body) > 20 {
		return nil, fmt.Errorf("manifestNumber out of range")
	}
	if m.ThisUpdate, err = derGeneralizedTime(f[1]); err != nil {
		return nil, err
	}
	if m.NextUpdate, err = derGeneralizedTime(f[2]); err != nil {
		return nil, err
	}
	if !m.NextUpdate.After(m.ThisUpdate) {
		return nil, fmt.Errorf("nextUpdate not after thisUpdate")
	}
	if oid, err := derOIDOf(f[3]); err != nil || !oid.Equal(oidSHA256) {
		return nil, fmt.Errorf("fileHashAlg not sha256")
	}

	files, err := derSeq(f[4], 0, maxManifestFiles)
	if err != nil {
		return nil, fmt.Errorf("fileList: %w", err)
	}
	seen := make(map[string]bool, len(files))
	for _, fh := range files {
		p, err := derSeq(fh, 2, 2)
		if err != nil {
			return nil, fmt.Errorf("FileAndHash: %w", err)
		}
		if !p[0].is(tagIA5String) || p[0].Constructed {
			return nil, fmt.Errorf("file name not IA5String")
		}
		name := string(p[0].Body)
		if !validFilename(name) {
			return nil, fmt.Errorf("bad file name %q", name)
		}
		if seen[name] {
			return nil, fmt.Errorf("duplicate file %q", name)
		}
		seen[name] = true
		h, unused, err := derBits(p[1])
		if err != nil || unused != 0 || len(h) != 32 {
			return nil, fmt.Errorf("bad hash for %q", name)
		}
		var mf mftFile
		mf.Name = name
		copy(mf.Hash[:], h)
		m.Files = append(m.Files, mf)
	}
	return m, nil
}

// validFilename : RFC 9286 4.2.2 = [a-zA-Z0-9_-]+ "." 확장자 3 글자 (경로 / .. 불가)
func validFilename(s string) bool {
	if len(s) < 5 || len(s) > 255 {
		return false
	}
	dot := len(s) - 4
	if s[dot] != '.' {
		return false
	}
	for i := 0; i < dot; i++ {
		ch := s[i]
		ok := ch >= 'a' && ch <= 'z' || ch >= 'A' && ch <= 'Z' || ch >= '0' && ch <= '9' || ch == '_' || ch == '-'
		if !ok {
			return false
		}
	}
	for i := dot + 1; i < len(s); i++ {
		if s[i] < 'a' || s[i] > 'z' {
			return false
		}
	}
	return true
}

// eeInherits : EE 인증서의 IP / AS 자원이 모두 inherit 인지 (있는 것만)
func eeInherits(c *rpkiCert) bool {
	for _, f := range []ipFamily{c.IPs.V4, c.IPs.V6} {
		if f.Present && !f.Inherit {
			return false
		}
	}
	if c.ASs.Present && !c.ASs.Inherit {
		return false
	}
	return true
}
