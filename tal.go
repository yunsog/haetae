package main

// tal.go : TAL (Trust Anchor Locator, RFC 8630)
//
// 파일 모양
//   # 주석 (선택)
//   https://.../ta.cer        TA 인증서 위치 (한 줄에 하나, 여러 개)
//   rsync://.../ta.cer
//   (빈 줄)
//   MIIBIjANBg...             TA 공개키 (SubjectPublicKeyInfo, base64, 여러 줄)
// TA 인증서는 저장소에서 받지만, 믿음의 근거는 TAL 의 공개키 (인증서 키가 이것과 같아야 함).
//
// 어디서 읽나 (10-31) : 기본 = 실행 파일 안에 넣은 TAL (빌드할 때 저장소 tals/*.tal 5 개, Go 표준 embed).
// -tal <폴더> 를 주면 그 폴더의 *.tal (시험 / 스냅샷 비교 / 키 교체 비상용). 다른 프로그램의 TAL 에 기대지 않음.

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"embed"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
)

// builtinTALs : 빌드할 때 tals/*.tal 이 실행 파일 안에 들어감 (바꾸려면 tals/ 고치고 다시 빌드)
//
//go:embed tals/*.tal
var builtinTALs embed.FS

type tal struct {
	Name string   // 파일 이름에서 .tal 뺀 것 (afrinic, apnic, ...) = VRP 의 TA 이름
	URIs []string // TA 인증서 위치
	SPKI []byte   // DER SubjectPublicKeyInfo
}

func parseTAL(path string) (*tal, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return parseTALBytes(filepath.Base(path), b)
}

// parseTALBytes : 파일 이름 (예 ripe.tal) 과 내용 -> tal
func parseTALBytes(name string, b []byte) (*tal, error) {
	if len(b) > 64*1024 {
		return nil, fmt.Errorf("TAL too large")
	}
	t := &tal{Name: strings.TrimSuffix(name, ".tal")}
	text := strings.ReplaceAll(string(b), "\r\n", "\n")
	lines := strings.Split(text, "\n")

	// 주석 건너뛰고 URI 줄, 빈 줄 하나, 그다음 base64
	i := 0
	for i < len(lines) && strings.HasPrefix(lines[i], "#") {
		i++
	}
	for ; i < len(lines) && lines[i] != ""; i++ {
		u := strings.TrimSpace(lines[i])
		if !validURI(u, "rsync://") && !validURI(u, "https://") {
			return nil, fmt.Errorf("TAL bad URI %q", u)
		}
		t.URIs = append(t.URIs, u)
	}
	if len(t.URIs) == 0 {
		return nil, fmt.Errorf("TAL without URI")
	}
	key, err := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(strings.Join(lines[i:], "")), ""))
	if err != nil {
		return nil, fmt.Errorf("TAL key base64: %w", err)
	}
	if _, err := x509.ParsePKIXPublicKey(key); err != nil {
		return nil, fmt.Errorf("TAL key: %w", err)
	}
	t.SPKI = key
	return t, nil
}

// rsyncURI : TAL 의 rsync URI (자식 인증서의 AIA 가 가리키는 위치)
func (t *tal) rsyncURI() string {
	for _, u := range t.URIs {
		if strings.HasPrefix(u, "rsync://") {
			return u
		}
	}
	return t.URIs[0]
}

// loadTA : 캐시에서 TA 인증서를 읽어 확인
// rpki-client 캐시 : <cache>/ta/<TAL 이름>/<URI 파일 이름>
func (t *tal) loadTA(cacheDir string) (*rpkiCert, error) {
	var lastErr error
	for _, u := range t.URIs {
		p := filepath.Join(cacheDir, "ta", t.Name, filepath.Base(u))
		der, err := os.ReadFile(p)
		if err != nil {
			lastErr = err
			continue
		}
		c, err := parseCert(der, false)
		if err != nil {
			return nil, fmt.Errorf("TA %s: %w", p, err)
		}
		if c.Kind != kindCA || !c.SelfSigned {
			return nil, fmt.Errorf("TA %s: not a self-signed CA", p)
		}
		if !bytes.Equal(c.X509.RawSubjectPublicKeyInfo, t.SPKI) {
			return nil, fmt.Errorf("TA %s: key differs from TAL", p)
		}
		if err := c.X509.CheckSignatureFrom(c.X509); err != nil {
			return nil, fmt.Errorf("TA %s: self signature: %w", p, err)
		}
		if c.IPs.V4.Inherit || c.IPs.V6.Inherit || c.ASs.Inherit {
			return nil, fmt.Errorf("TA %s: inherit not allowed", p)
		}
		return c, nil
	}
	return nil, fmt.Errorf("TA certificate not in cache: %v", lastErr)
}

// loadTALs : dir 이 비었으면 내장 TAL, 아니면 그 폴더의 *.tal. 하나라도 깨지면 오류 (반쪽 TA 로 돌지 않음)
// 돌려주는 source 는 로그용 ("내장" 또는 폴더 이름)
func loadTALs(dir string) ([]*tal, string, error) {
	var fsys fs.FS = builtinTALs
	pattern, source := "tals/*.tal", "내장"
	if dir != "" {
		fsys, pattern, source = os.DirFS(dir), "*.tal", dir
	}
	names, _ := fs.Glob(fsys, pattern)
	sort.Strings(names)
	if len(names) == 0 {
		return nil, source, fmt.Errorf("no TAL in %s", source)
	}
	var out []*tal
	for _, n := range names {
		b, err := fs.ReadFile(fsys, n)
		if err != nil {
			return nil, source, err
		}
		t, err := parseTALBytes(path.Base(n), b)
		if err != nil {
			return nil, source, fmt.Errorf("%s: %w", n, err)
		}
		out = append(out, t)
	}
	return out, source, nil
}

// talSummary : 로그용 한 줄 "afrinic ad69cadc45c0cd41, apnic ..." (공개키 SHA-256 앞 16 자 = tals/README.md 표와 같은 값)
func talSummary(tals []*tal) string {
	parts := make([]string, len(tals))
	for i, t := range tals {
		parts[i] = t.Name + " " + t.keyHash()
	}
	return strings.Join(parts, ", ")
}

// keyHash : 공개키 SHA-256 앞 16 자. TAL 파일의 base64 글자를 해시함 (tals/README.md 와 같은 계산)
func (t *tal) keyHash() string {
	h := sha256.Sum256([]byte(base64.StdEncoding.EncodeToString(t.SPKI)))
	return hex.EncodeToString(h[:])[:16]
}
