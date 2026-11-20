// SPDX-License-Identifier: Apache-2.0

package main

// valid.go : 직전 정상 publication point (RFC 9286 6.7, 0.2.0)
//
// 새로 받은 manifest / CRL / 파일이 틀리면 (해시 다름, 파일 없음, 서명, 기간 ...) 그 CA 를 바로 버리지 않고
// 마지막으로 확인을 통과한 묶음으로 다시 검증함 (rpki-client / Routinator 와 같음). 직전 묶음도 기간이 지나면 저절로 실패.
// manifest 번호가 직전보다 작아지면 (되돌리기) 새것을 틀린 것으로 봄 (RFC 9286 4.2.1).
//
// 번호 비교는 저장본이 지금도 유효할 때만 : 저장본이 만료됐으면 번호가 작은 새것을 받음 (CA 를 다시 만들어 번호가 처음부터인 경우,
// 전에는 저장본 만료 뒤 그 CA 가 영구히 빠짐, 11-05 검토 4).
//
// 저장 : <cache>/valid/<hex>/ 아래에 manifest 와 나열된 파일 (같은 이름), NUMBER (manifest 번호 10 진수)
//   <hex> = sha256(CA 공개 키 ‖ notify ‖ manifest URI). manifest URI 만으로 정하면 아무 CA 가 남의 manifest URI 를 쓴 자식 CA 를 만들어
//   남의 저장본 (번호) 을 덮어쓸 수 있음 (11-05 검토 3). 같은 키를 얻으려면 그 CA 의 공개 키와 받는 곳을 그대로 써야 함
//   = 들어오는 데이터가 진짜 그 CA 것. 0.3.0 전 저장 모양 (<manifest URI 경로>.d) 은 쓰지 않고 cleanValid 가 지움
//   파일은 받은 캐시의 hard link (내용이 바뀌면 캐시 쪽은 새 파일로 바뀌므로 저장본은 그대로). 다른 파일 시스템이면 복사
//   manifest 가 바뀐 publication point 만 다시 씀 (평소 회차는 수백 곳)
// 상주 모드만 씀 (validator.ValidDir). -validate (오프라인 비교) 는 끔 = rpki-client -n 과 같은 조건

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/big"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// validPPDir : CA 하나의 저장 폴더 (공개 키 + notify + manifest URI)
func validPPDir(validDir string, c *rpkiCert) string {
	h := sha256.New()
	h.Write(c.X509.RawSubjectPublicKeyInfo)
	h.Write([]byte{0})
	h.Write([]byte(c.Notify))
	h.Write([]byte{0})
	h.Write([]byte(c.Manifest))
	return filepath.Join(validDir, hex.EncodeToString(h.Sum(nil)))
}

// validAt : 저장 폴더 안의 파일 (객체 URI 의 파일 이름만 씀)
func validAt(dir string) func(uri string) (string, error) {
	return func(uri string) (string, error) {
		name := path.Base(uri)
		if name == "." || name == ".." || strings.ContainsAny(name, "/\\") {
			return "", fmt.Errorf("bad name %q", name)
		}
		return filepath.Join(dir, name), nil
	}
}

// storedNumber : 저장된 manifest 번호 (없으면 nil)
func storedNumber(dir string) *big.Int {
	b, err := os.ReadFile(filepath.Join(dir, "NUMBER"))
	if err != nil {
		return nil
	}
	n, ok := new(big.Int).SetString(strings.TrimSpace(string(b)), 10)
	if !ok {
		return nil
	}
	return n
}

// storedThisUpdate : 저장본 manifest 의 thisUpdate (THISUPDATE 파일, 0.4.0 부터). 없으면 0 = 비교 안 함
func storedThisUpdate(dir string) time.Time {
	b, err := os.ReadFile(filepath.Join(dir, "THISUPDATE"))
	if err != nil {
		return time.Time{}
	}
	n, err := strconv.ParseInt(strings.TrimSpace(string(b)), 10, 64)
	if err != nil {
		return time.Time{}
	}
	return time.Unix(n, 0)
}

// mftWentBack : 새 manifest 가 저장본보다 뒤로 갔는지 (RFC 9286 4.2.1 재생 방지 두 가지). "" = 아님
//   - manifestNumber 가 저장본보다 작음
//   - thisUpdate 가 저장본보다 앞섬 (prevTU 0 = 저장본에 THISUPDATE 없음, 비교 안 함)
//
// 번호 / thisUpdate 가 같은 것은 같은 manifest 를 다시 읽은 것이라 통과
func mftWentBack(m *rpkiManifest, prevNum *big.Int, prevTU time.Time) string {
	if m.Number.Cmp(prevNum) < 0 {
		return fmt.Sprintf("manifest number %s lower than previous %s", m.Number, prevNum)
	}
	if !prevTU.IsZero() && m.ThisUpdate.Before(prevTU) {
		return fmt.Sprintf("manifest thisUpdate %s before previous %s",
			m.ThisUpdate.UTC().Format(time.RFC3339), prevTU.UTC().Format(time.RFC3339))
	}
	return ""
}

// storeValid : 확인을 통과한 publication point 를 저장 (manifest 가 같고 파일이 온전하면 그대로 둠)
// 새 폴더 (dir.tmp) 에 다 만들고 파일마다 fsync 한 뒤 바꿔 끼움 -> 반쯤 쓴 저장본도, 정전 뒤 빈 파일도 없음 (B4).
// 회차당 약 700 폴더 / 2,100 파일 (11-12 운영), fsync 는 모두 약 0.8 초
func storeValid(dir, mftName string, pp *pubPoint) error {
	if old, err := os.ReadFile(filepath.Join(dir, mftName)); err == nil && bytes.Equal(old, pp.mftDER) && validComplete(dir, pp) {
		return nil // 같은 manifest = 같은 묶음 (나열된 파일은 해시로 묶여 있음)
	}
	tmp := dir + ".tmp"
	os.RemoveAll(tmp)
	if err := os.MkdirAll(tmp, 0755); err != nil {
		return err
	}
	put := func(name string, data []byte) error {
		dst := filepath.Join(tmp, name)
		if src := pp.paths[name]; src != "" && os.Link(src, dst) == nil {
			// hard link 원본이 읽은 뒤에 바뀌었을 수 있음 -> 내용이 확인한 것과 같을 때만 (다르면 복사)
			if b, err := os.ReadFile(dst); err == nil && bytes.Equal(b, data) {
				return syncPath(dst) // 원본 (RRDP / rsync 캐시) 은 fsync 없이 썼음 -> 같은 inode 를 여기서 내려씀
			}
			os.Remove(dst)
		}
		return writeFileSync(dst, data, 0644)
	}
	err := put(mftName, pp.mftDER)
	for _, f := range pp.files {
		if err == nil {
			err = put(f.Name, f.Data)
		}
	}
	if err == nil {
		err = writeFileSync(filepath.Join(tmp, "NUMBER"), []byte(pp.mft.Number.String()+"\n"), 0644)
	}
	if err == nil {
		err = writeFileSync(filepath.Join(tmp, "THISUPDATE"), []byte(strconv.FormatInt(pp.mft.ThisUpdate.Unix(), 10)+"\n"), 0644)
	}
	if err == nil {
		err = syncPath(tmp) // 폴더 안 이름 목록도
	}
	if err != nil {
		os.RemoveAll(tmp)
		return err
	}
	old := dir + ".old"
	os.RemoveAll(old)
	os.Rename(dir, old) // 처음이면 없음
	if err := os.Rename(tmp, dir); err != nil {
		os.Rename(old, dir)
		return err
	}
	os.RemoveAll(old)
	syncPath(filepath.Dir(dir)) // 바꿔 끼운 것 (rename) 도 디스크에. 실패해도 옛 저장본 또는 새 저장본 중 하나 = 온전함
	return nil
}

// validComplete : 저장본 폴더에 NUMBER 와 manifest 에 나열된 파일이 모두 맞는 크기로 있는지.
// fsync 전 판에서 정전이 나면 manifest 는 같은데 파일이 비어 있을 수 있음 -> 그때는 다시 저장 (B4)
func validComplete(dir string, pp *pubPoint) bool {
	if fi, err := os.Stat(filepath.Join(dir, "NUMBER")); err != nil || fi.Size() == 0 {
		return false
	}
	for _, f := range pp.files {
		fi, err := os.Stat(filepath.Join(dir, f.Name))
		if err != nil || fi.Size() != int64(len(f.Data)) {
			return false
		}
	}
	return true
}

// cleanValid : 이번 회차에 보지 않은 CA 의 저장본을 지움 (CA 가 없어짐). 모든 TA 가 끝까지 돈 회차에서만 부름
// valid/ 바로 아래만 봄 : 본 폴더 말고는 모두 지움 (저장 도중 끊긴 .tmp / .old, 0.3.0 전 모양의 호스트 폴더 포함)
func cleanValid(validDir string, seen map[string]bool) (removed int) {
	ents, err := os.ReadDir(validDir)
	if err != nil {
		return 0
	}
	for _, e := range ents {
		p := filepath.Join(validDir, e.Name())
		if seen[p] {
			continue
		}
		os.RemoveAll(p)
		if !strings.HasSuffix(p, ".tmp") && !strings.HasSuffix(p, ".old") {
			removed++
		}
	}
	return removed
}
