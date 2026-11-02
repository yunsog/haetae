package main

// valid.go : 직전 정상 publication point (RFC 9286 6.7, 0.2.0)
//
// 새로 받은 manifest / CRL / 파일이 틀리면 (해시 다름, 파일 없음, 서명, 기간 ...) 그 CA 를 바로 버리지 않고
// 마지막으로 확인을 통과한 묶음으로 다시 검증함 (rpki-client / Routinator 와 같음). 직전 묶음도 기간이 지나면 저절로 실패.
// manifest 번호가 직전보다 작아지면 (되돌리기) 새것을 틀린 것으로 봄 (RFC 9286 4.2.1).
//
// 저장 : <cache>/valid/<manifest URI 경로>.d/ 아래에 manifest 와 나열된 파일 (같은 이름), NUMBER (manifest 번호 10 진수)
//   파일은 받은 캐시의 hard link (내용이 바뀌면 캐시 쪽은 새 파일로 바뀌므로 저장본은 그대로). 다른 파일 시스템이면 복사
//   manifest 가 바뀐 publication point 만 다시 씀 (평소 회차는 수백 곳)
// 상주 모드만 씀 (validator.ValidDir). -validate (오프라인 비교) 는 끔 = rpki-client -n 과 같은 조건

import (
	"bytes"
	"fmt"
	"math/big"
	"os"
	"path"
	"path/filepath"
	"strings"
)

// validPPDir : manifest URI 의 저장 폴더
func validPPDir(validDir, mftURI string) (string, error) {
	p, err := uriPath(validDir, mftURI)
	if err != nil {
		return "", err
	}
	return p + ".d", nil
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

// storeValid : 확인을 통과한 publication point 를 저장 (manifest 가 같으면 그대로 둠)
// 새 폴더 (dir.tmp) 에 다 만든 뒤 바꿔 끼움 -> 반쯤 쓴 저장본이 없음
func storeValid(dir, mftName string, pp *pubPoint) error {
	if old, err := os.ReadFile(filepath.Join(dir, mftName)); err == nil && bytes.Equal(old, pp.mftDER) {
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
				return nil
			}
			os.Remove(dst)
		}
		return os.WriteFile(dst, data, 0644)
	}
	err := put(mftName, pp.mftDER)
	for _, f := range pp.files {
		if err == nil {
			err = put(f.Name, f.Data)
		}
	}
	if err == nil {
		err = os.WriteFile(filepath.Join(tmp, "NUMBER"), []byte(pp.mft.Number.String()+"\n"), 0644)
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
	return nil
}

// cleanValid : 이번 회차에 보지 않은 CA 의 저장본을 지움 (CA 가 없어짐). 모든 TA 가 끝까지 돈 회차에서만 부름
func cleanValid(validDir string, seen map[string]bool) (removed int) {
	filepath.WalkDir(validDir, func(p string, e os.DirEntry, err error) error {
		if err != nil || !e.IsDir() {
			return nil
		}
		switch {
		case strings.HasSuffix(p, ".d.tmp"), strings.HasSuffix(p, ".d.old"):
			os.RemoveAll(p) // 저장 도중 끊긴 흔적
			return filepath.SkipDir
		case strings.HasSuffix(p, ".d"):
			if !seen[p] {
				os.RemoveAll(p)
				removed++
			}
			return filepath.SkipDir
		}
		return nil
	})
	return removed
}
