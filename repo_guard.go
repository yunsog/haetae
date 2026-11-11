package main

// repo_guard.go : 저장소 수집의 제한 (11-05 검토 10 / 11)
//
// 믿을 수 없는 CA 가 인증서에 적은 저장소 주소로 해태를 오래 붙잡거나 디스크를 채우지 못하게 함.
//   canonicalNotify : notify URI 정규화. 모양만 다른 같은 저장소 (?1 ?2, 대문자 호스트, :443) 를 한 번만 받음
//   maxReposPerTA   : TA 하나 아래 서로 다른 저장소 수 상한 (validator.repoAllowed, validate.go)
//   회차 기한       : fetch.deadline 이 지나면 남은 저장소는 받지 않고 직전 데이터로 (A2)
//   디스크          : 캐시 파일 시스템의 남은 양이 minFreeDisk 아래면 새 저장소를 받지 않음
//   cleanRepos      : 오래 안 쓴 rrdp/ rsync/ 폴더를 지움 (모든 TA 가 끝까지 돈 회차만)

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

const (
	// TA 하나 아래 서로 다른 저장소 (RRDP notify 또는 rsync 모듈) 수. 2026-11 운영 = 5 TA 합쳐 125 개
	maxReposPerTA = 1000
	// 이 시간 동안 어느 회차도 쓰지 않은 저장소 폴더는 지움 (잠깐 빠졌다 돌아오는 저장소가 snapshot 부터 다시 받지 않게 며칠 둠)
	repoKeepUnused = 72 * time.Hour
	// 캐시 파일 시스템에 이만큼 남지 않으면 새 저장소 (받은 적 없는 것) 는 받지 않음. 이미 받는 저장소는 그대로
	minFreeDisk = 10 << 30
)

var (
	errRunDeadline = errors.New("not fetched: run deadline passed (using previous data)")
	errLowDisk     = errors.New("not fetched: low disk space for a new repository")
)

// canonicalNotify : notify URI 를 한 모양으로 (호스트 소문자, :443 뗌). query / fragment / 사용자 정보는 오류
// (RRDP 에 필요 없는 것 : 붙이면 같은 저장소를 다른 저장소로 여러 번 받게 됨)
func canonicalNotify(u string) (string, error) {
	p, err := url.Parse(u)
	if err != nil {
		return "", err
	}
	switch {
	case p.Scheme != "https" || p.Host == "" || p.Opaque != "":
		return "", fmt.Errorf("not an https URL")
	case p.User != nil:
		return "", fmt.Errorf("user info in URL")
	case p.RawQuery != "" || p.ForceQuery:
		return "", fmt.Errorf("query in URL")
	case p.Fragment != "" || strings.Contains(u, "#"):
		return "", fmt.Errorf("fragment in URL")
	}
	return "https://" + canonHost(p) + p.EscapedPath(), nil
}

// canonHost : 호스트 소문자 + 기본 포트 (443) 뗌 (같은 서버인지 비교할 때도 씀)
func canonHost(p *url.URL) string {
	host, port := strings.ToLower(p.Hostname()), p.Port()
	if port == "443" {
		port = ""
	}
	if port != "" {
		return net.JoinHostPort(host, port)
	}
	if strings.Contains(host, ":") {
		return "[" + host + "]" // IPv6 주소
	}
	return host
}

// sameHost : 두 URL 이 같은 서버 (canonHost 로 비교)
func sameHost(a, b *url.URL) bool { return canonHost(a) == canonHost(b) }

// ---- 회차 기한 ----

// pastDeadline : 이번 회차의 수집 기한이 지났나
func (f *fetcher) pastDeadline() bool {
	return !f.deadline.IsZero() && !time.Now().Before(f.deadline)
}

// fetchTimeout : 저장소 하나에 줄 시간 = Timeout 과 회차 기한까지 남은 시간 중 짧은 것
func (f *fetcher) fetchTimeout() time.Duration {
	d := f.Timeout
	if !f.deadline.IsZero() {
		if r := time.Until(f.deadline); r < d {
			d = max(r, time.Second)
		}
	}
	return d
}

// ---- 디스크 ----

// freeDisk : dir 이 있는 파일 시스템의 남은 바이트 (일반 사용자 기준). 모르면 -1
func freeDisk(dir string) int64 {
	var st syscall.Statfs_t
	if err := syscall.Statfs(dir, &st); err != nil {
		return -1
	}
	return int64(st.Bavail) * int64(st.Bsize)
}

// checkDisk : 회차 시작 때 남은 양을 보고 LowDisk 를 정함 (모자라면 경고 한 줄)
func (f *fetcher) checkDisk() {
	free := freeDisk(f.CacheDir)
	f.LowDisk = free >= 0 && free < minFreeDisk
	if f.LowDisk {
		f.logf("WARNING low disk: %d MB free under %s (< %d MB), new repositories are not fetched", free>>20, f.CacheDir, minFreeDisk>>20)
	}
}

// ---- 오래 안 쓴 저장소 폴더 정리 ----

// cleanRepos : 이번 회차에 쓴 저장소는 시각을 새로 적고 (rrdp = <hash>.state, rsync = 모듈 폴더의 mtime),
// repoKeepUnused 넘게 안 쓴 rrdp/ rsync/ 항목을 지움. 지운 저장소 수. 모든 TA 가 끝까지 돈 회차에서만 부름
func (f *fetcher) cleanRepos() int {
	f.mu.Lock()
	usedRRDP, usedRsync := map[string]bool{}, map[string]bool{}
	for key := range f.repos {
		switch {
		case strings.HasPrefix(key, "rrdp "):
			dir, _ := rrdpPaths(f.CacheDir, strings.TrimPrefix(key, "rrdp "))
			usedRRDP[filepath.Base(dir)] = true
		case strings.HasPrefix(key, "rsync "):
			usedRsync[rsyncDir(f.CacheDir, strings.TrimPrefix(key, "rsync "))] = true
		}
	}
	f.mu.Unlock()
	now := time.Now()
	old := func(p string) bool {
		st, err := os.Stat(p)
		return err == nil && now.Sub(st.ModTime()) > repoKeepUnused
	}
	removed := 0

	// rrdp/<hash>, <hash>.state, 끊긴 흔적 <hash>.new / .old / .stage
	rdir := filepath.Join(f.CacheDir, "rrdp")
	ents, _ := os.ReadDir(rdir)
	gone := map[string]bool{}
	for _, e := range ents {
		base, _, _ := strings.Cut(e.Name(), ".")
		if usedRRDP[base] {
			os.Chtimes(filepath.Join(rdir, base+".state"), now, now)
			continue
		}
		if !gone[base] {
			st := filepath.Join(rdir, base+".state")
			if _, err := os.Stat(st); err != nil {
				st = filepath.Join(rdir, base) // 상태 파일이 없으면 폴더 시각
			}
			if !old(st) {
				continue
			}
			gone[base] = true
			removed++
		}
		os.RemoveAll(filepath.Join(rdir, e.Name()))
	}

	// rsync/<host>/<module>
	sdir := filepath.Join(f.CacheDir, "rsync")
	hosts, _ := os.ReadDir(sdir)
	for _, h := range hosts {
		hp := filepath.Join(sdir, h.Name())
		mods, _ := os.ReadDir(hp)
		for _, m := range mods {
			mp := filepath.Join(hp, m.Name())
			if usedRsync[mp] {
				os.Chtimes(mp, now, now)
			} else if old(mp) {
				os.RemoveAll(mp)
				removed++
			}
		}
		if rest, _ := os.ReadDir(hp); len(rest) == 0 {
			os.Remove(hp)
		}
	}
	return removed
}
