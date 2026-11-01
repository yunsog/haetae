package main

// rsync.go : 외부 rsync 명령으로 수집 (RRDP 가 없거나 오래 실패한 저장소)
//
//   rsync -rt --delete ... rsync://host/path/ <cache>/rsync/<host>/<path>/
// -r 만 쓰고 -l 을 안 쓰므로 심볼릭 링크는 건너뜀. 파일 하나 4 MB 상한, 시간 제한은 ctx (넘으면 프로세스 그룹 kill).

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
)

// rsyncDir : caRepository URI 의 캐시 폴더
func rsyncDir(cacheDir, repo string) string {
	return filepath.Join(cacheDir, "rsync", filepath.FromSlash(strings.TrimSuffix(strings.TrimPrefix(repo, "rsync://"), "/")))
}

// runRsync : repo (rsync://host/path) 폴더 전체를 받음
func (f *fetcher) runRsync(ctx context.Context, repo string) error {
	if !validURI(repo, "rsync://") {
		return fmt.Errorf("bad rsync URI %q", repo)
	}
	src := strings.TrimSuffix(repo, "/") + "/"
	dst := rsyncDir(f.CacheDir, repo)
	if err := os.MkdirAll(dst, 0755); err != nil {
		return err
	}
	cmd := exec.CommandContext(ctx, f.RsyncBin,
		"-rt", "--delete", "--no-motd", "--timeout=60", "--contimeout=15",
		fmt.Sprintf("--max-size=%d", maxObjectSize),
		"--include=*/", "--include=*.cer", "--include=*.crl", "--include=*.mft", "--include=*.roa",
		"--include=*.asa", "--include=*.gbr", "--include=*.spl", "--include=*.tak", "--exclude=*",
		"--", src, dst+"/")
	cmd.Env = []string{"PATH=/usr/bin:/bin", "LANG=C"}
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		// rsync 가 띄운 자식까지 같이 죽임
		return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		msg := strings.TrimSpace(string(out))
		if len(msg) > 300 {
			msg = msg[len(msg)-300:]
		}
		return fmt.Errorf("rsync %s: %v: %s", src, err, msg)
	}
	f.addRsync()
	return nil
}
