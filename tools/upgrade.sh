#!/bin/sh
# tools/upgrade.sh : 무중단 판 올리기 (설명서 "무중단 판 올리기" 절 = 국문 docs/manual.md 6.6, 영문 docs/en/manual.md 6.7, handover.go)
#   Seamless upgrade : build, test, install, SIGUSR2, then wait for "handover: resumed" / "aborted" in the journal.
#   Assumes the systemd unit "haetae" and the binary at /usr/local/bin/haetae (deploy/haetae.service). Run from anywhere.
#   빌드 -> 시험 -> 설치 (sudo) -> SIGUSR2 (sudo) -> 기록에서 "handover: resumed" 또는 "aborted" 를 기다림
#   돌던 회차가 있으면 그것이 끝난 뒤 넘김 (최대 15 분). 실패하면 옛 판이 그대로 계속 (그때는 이유를 보고 restart 여부를 정함)
#   주의 : 지금 도는 판에 이 기능이 있어야 함 (0.2.0 handover 전 바이너리에 USR2 를 보내면 프로세스가 끝나고 systemd 가 30 초 뒤 다시 띄움)
#   -n : 시험 (go test) 건너뜀
set -e
cd "$(dirname "$0")/.."
if [ "$1" != "-n" ]; then
	go test -count=1 ./... >/dev/null
	echo "go test ok"
fi
go build -o haetae .
pid=$(systemctl show -p MainPID --value haetae)
if [ -z "$pid" ] || [ "$pid" = 0 ]; then
	echo "haetae is not running : use sudo systemctl start haetae" >&2
	exit 1
fi
sudo install -m 755 haetae /usr/local/bin/haetae
since=$(date '+%Y-%m-%d %H:%M:%S')
sudo systemctl kill -s USR2 --kill-whom=main haetae
echo "SIGUSR2 sent to pid $pid at $since, waiting (a running cycle finishes first, up to 15 min)"
i=0
while [ $i -lt 1000 ]; do
	line=$(journalctl -u haetae --since "$since" --no-pager -o cat 2>/dev/null | grep -E 'handover: (resumed|aborted)' | tail -1)
	if [ -n "$line" ]; then
		journalctl -u haetae --since "$since" --no-pager -o cat | grep -E 'handover|resumed \(' | tail -20
		now=$(systemctl show -p MainPID --value haetae)
		echo "pid before $pid, now $now"
		case "$line" in *resumed*) exit 0 ;; *) exit 1 ;; esac
	fi
	sleep 1
	i=$((i + 1))
done
echo "no handover result after 1000 s : check journalctl -u haetae" >&2
exit 1
