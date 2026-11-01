package main

// history.go : 회차 이력 (/api/v1/history, 30 일) 과 Prometheus /metrics
//
// 이력은 <state>/history.jsonl 에 한 줄씩 덧붙임 (재시작해도 유지).
// 메모리에는 30 일치만 두고, 파일 줄 수가 그 두 배를 넘으면 메모리 것으로 다시 씀.

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

const historyKeep = 30 * 24 * time.Hour

// histRun : 이력 한 줄
type histRun struct {
	Start       time.Time      `json:"start"`
	DurationS   int            `json:"duration_s"`
	Applied     bool           `json:"applied"`
	Reason      string         `json:"reason,omitempty"`
	Serial      uint32         `json:"serial"`
	VRPs        int            `json:"vrps"`
	VAPs        int            `json:"vaps"`
	Keys        int            `json:"router_keys"`
	Announced   int            `json:"announced"`
	Withdrawn   int            `json:"withdrawn"`
	PerTA       map[string]int `json:"vrps_per_ta"`
	Rejected    map[string]int `json:"rejected"`
	ReposFailed int            `json:"repos_failed"` // 결과가 ok 가 아닌 저장소 수
	Unsafe      int            `json:"unsafe_vrps"`
	MB          int64          `json:"downloaded_mb"`
	MemMB       int64          `json:"mem_mb"`
}

func historyPath(stateDir string) string { return filepath.Join(stateDir, "history.jsonl") }

// loadHistory : 파일에서 30 일 안의 것만
func loadHistory(stateDir string) ([]histRun, int) {
	f, err := os.Open(historyPath(stateDir))
	if err != nil {
		return nil, 0
	}
	defer f.Close()
	var out []histRun
	lines := 0
	cut := time.Now().Add(-historyKeep)
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 1<<20)
	for sc.Scan() {
		lines++
		var h histRun
		if json.Unmarshal(sc.Bytes(), &h) == nil && h.Start.After(cut) {
			out = append(out, h)
		}
	}
	return out, lines
}

// addHistory : 한 줄 추가 (메모리 + 파일)
func (d *daemon) addHistory(h histRun) {
	d.mu.Lock()
	cut := time.Now().Add(-historyKeep)
	i := sort.Search(len(d.hist), func(i int) bool { return d.hist[i].Start.After(cut) })
	d.hist = append(d.hist[i:], h)
	hist := d.hist
	d.histLines++
	rewrite := d.histLines > 2*len(hist)+10
	if rewrite {
		d.histLines = len(hist)
	}
	d.mu.Unlock()

	p := historyPath(d.cfg.StateDir)
	if rewrite {
		err := writeAtomic(d.cfg.StateDir, "history.jsonl", func(w *bufio.Writer) error {
			enc := json.NewEncoder(w)
			for i := range hist {
				if err := enc.Encode(&hist[i]); err != nil {
					return err
				}
			}
			return nil
		})
		if err != nil {
			log.Printf("history: %v", err)
		}
		return
	}
	b, _ := json.Marshal(h)
	f, err := os.OpenFile(p, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		log.Printf("history: %v", err)
		return
	}
	f.Write(append(b, '\n'))
	f.Close()
}

// memRSS : 이 프로세스의 지금 RSS (바이트)
func memRSS() int64 {
	b, err := os.ReadFile("/proc/self/statm")
	if err != nil {
		return 0
	}
	f := strings.Fields(string(b))
	if len(f) < 2 {
		return 0
	}
	n, _ := strconv.ParseInt(f[1], 10, 64)
	return n * int64(os.Getpagesize())
}

// GET /api/v1/history?hours=24 (최대 720)
func (d *daemon) handleHistory(w http.ResponseWriter, r *http.Request) {
	hours := 24
	if s := r.URL.Query().Get("hours"); s != "" {
		n, err := strconv.Atoi(s)
		if err != nil || n < 1 || n > 720 {
			http.Error(w, "hours = 1..720", 400)
			return
		}
		hours = n
	}
	cut := time.Now().Add(-time.Duration(hours) * time.Hour)
	d.mu.Lock()
	out := []histRun{}
	for _, h := range d.hist {
		if h.Start.After(cut) {
			out = append(out, h)
		}
	}
	d.mu.Unlock()
	writeJSON(w, map[string]any{"runs": out})
}

// ---- /metrics (Prometheus text) ----

func (d *daemon) handleMetrics(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	bw := bufio.NewWriter(w)
	defer bw.Flush()

	d.st.mu.RLock()
	ses, ser, cur := d.st.Session, d.st.Serial, d.st.Cur
	d.st.mu.RUnlock()
	d.mu.Lock()
	last, lastOK, runs, rtrOpen, view := d.last, d.lastOK, d.runs, d.rtrOpen, d.view
	d.mu.Unlock()

	metric(bw, "haetae_session", "RTR session id", "gauge", nil, float64(ses))
	metric(bw, "haetae_serial", "RTR serial", "gauge", nil, float64(ser))
	metric(bw, "haetae_runs_total", "validation runs since start", "counter", nil, float64(runs))
	metric(bw, "haetae_rtr_open", "RTR listener open (1/0)", "gauge", nil, b2f(rtrOpen))
	if cur != nil {
		metric(bw, "haetae_vrps", "VRPs served (unique, RTR)", "gauge", nil, float64(len(cur.VRPs)))
		metric(bw, "haetae_vaps", "ASPA customers served", "gauge", nil, float64(len(cur.ASPAs)))
		metric(bw, "haetae_router_keys", "router keys served", "gauge", nil, float64(len(cur.Keys)))
		metric(bw, "haetae_data_time_seconds", "validation time of served data (epoch)", "gauge", nil, float64(cur.Built.Unix()))
	}
	if !lastOK.IsZero() {
		metric(bw, "haetae_last_applied_seconds", "last time a new set was applied (epoch)", "gauge", nil, float64(lastOK.Unix()))
	}
	if last != nil {
		metric(bw, "haetae_last_run_start_seconds", "last run start (epoch)", "gauge", nil, float64(last.Start.Unix()))
		metric(bw, "haetae_last_run_duration_seconds", "last run duration", "gauge", nil, last.DurationS)
		metric(bw, "haetae_last_run_applied", "last run applied (1/0)", "gauge", nil, b2f(last.Applied))
		metric(bw, "haetae_last_run_downloaded_bytes", "bytes downloaded in last run", "gauge", nil, float64(last.MB<<20))
		head(bw, "haetae_vrps_per_ta", "VRPs per TA (last run)", "gauge")
		for _, ta := range sortedKeys(last.PerTA) {
			sample(bw, "haetae_vrps_per_ta", map[string]string{"ta": ta}, float64(last.PerTA[ta]))
		}
		head(bw, "haetae_objects", "objects by type and state (last run)", "gauge")
		head2 := false
		for _, k := range sortedKeys(last.Counts) {
			if w, ok := strings.CutPrefix(k, "warn: "); ok {
				if !head2 {
					head(bw, "haetae_warnings", "warnings (last run)", "gauge")
					head2 = true
				}
				sample(bw, "haetae_warnings", map[string]string{"warning": w}, float64(last.Counts[k]))
				continue
			}
			if t, st, ok := strings.Cut(k, " "); ok && (st == "valid" || st == "rejected") {
				sample(bw, "haetae_objects", map[string]string{"type": t, "state": st}, float64(last.Counts[k]))
			}
		}
		head(bw, "haetae_repositories", "repositories by type and result (last run)", "gauge")
		for _, k := range sortedKeys(last.Repos) {
			t, res, _ := strings.Cut(k, " ")
			sample(bw, "haetae_repositories", map[string]string{"type": t, "result": res}, float64(last.Repos[k]))
		}
	}
	if view != nil {
		metric(bw, "haetae_unsafe_vrps", "VRPs overlapping resources of rejected CAs", "gauge", nil, float64(len(view.Unsafe)))
	}
	if d.rtr != nil {
		metric(bw, "haetae_rtr_clients", "connected RTR clients", "gauge", nil, float64(len(d.rtr.clientsInfo())))
	}
	metric(bw, "haetae_memory_rss_bytes", "resident memory", "gauge", nil, float64(memRSS()))
}

func b2f(b bool) float64 {
	if b {
		return 1
	}
	return 0
}

func sortedKeys(m map[string]int) []string {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	return ks
}

func head(w io.Writer, name, help, typ string) {
	fmt.Fprintf(w, "# HELP %s %s\n# TYPE %s %s\n", name, help, name, typ)
}

func sample(w io.Writer, name string, labels map[string]string, v float64) {
	if len(labels) == 0 {
		fmt.Fprintf(w, "%s %s\n", name, strconv.FormatFloat(v, 'f', -1, 64))
		return
	}
	ks := make([]string, 0, len(labels))
	for k := range labels {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	parts := make([]string, len(ks))
	for i, k := range ks {
		parts[i] = fmt.Sprintf("%s=%s", k, strconv.Quote(labels[k]))
	}
	fmt.Fprintf(w, "%s{%s} %s\n", name, strings.Join(parts, ","), strconv.FormatFloat(v, 'f', -1, 64))
}

func metric(w io.Writer, name, help, typ string, labels map[string]string, v float64) {
	head(w, name, help, typ)
	sample(w, name, labels, v)
}
