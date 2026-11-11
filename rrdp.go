package main

// rrdp.go : RRDP 수집 (RFC 8182)
//
// 저장소마다 notification.xml (https) 하나
//   <notification session_id serial> <snapshot uri hash/> <delta serial uri hash/>... </notification>
// 처음 (또는 session 이 바뀌면) snapshot 전체, 그다음부터는 serial 이 이어지는 delta 만 받음.
// snapshot / delta 안의 <publish uri="rsync://...">base64</publish> 를 파일 트리에 씀.
//
// 저장 위치 (결정 B4, 저장소끼리 섞이지 않게 저장소마다 따로)
//   <cache>/rrdp/<sha256(notification URI)>/<host>/<path>   객체
//   <cache>/rrdp/<sha256(notification URI)>.state            session / serial / 마지막 성공 (JSON)
// 안전장치 (B3) : https 만, 다른 호스트 redirect 금지, snapshot / delta 는 notification 과 같은 호스트,
//   파일 크기 / 개수 상한, 해시 확인, URI 의 .. 금지, 저장소당 시간 제한 (ctx)

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const (
	rrdpNS              = "http://www.ripe.net/rpki/rrdp"
	maxNotificationSize = 32 << 20 // 32 MB
	maxSnapshotSize     = 4 << 30  // 4 GB (RIPE 가 수백 MB)
	maxDeltaSize        = 256 << 20
	maxRRDPFiles        = 2000000 // snapshot 하나의 파일 수
	maxDeltasPerFetch   = 100     // 이보다 많이 밀렸으면 snapshot
)

// netError : 망 문제 (접속 / 시간 초과 / 5xx / 429 / 받는 도중 끊김). 저장소 내용이 틀린 것과 구별
// delta 를 망 문제로 못 받았을 때 snapshot (수백 MB) 을 다시 받으러 가지 않으려고 씀
type netError struct {
	err        error
	retryAfter time.Duration // 서버가 준 Retry-After (429 / 503, 없으면 0) -> 저장소 재시도 간격 (repo.go)
}

func (e *netError) Error() string { return e.err.Error() }
func (e *netError) Unwrap() error { return e.err }

func isNetError(err error) bool {
	var ne *netError
	return errors.As(err, &ne)
}

type rrdpState struct {
	Notify      string    `json:"notify"`
	Session     string    `json:"session"`
	Serial      uint64    `json:"serial"`
	LastSuccess time.Time `json:"last_success"`
	// 조건부 GET (11-02) : 이 serial 까지 다 맞춘 notification 의 ETag / Last-Modified. 다음에 If-None-Match / If-Modified-Since 로 물어
	// 304 면 받지 않음. 끝까지 맞추지 못한 상태 (delta 일부만) 는 비워 둠. NotifyAt = notification 을 마지막으로 통째로 받은 시각
	ETag         string    `json:"etag,omitempty"`
	LastModified string    `json:"last_modified,omitempty"`
	NotifyAt     time.Time `json:"notify_at,omitzero"`
}

// rrdpFullEvery : 304 를 믿는 최대 시간. 이보다 오래 통째로 받지 않았으면 조건 없이 받음 (서버가 304 를 잘못 줘도 1 시간 안에 바로잡힘)
const rrdpFullEvery = time.Hour

// errNotModified : 조건부 GET 에 서버가 304 (notification 이 그대로)
var errNotModified = errors.New("not modified")

// notification.xml
type rrdpNotification struct {
	XMLName  xml.Name `xml:"notification"`
	Version  string   `xml:"version,attr"`
	Session  string   `xml:"session_id,attr"`
	Serial   string   `xml:"serial,attr"`
	Snapshot struct {
		URI  string `xml:"uri,attr"`
		Hash string `xml:"hash,attr"`
	} `xml:"snapshot"`
	Deltas []struct {
		Serial string `xml:"serial,attr"`
		URI    string `xml:"uri,attr"`
		Hash   string `xml:"hash,attr"`
	} `xml:"delta"`
}

// rrdpResult : 한 번 수집한 결과 (상태 API 용)
type rrdpResult struct {
	Action string // none / delta / snapshot
	Serial uint64
	Files  int // 쓰거나 지운 파일 수
}

// rrdpDir : 저장소 객체 폴더와 상태 파일
func rrdpPaths(cacheDir, notify string) (dir, state string) {
	h := sha256.Sum256([]byte(notify))
	k := hex.EncodeToString(h[:])
	return filepath.Join(cacheDir, "rrdp", k), filepath.Join(cacheDir, "rrdp", k+".state")
}

func loadRRDPState(p string) (*rrdpState, error) {
	b, err := os.ReadFile(p)
	if err != nil {
		return nil, err
	}
	var s rrdpState
	if err := json.Unmarshal(b, &s); err != nil {
		return nil, err
	}
	return &s, nil
}

func saveRRDPState(p string, s *rrdpState) error {
	b, _ := json.MarshalIndent(s, "", " ")
	tmp := p + ".tmp"
	if err := os.WriteFile(tmp, b, 0644); err != nil {
		return err
	}
	return os.Rename(tmp, p)
}

// newHTTPClient : redirect 는 같은 호스트 https 로만, 최대 3 번
func newHTTPClient() *http.Client {
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.ResponseHeaderTimeout = 30 * time.Second
	tr.MaxIdleConnsPerHost = 4
	return &http.Client{
		Transport: tr,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 3 {
				return errors.New("too many redirects")
			}
			if req.URL.Scheme != "https" || !sameHost(req.URL, via[0].URL) {
				return fmt.Errorf("redirect to other host / scheme %s", req.URL)
			}
			return nil
		},
	}
}

// httpGet : url 을 tmpDir 의 임시 파일로 받음 (크기 상한, wantHash 가 있으면 SHA-256 확인)
// 돌려준 파일은 부르는 쪽이 지움
func (f *fetcher) httpGet(ctx context.Context, u string, max int64, wantHash string) (string, error) {
	p, _, err := f.httpGetCond(ctx, u, max, wantHash, "", "")
	return p, err
}

// httpGetCond : httpGet + 조건부 GET. etag / lastMod 를 주면 If-None-Match / If-Modified-Since,
// 304 면 errNotModified. 돌려주는 헤더 = 응답의 ETag / Last-Modified 를 읽으려고
func (f *fetcher) httpGetCond(ctx context.Context, u string, max int64, wantHash, etag, lastMod string) (string, http.Header, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", u, nil)
	if err != nil {
		return "", nil, err
	}
	req.Header.Set("User-Agent", "haetae/"+version)
	if etag != "" {
		req.Header.Set("If-None-Match", etag)
	}
	if lastMod != "" {
		req.Header.Set("If-Modified-Since", lastMod)
	}
	resp, err := f.client.Do(req)
	if err != nil {
		return "", nil, &netError{err: err}
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotModified && (etag != "" || lastMod != "") {
		return "", resp.Header, errNotModified
	}
	if resp.StatusCode != 200 {
		err := fmt.Errorf("HTTP %d", resp.StatusCode)
		if resp.StatusCode >= 500 || resp.StatusCode == 429 {
			// 서버 쪽 일시 문제. 4xx (없음 등) 는 내용 문제로 봄
			return "", nil, &netError{err: err, retryAfter: parseRetryAfter(resp.Header.Get("Retry-After"))}
		}
		return "", nil, err
	}
	if resp.ContentLength > max {
		return "", nil, fmt.Errorf("too large (%d)", resp.ContentLength)
	}
	tmp, err := os.CreateTemp(f.tmpDir, "dl.*")
	if err != nil {
		return "", nil, err
	}
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(tmp, h), io.LimitReader(resp.Body, max+1))
	tmp.Close()
	if err != nil {
		err = &netError{err: err} // 받는 도중 끊김
	} else if n > max {
		err = fmt.Errorf("too large (> %d)", max)
	}
	if err == nil && wantHash != "" && !strings.EqualFold(hex.EncodeToString(h.Sum(nil)), wantHash) {
		err = fmt.Errorf("hash mismatch")
	}
	if err != nil {
		os.Remove(tmp.Name())
		return "", nil, err
	}
	f.addBytes(n)
	return tmp.Name(), resp.Header, nil
}

// parseRetryAfter : 초 또는 HTTP 날짜. 모르면 0
func parseRetryAfter(v string) time.Duration {
	if v == "" {
		return 0
	}
	if n, err := strconv.Atoi(v); err == nil && n > 0 {
		return time.Duration(n) * time.Second
	}
	if t, err := http.ParseTime(v); err == nil {
		return time.Until(t)
	}
	return 0
}

// sameOrigin : snapshot / delta 는 notification 과 같은 https 호스트
func sameOrigin(notify, u string) bool {
	a, err1 := url.Parse(notify)
	b, err2 := url.Parse(u)
	return err1 == nil && err2 == nil && b.Scheme == "https" && sameHost(a, b)
}

func validHash(h string) bool {
	if len(h) != 64 {
		return false
	}
	_, err := hex.DecodeString(h)
	return err == nil
}

// fetchNotification : notification.xml 받기 + 검사
// fetchNotification : notification.xml 을 받아 확인. st 가 있으면 조건부 GET (304 = errNotModified, 그대로).
// 돌려주는 헤더 = ETag / Last-Modified (다 맞춘 뒤 상태에 적음)
func (f *fetcher) fetchNotification(ctx context.Context, notify string, st *rrdpState) (*rrdpNotification, uint64, http.Header, error) {
	var etag, lastMod string
	if st != nil && time.Since(st.NotifyAt) < rrdpFullEvery {
		etag, lastMod = st.ETag, st.LastModified
	}
	tmp, hdr, err := f.httpGetCond(ctx, notify, maxNotificationSize, "", etag, lastMod)
	if err == errNotModified {
		return nil, 0, nil, err
	}
	if err != nil {
		return nil, 0, nil, fmt.Errorf("notification: %w", err)
	}
	n, serial, err := parseNotification(notify, tmp)
	return n, serial, hdr, err
}

// parseNotification : 받은 notification 파일을 읽고 확인 (같은 호스트, 해시 모양, serial)
func parseNotification(notify, tmp string) (*rrdpNotification, uint64, error) {
	defer os.Remove(tmp)
	b, err := os.ReadFile(tmp)
	if err != nil {
		return nil, 0, err
	}
	var n rrdpNotification
	if err := newXMLDecoder(bytes.NewReader(b)).Decode(&n); err != nil {
		return nil, 0, fmt.Errorf("notification XML: %w", err)
	}
	if n.XMLName.Space != rrdpNS || n.Version != "1" || n.Session == "" || len(n.Session) > 64 {
		return nil, 0, fmt.Errorf("notification: bad namespace / version / session")
	}
	serial, err := strconv.ParseUint(n.Serial, 10, 64)
	if err != nil || serial == 0 {
		return nil, 0, fmt.Errorf("notification: bad serial %q", n.Serial)
	}
	if !sameOrigin(notify, n.Snapshot.URI) || !validHash(n.Snapshot.Hash) {
		return nil, 0, fmt.Errorf("notification: bad snapshot uri / hash")
	}
	for _, d := range n.Deltas {
		if !sameOrigin(notify, d.URI) || !validHash(d.Hash) {
			return nil, 0, fmt.Errorf("notification: bad delta uri / hash")
		}
	}
	return &n, serial, nil
}

// syncRRDP : 저장소 하나를 최신으로. 성공하면 객체 폴더를 돌려줌
func (f *fetcher) syncRRDP(ctx context.Context, notify string) (string, rrdpResult, error) {
	var res rrdpResult
	dir, statePath := rrdpPaths(f.CacheDir, notify)
	st, _ := loadRRDPState(statePath)
	if st != nil {
		// snapshot 을 바꿔 끼우다 (두 Rename 사이) 죽었으면 상태만 남고 폴더가 없음 -> 상태를 믿지 않고 snapshot
		if fi, err := os.Stat(dir); err != nil || !fi.IsDir() || st.Notify != notify {
			if err != nil || !fi.IsDir() {
				f.logf("rrdp %s: state serial %d but no folder, taking snapshot", notify, st.Serial)
			}
			st = nil
		}
	}
	n, serial, hdr, err := f.fetchNotification(ctx, notify, st)
	if err == errNotModified {
		// 304 : notification 이 지난번 (다 맞춘 것) 과 같음 = 폴더가 최신
		res.Action, res.Serial = "none", st.Serial
		st.LastSuccess = time.Now()
		return dir, res, saveRRDPState(statePath, st)
	}
	if err != nil {
		return dir, res, err
	}
	res.Serial = serial
	// 다 맞추면 (none / delta / snapshot 성공) 이 notification 의 ETag / Last-Modified 를 적음
	done := func(s *rrdpState) *rrdpState {
		s.ETag, s.LastModified, s.NotifyAt = hdr.Get("ETag"), hdr.Get("Last-Modified"), time.Now()
		return s
	}
	if st != nil && st.Session == n.Session {
		if st.Serial == serial {
			res.Action = "none"
			st.LastSuccess = time.Now()
			return dir, res, saveRRDPState(statePath, done(st))
		}
		if st.Serial < serial && serial-st.Serial <= maxDeltasPerFetch {
			files, upTo, dirty, err := f.applyDeltas(ctx, n, st, dir)
			if err == nil {
				res.Action, res.Files = "delta", files
				st.Serial, st.LastSuccess = serial, time.Now()
				return dir, res, saveRRDPState(statePath, done(st))
			}
			if dirty {
				// delta 를 적용하다 실패 = 폴더가 어중간함 -> 상태 지우고 snapshot (상태가 없으면 이 폴더를 대체로도 안 씀)
				f.logf("rrdp %s: delta failed while applying (%v), trying snapshot", notify, err)
				os.Remove(statePath)
			} else {
				// 받기 실패 = 폴더는 done 까지 온전 -> 거기까지 기록 (다음 회차에 이어서, 직전 데이터로 대체 가능)
				if upTo > st.Serial {
					st.Serial = upTo
					st.ETag, st.LastModified = "", "" // 끝까지 못 맞춤 : 다음에 조건 없이 받음
					saveRRDPState(statePath, st)
				}
				if ctx.Err() != nil || isNetError(err) {
					// 시간 초과 / 망 문제 : snapshot 도 같은 망으로 받아야 하니 여기서 그만 (직전 데이터로 대체, 다음 회차에 이어서)
					return dir, res, fmt.Errorf("delta (applied up to %d): %w", upTo, err)
				}
				f.logf("rrdp %s: delta failed (%v), trying snapshot", notify, err)
			}
		}
	}

	files, err := f.applySnapshot(ctx, n, serial, dir)
	if err != nil {
		return dir, res, err
	}
	res.Action, res.Files = "snapshot", files
	return dir, res, saveRRDPState(statePath, done(&rrdpState{Notify: notify, Session: n.Session, Serial: serial, LastSuccess: time.Now()}))
}

// applyDeltas : st.Serial+1 .. 최신 delta 를 차례로 적용 (중간이 빠졌으면 오류 -> snapshot)
// done = 끝까지 적용한 마지막 serial, dirty = delta 하나를 적용하다 실패 (폴더가 어중간함)
func (f *fetcher) applyDeltas(ctx context.Context, n *rrdpNotification, st *rrdpState, dir string) (total int, done uint64, dirty bool, err error) {
	byS := map[uint64]int{}
	for i, d := range n.Deltas {
		s, err := strconv.ParseUint(d.Serial, 10, 64)
		if err != nil {
			return 0, st.Serial, false, fmt.Errorf("bad delta serial")
		}
		byS[s] = i
	}
	last, _ := strconv.ParseUint(n.Serial, 10, 64)
	done = st.Serial
	for s := st.Serial + 1; s <= last; s++ {
		i, ok := byS[s]
		if !ok {
			return total, done, false, fmt.Errorf("delta %d not listed", s)
		}
		d := n.Deltas[i]
		tmp, err := f.httpGet(ctx, d.URI, maxDeltaSize, d.Hash)
		if err != nil {
			return total, done, false, fmt.Errorf("delta %d: %w", s, err)
		}
		cnt, dirty, err := applyDeltaFile(tmp, n.Session, s, dir)
		os.Remove(tmp)
		total += cnt
		if err != nil {
			return total, done, dirty, fmt.Errorf("delta %d: %w", s, err)
		}
		done = s
	}
	return total, done, false, nil
}

// applySnapshot : 새 폴더에 전부 쓰고 성공하면 바꿔 끼움 (실패해도 이전 폴더는 그대로)
func (f *fetcher) applySnapshot(ctx context.Context, n *rrdpNotification, serial uint64, dir string) (int, error) {
	tmp, err := f.httpGet(ctx, n.Snapshot.URI, maxSnapshotSize, n.Snapshot.Hash)
	if err != nil {
		return 0, fmt.Errorf("snapshot: %w", err)
	}
	defer os.Remove(tmp)
	newDir := dir + ".new"
	os.RemoveAll(newDir)
	// 객체가 하나도 없는 snapshot (빈 저장소) 도 폴더는 있어야 바꿔 끼움
	if err := os.MkdirAll(newDir, 0755); err != nil {
		return 0, err
	}
	cnt, err := applySnapshotFile(tmp, n.Session, serial, newDir)
	if err != nil {
		os.RemoveAll(newDir)
		return cnt, fmt.Errorf("snapshot: %w", err)
	}
	old := dir + ".old"
	os.RemoveAll(old)
	if _, err := os.Stat(dir); err == nil {
		if err := os.Rename(dir, old); err != nil {
			return cnt, err
		}
	}
	if err := os.Rename(newDir, dir); err != nil {
		os.Rename(old, dir) // 옛 폴더를 제자리로 (상태 파일은 옛 serial 그대로)
		return cnt, err
	}
	os.RemoveAll(old)
	return cnt, nil
}

// rrdpOp : snapshot / delta 안의 publish 또는 withdraw 하나
type rrdpOp struct {
	Publish bool
	URI     string
	Hash    string
	Path    string // dir 아래 파일 경로
	Data    []byte // publish 내용
}

// parseRRDPFile : snapshot / delta XML 을 흘려 읽으며 요소마다 fn 을 부름 (파일은 건드리지 않음)
// snapshot : publish 만 (hash 없음). delta : publish (hash 있으면 교체, 없으면 새 파일), withdraw (hash 필수)
func parseRRDPFile(path, kind, session string, serial uint64, dir string, fn func(op rrdpOp) error) (int, error) {
	isSnapshot := kind == "snapshot"
	fh, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer fh.Close()
	// encoding/xml 은 토큰 (글자 덩어리, 주석, CDATA ...) 하나를 통째로 메모리에 올린 뒤 돌려줌
	// -> 토큰마다 읽을 수 있는 바이트에 상한 (lim.reset), publish 는 글자 합에 상한 (readRRDPText)
	lim := &tokenLimit{r: fh, max: maxTextRun}
	d := newXMLDecoder(lim)

	count := 0
	sawRoot := false
	for {
		lim.reset()
		tok, err := d.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return count, fmt.Errorf("XML: %w", err)
		}
		se, ok := tok.(xml.StartElement)
		if !ok {
			continue
		}
		if !sawRoot {
			// 루트 : <snapshot|delta xmlns version="1" session_id serial>
			if se.Name.Local != kind || se.Name.Space != rrdpNS {
				return 0, fmt.Errorf("root %s, want %s", se.Name.Local, kind)
			}
			if attr(se, "version") != "1" || attr(se, "session_id") != session || attr(se, "serial") != strconv.FormatUint(serial, 10) {
				return 0, fmt.Errorf("%s session / serial mismatch", kind)
			}
			sawRoot = true
			continue
		}
		el := struct{ URI, Hash, Data string }{URI: attr(se, "uri"), Hash: attr(se, "hash")}
		if el.Data, err = readRRDPText(d, lim, maxTextRun); err != nil {
			return count, fmt.Errorf("XML element %s: %w", se.Name.Local, err)
		}
		if count++; count > maxRRDPFiles {
			return count, fmt.Errorf("too many files")
		}
		if !validURI(el.URI, "rsync://") {
			return count, fmt.Errorf("bad publish uri %q", el.URI)
		}
		op := rrdpOp{URI: el.URI, Hash: el.Hash, Path: filepath.Join(dir, filepath.FromSlash(strings.TrimPrefix(el.URI, "rsync://")))}
		switch {
		case se.Name.Local == "publish":
			if isSnapshot && el.Hash != "" {
				return count, fmt.Errorf("snapshot publish with hash")
			}
			data, err := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(el.Data), ""))
			if err != nil {
				return count, fmt.Errorf("publish %s: base64: %w", el.URI, err)
			}
			if len(data) > maxObjectSize {
				return count, fmt.Errorf("publish %s: too large", el.URI)
			}
			op.Publish, op.Data = true, data
		case se.Name.Local == "withdraw" && !isSnapshot:
			if el.Hash == "" {
				return count, fmt.Errorf("withdraw %s without hash", el.URI)
			}
		default:
			return count, fmt.Errorf("unexpected element %s", se.Name.Local)
		}
		if err := fn(op); err != nil {
			return count, err
		}
	}
	if !sawRoot {
		return 0, fmt.Errorf("empty %s", kind)
	}
	return count, nil
}

// applySnapshotFile : snapshot 을 (새) 폴더 dir 에 씀
func applySnapshotFile(path, session string, serial uint64, dir string) (int, error) {
	return parseRRDPFile(path, "snapshot", session, serial, dir, func(op rrdpOp) error {
		return writeFileAtomic(op.Path, op.Data)
	})
}

// applyDeltaFile : delta 하나를 두 단계로 적용
//  1. 전부 읽고 확인 (기존 파일 해시), 새 내용은 dir+".stage" 에 임시 저장 -> 여기서 실패하면 dir 은 그대로
//  2. 확인이 끝나면 옮김 (rename) / 지움 -> 여기서 실패 (디스크 오류 등) 하면 dirty = 폴더가 어중간함
//
// 같은 URI 가 한 delta 에 여러 번 나오면 앞의 요소를 적용한 상태 기준으로 확인 (옮길 때도 같은 순서)
func applyDeltaFile(path, session string, serial uint64, dir string) (count int, dirty bool, err error) {
	stage := dir + ".stage"
	os.RemoveAll(stage)
	defer os.RemoveAll(stage)
	if err := os.MkdirAll(stage, 0755); err != nil {
		return 0, false, err
	}
	type staged struct {
		op  rrdpOp
		tmp string // publish 내용 임시 파일
	}
	var ops []staged
	after := map[string]string{} // 이 delta 에서 이미 나온 URI -> 적용 뒤 해시 ("" = 없음)
	count, err = parseRRDPFile(path, "delta", session, serial, dir, func(op rrdpOp) error {
		check := func() error { return checkExisting(op.Path, op.Hash) }
		if h, ok := after[op.URI]; ok {
			check = func() error { return checkHash(h, op.Hash) }
		}
		if op.Publish {
			after[op.URI] = hashHex(op.Data)
		} else {
			after[op.URI] = ""
		}
		if err := check(); err != nil {
			if op.Publish {
				return fmt.Errorf("publish %s: %w", op.URI, err)
			}
			return fmt.Errorf("withdraw %s: %w", op.URI, err)
		}
		st := staged{op: op}
		if op.Publish {
			st.tmp = filepath.Join(stage, strconv.Itoa(len(ops)))
			if err := os.WriteFile(st.tmp, op.Data, 0644); err != nil {
				return err
			}
			st.op.Data = nil // 메모리에 들고 있지 않음
		}
		ops = append(ops, st)
		return nil
	})
	if err != nil {
		return count, false, err
	}
	for _, st := range ops {
		if st.op.Publish {
			if err := os.MkdirAll(filepath.Dir(st.op.Path), 0755); err != nil {
				return count, true, err
			}
			if err := os.Rename(st.tmp, st.op.Path); err != nil {
				return count, true, err
			}
		} else if err := os.Remove(st.op.Path); err != nil {
			return count, true, err
		}
	}
	return count, false, nil
}

// maxTextRun : publish 하나의 글자 수 상한 = base64 (객체 상한의 4/3) + 줄바꿈 / 공백 여유. XML 토큰 하나의 바이트 상한도 이 값
const maxTextRun = maxObjectSize/3*4*2 + 1<<20

// tokenLimit : XML 토큰 하나를 읽는 동안 max 바이트 넘게 읽으면 오류 (reset 으로 다시 셈)
// 전 방식 (textRunLimit = '<' 없이 이어지는 길이) 은 주석 / CDATA 안에 '<' 를 넣거나 글자를 <!----> 로 잘게 나누면
// 우회됨 (11-05 검토 2). 토큰 종류와 상관없이 decoder 가 한 번에 메모리에 올리는 양을 막음
type tokenLimit struct {
	r    io.Reader
	max  int
	left int
}

func (t *tokenLimit) reset() { t.left = t.max }

func (t *tokenLimit) Read(p []byte) (int, error) {
	if t.left <= 0 {
		return 0, fmt.Errorf("XML token longer than %d bytes", t.max)
	}
	if len(p) > t.left {
		p = p[:t.left]
	}
	n, err := t.r.Read(p)
	t.left -= n
	return n, err
}

// readRRDPText : publish / withdraw 의 시작 태그 뒤부터 끝 태그까지 글자를 모음 (합이 max 넘으면 오류)
// 자식 요소는 오류, 주석 / 처리 명령은 건너뜀 (CDATA 는 글자로 셈)
func readRRDPText(d *xml.Decoder, lim *tokenLimit, max int) (string, error) {
	var sb strings.Builder
	for {
		lim.reset()
		tok, err := d.Token()
		if err != nil {
			return "", err
		}
		switch t := tok.(type) {
		case xml.CharData:
			if sb.Len()+len(t) > max {
				return "", fmt.Errorf("XML text longer than %d bytes", max)
			}
			sb.Write(t)
		case xml.StartElement:
			return "", fmt.Errorf("unexpected child element %s", t.Name.Local)
		case xml.EndElement:
			return sb.String(), nil
		}
	}
}

// newXMLDecoder : encoding 선언이 US-ASCII / UTF-8 / ISO-8859-1 이어도 받음
// (ASCII 는 UTF-8 의 부분집합. RRDP 내용은 URI 와 base64 뿐이라 실제로 ASCII)
func newXMLDecoder(r io.Reader) *xml.Decoder {
	d := xml.NewDecoder(r)
	d.CharsetReader = func(label string, in io.Reader) (io.Reader, error) {
		switch strings.ToLower(label) {
		case "us-ascii", "ascii", "utf-8", "utf8", "iso-8859-1", "latin1":
			return in, nil
		}
		return nil, fmt.Errorf("XML encoding %q not supported", label)
	}
	return d
}

func attr(se xml.StartElement, name string) string {
	for _, a := range se.Attr {
		if a.Name.Local == name {
			return a.Value
		}
	}
	return ""
}

// checkExisting : hash 가 있으면 그 파일이 있고 해시가 같아야 함, 없으면 파일이 없어야 함 (RFC 8182 3.5.3)
func checkExisting(p, hash string) error {
	if hash == "" {
		// 이미 있는 파일을 hash 없이 publish : RFC 로는 오류지만 실제로 있어서 덮어씀 (rpki-client 도 받음)
		return nil
	}
	b, err := os.ReadFile(p)
	if err != nil {
		return fmt.Errorf("file to replace / withdraw missing")
	}
	return checkHash(hashHex(b), hash)
}

// checkHash : cur = 지금 파일 해시 ("" = 없음), want = delta 의 hash ("" = 새 파일)
func checkHash(cur, want string) error {
	switch {
	case want == "":
		return nil
	case cur == "":
		return fmt.Errorf("file to replace / withdraw missing")
	case !strings.EqualFold(cur, want):
		return fmt.Errorf("hash of existing file differs")
	}
	return nil
}

func hashHex(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

// writeFileAtomic : 폴더 만들고 임시 파일 -> rename
func writeFileAtomic(p string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(p), 0755); err != nil {
		return err
	}
	tmp := p + ".tmp"
	if err := os.WriteFile(tmp, data, 0644); err != nil {
		return err
	}
	return os.Rename(tmp, p)
}
