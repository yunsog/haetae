package main

// output.go : 검증 결과 파일
//
//   json          rpki-client 모양 (metadata, roas, aspas, bgpsec_keys) -> vrp_diff / 비교용
//   csv           rpki-client 모양 (ASN,IP Prefix,Max Length,Trust Anchor,Expires)
//   objects.jsonl 전체 객체 목록 (E6) : 객체 하나에 한 줄
//   rejects.txt   거부된 객체 (URI<TAB>이유)
//   summary.txt   종류별 개수, 경고 개수
// 파일은 임시 이름으로 쓰고 rename (읽는 쪽이 반쯤 쓴 파일을 보지 않게)

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"
)

// writeAtomic : dir/name 에 fn 이 쓰는 내용을 원자적으로 저장
func writeAtomic(dir, name string, fn func(w *bufio.Writer) error) error {
	tmp, err := os.CreateTemp(dir, "."+name+".*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	w := bufio.NewWriterSize(tmp, 1<<20)
	if err := fn(w); err != nil {
		tmp.Close()
		return err
	}
	if err := w.Flush(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(0644); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), filepath.Join(dir, name))
}

// sortedVRPs : 주소, prefix 길이, maxLength, ASN, TA 순
func (v *validator) sortedVRPs() []vrpKey {
	ks := make([]vrpKey, 0, len(v.vrps))
	for k := range v.vrps {
		ks = append(ks, k)
	}
	sort.Slice(ks, func(i, j int) bool {
		a, b := ks[i], ks[j]
		if c := a.Prefix.Addr().Compare(b.Prefix.Addr()); c != 0 {
			return c < 0
		}
		if a.Prefix.Bits() != b.Prefix.Bits() {
			return a.Prefix.Bits() < b.Prefix.Bits()
		}
		if a.MaxLength != b.MaxLength {
			return a.MaxLength < b.MaxLength
		}
		if a.ASN != b.ASN {
			return a.ASN < b.ASN
		}
		return a.TA < b.TA
	})
	return ks
}

func (v *validator) writeOutputs(dir string, started time.Time) error {
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}
	vrps := v.sortedVRPs()

	// aspas : customer 순, provider 오름차순
	akeys := make([]aspaKey, 0, len(v.aspas))
	for k := range v.aspas {
		akeys = append(akeys, k)
	}
	sort.Slice(akeys, func(i, j int) bool {
		if akeys[i].Customer != akeys[j].Customer {
			return akeys[i].Customer < akeys[j].Customer
		}
		return akeys[i].TA < akeys[j].TA
	})
	sort.Slice(v.rkeys, func(i, j int) bool {
		if v.rkeys[i].ASN != v.rkeys[j].ASN {
			return v.rkeys[i].ASN < v.rkeys[j].ASN
		}
		return bytes.Compare(v.rkeys[i].SKI, v.rkeys[j].SKI) < 0
	})

	err := writeAtomic(dir, "csv", func(w *bufio.Writer) error {
		w.WriteString("ASN,IP Prefix,Max Length,Trust Anchor,Expires\n")
		for _, k := range vrps {
			fmt.Fprintf(w, "AS%d,%s,%d,%s,%d\n", k.ASN, k.Prefix, k.MaxLength, k.TA, v.vrps[k].Unix())
		}
		return nil
	})
	if err != nil {
		return err
	}

	err = writeAtomic(dir, "json", func(w *bufio.Writer) error {
		meta := map[string]any{
			"buildtime":   started.UTC().Format("2006-01-02T15:04:05Z"),
			"evaltime":    v.Now.UTC().Format("2006-01-02T15:04:05Z"),
			"elapsedtime": int(time.Since(started).Seconds()),
			"uniquevrps":  len(vrps),
			"uniquevaps":  len(akeys),
			"bgpsec_keys": len(v.rkeys),
			"failed_tals": v.failedTA,
			"counts":      v.count,
		}
		mb, _ := json.MarshalIndent(meta, "\t", "\t")
		fmt.Fprintf(w, "{\n\t\"metadata\": %s,\n\t\"roas\": [\n", mb)
		for i, k := range vrps {
			sep := ","
			if i == len(vrps)-1 {
				sep = ""
			}
			fmt.Fprintf(w, "\t\t{ \"asn\": %d, \"prefix\": \"%s\", \"maxLength\": %d, \"ta\": \"%s\", \"expires\": %d }%s\n",
				k.ASN, k.Prefix, k.MaxLength, k.TA, v.vrps[k].Unix(), sep)
		}
		w.WriteString("\t],\n\t\"aspas\": [\n")
		for i, k := range akeys {
			a := v.aspas[k]
			ps := make([]uint32, 0, len(a.Providers))
			for p := range a.Providers {
				ps = append(ps, p)
			}
			sort.Slice(ps, func(i, j int) bool { return ps[i] < ps[j] })
			pb, _ := json.Marshal(ps)
			sep := ","
			if i == len(akeys)-1 {
				sep = ""
			}
			fmt.Fprintf(w, "\t\t{ \"customer_asid\": %d, \"ta\": \"%s\", \"expires\": %d, \"providers\": %s }%s\n",
				k.Customer, k.TA, a.Expires.Unix(), pb, sep)
		}
		w.WriteString("\t],\n\t\"bgpsec_keys\": [\n")
		for i, r := range v.rkeys {
			sep := ","
			if i == len(v.rkeys)-1 {
				sep = ""
			}
			fmt.Fprintf(w, "\t\t{ \"asn\": %d, \"ski\": \"%X\", \"pubkey\": \"%s\", \"ta\": \"%s\", \"expires\": %d }%s\n",
				r.ASN, r.SKI, base64.StdEncoding.EncodeToString(r.SPKI), r.TA, r.Expires.Unix(), sep)
		}
		w.WriteString("\t]\n}\n")
		return nil
	})
	if err != nil {
		return err
	}

	sort.Slice(v.objects, func(i, j int) bool { return v.objects[i].URI < v.objects[j].URI })
	err = writeAtomic(dir, "objects.jsonl", func(w *bufio.Writer) error {
		enc := json.NewEncoder(w)
		for i := range v.objects {
			if err := enc.Encode(&v.objects[i]); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return err
	}

	err = writeAtomic(dir, "rejects.txt", func(w *bufio.Writer) error {
		for _, o := range v.objects {
			if o.Status == "rejected" {
				fmt.Fprintf(w, "%s\t%s\n", o.URI, o.Reason)
			}
		}
		return nil
	})
	if err != nil {
		return err
	}

	return writeAtomic(dir, "summary.txt", func(w *bufio.Writer) error {
		fmt.Fprintf(w, "evaltime %s\nelapsed %s\nvrps %d\nvaps %d\nbgpsec_keys %d\nfailed_tals %v\n",
			v.Now.UTC().Format(time.RFC3339), time.Since(started).Round(time.Second), len(vrps), len(akeys), len(v.rkeys), v.failedTA)
		keys := make([]string, 0, len(v.count))
		for k := range v.count {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			fmt.Fprintf(w, "%8d  %s\n", v.count[k], k)
		}
		for what, ex := range v.warnEx {
			for _, e := range ex {
				fmt.Fprintf(w, "example  %s : %s\n", what, e)
			}
		}
		return nil
	})
}
