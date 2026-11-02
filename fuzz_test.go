package main

// fuzz_test.go : 파서 fuzz 시험 (입력 = 인터넷의 믿을 수 없는 저장소). 객체 하나가 무엇이든 panic / 무한 루프 없이 오류로 끝나야 함
//
//   go test .                               씨앗 (testdata/seed 의 실제 객체 + 잘린 / 빈 입력) 만 한 번씩 = 보통 시험
//   go test -run x -fuzz FuzzParseROA -fuzztime 60s .   무작위로 바꿔 가며 계속 (하나씩, 찾은 입력은 testdata/fuzz/ 에 남음)
//
// 씨앗 객체 : 공개 RPKI 저장소에서 받은 것 (RIPE NCC TA 의 CRL / manifest, CA 인증서, ROA, ASPA)

import (
	"os"
	"testing"
)

// addSeeds : 씨앗 파일과 그 변형 (빈 것, 앞 절반, 한 바이트 바꾼 것)
func addSeeds(f *testing.F, files ...string) {
	f.Add([]byte{})
	f.Add([]byte{0x30, 0x80}) // 길이가 정해지지 않은 SEQUENCE (DER 에서 금지)
	for _, name := range files {
		b, err := os.ReadFile("testdata/seed/" + name)
		if err != nil {
			f.Fatalf("seed %s: %v", name, err)
		}
		f.Add(b)
		f.Add(b[:len(b)/2])
		c := append([]byte(nil), b...)
		c[len(c)/3] ^= 0xff
		f.Add(c)
	}
}

func FuzzParseCert(f *testing.F) {
	addSeeds(f, "ca.cer")
	f.Fuzz(func(t *testing.T, b []byte) {
		parseCert(b, false)
		parseCert(b, true)
	})
}

func FuzzParseCRL(f *testing.F) {
	addSeeds(f, "ta.crl")
	f.Fuzz(func(t *testing.T, b []byte) { parseCRL(b) })
}

func FuzzParseManifest(f *testing.F) {
	addSeeds(f, "ta.mft")
	f.Fuzz(func(t *testing.T, b []byte) { parseManifest(b) })
}

func FuzzParseROA(f *testing.F) {
	addSeeds(f, "a.roa")
	f.Fuzz(func(t *testing.T, b []byte) { parseROA(b) })
}

func FuzzParseASPA(f *testing.F) {
	addSeeds(f, "a.asa")
	f.Fuzz(func(t *testing.T, b []byte) { parseASPA(b) })
}

// 서명 객체 껍데기 (CMS) 위에 올라가는 나머지 종류 : 씨앗은 ROA / ASPA 를 빌려 씀 (eContent 종류가 달라 대부분 오류 = 오류 길도 시험)
func FuzzParseOtherSigned(f *testing.F) {
	addSeeds(f, "a.roa", "a.asa")
	f.Fuzz(func(t *testing.T, b []byte) {
		parseGBR(b)
		parseSPL(b)
		parseTAK(b)
		parseRSC(b)
	})
}

// 씨앗이 실제로 파싱되는지 (씨앗이 깨져 있으면 fuzz 가 오류 길만 돎)
func TestFuzzSeedsParse(t *testing.T) {
	read := func(n string) []byte {
		b, err := os.ReadFile("testdata/seed/" + n)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	if _, err := parseCert(read("ca.cer"), false); err != nil {
		t.Errorf("ca.cer: %v", err)
	}
	if _, err := parseCRL(read("ta.crl")); err != nil {
		t.Errorf("ta.crl: %v", err)
	}
	if _, err := parseManifest(read("ta.mft")); err != nil {
		t.Errorf("ta.mft: %v", err)
	}
	if _, err := parseROA(read("a.roa")); err != nil {
		t.Errorf("a.roa: %v", err)
	}
	if _, err := parseASPA(read("a.asa")); err != nil {
		t.Errorf("a.asa: %v", err)
	}
}
