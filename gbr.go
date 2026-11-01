package main

// gbr.go : Ghostbusters Record (RFC 6493)
//
// CA 운영자 연락처를 vCard 텍스트로 서명해 둔 객체 (.gbr). 라우팅에는 안 쓰고 상태 API 에서 보여 줌.
// eContent = vCard 텍스트 그대로 (DER 아님).
//   BEGIN:VCARD / VERSION / FN / ORG / ADR / TEL / EMAIL / END:VCARD
// RFC 6493 은 VERSION:4.0, FN / ORG 필수, ADR / TEL / EMAIL 중 하나 이상을 요구하지만
// 실제 게시물에 VERSION:3.0 도 있음 -> 형식이 맞으면 받고, 프로파일 차이는 Warn 에 기록.

import (
	"encoding/asn1"
	"fmt"
	"strings"
)

var oidCTGhostbusters = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 1, 35}

const maxVCardSize = 64 * 1024

type rpkiGBR struct {
	*signedObject
	VCard string            // 원문 (줄바꿈 CRLF -> LF)
	Props map[string]string // FN, ORG, ADR, TEL, EMAIL (첫 값)
	Warn  []string          // RFC 6493 프로파일과 다른 점
}

func parseGBR(der []byte) (*rpkiGBR, error) {
	so, err := parseSignedObject(der, oidCTGhostbusters)
	if err != nil {
		return nil, err
	}
	g := &rpkiGBR{signedObject: so, Props: map[string]string{}}
	if len(so.Content) > maxVCardSize {
		return nil, fmt.Errorf("vCard too large")
	}
	for _, ch := range so.Content {
		// 출력 가능한 ASCII + 탭 / 줄바꿈만 (UTF-8 은 받되 제어 문자는 거부)
		if ch < 0x20 && ch != '\t' && ch != '\r' && ch != '\n' || ch == 0x7f {
			return nil, fmt.Errorf("vCard with control character")
		}
	}
	g.VCard = strings.ReplaceAll(string(so.Content), "\r\n", "\n")

	lines := strings.Split(strings.TrimRight(g.VCard, "\n"), "\n")
	if len(lines) < 3 || lines[0] != "BEGIN:VCARD" || lines[len(lines)-1] != "END:VCARD" {
		return nil, fmt.Errorf("not a vCard (BEGIN / END)")
	}
	for _, l := range lines[1 : len(lines)-1] {
		i := strings.IndexByte(l, ':')
		if i <= 0 {
			return nil, fmt.Errorf("vCard line without name: %q", l)
		}
		// 이름 뒤 ;TYPE=... 같은 매개변수는 떼고 이름만
		name := strings.ToUpper(strings.SplitN(l[:i], ";", 2)[0])
		val := l[i+1:]
		switch name {
		case "VERSION":
			if val != "4.0" {
				g.Warn = append(g.Warn, "VERSION "+val+" (RFC 6493 = 4.0)")
			}
		case "FN", "ORG", "ADR", "TEL", "EMAIL":
			if _, ok := g.Props[name]; !ok {
				g.Props[name] = val
			}
		case "N":
		default:
			g.Warn = append(g.Warn, "property "+name+" not in RFC 6493")
		}
	}
	if g.Props["FN"] == "" {
		return nil, fmt.Errorf("vCard without FN")
	}
	if g.Props["ORG"] == "" {
		g.Warn = append(g.Warn, "no ORG")
	}
	if g.Props["ADR"] == "" && g.Props["TEL"] == "" && g.Props["EMAIL"] == "" {
		return nil, fmt.Errorf("vCard without ADR / TEL / EMAIL")
	}
	return g, nil
}
