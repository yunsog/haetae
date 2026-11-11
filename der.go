package main

// der.go : DER 읽기 도우미 (엄격)
//
// ASN.1 DER 은 TLV (Tag, Length, Value) 의 나열. C 로 치면
//   struct { u8 tag; 길이; u8 value[길이]; }  이 중첩된 것.
// 믿을 수 없는 입력이므로 다음을 모두 거부한다.
//   - 무한 길이 (BER 0x80), 최소가 아닌 길이 표현, 길이가 남은 바이트보다 큼
//   - 여러 바이트 tag 번호 (RPKI 에서는 쓰지 않음)
// 복사는 하지 않음 : derNode 의 Body / Full 은 원래 버퍼의 slice.

import (
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"
	"time"
)

// 객체 파일 하나의 크기 상한 (바이너리 = DER). RFC 에 없는 값, RP 마다 정함 (rpki-client 4 MB, Routinator 기본 20 MB).
// 0.2.0 : 4 MB -> 20 MB (11-02 사용자 결정, Routinator 기본값과 같음). 실제 가장 큰 객체 = ARIN CA manifest 3.87 MB (2026-11) 로 4 MB 의 97 %,
// 넘는 날 그 CA 전체가 빠짐. 이 값에서 rsync --max-size, TA 받기, RRDP base64 글자 상한 (maxTextRun) 이 따라 정해짐
const maxObjectSize = 20000000

// tag 클래스
const (
	classUniversal = 0
	classContext   = 2
)

// universal tag 번호
const (
	tagBoolean         = 1
	tagInteger         = 2
	tagBitString       = 3
	tagOctetString     = 4
	tagNull            = 5
	tagOID             = 6
	tagUTF8String      = 12
	tagSequence        = 16
	tagSet             = 17
	tagPrintableString = 19
	tagIA5String       = 22
	tagUTCTime         = 23
	tagGeneralizedTime = 24
)

// derNode : TLV 하나
type derNode struct {
	Class       int    // 0 universal, 1 application, 2 context, 3 private
	Constructed bool   // SEQUENCE / SET / [n] EXPLICIT 등 안에 TLV 가 들어 있음
	Tag         int    // tag 번호 (0..30)
	Full        []byte // tag + length + value 전체 (서명 대상 등에 씀)
	Body        []byte // value 부분만
}

var errDER = errors.New("bad DER")

func derErr(format string, a ...any) error {
	return fmt.Errorf("%w: %s", errDER, fmt.Sprintf(format, a...))
}

// derRead : b 의 앞에서 TLV 하나를 읽고 나머지를 돌려줌
func derRead(b []byte) (n derNode, rest []byte, err error) {
	if len(b) < 2 {
		return n, nil, derErr("short header")
	}
	t := b[0]
	n.Class = int(t >> 6)
	n.Constructed = t&0x20 != 0
	n.Tag = int(t & 0x1f)
	if n.Tag == 0x1f {
		return n, nil, derErr("multi-byte tag")
	}

	// 길이 : 0..127 은 한 바이트, 그 이상은 0x80|바이트수 + 빅엔디안
	l := int(b[1])
	hdr := 2
	if l&0x80 != 0 {
		nb := l & 0x7f
		if nb == 0 {
			return n, nil, derErr("indefinite length")
		}
		if nb > 4 {
			return n, nil, derErr("length too long")
		}
		if len(b) < 2+nb {
			return n, nil, derErr("short length")
		}
		if b[2] == 0 {
			return n, nil, derErr("non-minimal length")
		}
		l = 0
		for i := 0; i < nb; i++ {
			l = l<<8 | int(b[2+i])
		}
		if l < 128 {
			return n, nil, derErr("non-minimal length")
		}
		hdr = 2 + nb
	}
	if l > len(b)-hdr {
		return n, nil, derErr("length %d > remaining %d", l, len(b)-hdr)
	}
	n.Full = b[:hdr+l]
	n.Body = b[hdr : hdr+l]
	return n, b[hdr+l:], nil
}

// derOne : b 전체가 정확히 TLV 하나여야 함 (뒤에 남는 바이트 거부)
func derOne(b []byte) (derNode, error) {
	n, rest, err := derRead(b)
	if err != nil {
		return n, err
	}
	if len(rest) != 0 {
		return n, derErr("%d trailing bytes", len(rest))
	}
	return n, nil
}

// derChildren : constructed TLV 의 자식 목록 (최대 max 개)
// 상한은 담으면서 봄 : 다 담은 뒤에 세면 2 바이트 원소 (빈 SEQUENCE) 가 derNode 72 바이트가 되어
// 20 MB 객체 하나가 서명 확인 전에 수 GB 를 씀 (11-05 검토 1)
func derChildren(n derNode, max int) ([]derNode, error) {
	if !n.Constructed {
		return nil, derErr("not constructed (tag %d)", n.Tag)
	}
	var out []derNode
	b := n.Body
	for len(b) > 0 {
		if len(out) >= max {
			return nil, derErr("more than %d items", max)
		}
		c, rest, err := derRead(b)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
		b = rest
	}
	return out, nil
}

// is : universal tag 확인
func (n derNode) is(tag int) bool {
	return n.Class == classUniversal && n.Tag == tag
}

// isCtx : context [tag] 확인
func (n derNode) isCtx(tag int) bool {
	return n.Class == classContext && n.Tag == tag
}

// derSeq : SEQUENCE 이고 자식 수가 min..max 인지 확인하고 자식을 돌려줌
func derSeq(n derNode, min, max int) ([]derNode, error) {
	if !n.is(tagSequence) || !n.Constructed {
		return nil, derErr("want SEQUENCE, got class %d tag %d", n.Class, n.Tag)
	}
	c, err := derChildren(n, max)
	if err != nil {
		return nil, err
	}
	if len(c) < min {
		return nil, derErr("SEQUENCE has %d items, want %d..%d", len(c), min, max)
	}
	return c, nil
}

// derOIDOf : OBJECT IDENTIFIER
func derOIDOf(n derNode) (asn1.ObjectIdentifier, error) {
	if !n.is(tagOID) || n.Constructed {
		return nil, derErr("want OID")
	}
	var oid asn1.ObjectIdentifier
	// encoding/asn1 이 OID 내용 (최소 표현 등) 을 검사
	rest, err := asn1.Unmarshal(n.Full, &oid)
	if err != nil || len(rest) != 0 {
		return nil, derErr("bad OID: %v", err)
	}
	return oid, nil
}

// derBigInt : INTEGER (최소 표현 확인)
func derBigInt(n derNode) (*big.Int, error) {
	if !n.is(tagInteger) || n.Constructed {
		return nil, derErr("want INTEGER")
	}
	b := n.Body
	if len(b) == 0 {
		return nil, derErr("empty INTEGER")
	}
	if len(b) > 1 && ((b[0] == 0 && b[1]&0x80 == 0) || (b[0] == 0xff && b[1]&0x80 != 0)) {
		return nil, derErr("non-minimal INTEGER")
	}
	v := new(big.Int).SetBytes(b)
	if b[0]&0x80 != 0 { // 음수 : 2 의 보수
		v.Sub(v, new(big.Int).Lsh(big.NewInt(1), uint(len(b)*8)))
	}
	return v, nil
}

// derUint : 0 이상 max 이하 INTEGER (ASN, 버전 번호 등)
func derUint(n derNode, max uint64) (uint64, error) {
	v, err := derBigInt(n)
	if err != nil {
		return 0, err
	}
	if v.Sign() < 0 || !v.IsUint64() || v.Uint64() > max {
		return 0, derErr("INTEGER %s out of range 0..%d", v, max)
	}
	return v.Uint64(), nil
}

// derBits : BIT STRING -> (바이트, 사용 안 하는 끝 비트 수)
// DER 이므로 사용 안 하는 비트는 0 이어야 함
func derBits(n derNode) ([]byte, int, error) {
	if !n.is(tagBitString) || n.Constructed {
		return nil, 0, derErr("want BIT STRING")
	}
	b := n.Body
	if len(b) == 0 {
		return nil, 0, derErr("empty BIT STRING")
	}
	unused := int(b[0])
	b = b[1:]
	if unused > 7 || (len(b) == 0 && unused != 0) {
		return nil, 0, derErr("bad BIT STRING unused %d", unused)
	}
	if unused > 0 && b[len(b)-1]&(1<<unused-1) != 0 {
		return nil, 0, derErr("BIT STRING padding bits not zero")
	}
	return b, unused, nil
}

// derOctets : OCTET STRING
func derOctets(n derNode) ([]byte, error) {
	if !n.is(tagOctetString) || n.Constructed {
		return nil, derErr("want OCTET STRING")
	}
	return n.Body, nil
}

// derTime : GeneralizedTime (YYYYMMDDHHMMSSZ, RFC 5280 형식만)
func derGeneralizedTime(n derNode) (time.Time, error) {
	if !n.is(tagGeneralizedTime) || n.Constructed {
		return time.Time{}, derErr("want GeneralizedTime")
	}
	s := string(n.Body)
	if len(s) != 15 || s[14] != 'Z' {
		return time.Time{}, derErr("bad GeneralizedTime %q", s)
	}
	t, err := time.Parse("20060102150405Z", s)
	if err != nil {
		return time.Time{}, derErr("bad GeneralizedTime %q", s)
	}
	return t, nil
}
