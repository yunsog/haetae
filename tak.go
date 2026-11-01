package main

// tak.go : Trust Anchor Key (RFC 9691)
//
// TA 키를 바꿀 때 TA 가 "지금 키 / 이전 키 / 다음 키" 를 서명해 알리는 객체 (.tak).
// RP 는 이것을 보고 TAL 을 새 키로 바꿀 수 있음 (자동 교체는 하지 않고 기록 / 경고만 할 예정).
//   TAK ::= SEQUENCE {
//     version INTEGER DEFAULT 0,
//     current TAKey,
//     predecessor [0] EXPLICIT TAKey OPTIONAL,
//     successor   [1] EXPLICIT TAKey OPTIONAL }
//   TAKey ::= SEQUENCE {
//     comments SEQUENCE OF UTF8String,
//     certificateURIs SEQUENCE (1..MAX) OF IA5String,
//     subjectPublicKeyInfo SubjectPublicKeyInfo }

import (
	"crypto/sha1"
	"crypto/x509"
	"encoding/asn1"
	"fmt"
)

var oidCTTAK = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 1, 50}

type taKey struct {
	Comments []string
	URIs     []string // rsync:// 또는 https:// (TA 인증서 위치)
	SPKI     []byte   // DER SubjectPublicKeyInfo
	SKI      []byte   // SHA-1(공개키 비트) = 그 키로 만든 TA 인증서의 SKI
}

type rpkiTAK struct {
	*signedObject
	Current     taKey
	Predecessor *taKey
	Successor   *taKey
}

func parseTAK(der []byte) (*rpkiTAK, error) {
	so, err := parseSignedObject(der, oidCTTAK)
	if err != nil {
		return nil, err
	}
	t := &rpkiTAK{signedObject: so}
	// RFC 9691 : EE 자원은 inherit
	if !eeInherits(so.EE) {
		return nil, fmt.Errorf("TAK EE resources not inherit")
	}

	top, err := derOne(so.Content)
	if err != nil {
		return nil, err
	}
	f, err := derSeq(top, 1, 3)
	if err != nil {
		return nil, fmt.Errorf("TAK: %w", err)
	}
	if f[0].is(tagInteger) {
		return nil, fmt.Errorf("TAK version present (only v0)")
	}
	if t.Current, err = parseTAKey(f[0]); err != nil {
		return nil, fmt.Errorf("TAK current: %w", err)
	}
	for _, n := range f[1:] {
		inner, err := derOne(n.Body)
		if err != nil || !n.Constructed || n.Class != classContext {
			return nil, fmt.Errorf("TAK predecessor / successor: bad tag")
		}
		k, err := parseTAKey(inner)
		if err != nil {
			return nil, err
		}
		switch {
		case n.Tag == 0 && t.Predecessor == nil && t.Successor == nil:
			t.Predecessor = &k
		case n.Tag == 1 && t.Successor == nil:
			t.Successor = &k
		default:
			return nil, fmt.Errorf("TAK predecessor / successor order")
		}
	}
	return t, nil
}

func parseTAKey(n derNode) (taKey, error) {
	var k taKey
	f, err := derSeq(n, 3, 3)
	if err != nil {
		return k, err
	}
	cs, err := derSeq(f[0], 0, 1000)
	if err != nil {
		return k, fmt.Errorf("comments: %w", err)
	}
	for _, c := range cs {
		if !c.is(tagUTF8String) || c.Constructed {
			return k, fmt.Errorf("comment not UTF8String")
		}
		k.Comments = append(k.Comments, string(c.Body))
	}
	us, err := derSeq(f[1], 1, 100)
	if err != nil {
		return k, fmt.Errorf("certificateURIs: %w", err)
	}
	for _, u := range us {
		if !u.is(tagIA5String) || u.Constructed {
			return k, fmt.Errorf("certificateURI not IA5String")
		}
		s := string(u.Body)
		if !validURI(s, "rsync://") && !validURI(s, "https://") {
			return k, fmt.Errorf("bad certificateURI %q", s)
		}
		k.URIs = append(k.URIs, s)
	}
	// 공개키 : RSA 여야 하고 crypto/x509 로 형식 확인
	k.SPKI = f[2].Full
	if _, err := x509.ParsePKIXPublicKey(k.SPKI); err != nil {
		return k, fmt.Errorf("subjectPublicKeyInfo: %w", err)
	}
	spki, err := derSeq(f[2], 2, 2)
	if err != nil {
		return k, err
	}
	bits, _, err := derBits(spki[1])
	if err != nil {
		return k, err
	}
	h := sha1.Sum(bits)
	k.SKI = h[:]
	return k, nil
}
