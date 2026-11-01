package main

// cms.go : RPKI 서명 객체 (RFC 6488 CMS SignedData) 껍데기
//
// ROA, manifest 등은 모두 같은 모양
//   ContentInfo { signedData,
//     SignedData { version 3, digestAlgorithms {sha256}, encapContentInfo { eContentType, eContent },
//                  certificates [0] { EE 인증서 1 개 }, signerInfos { SignerInfo 1 개 } } }
// SignerInfo 의 서명 = EE 공개키로 signedAttrs (DER, tag 를 SET 으로 바꾼 것) 를 RSA-SHA256 서명
// signedAttrs 의 messageDigest = SHA-256(eContent)
// 여기서는 EE 인증서 자체 서명 (부모 키) 은 안 봄 -> validate.go

import (
	"bytes"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/asn1"
	"fmt"
	"time"
)

var (
	oidSignedData   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}
	oidSHA256       = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	oidRSA          = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}
	oidSHA256RSA    = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 11}
	oidAttrCType    = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 3}
	oidAttrDigest   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 4}
	oidAttrSignTime = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 5}
	oidAttrBinTime  = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 2, 46}

	// eContentType
	oidCTROA      = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 1, 24}
	oidCTManifest = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 1, 26}
)

// signedObject : 껍데기를 벗긴 결과
type signedObject struct {
	EE          *rpkiCert
	ContentType asn1.ObjectIdentifier
	Content     []byte    // eContent (ROA / manifest 본문 DER)
	SigningTime time.Time // 있으면 (참고용)
}

// parseSignedObject : 파일 바이트 -> 서명 확인까지 한 signedObject
// want : 기대하는 eContentType (파일 확장자로 정함)
func parseSignedObject(der []byte, want asn1.ObjectIdentifier) (*signedObject, error) {
	return parseSignedObjectOpt(der, want, false)
}

// parseSignedObjectOpt : eeNoSIA = EE 에 SIA 가 없어야 함 (RSC)
func parseSignedObjectOpt(der []byte, want asn1.ObjectIdentifier, eeNoSIA bool) (*signedObject, error) {
	if len(der) > maxObjectSize {
		return nil, fmt.Errorf("object too large")
	}
	top, err := derOne(der)
	if err != nil {
		return nil, err
	}
	ci, err := derSeq(top, 2, 2)
	if err != nil {
		return nil, fmt.Errorf("ContentInfo: %w", err)
	}
	if oid, err := derOIDOf(ci[0]); err != nil || !oid.Equal(oidSignedData) {
		return nil, fmt.Errorf("ContentInfo: not signedData")
	}
	sdw, err := explicit(ci[1], 0)
	if err != nil {
		return nil, fmt.Errorf("ContentInfo content: %w", err)
	}
	// SignedData : version, digestAlgorithms, encapContentInfo, [0] certificates, [1] crls 금지, signerInfos
	sd, err := derSeq(sdw, 5, 5)
	if err != nil {
		return nil, fmt.Errorf("SignedData (crls not allowed): %w", err)
	}
	if v, err := derUint(sd[0], 10); err != nil || v != 3 {
		return nil, fmt.Errorf("SignedData version not 3")
	}
	if err := checkDigestAlgs(sd[1]); err != nil {
		return nil, err
	}

	so := &signedObject{}
	if err := so.parseEncap(sd[2], want); err != nil {
		return nil, err
	}

	// certificates [0] IMPLICIT SET OF : EE 인증서 정확히 1 개
	if !sd[3].isCtx(0) || !sd[3].Constructed {
		return nil, fmt.Errorf("SignedData: certificates missing")
	}
	certs, err := derChildren(sd[3])
	if err != nil || len(certs) != 1 {
		return nil, fmt.Errorf("SignedData: want exactly 1 certificate")
	}
	if so.EE, err = parseCertOpt(certs[0].Full, true, eeNoSIA); err != nil {
		return nil, fmt.Errorf("EE: %w", err)
	}

	// signerInfos SET OF : 정확히 1 개
	if !sd[4].is(tagSet) || !sd[4].Constructed {
		return nil, fmt.Errorf("SignedData: signerInfos not SET")
	}
	sis, err := derChildren(sd[4])
	if err != nil || len(sis) != 1 {
		return nil, fmt.Errorf("SignedData: want exactly 1 SignerInfo")
	}
	if err := so.checkSignerInfo(sis[0]); err != nil {
		return nil, err
	}
	return so, nil
}

// explicit : [tag] EXPLICIT 안의 TLV 하나
func explicit(n derNode, tag int) (derNode, error) {
	if !n.isCtx(tag) || !n.Constructed {
		return derNode{}, derErr("want [%d] EXPLICIT", tag)
	}
	return derOne(n.Body)
}

// algID : AlgorithmIdentifier { OID, 매개변수 없음 또는 NULL }
func algID(n derNode) (asn1.ObjectIdentifier, error) {
	a, err := derSeq(n, 1, 2)
	if err != nil {
		return nil, err
	}
	if len(a) == 2 && (!a[1].is(tagNull) || len(a[1].Body) != 0) {
		return nil, fmt.Errorf("algorithm parameters not NULL")
	}
	return derOIDOf(a[0])
}

// checkDigestAlgs : SET { sha256 } 하나만
func checkDigestAlgs(n derNode) error {
	if !n.is(tagSet) || !n.Constructed {
		return fmt.Errorf("digestAlgorithms not SET")
	}
	algs, err := derChildren(n)
	if err != nil || len(algs) != 1 {
		return fmt.Errorf("digestAlgorithms: want 1")
	}
	oid, err := algID(algs[0])
	if err != nil || !oid.Equal(oidSHA256) {
		return fmt.Errorf("digestAlgorithm not sha256")
	}
	return nil
}

// parseEncap : encapContentInfo { eContentType, [0] EXPLICIT OCTET STRING }
func (so *signedObject) parseEncap(n derNode, want asn1.ObjectIdentifier) error {
	e, err := derSeq(n, 2, 2)
	if err != nil {
		return fmt.Errorf("encapContentInfo (eContent missing?): %w", err)
	}
	if so.ContentType, err = derOIDOf(e[0]); err != nil {
		return err
	}
	if !so.ContentType.Equal(want) {
		return fmt.Errorf("eContentType %s, want %s", so.ContentType, want)
	}
	oc, err := explicit(e[1], 0)
	if err != nil {
		return fmt.Errorf("eContent: %w", err)
	}
	// DER : OCTET STRING 은 primitive (BER 조각 나눔 금지)
	if so.Content, err = derOctets(oc); err != nil {
		return fmt.Errorf("eContent: %w", err)
	}
	return nil
}

// checkSignerInfo : SignerInfo 검사 + 서명 확인
//
//	SEQUENCE { version 3, sid [0] SKI, digestAlgorithm, signedAttrs [0], signatureAlgorithm, signature }
func (so *signedObject) checkSignerInfo(n derNode) error {
	si, err := derSeq(n, 6, 6)
	if err != nil {
		return fmt.Errorf("SignerInfo (unsignedAttrs not allowed): %w", err)
	}
	if v, err := derUint(si[0], 10); err != nil || v != 3 {
		return fmt.Errorf("SignerInfo version not 3")
	}
	// sid = subjectKeyIdentifier [0] IMPLICIT OCTET STRING = EE 의 SKI
	if !si[1].isCtx(0) || si[1].Constructed {
		return fmt.Errorf("SignerInfo sid not subjectKeyIdentifier")
	}
	if !bytes.Equal(si[1].Body, so.EE.SKI) {
		return fmt.Errorf("SignerInfo sid != EE SKI")
	}
	if oid, err := algID(si[2]); err != nil || !oid.Equal(oidSHA256) {
		return fmt.Errorf("SignerInfo digestAlgorithm not sha256")
	}
	if !si[3].isCtx(0) || !si[3].Constructed {
		return fmt.Errorf("signedAttrs missing")
	}
	digest, err := so.parseSignedAttrs(si[3])
	if err != nil {
		return err
	}
	sigAlg, err := algID(si[4])
	if err != nil || !(sigAlg.Equal(oidRSA) || sigAlg.Equal(oidSHA256RSA)) {
		return fmt.Errorf("signatureAlgorithm not RSA")
	}
	sig, err := derOctets(si[5])
	if err != nil {
		return err
	}

	// messageDigest == SHA-256(eContent)
	h := sha256.Sum256(so.Content)
	if !bytes.Equal(digest, h[:]) {
		return fmt.Errorf("messageDigest mismatch")
	}

	// 서명 대상 = signedAttrs 를 SET OF (tag 0x31) 로 다시 쓴 DER
	signed := append([]byte{0x31}, si[3].Full[1:]...)
	sh := sha256.Sum256(signed)
	pk, ok := so.EE.X509.PublicKey.(*rsa.PublicKey)
	if !ok {
		return fmt.Errorf("EE key not RSA")
	}
	if err := rsa.VerifyPKCS1v15(pk, crypto.SHA256, sh[:], sig); err != nil {
		return fmt.Errorf("CMS signature: %w", err)
	}
	return nil
}

// parseSignedAttrs : contentType (필수) + messageDigest (필수) + signingTime / binarySigningTime (선택)
// 그 외 속성, 중복, 값 여러 개는 거부. messageDigest 값을 돌려줌
func (so *signedObject) parseSignedAttrs(n derNode) ([]byte, error) {
	attrs, err := derChildren(n)
	if err != nil {
		return nil, err
	}
	var digest []byte
	seen := map[string]bool{}
	for _, a := range attrs {
		f, err := derSeq(a, 2, 2)
		if err != nil {
			return nil, fmt.Errorf("signedAttr: %w", err)
		}
		oid, err := derOIDOf(f[0])
		if err != nil {
			return nil, err
		}
		if seen[oid.String()] {
			return nil, fmt.Errorf("duplicate signedAttr %s", oid)
		}
		seen[oid.String()] = true
		if !f[1].is(tagSet) || !f[1].Constructed {
			return nil, fmt.Errorf("signedAttr values not SET")
		}
		vals, err := derChildren(f[1])
		if err != nil || len(vals) != 1 {
			return nil, fmt.Errorf("signedAttr %s: want 1 value", oid)
		}
		v := vals[0]
		switch {
		case oid.Equal(oidAttrCType):
			ct, err := derOIDOf(v)
			if err != nil || !ct.Equal(so.ContentType) {
				return nil, fmt.Errorf("contentType attr != eContentType")
			}
		case oid.Equal(oidAttrDigest):
			if digest, err = derOctets(v); err != nil {
				return nil, err
			}
		case oid.Equal(oidAttrSignTime):
			// UTCTime 또는 GeneralizedTime. 값은 참고용이라 encoding/asn1 로 읽음
			var t time.Time
			if _, err := asn1.Unmarshal(v.Full, &t); err != nil {
				return nil, fmt.Errorf("bad signingTime")
			}
			so.SigningTime = t
		case oid.Equal(oidAttrBinTime):
			if _, err := derUint(v, 1<<62); err != nil {
				return nil, fmt.Errorf("bad binarySigningTime")
			}
		default:
			return nil, fmt.Errorf("unexpected signedAttr %s", oid)
		}
	}
	if !seen[oidAttrCType.String()] || digest == nil {
		return nil, fmt.Errorf("signedAttrs without contentType / messageDigest")
	}
	return digest, nil
}
