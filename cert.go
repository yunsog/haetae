package main

// cert.go : X.509 인증서 RPKI 프로파일 (RFC 6487)
//
// 기본 파싱 / 서명 확인은 crypto/x509, 그 위에 RPKI 규칙을 직접 검사.
// 종류
//   CA     : 자식 인증서 / manifest / CRL 을 내는 인증서 (.cer, TA 포함)
//   EE     : 서명 객체 (ROA, manifest 등) 안에 들어 있는 1 회용 인증서
//   router : BGPsec 라우터 인증서 (.cer, 이 RP 범위 밖 -> 파싱만 하고 건너뜀)
// 이 파일은 인증서 하나만 봄. 부모와의 관계 (서명, 자원 포함, 유효기간) 는 validate.go (2 단계).

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"fmt"
	"strings"
)

type certKind int

const (
	kindCA certKind = iota
	kindEE
	kindRouter
)

func (k certKind) String() string {
	return [...]string{"CA", "EE", "router"}[k]
}

// OID
var (
	oidExtSKI      = asn1.ObjectIdentifier{2, 5, 29, 14}
	oidExtKeyUsage = asn1.ObjectIdentifier{2, 5, 29, 15}
	oidExtBasic    = asn1.ObjectIdentifier{2, 5, 29, 19}
	oidExtCRLDP    = asn1.ObjectIdentifier{2, 5, 29, 31}
	oidExtPolicies = asn1.ObjectIdentifier{2, 5, 29, 32}
	oidExtAKI      = asn1.ObjectIdentifier{2, 5, 29, 35}
	oidExtEKU      = asn1.ObjectIdentifier{2, 5, 29, 37}
	oidExtAIA      = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 1}
	oidExtIPAddr   = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 7}
	oidExtASNum    = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 8}
	oidExtSIA      = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 11}

	oidADCAIssuers    = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 2}
	oidADCARepository = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 5}
	oidADManifest     = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 10}
	oidADSignedObject = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 11}
	oidADNotify       = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 13}

	oidPolicyRPKI    = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 14, 2}
	oidKPBGPsecRoute = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 30}
)

// rpkiCert : 검사를 통과한 인증서
type rpkiCert struct {
	X509 *x509.Certificate
	Kind certKind

	SKI, AKI []byte // 키 식별자 (AKI 는 TA 면 없을 수 있음)

	// SIA (Subject Information Access)
	CARepository string // CA : rsync://.../ (publication point 폴더)
	Manifest     string // CA : rsync://.../xxx.mft
	Notify       string // CA : https://.../notification.xml (RRDP, 없을 수 있음)
	SignedObject string // EE : rsync://.../xxx.roa 등 (자기 객체 위치)

	// 부모를 가리키는 것 (TA 는 없음)
	CRLDP     string // CRL 위치 rsync://
	CAIssuers string // 부모 인증서 위치 rsync:// (AIA)

	IPs ipResources
	ASs asResources

	SelfSigned bool // subject == issuer 이고 AKI 없음 또는 AKI == SKI (TA 후보)
}

// parseCert : DER 인증서 하나를 RPKI 프로파일로 검사
// wantEE : 서명 객체 안의 EE 인증서면 true (.cer 파일이면 false)
func parseCert(der []byte, wantEE bool) (*rpkiCert, error) {
	return parseCertOpt(der, wantEE, false)
}

// parseCertOpt : eeNoSIA = SIA 가 없어야 하는 EE (RSC, RFC 9323 2 절 : 저장소에 게시하지 않음)
func parseCertOpt(der []byte, wantEE, eeNoSIA bool) (*rpkiCert, error) {
	if len(der) > maxObjectSize {
		return nil, fmt.Errorf("certificate too large")
	}
	// crypto/x509 는 뒤에 남는 바이트를 거부하지만 DER 엄격성을 한 번 더 확인
	if _, err := derOne(der); err != nil {
		return nil, err
	}
	x, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	c := &rpkiCert{X509: x}

	if x.Version != 3 {
		return nil, fmt.Errorf("version %d, want 3", x.Version)
	}
	if x.SerialNumber.Sign() <= 0 {
		return nil, fmt.Errorf("serial not positive")
	}

	// 확장 : 아는 것만 허용. 같은 OID 두 번은 crypto/x509 가 이미 거부
	var basic, ku, ipExt, asExt, policies, eku, sia bool
	for _, e := range x.Extensions {
		id := e.Id
		switch {
		case id.Equal(oidExtSKI):
			c.SKI = x.SubjectKeyId
		case id.Equal(oidExtAKI):
			c.AKI = x.AuthorityKeyId
		case id.Equal(oidExtKeyUsage):
			if !e.Critical {
				return nil, fmt.Errorf("keyUsage not critical")
			}
			ku = true
		case id.Equal(oidExtBasic):
			if !e.Critical {
				return nil, fmt.Errorf("basicConstraints not critical")
			}
			basic = true
		case id.Equal(oidExtCRLDP):
			if err := c.parseCRLDP(x); err != nil {
				return nil, err
			}
		case id.Equal(oidExtPolicies):
			if !e.Critical {
				return nil, fmt.Errorf("certificatePolicies not critical")
			}
			policies = true
		case id.Equal(oidExtAIA):
			if err := c.parseAIA(e.Value); err != nil {
				return nil, err
			}
		case id.Equal(oidExtSIA):
			sia = true
			if err := c.parseSIA(e.Value); err != nil {
				return nil, err
			}
		case id.Equal(oidExtIPAddr):
			if !e.Critical {
				return nil, fmt.Errorf("IP resources not critical")
			}
			if c.IPs, err = parseIPAddrBlocks(e.Value); err != nil {
				return nil, fmt.Errorf("IP resources: %w", err)
			}
			ipExt = true
		case id.Equal(oidExtASNum):
			if !e.Critical {
				return nil, fmt.Errorf("AS resources not critical")
			}
			if c.ASs, err = parseASIdentifiers(e.Value); err != nil {
				return nil, fmt.Errorf("AS resources: %w", err)
			}
			asExt = true
		case id.Equal(oidExtEKU):
			eku = true
		default:
			if e.Critical {
				return nil, fmt.Errorf("unknown critical extension %s", id)
			}
			// 모르는 비 critical 확장은 무시 (rpki-client 와 비교해 보고 정함)
		}
	}

	// 공통
	if len(c.SKI) != 20 {
		return nil, fmt.Errorf("SKI missing or not 20 bytes")
	}
	if c.AKI != nil && len(c.AKI) != 20 {
		return nil, fmt.Errorf("AKI not 20 bytes")
	}
	if !ku {
		return nil, fmt.Errorf("keyUsage missing")
	}
	if !policies {
		return nil, fmt.Errorf("certificatePolicies missing")
	}
	if len(x.PolicyIdentifiers) != 1 || !x.PolicyIdentifiers[0].Equal(oidPolicyRPKI) {
		return nil, fmt.Errorf("policy is not RPKI (%v)", x.PolicyIdentifiers)
	}
	if x.SignatureAlgorithm != x509.SHA256WithRSA {
		return nil, fmt.Errorf("signature algorithm %v", x.SignatureAlgorithm)
	}
	c.SelfSigned = bytesEqualName(x) && (c.AKI == nil || string(c.AKI) == string(c.SKI))

	// 종류 판정
	switch {
	case basic:
		c.Kind = kindCA
	case eku && !wantEE:
		c.Kind = kindRouter
	default:
		c.Kind = kindEE
	}
	if wantEE && c.Kind != kindEE {
		return nil, fmt.Errorf("want EE certificate, got %s", c.Kind)
	}
	if !wantEE && c.Kind == kindEE {
		return nil, fmt.Errorf("EE certificate in .cer file")
	}

	switch c.Kind {
	case kindCA:
		err = c.checkCA()
	case kindEE:
		err = c.checkEE(ipExt, asExt, sia, eeNoSIA)
	case kindRouter:
		err = c.checkRouter(ipExt, asExt)
	}
	if err != nil {
		return nil, err
	}
	if !c.SelfSigned || c.Kind != kindCA {
		// TA 가 아니면 부모를 가리키는 것이 있어야 함
		if c.AKI == nil || c.CRLDP == "" || c.CAIssuers == "" {
			return nil, fmt.Errorf("non-TA certificate without AKI / CRLDP / AIA")
		}
	}
	return c, nil
}

// bytesEqualName : subject == issuer (DER 그대로 비교)
func bytesEqualName(x *x509.Certificate) bool {
	return string(x.RawSubject) == string(x.RawIssuer)
}

// checkCA : CA 인증서 규칙
func (c *rpkiCert) checkCA() error {
	x := c.X509
	if !x.IsCA {
		return fmt.Errorf("basicConstraints cA false")
	}
	if x.MaxPathLen >= 0 && (x.MaxPathLen > 0 || x.MaxPathLenZero) {
		return fmt.Errorf("pathLenConstraint present")
	}
	if x.KeyUsage != x509.KeyUsageCertSign|x509.KeyUsageCRLSign {
		return fmt.Errorf("CA keyUsage %#x, want keyCertSign|cRLSign", x.KeyUsage)
	}
	if len(x.ExtKeyUsage) > 0 || len(x.UnknownExtKeyUsage) > 0 {
		return fmt.Errorf("CA with extKeyUsage")
	}
	if c.CARepository == "" || c.Manifest == "" {
		return fmt.Errorf("CA SIA without caRepository / rpkiManifest")
	}
	if c.SignedObject != "" {
		return fmt.Errorf("CA SIA with signedObject")
	}
	if !c.IPs.V4.Present && !c.IPs.V6.Present && !c.ASs.Present {
		return fmt.Errorf("no IP or AS resources")
	}
	return checkRSAKey(x)
}

// checkEE : 서명 객체 EE 인증서 규칙
// noSIA = RSC 의 EE (SIA 가 있으면 안 됨)
func (c *rpkiCert) checkEE(ipExt, asExt, sia, noSIA bool) error {
	x := c.X509
	if x.KeyUsage != x509.KeyUsageDigitalSignature {
		return fmt.Errorf("EE keyUsage %#x, want digitalSignature", x.KeyUsage)
	}
	switch {
	case noSIA && sia:
		return fmt.Errorf("RSC EE certificate with SIA extension")
	case !noSIA && c.SignedObject == "":
		return fmt.Errorf("EE SIA without signedObject")
	}
	if c.CARepository != "" || c.Manifest != "" {
		return fmt.Errorf("EE SIA with CA access methods")
	}
	if !ipExt && !asExt {
		return fmt.Errorf("no IP or AS resources")
	}
	return checkRSAKey(x)
}

// checkRouter : BGPsec 라우터 인증서 (RFC 8209)
// EE 와 비슷하지만 .cer 파일로 게시, EKU = id-kp-bgpsec-router, 키 = ECDSA P-256,
// AS 자원만 (inherit 없음). RTR v1 Router Key PDU 로 라우터에 줌
func (c *rpkiCert) checkRouter(ipExt, asExt bool) error {
	x := c.X509
	if ipExt || !asExt {
		return fmt.Errorf("router certificate must have AS resources only")
	}
	if c.ASs.Inherit || len(c.ASs.Ranges) == 0 {
		return fmt.Errorf("router certificate AS resources inherit or empty")
	}
	if x.KeyUsage != x509.KeyUsageDigitalSignature {
		return fmt.Errorf("router keyUsage %#x, want digitalSignature", x.KeyUsage)
	}
	if c.CARepository != "" || c.Manifest != "" {
		return fmt.Errorf("router certificate SIA with CA access methods")
	}
	if len(x.ExtKeyUsage) > 0 {
		return fmt.Errorf("router certificate with other extKeyUsage")
	}
	ok := false
	for _, k := range x.UnknownExtKeyUsage {
		if k.Equal(oidKPBGPsecRoute) {
			ok = true
		}
	}
	if !ok {
		return fmt.Errorf("EKU without id-kp-bgpsec-router")
	}
	pk, isEC := x.PublicKey.(*ecdsa.PublicKey)
	if !isEC || pk.Curve != elliptic.P256() {
		return fmt.Errorf("router key is not ECDSA P-256")
	}
	return nil
}

// checkRSAKey : RFC 7935 = RSA 2048, 지수 65537
func checkRSAKey(x *x509.Certificate) error {
	pk, ok := x.PublicKey.(*rsa.PublicKey)
	if !ok {
		return fmt.Errorf("public key is not RSA")
	}
	if pk.N.BitLen() != 2048 {
		return fmt.Errorf("RSA key %d bits, want 2048", pk.N.BitLen())
	}
	if pk.E != 65537 {
		return fmt.Errorf("RSA exponent %d, want 65537", pk.E)
	}
	return nil
}

// parseCRLDP : CRL 위치는 rsync URI 하나 (crypto/x509 가 파싱해 둔 것 사용)
func (c *rpkiCert) parseCRLDP(x *x509.Certificate) error {
	if len(x.CRLDistributionPoints) != 1 {
		return fmt.Errorf("CRLDP has %d URIs, want 1", len(x.CRLDistributionPoints))
	}
	u := x.CRLDistributionPoints[0]
	if !validURI(u, "rsync://") || !strings.HasSuffix(u, ".crl") {
		return fmt.Errorf("bad CRLDP %q", u)
	}
	c.CRLDP = u
	return nil
}

// accessDesc : SIA / AIA 의 AccessDescription 하나 = (method OID, URI)
type accessDesc struct {
	Method asn1.ObjectIdentifier
	URI    string
}

// parseAccess : SEQUENCE OF AccessDescription { OID, GeneralName }
// GeneralName 은 uniformResourceIdentifier [6] IA5String 만 허용
func parseAccess(der []byte) ([]accessDesc, error) {
	top, err := derOne(der)
	if err != nil {
		return nil, err
	}
	items, err := derSeq(top, 1, 16)
	if err != nil {
		return nil, err
	}
	var out []accessDesc
	for _, it := range items {
		f, err := derSeq(it, 2, 2)
		if err != nil {
			return nil, err
		}
		oid, err := derOIDOf(f[0])
		if err != nil {
			return nil, err
		}
		if !f[1].isCtx(6) || f[1].Constructed {
			return nil, fmt.Errorf("access location is not URI")
		}
		out = append(out, accessDesc{oid, string(f[1].Body)})
	}
	return out, nil
}

// parseAIA : caIssuers rsync URI 하나
func (c *rpkiCert) parseAIA(der []byte) error {
	ads, err := parseAccess(der)
	if err != nil {
		return fmt.Errorf("AIA: %w", err)
	}
	for _, a := range ads {
		if !a.Method.Equal(oidADCAIssuers) {
			return fmt.Errorf("AIA: unexpected method %s", a.Method)
		}
		if !validURI(a.URI, "rsync://") {
			continue // rsync 아닌 것 (http 등) 은 무시
		}
		if c.CAIssuers != "" {
			return fmt.Errorf("AIA: more than one rsync caIssuers")
		}
		c.CAIssuers = a.URI
	}
	if c.CAIssuers == "" {
		return fmt.Errorf("AIA: no rsync caIssuers")
	}
	return nil
}

// parseSIA : CA 는 caRepository / rpkiManifest / rpkiNotify, EE 는 signedObject
// 같은 method 가 여러 번이면 rsync 하나만 씀 (다른 scheme 은 무시)
func (c *rpkiCert) parseSIA(der []byte) error {
	ads, err := parseAccess(der)
	if err != nil {
		return fmt.Errorf("SIA: %w", err)
	}
	set := func(dst *string, uri, scheme, name string) error {
		if !validURI(uri, scheme) {
			return nil
		}
		if *dst != "" {
			return fmt.Errorf("SIA: duplicate %s", name)
		}
		*dst = uri
		return nil
	}
	for _, a := range ads {
		m := a.Method
		switch {
		case m.Equal(oidADCARepository):
			err = set(&c.CARepository, a.URI, "rsync://", "caRepository")
		case m.Equal(oidADManifest):
			err = set(&c.Manifest, a.URI, "rsync://", "rpkiManifest")
		case m.Equal(oidADNotify):
			err = set(&c.Notify, a.URI, "https://", "rpkiNotify")
		case m.Equal(oidADSignedObject):
			err = set(&c.SignedObject, a.URI, "rsync://", "signedObject")
		default:
			// 모르는 access method 는 무시
		}
		if err != nil {
			return err
		}
	}
	if c.Manifest != "" && !strings.HasSuffix(c.Manifest, ".mft") {
		return fmt.Errorf("SIA: rpkiManifest %q not .mft", c.Manifest)
	}
	// caRepository 는 끝에 / 가 없어도 됨 (registro.br 등 실제로 있음) -> 폴더 경계로 비교
	if c.CARepository != "" && c.Manifest != "" &&
		!strings.HasPrefix(c.Manifest, strings.TrimSuffix(c.CARepository, "/")+"/") {
		return fmt.Errorf("SIA: rpkiManifest not under caRepository")
	}
	return nil
}

// validURI : scheme 으로 시작, 출력 가능한 ASCII, 경로 탈출 (..) 없음, 길이 상한
func validURI(u, scheme string) bool {
	if len(u) > 2048 || !strings.HasPrefix(u, scheme) || len(u) == len(scheme) {
		return false
	}
	for i := 0; i < len(u); i++ {
		if u[i] <= 0x20 || u[i] >= 0x7f {
			return false
		}
	}
	rest := u[len(scheme):]
	for _, part := range strings.Split(rest, "/") {
		if part == ".." || part == "." {
			return false
		}
	}
	return true
}

// routerKey : BGPsec 라우터 키 하나 (RTR Router Key PDU = ASN + SKI + SubjectPublicKeyInfo)
type routerKey struct {
	ASN  uint32
	SKI  []byte // 20 바이트
	SPKI []byte // DER SubjectPublicKeyInfo
}

// AS 범위를 펼칠 때 상한 (라우터 인증서는 보통 AS 하나)
const maxRouterASNs = 256

// routerKeys : 라우터 인증서의 AS 마다 routerKey 하나
func (c *rpkiCert) routerKeys() ([]routerKey, error) {
	if c.Kind != kindRouter {
		return nil, fmt.Errorf("not a router certificate")
	}
	var out []routerKey
	for _, r := range c.ASs.Ranges {
		if uint64(r.Max)-uint64(r.Min)+uint64(len(out)) >= maxRouterASNs {
			return nil, fmt.Errorf("router certificate with too many ASNs")
		}
		for as := uint64(r.Min); as <= uint64(r.Max); as++ {
			out = append(out, routerKey{uint32(as), c.SKI, c.X509.RawSubjectPublicKeyInfo})
		}
	}
	return out, nil
}
