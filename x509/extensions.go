package x509

import (
	"bytes"
	"crypto/dsa"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"

	"golang.org/x/crypto/cryptobyte"
	cryptobyte_asn1 "golang.org/x/crypto/cryptobyte/asn1"
)

/*
In addition I would like to pass along additional information about the soon-to-be supported Dilithium (this list already includes the supported round 2 6-5 strength) and Kyber strengths:
The following object identifiers (OIDs) from IBM’s networking OID range
are reserved for Crystals variants:
-- round 2 Dilithium, with SHAKE(-256) as PRF:
1.3.6.1.4.1.2.267.1 dilithium
1.3.6.1.4.1.2.267.1.5.4 dilithium-rec -- NIST ’recommended’
1.3.6.1.4.1.2.267.1.6.5 dilithium-high -- NIST ’high-security’
1.3.6.1.4.1.2.267.1.8.7 dilithium-87 -- used for outbound-authentication
-- round 3 Dilithium, with SHAKE(-256) as PRF:
1.3.6.1.4.1.2.267.7 dilithium-r3
1.3.6.1.4.1.2.267.7.4.4 dilithium-r3-weak
1.3.6.1.4.1.2.267.7.6.5 dilithium-r3-rec -- NIST ’recommended’
1.3.6.1.4.1.2.267.7.8.7 dilithium-r3-vhigh -- NIST ’high-security’
-- round 2 Dilithium, equivalents with SHA-512 as PRF:
1.3.6.1.4.1.2.267.3 dilithium-sha512
1.3.6.1.4.1.2.267.3.5.4 dilithium-sha512-rec -- see NIST recommended
1.3.6.1.4.1.2.267.3.6.5 dilithium-sha512-high -- see NIST high-security
1.3.6.1.4.1.2.267.3.7.6 dilithium-sha512-vhigh -- see NIST ’vhigh’
-- round 2 Kyber submissions, with SHAKE(-128) as PRF:
1.3.6.1.4.1.2.267.5 Kyber-r2
1.3.6.1.4.1.2.267.5.3.3 Kyber-r2rec
1.3.6.1.4.1.2.267.5.4.4 Kyber-r2high
From: Siemion - Przemyslaw Jakub <przemyslaw.siemion@gruposantander.com>
 Sent: Tuesday, May 10, 2022 11:50 AM
 To: John Harrison <jharriso@us.ibm.com>
 Cc: Elton Desouza <Elton.Desouza@ca.ibm.com>
 Subject: [EXTERNAL] RE: Dilithium ASN1 Information
Thanks, that clarifies a lot. And no, we are not protocol experts. One OID that I we are using is the signature/hash-and-cipher identifier used by x509. I have found a proposal (?) for SHAKE256-Dilithium ({2.16.840.1.101.3.4.3.20}), but I am
ZjQcmQRYFpfptBannerStart
This Message Is From an External Sender
This message came from outside your organization.
ZjQcmQRYFpfptBannerEnd
Thanks, that clarifies a lot. And no, we are not protocol experts.
One OID that I we are using is the signature/hash-and-cipher identifier used by x509.
I have found a proposal (?) for SHAKE256-Dilithium ({2.16.840.1.101.3.4.3.20}), but I am not sure of its status. Also not sure about the recommendation to always use Dilithium with Shake.
Happy to learn more about this bookkeeping side of things…
Cheers
Przemek
From: John Harrison [mailto:jharriso@us.ibm.com]
 Sent: Tuesday, May 10, 2022 5:39 PM
 To: Siemion - Przemyslaw Jakub <przemyslaw.siemion@gruposantander.com>
 Cc: Elton Desouza <Elton.Desouza@ca.ibm.com>
 Subject: #External Sender# Dilithium ASN1 Information
Perhaps this information is common knowledge to you and your team, but I thought I would share it with you.
 -- public-key encoding: use regular subjectPublicKeyInfo fields (SPKIs)
-- as specified by RFC 3279.
-- Encode Dilithium public keys as:
--
DilithiumPublicKey ::= BIT STRING {
  SEQUENCE {
  rho BIT STRING, -- nonce
  t1 BIT STRING -- from vector(L)
  }
}
-- private-key encoding: use PKCS#8 structures as specified by RFC 5959.
-- The Dilithium-specific form is:
--
DilithiumPrivateKey ::= SEQUENCE {
  version INTEGER, -- v0; reserved 0
  rho BIT STRING, -- nonce
  key BIT STRING, -- key/seed/D
  tr BIT STRING, -- PRF bytes (’CRH’ in specification)
  s1 BIT STRING, -- vector(L)
  s2 BIT STRING, -- vector(K)
  t0 BIT STRING -- low bits(vector L)
  t1 [0] IMPLICIT OPTIONAL {
  t1 BIT STRING -- high bits(vector L) -- see also public key/SPKI
  }
}
*/

type PublicKeyAlgorithm int

const (
	UnknownPublicKeyAlgorithm PublicKeyAlgorithm = iota
	RSA
	DSA // Unsupported.
	ECDSA
	Ed25519
	DilithiumR3
)

var publicKeyAlgoName = [...]string{
	RSA:         "RSA",
	DSA:         "DSA",
	ECDSA:       "ECDSA",
	Ed25519:     "Ed25519",
	DilithiumR3: "DilithiumR3",
}

//
// pkcs-1 OBJECT IDENTIFIER ::== { iso(1) member-body(2) us(840)
//    rsadsi(113549) pkcs(1) 1 }
//
// rsaEncryption OBJECT IDENTIFIER ::== { pkcs1-1 1 }
//
// id-dsa OBJECT IDENTIFIER ::== { iso(1) member-body(2) us(840)
//    x9-57(10040) x9cm(4) 1 }
//
// RFC 5480, 2.1.1 Unrestricted Algorithm Identifier and Parameters
//
// id-ecPublicKey OBJECT IDENTIFIER ::= {
//       iso(1) member-body(2) us(840) ansi-X9-62(10045) keyType(2) 1 }
var (
	oidPublicKeyRSA     = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}
	oidPublicKeyDSA     = asn1.ObjectIdentifier{1, 2, 840, 10040, 4, 1}
	oidPublicKeyECDSA   = asn1.ObjectIdentifier{1, 2, 840, 10045, 2, 1}
	oidPublicKeyEd25519 = oidSignatureEd25519
	OidDilithiumRawHigh = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 2, 267, 1, 6, 5}
)

func getPublicKeyAlgorithmFromOID(oid asn1.ObjectIdentifier) PublicKeyAlgorithm {
	switch {
	case oid.Equal(oidPublicKeyRSA):
		return RSA
	case oid.Equal(oidPublicKeyDSA):
		return DSA
	case oid.Equal(oidPublicKeyECDSA):
		return ECDSA
	case oid.Equal(oidPublicKeyEd25519):
		return Ed25519
	case oid.Equal(OidDilithiumRawHigh):
		return DilithiumR3
	}
	return UnknownPublicKeyAlgorithm
}

func parsePublicKey(algo PublicKeyAlgorithm, keyData *publicKeyInfo) (interface{}, error) {
	der := cryptobyte.String(keyData.PublicKey.RightAlign())
	switch algo {
	case RSA:
		// RSA public keys must have a NULL in the parameters.
		// See RFC 3279, Section 2.3.1.
		if !bytes.Equal(keyData.Algorithm.Parameters.FullBytes, asn1.NullBytes) {
			return nil, errors.New("x509: RSA key missing NULL parameters")
		}

		p := &pkcs1PublicKey{N: new(big.Int)}
		if !der.ReadASN1(&der, cryptobyte_asn1.SEQUENCE) {
			return nil, errors.New("x509: invalid RSA public key")
		}
		if !der.ReadASN1Integer(p.N) {
			return nil, errors.New("x509: invalid RSA modulus")
		}
		if !der.ReadASN1Integer(&p.E) {
			return nil, errors.New("x509: invalid RSA public exponent")
		}

		if p.N.Sign() <= 0 {
			return nil, errors.New("x509: RSA modulus is not a positive number")
		}
		if p.E <= 0 {
			return nil, errors.New("x509: RSA public exponent is not a positive number")
		}

		pub := &rsa.PublicKey{
			E: p.E,
			N: p.N,
		}
		return pub, nil
	case ECDSA:
		paramsDer := cryptobyte.String(keyData.Algorithm.Parameters.FullBytes)
		namedCurveOID := new(asn1.ObjectIdentifier)
		if !paramsDer.ReadASN1ObjectIdentifier(namedCurveOID) {
			return nil, errors.New("x509: invalid ECDSA parameters")
		}
		namedCurve := namedCurveFromOID(*namedCurveOID)
		if namedCurve == nil {
			return nil, errors.New("x509: unsupported elliptic curve")
		}
		x, y := elliptic.Unmarshal(namedCurve, der)
		if x == nil {
			return nil, errors.New("x509: failed to unmarshal elliptic curve point")
		}
		pub := &ecdsa.PublicKey{
			Curve: namedCurve,
			X:     x,
			Y:     y,
		}
		return pub, nil
	case Ed25519:
		// RFC 8410, Section 3
		// > For all of the OIDs, the parameters MUST be absent.
		if len(keyData.Algorithm.Parameters.FullBytes) != 0 {
			return nil, errors.New("x509: Ed25519 key encoded with illegal parameters")
		}
		if len(der) != ed25519.PublicKeySize {
			return nil, errors.New("x509: wrong Ed25519 public key size")
		}
		return ed25519.PublicKey(der), nil
	case DSA:
		y := new(big.Int)
		if !der.ReadASN1Integer(y) {
			return nil, errors.New("x509: invalid DSA public key")
		}
		pub := &dsa.PublicKey{
			Y: y,
			Parameters: dsa.Parameters{
				P: new(big.Int),
				Q: new(big.Int),
				G: new(big.Int),
			},
		}
		paramsDer := cryptobyte.String(keyData.Algorithm.Parameters.FullBytes)
		if !paramsDer.ReadASN1(&paramsDer, cryptobyte_asn1.SEQUENCE) ||
			!paramsDer.ReadASN1Integer(pub.Parameters.P) ||
			!paramsDer.ReadASN1Integer(pub.Parameters.Q) ||
			!paramsDer.ReadASN1Integer(pub.Parameters.G) {
			return nil, errors.New("x509: invalid DSA parameters")
		}
		if pub.Y.Sign() <= 0 || pub.Parameters.P.Sign() <= 0 ||
			pub.Parameters.Q.Sign() <= 0 || pub.Parameters.G.Sign() <= 0 {
			return nil, errors.New("x509: zero or negative DSA parameter")
		}
		return pub, nil
	case DilithiumR3:
		return &PQPublicKeyStruct{RawBytes: der, OID: OidDilithiumRawHigh}, nil
	default:
		return nil, nil
	}
}

func marshalPublicKey(pub interface{}) (publicKeyBytes []byte, publicKeyAlgorithm pkix.AlgorithmIdentifier, err error) {
	if pqpub, ok := pub.(PQPublicKey); ok {
		publicKeyBytes = pqpub.Bytes()
		publicKeyAlgorithm.Algorithm = pqpub.GetOID()
		return
	}
	switch pub := pub.(type) {
	case *rsa.PublicKey:
		publicKeyBytes, err = asn1.Marshal(pkcs1PublicKey{
			N: pub.N,
			E: pub.E,
		})
		if err != nil {
			return nil, pkix.AlgorithmIdentifier{}, err
		}
		publicKeyAlgorithm.Algorithm = oidPublicKeyRSA
		// This is a NULL parameters value which is required by
		// RFC 3279, Section 2.3.1.
		publicKeyAlgorithm.Parameters = asn1.NullRawValue
	case *ecdsa.PublicKey:
		publicKeyBytes = elliptic.Marshal(pub.Curve, pub.X, pub.Y)
		oid, ok := oidFromNamedCurve(pub.Curve)
		if !ok {
			return nil, pkix.AlgorithmIdentifier{}, errors.New("x509: unsupported elliptic curve")
		}
		publicKeyAlgorithm.Algorithm = oidPublicKeyECDSA
		var paramBytes []byte
		paramBytes, err = asn1.Marshal(oid)
		if err != nil {
			return
		}
		publicKeyAlgorithm.Parameters.FullBytes = paramBytes
	case ed25519.PublicKey:
		publicKeyBytes = pub
		publicKeyAlgorithm.Algorithm = oidPublicKeyEd25519
	default:
		return nil, pkix.AlgorithmIdentifier{}, fmt.Errorf("x509: unsupported public key type: %T", pub)
	}

	return publicKeyBytes, publicKeyAlgorithm, nil
}
