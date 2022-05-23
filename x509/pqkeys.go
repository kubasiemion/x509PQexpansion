package x509

import (
	"bytes"
	"crypto"
	"encoding/asn1"
	"fmt"
	"io"
)

type PQPrivateKey struct {
	Privbytes    []byte
	Pubbytes     []byte
	OID          asn1.ObjectIdentifier
	SingInternal func(*PQPrivateKey, io.Reader, []byte, crypto.SignerOpts) ([]byte, error)
}

func (pqpriv *PQPrivateKey) Bytes() []byte {
	return pqpriv.Privbytes
}

func (pqpriv *PQPrivateKey) Public() crypto.PublicKey {
	return &PQPublicKey{pqpriv.Pubbytes, pqpriv.OID}
}

func (pqpriv *PQPrivateKey) GetOID() asn1.ObjectIdentifier {
	return pqpriv.OID
}

func (pqpriv *PQPrivateKey) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	if pqpriv.SingInternal == nil {
		return nil, fmt.Errorf("Signing function not set in PQK wrapper")
	}

	return pqpriv.SingInternal(pqpriv, rand, digest, opts)
}

type PQPublicKey struct {
	RawBytes []byte
	OID      asn1.ObjectIdentifier
}

func (pqpb *PQPublicKey) GetOID() asn1.ObjectIdentifier {
	return pqpb.OID
}

func (pqpb *PQPublicKey) Equal(p2 crypto.PublicKey) bool {
	if pq2, ok := p2.(*PQPublicKey); !ok {
		return false
	} else {
		return pqpb.OID.Equal(pq2.GetOID()) && bytes.Equal(pqpb.RawBytes, pq2.Bytes())
	}

}

func (pqpb *PQPublicKey) Bytes() []byte {
	return pqpb.RawBytes
}

func areKeyOIDandSigAlgoCompatible(key asn1.ObjectIdentifier, signAlgo SignatureAlgorithm) bool {
	return true
}
