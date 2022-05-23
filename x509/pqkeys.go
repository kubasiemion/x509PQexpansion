package x509

import (
	"bytes"
	"crypto"
	"encoding/asn1"
	"fmt"
	"io"
)

type PQPublicKey interface {
	Equal(PQPublicKey) bool
	GetOID() asn1.ObjectIdentifier
	Bytes() []byte
}

type PQPrivateKey interface {
	Public() crypto.PublicKey
	Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) (signature []byte, err error)
	GetOID() asn1.ObjectIdentifier
	Bytes() []byte
}

type PQPrivateKeyStruct struct {
	Privbytes    []byte
	Pubbytes     []byte
	OID          asn1.ObjectIdentifier
	SingInternal func(PQPrivateKey, io.Reader, []byte, crypto.SignerOpts) ([]byte, error)
}

func (pqpriv *PQPrivateKeyStruct) Bytes() []byte {
	return pqpriv.Privbytes
}

func (pqpriv *PQPrivateKeyStruct) Public() crypto.PublicKey {
	return &PQPublicKeyStruct{pqpriv.Pubbytes, pqpriv.OID}
}

func (pqpriv *PQPrivateKeyStruct) GetOID() asn1.ObjectIdentifier {
	return pqpriv.OID
}

func (pqpriv *PQPrivateKeyStruct) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	if pqpriv.SingInternal == nil {
		return nil, fmt.Errorf("Signing function not set in PQK wrapper")
	}
	var pqinterface PQPrivateKey
	pqinterface = pqpriv
	return pqpriv.SingInternal(pqinterface, rand, digest, opts)
}

type PQPublicKeyStruct struct {
	RawBytes []byte
	OID      asn1.ObjectIdentifier
}

func (pqpb *PQPublicKeyStruct) GetOID() asn1.ObjectIdentifier {
	return pqpb.OID
}

func (pqpb *PQPublicKeyStruct) Equal(p2 PQPublicKey) bool {
	return pqpb.OID.Equal(p2.GetOID()) && bytes.Equal(pqpb.RawBytes, p2.Bytes())
}

func (pqpb *PQPublicKeyStruct) Bytes() []byte {
	return pqpb.RawBytes
}
