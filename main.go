package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"time"

	"github.com/kubasiemion/x509PQexpansion/x509"
)

func main() {
	b, e := os.ReadFile("selfSignedRSA4096cert.pem")
	if e != nil {
		fmt.Println(e)
		return
	}
	block, _ := pem.Decode(b)
	parent, e := x509.ParseCertificate(block.Bytes)
	if e != nil {
		fmt.Println(e)
		return
	}
	//fmt.Println(hex.EncodeToString(block.Bytes))

	ca := getTemplate()
	var pub x509.PQPublicKey
	pub = &x509.PQPublicKeyStruct{OID: x509.OidDilithiumRawHigh, RawBytes: getDilTestPub()}
	fmt.Println(len(pub.Bytes()))

	prpem, e := os.ReadFile("aaaRSA4096key.pem")
	if e != nil {
		fmt.Println(e)
		return
	}
	block, _ = pem.Decode(prpem)
	prkey, e := x509.ParsePKCS8PrivateKey(block.Bytes)
	if e != nil {
		fmt.Println(e)
		return
	}
	certb, e := x509.CreateCertificate(rand.Reader, ca, parent, pub, prkey)
	if e != nil {
		fmt.Println(e)
		return
	}
	fmt.Println(hex.EncodeToString(certb))
	fmt.Println(len(certb))
	block = &pem.Block{Type: "CERTIFICATE", Bytes: certb}
	certbuf := new(bytes.Buffer)
	e = pem.Encode(certbuf, block)
	if e != nil {
		fmt.Println(e)
		return
	}
	fmt.Println(string(certbuf.Bytes()))

	p2, e := x509.ParseCertificate(certb)
	if e != nil {
		fmt.Println(e)
		return
	}
	cpool := x509.NewCertPool()
	cpool.AddCert(parent)
	chain, err := p2.Verify(x509.VerifyOptions{Roots: cpool})
	fmt.Println(err, chain)

	var PrivKey x509.PQPrivateKey
	PrivKey = &x509.PQPrivateKeyStruct{Privbytes: getDilTestPriv(), OID: x509.OidDilithiumRawHigh}

	xc, e := x509.CreateCertificate(rand.Reader, ca, p2, prkey.(*rsa.PrivateKey).PublicKey, PrivKey)
	if e != nil {
		fmt.Println(e)
		return
	}
	fmt.Println(len(xc))
}

func getTemplate() *x509.Certificate {
	ca := &x509.Certificate{
		SerialNumber: big.NewInt(2019),
		Subject: pkix.Name{
			Organization:  []string{"SANTALAB"},
			Country:       []string{"ES"},
			Province:      []string{""},
			Locality:      []string{"Madrid"},
			StreetAddress: []string{"Santa Campus"},
			PostalCode:    []string{"28266"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(1, 0, 0),
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}

	return ca
}
