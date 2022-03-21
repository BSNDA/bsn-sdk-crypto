package csr

import (
	"crypto"
	"crypto/rand"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"github.com/pkg/errors"
	"net"
	"net/mail"
	"net/url"

	"github.com/cloudflare/cfssl/csr"
	"github.com/tjfoc/gmsm/sm2"
)

// Generate creates a new CSR from a CertificateRequest structure and
// an existing key. The KeyRequest field is ignored.
func GenerateSM2CSR(priv crypto.Signer, req *csr.CertificateRequest) (csr []byte, err error) {

	var tpl = sm2.CertificateRequest{
		Subject:            req.Name(),
		SignatureAlgorithm: sm2.SM2WithSM3,
	}

	for i := range req.Hosts {
		if ip := net.ParseIP(req.Hosts[i]); ip != nil {
			tpl.IPAddresses = append(tpl.IPAddresses, ip)
		} else if email, err := mail.ParseAddress(req.Hosts[i]); err == nil && email != nil {
			tpl.EmailAddresses = append(tpl.EmailAddresses, email.Address)
		} else if uri, err := url.ParseRequestURI(req.Hosts[i]); err == nil && uri != nil {
			//tpl.URIs = append(tpl.URIs, uri)
		} else {
			tpl.DNSNames = append(tpl.DNSNames, req.Hosts[i])
		}
	}

	if req.CA != nil {
		err = appendCAInfoToCSRSm2(req.CA, &tpl)
		if err != nil {
			err = errors.New("")
			return
		}
	}

	csr, err = sm2.CreateCertificateRequest(rand.Reader, &tpl, priv)
	if err != nil {
		err = errors.New("")
		return
	}
	block := pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: csr,
	}

	csr = pem.EncodeToMemory(&block)
	return
}

type BasicConstraints struct {
	IsCA       bool `asn1:"optional"`
	MaxPathLen int  `asn1:"optional,default:-1"`
}

// appendCAInfoToCSR appends CAConfig BasicConstraint extension to a CSR
func appendCAInfoToCSRSm2(reqConf *csr.CAConfig, csr *sm2.CertificateRequest) error {
	pathlen := reqConf.PathLength
	if pathlen == 0 && !reqConf.PathLenZero {
		pathlen = -1
	}
	val, err := asn1.Marshal(BasicConstraints{true, pathlen})

	if err != nil {
		return err
	}

	csr.ExtraExtensions = []pkix.Extension{
		{
			Id:       asn1.ObjectIdentifier{2, 5, 29, 19},
			Value:    val,
			Critical: true,
		},
	}

	return nil
}
