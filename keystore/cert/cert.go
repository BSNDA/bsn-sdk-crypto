package cert

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"

	"github.com/BSNDA/bsn-sdk-crypto/errors"
	ksecdsa "github.com/BSNDA/bsn-sdk-crypto/keystore/ecdsa"
	"github.com/BSNDA/bsn-sdk-crypto/keystore/key"
	kssm "github.com/BSNDA/bsn-sdk-crypto/keystore/sm"
	"github.com/tjfoc/gmsm/sm2"
)

func KeyImport(raw interface{}) (key.Key, error) {
	lowLevelKey, ok := raw.(*ecdsa.PublicKey)
	if !ok {
		return nil, errors.New("Invalid raw material. Expected *ecdsa.PublicKey.")
	}

	return ksecdsa.NewEcdsaPublicKey(lowLevelKey), nil
}

func ImportCert(cert []byte) (key.Key, error) {
	dcert, _ := pem.Decode(cert)
	if dcert == nil {
		return nil, errors.New("Unable to decode cert bytes [%v]")
	}
	x509Cert, err := x509.ParseCertificate(dcert.Bytes)
	if err != nil {
		smx509Cert, err := sm2.ParseCertificate(dcert.Bytes)
		if err == nil {
			//pk := smx509Cert.PublicKey
			lowLevelKey, err := sm2.ParseSm2PublicKey(smx509Cert.RawSubjectPublicKeyInfo)
			if err != nil {
				return nil, errors.New("Invalid raw material. Expected *sm2.PublicKey.")
			}
			return kssm.NewSMPublicKey(lowLevelKey), nil
		}
		return nil, errors.New("Unable to parse cert from decoded bytes: %s")
	}
	pk := x509Cert.PublicKey

	return KeyImport(pk)
}
