package key

import (
	"github.com/BSNDA/bsn-sdk-crypto/crypto/sm"
	"math/big"

	"github.com/BSNDA/bsn-sdk-crypto/crypto/ecdsa"
	"github.com/BSNDA/bsn-sdk-crypto/types"

	"github.com/cloudflare/cfssl/csr"
	"github.com/pkg/errors"
)

func NewPrivateKeyByGen(algo types.KeyType) (PrivateKeyProvider, error) {
	switch algo {
	case types.SM:
		key, err := sm.GenerateKey()
		if err != nil {
			return nil, errors.WithMessage(err, "new sm private key has error")
		}
		return &smPrivateKey{key: key}, nil
	case types.ECDSA_R1:
		key, err := ecdsa.NewSecp256r1Key()
		if err != nil {
			return nil, errors.WithMessage(err, "new secp256r1 private key has error")
		}
		return &ecdsaPrivateKey{key: key}, nil
	case types.ECDSA_K1:
		key, err := ecdsa.NewSecp256k1Key()
		if err != nil {
			return nil, errors.WithMessage(err, "new secp256k1 private key has error")
		}
		return &ecdsaPrivateKey{key: key}, nil
	}
	return nil, errors.Errorf("Unsupported algorithm : %s", algo.String())
}

func NewPrivateKeyProvider(algo types.KeyType, pem string) (PrivateKeyProvider, error) {

	switch algo {
	case types.ECDSA_R1, types.ECDSA_K1:
		return NewECDSDAPrivateKey(pem)
	case types.SM:
		return NewSMPrivateKey(pem)
	}

	return nil, errors.Errorf("Unsupported algorithm : %s", algo.String())

}

func NewPublicProvider(algo types.KeyType, pem string) (PublicKeyProvider, error) {

	switch algo {
	case types.ECDSA_R1, types.ECDSA_K1:
		return NewECDSAPublicKey(pem)
	case types.SM:
		return NewSMPublicKey(pem)
	}

	return nil, errors.Errorf("Unsupported algorithm : %s", algo.String())

}

type HashProvider interface {
	Hash(msg []byte) []byte
}

type KeyProvider interface {
	Key() interface{}
	Bytes() []byte
	KeyPEM() ([]byte, error)
	SKI() []byte
	Algorithm() types.KeyType
}

type PrivateKeyProvider interface {
	KeyProvider
	HashProvider
	PublicKey() PublicKeyProvider
	Sign(digest []byte) ([]byte, error)
	SignTx(digest []byte) (r, s, v *big.Int, err error)
	GenCSR(req *csr.CertificateRequest) ([]byte, error)
}

type PublicKeyProvider interface {
	KeyProvider
	HashProvider

	Verify(sign, digest []byte) (bool, error)
}

func NewCertificateRequest(name string) *csr.CertificateRequest {
	cr := &csr.CertificateRequest{}
	cr.CN = name
	cr.Names = append(cr.Names, csr.Name{
		OU: "client",
		O:  "Bsn",
	})

	return cr

}
