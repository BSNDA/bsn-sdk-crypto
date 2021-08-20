package crypto

import (
	"crypto/ecdsa"
	"github.com/BSNDA/bsn-sdk-crypto/crypto/eth"
	"github.com/BSNDA/bsn-sdk-crypto/crypto/sm"
	"github.com/BSNDA/bsn-sdk-crypto/errors"
	"github.com/tjfoc/gmsm/sm2"
	"math/big"
)

type AlgorithmType int

const (
	PublicKeyType = "PUBLIC KEY"
	CertType      = "CERTIFICATE"

	SM  AlgorithmType = 1
	R1  AlgorithmType = 2
	K1  AlgorithmType = 3
	ETH AlgorithmType = 4
)

func SignData(at AlgorithmType, key interface{}, digest []byte) (r, s, pub *big.Int, err error) {

	switch at {
	case SM:
		privKey := key.(*sm2.PrivateKey)
		return sm.SignData(privKey, digest)
	case ETH:
		privKey := key.(*ecdsa.PrivateKey)
		r, s, v, _, err := eth.SignData(privKey, digest)
		return r, s, v, err
	default:
		return nil, nil, nil, errors.New("no sign func")
	}
}
