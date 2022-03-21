package eth

import (
	"crypto/ecdsa"
	"github.com/ethereum/go-ethereum/crypto"
	"math/big"
)

func SignData(privk *ecdsa.PrivateKey, digest []byte) (r, s, v *big.Int, err error) {

	sig, err := crypto.Sign(digest, privk)
	if err != nil {
		return nil, nil, nil, err
	}

	r = new(big.Int).SetBytes(sig[:32])
	s = new(big.Int).SetBytes(sig[32:64])
	v = new(big.Int).SetBytes([]byte{sig[64] + 27})

	//sign = sig[:64]

	return
}
