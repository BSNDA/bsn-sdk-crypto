package keystore

import (
	"crypto"
	"github.com/BSNDA/bsn-sdk-crypto/keystore/key"
	"github.com/pkg/errors"
)

func BCCSPKeyRequestGenerate(ks key.KeyStore, keyOpts key.KeyGenOpts) (key.Key, crypto.Signer, error) {

	key, err := KeyGen(keyOpts)
	if err != nil {
		return nil, nil, err
	}

	ks.StoreKey(key)

	cspSigner, err := New(key)
	if err != nil {
		return nil, nil, errors.WithMessage(err, "Failed initializing CryptoSigner")
	}
	return key, cspSigner, nil
}
