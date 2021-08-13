package keystore

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	ksecdsa "github.com/BSNDA/bsn-sdk-crypto/keystore/ecdsa"
	"github.com/BSNDA/bsn-sdk-crypto/keystore/key"
	"github.com/BSNDA/bsn-sdk-crypto/keystore/sm"
	"github.com/tjfoc/gmsm/sm2"
)

type ecdsaKeyGenerator struct {
	curve elliptic.Curve
}

func (kg *ecdsaKeyGenerator) KeyGen(opts key.KeyGenOpts) (key.Key, error) {

	privKey, err := ecdsa.GenerateKey(kg.curve, rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("Failed generating ECDSA key for [%v]: [%s]", kg.curve, err)
	}

	return ksecdsa.NewEcdsaPrivateKey(privKey), nil
}

func KeyGen(opts key.KeyGenOpts) (key.Key, error) {

	algor := opts.Algorithm()

	switch algor {
	case key.SM2:
		privKey, err := sm2.GenerateKey()
		if err != nil {
			return nil, fmt.Errorf("Failed generating SM2 key for %s", err)
		}
		return sm.NewSMPrivateKey(privKey), nil
	case key.ECDSAP256:
		curve := elliptic.P256()
		privKey, err := ecdsa.GenerateKey(curve, rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("Failed generating ECDSA key for [%v]: [%s]", curve, err)
		}

		return ksecdsa.NewEcdsaPrivateKey(privKey), nil
	}

	return nil, fmt.Errorf("Failed generating ")

}
