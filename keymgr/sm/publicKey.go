package sm

import (
	"crypto/elliptic"
	"crypto/sha256"
	"github.com/tjfoc/gmsm/sm2"
	"github.com/tjfoc/gmsm/sm3"
)

type SMPublicKey struct {
	pubKey *sm2.PublicKey
}

func (k *SMPublicKey) SKI() []byte {
	if k.pubKey == nil {
		return nil
	}

	// Marshall the public key
	raw := elliptic.Marshal(k.pubKey.Curve, k.pubKey.X, k.pubKey.Y)

	// Hash it
	hash := sha256.New()
	hash.Write(raw)
	return hash.Sum(nil)
}

func (k *SMPublicKey) PEM() (string, error) {

	pemBytes, err := sm2.WritePublicKeytoMem(k.pubKey, nil)

	if err != nil {
		return "", err
	}
	return string(pemBytes), nil
}

func (e *SMPublicKey) Hash(msg []byte) ([]byte, error) {

	h := sm3.New()

	h.Write([]byte(msg))
	hash := h.Sum(nil)

	return hash, nil
}
