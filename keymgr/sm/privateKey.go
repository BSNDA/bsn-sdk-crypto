package sm

import (
	"crypto/elliptic"
	"crypto/sha256"
	"github.com/tjfoc/gmsm/sm2"
	"github.com/tjfoc/gmsm/sm3"
)

var (
	default_uid = []byte{0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38}
)

type SMPrivateKey struct {
	privKey *sm2.PrivateKey
}

func (k *SMPrivateKey) SKI() []byte {
	if k.privKey == nil {
		return nil
	}

	// Marshall the public key
	raw := elliptic.Marshal(k.privKey.Curve, k.privKey.PublicKey.X, k.privKey.PublicKey.Y)

	// Hash it
	hash := sha256.New()
	hash.Write(raw)
	return hash.Sum(nil)
}

func (k *SMPrivateKey) PEM() (string, error) {

	pemBytes, err := sm2.WritePrivateKeytoMem(k.privKey, nil)

	if err != nil {
		return "", err
	}
	return string(pemBytes), nil
}

func (e *SMPrivateKey) Hash(msg []byte) ([]byte, error) {

	h := sm3.New()

	h.Write([]byte(msg))
	hash := h.Sum(nil)

	return hash, nil
}

func (e *SMPrivateKey) Sign(digest []byte) ([]byte, error) {
	r, s, err := sm2.Sm2Sign(e.privKey, digest, default_uid)

	sign, err := sm2.SignDigitToSignData(r, s)
	if err != nil {
		return nil, err
	}

	return sign, nil

}
