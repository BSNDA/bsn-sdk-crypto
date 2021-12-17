package signer

import (
	"crypto"
	"github.com/tjfoc/gmsm/sm2"
	"io"
)

var (
	default_uid = []byte{0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38}
)

func NewSMSigner(key *sm2.PrivateKey) crypto.Signer {
	return &smSigner{
		privKey: key,
	}
}

type smSigner struct {
	privKey *sm2.PrivateKey
}

func (sig *smSigner) Public() crypto.PublicKey {
	return sig.privKey.Public()
}

func (sig *smSigner) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	r, s, err := sm2.Sm2Sign(sig.privKey, digest, default_uid)
	if err != nil {
		return nil, err
	}
	sign, err := sm2.SignDigitToSignData(r, s)
	return sign, err
}
