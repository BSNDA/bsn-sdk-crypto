package key

import (
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/pem"
	"github.com/BSNDA/bsn-sdk-crypto/crypto/sm"
	"github.com/BSNDA/bsn-sdk-crypto/types"
	"github.com/pkg/errors"

	"github.com/tjfoc/gmsm/sm3"
)

func NewSMPublicKey(data string) (*smPublicKey, error) {
	block, _ := pem.Decode([]byte(data))
	if block == nil {
		return nil, errors.New("not pem")
	}
	var key *sm.PublicKey
	var err error

	switch block.Type {
	case PublicKeyType:
		key, err = sm.ReadPublicKeyFromMem([]byte(data), nil)
	case CertType:
		x509Cert, err := sm.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, err
		}
		key, err = sm.ParseSm2PublicKey(x509Cert.RawSubjectPublicKeyInfo)
	default:
		err = errors.Errorf("Unsupported %s", block.Type)
	}
	if err != nil {
		return nil, err
	}

	return &smPublicKey{
		key: key,
	}, nil
}

type smPublicKey struct {
	key *sm.PublicKey
}

func (e *smPublicKey) Key() interface{} {

	return e.key
}

func (e *smPublicKey) Bytes() []byte {

	if e.key == nil || e.key.X == nil || e.key.Y == nil {
		return nil
	}
	return elliptic.Marshal(e.key.Curve, e.key.X, e.key.Y)
}

func (e *smPublicKey) Algorithm() types.KeyType {

	return types.SM
}

func (e *smPublicKey) Hash(msg []byte) []byte {

	h := sm3.New()

	h.Write(msg)
	hash := h.Sum(nil)

	return hash
}

func (e *smPublicKey) Verify(sign, digest []byte) (bool, error) {
	r, s, _ := sm.SignDataToSignDigit(sign)

	v := sm.Sm2Verify(e.key, digest, r, s)

	return v, nil

}

func (e *smPublicKey) KeyPEM() ([]byte, error) {
	return sm.WritePublicKeytoMem(e.key, nil)
}

// SKI returns the subject key identifier of this key.
func (e *smPublicKey) SKI() []byte {
	if e.key == nil {
		return nil
	}

	// Marshall the public key
	raw := elliptic.Marshal(e.key.Curve, e.key.X, e.key.Y)

	// Hash it
	hash := sha256.New()
	hash.Write(raw)
	return hash.Sum(nil)
}
