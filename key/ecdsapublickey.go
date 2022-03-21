package key

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/pem"
	ec "github.com/BSNDA/bsn-sdk-crypto/crypto/ecdsa"
	"github.com/BSNDA/bsn-sdk-crypto/types"
	"github.com/pkg/errors"
	"reflect"
)

const (
	PublicKeyType = "PUBLIC KEY"
	CertType      = "CERTIFICATE"
)

func NewECDSAPublicKey(data string) (*ecdsaPublicKey, error) {
	block, _ := pem.Decode([]byte(data))
	if block == nil {
		return nil, errors.New("not pem")
	}
	var key *ecdsa.PublicKey
	var err error

	switch block.Type {
	case PublicKeyType:
		key, err = ec.LoadPublicKeyByPEM(data)
	case CertType:
		key, err = ec.LoadPublicKeyByCertPem(data)
	default:
		err = errors.Errorf("Unsupported %s", block.Type)
	}
	if err != nil {
		return nil, err
	}

	return &ecdsaPublicKey{
		key: key,
	}, nil
}

type ecdsaPublicKey struct {
	key *ecdsa.PublicKey
}

func (e *ecdsaPublicKey) Key() interface{} {

	return e.key
}
func (e *ecdsaPublicKey) Bytes() []byte {

	if e.key == nil || e.key.X == nil || e.key.Y == nil {
		return nil
	}
	return elliptic.Marshal(e.key.Curve, e.key.X, e.key.Y)
}
func (e *ecdsaPublicKey) Algorithm() types.KeyType {

	if reflect.TypeOf(e.key.Curve) == reflect.TypeOf(elliptic.P256()) {
		return types.ECDSA_R1
	} else {
		return types.ECDSA_K1
	}
}

func (e *ecdsaPublicKey) Hash(msg []byte) []byte {

	h := sha256.New()

	h.Write(msg)
	hash := h.Sum(nil)

	return hash
}

func (e *ecdsaPublicKey) Verify(sign, digest []byte) (bool, error) {
	return ec.VerifyECDSA(e.key, sign, digest)

}

func (e *ecdsaPublicKey) KeyPEM() ([]byte, error) {
	return ec.PublicKeyToPEM(e.key)
}

// SKI returns the subject key identifier of this key.
func (e *ecdsaPublicKey) SKI() []byte {
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
