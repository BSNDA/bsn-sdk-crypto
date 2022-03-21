package key

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	math "github.com/BSNDA/bsn-sdk-crypto/common"
	ec "github.com/BSNDA/bsn-sdk-crypto/crypto/ecdsa"
	"github.com/BSNDA/bsn-sdk-crypto/crypto/eth"
	"github.com/BSNDA/bsn-sdk-crypto/types"
	"github.com/cloudflare/cfssl/csr"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/pkg/errors"
	"math/big"
	"reflect"
)

func NewECDSDAPrivateKey(pem string) (*ecdsaPrivateKey, error) {
	key, err := ec.LoadPrivateKeyByPEM(pem)
	if err != nil {
		return nil, err
	}

	return &ecdsaPrivateKey{key: key}, nil
}

type ecdsaPrivateKey struct {
	key *ecdsa.PrivateKey
}

func (e *ecdsaPrivateKey) Key() interface{} {

	return e.key
}

func (e *ecdsaPrivateKey) Bytes() []byte {
	if e.key == nil {
		return nil
	}
	return math.PaddedBigBytes(e.key.D, e.key.Params().BitSize/8)
}

func (e *ecdsaPrivateKey) PublicKey() PublicKeyProvider {
	return &ecdsaPublicKey{
		key: &e.key.PublicKey,
	}
}

func (e *ecdsaPrivateKey) Algorithm() types.KeyType {
	if reflect.TypeOf(e.key.Curve) == reflect.TypeOf(elliptic.P256()) {
		return types.ECDSA_R1
	} else {
		return types.ECDSA_K1
	}

}

func (e *ecdsaPrivateKey) Hash(msg []byte) []byte {

	h := sha256.New()

	h.Write(msg)
	hash := h.Sum(nil)

	return hash
}

func (e *ecdsaPrivateKey) Sign(digest []byte) ([]byte, error) {
	return ec.SignECDSA(e.key, digest)

}

func (e *ecdsaPrivateKey) SignTx(digest []byte) (r, s, v *big.Int, err error) {

	if e.Algorithm() == types.ECDSA_K1 {
		return eth.SignData(e.key, digest)
	} else {
		sig, err := crypto.Sign(digest, e.key)
		if err != nil {
			return nil, nil, nil, err
		}

		r = new(big.Int).SetBytes(sig[:32])
		s = new(big.Int).SetBytes(sig[32:64])
		v = new(big.Int).SetBytes([]byte{sig[64] + 27})
		return r, s, v, nil
	}
}

func (e *ecdsaPrivateKey) GenCSR(req *csr.CertificateRequest) ([]byte, error) {

	if req.KeyRequest == nil {
		req.KeyRequest = newCfsslBasicKeyRequest()
	}

	if e.Algorithm() == types.ECDSA_R1 {
		return csr.Generate(e.key, req)
	} else {
		return nil, errors.New("not supported")
	}
}

func newCfsslBasicKeyRequest() *csr.KeyRequest {
	return &csr.KeyRequest{A: "ecdsa", S: 256}
}

func (e *ecdsaPrivateKey) KeyPEM() ([]byte, error) {
	return ec.PrivateKeyToPEM(e.key)
}

func (e *ecdsaPrivateKey) SKI() []byte {

	if e.key == nil {
		return nil
	}
	// Marshall the public key
	raw := elliptic.Marshal(e.key.Curve, e.key.PublicKey.X, e.key.PublicKey.Y)

	// Hash it
	hash := sha256.New()
	hash.Write(raw)
	return hash.Sum(nil)
}
