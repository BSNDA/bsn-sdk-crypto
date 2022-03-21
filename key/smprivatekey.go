package key

import (
	"crypto/elliptic"
	"crypto/sha256"
	"math/big"

	math "github.com/BSNDA/bsn-sdk-crypto/common"
	"github.com/BSNDA/bsn-sdk-crypto/crypto/sm"
	smcsr "github.com/BSNDA/bsn-sdk-crypto/crypto/sm/csr"
	"github.com/BSNDA/bsn-sdk-crypto/types"

	"github.com/cloudflare/cfssl/csr"
	"github.com/tjfoc/gmsm/sm3"
)

func NewSMPrivateKey(pem string) (*smPrivateKey, error) {
	key, err := sm.ReadPrivateKeyFromMem([]byte(pem), nil)
	if err != nil {
		return nil, err
	}

	return &smPrivateKey{key: key}, nil
}

type smPrivateKey struct {
	key *sm.PrivateKey
}

func (e *smPrivateKey) Algorithm() types.KeyType {

	return types.SM
}

func (e *smPrivateKey) Bytes() []byte {
	if e.key == nil {
		return nil
	}
	return math.PaddedBigBytes(e.key.D, e.key.Params().BitSize/8)
}

func (e *smPrivateKey) PublicKey() PublicKeyProvider {

	puk := &sm.PublicKey{
		&e.key.PublicKey,
	}

	return &smPublicKey{
		key: puk,
	}
}

func (e *smPrivateKey) Key() interface{} {

	return e.key
}

func (e *smPrivateKey) Hash(msg []byte) []byte {

	h := sm3.New()
	h.Write(msg)
	hash := h.Sum(nil)

	return hash
}

func (e *smPrivateKey) SignTx(digest []byte) (r, s, pub *big.Int, err error) {

	r, s, err = sm.Sm2Sign(e.key, digest)

	if err != nil {
		return
	}

	pb := sm.FromECDSAPub(&e.key.PublicKey)
	pub = new(big.Int).SetBytes(pb[1:])
	return

}

func (e *smPrivateKey) Sign(digest []byte) ([]byte, error) {
	r, s, err := sm.Sm2Sign(e.key, digest)

	sign, err := sm.SignDigitToSignData(r, s)
	if err != nil {
		return nil, err
	}

	return sign, nil

}

func (e *smPrivateKey) GenCSR(req *csr.CertificateRequest) ([]byte, error) {
	if req.KeyRequest == nil {
		req.KeyRequest = newSm2BasicKeyRequest()
	}
	return smcsr.GenerateSM2CSR(e.key, req)
}

func newSm2BasicKeyRequest() *csr.KeyRequest {
	return &csr.KeyRequest{A: "sm2", S: 256}
}

func (e *smPrivateKey) KeyPEM() ([]byte, error) {
	return sm.WritePrivateKeytoMem(e.key, nil)
}

func (e *smPrivateKey) SKI() []byte {

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
