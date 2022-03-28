package sm

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"github.com/tjfoc/gmsm/x509"
	"math/big"

	math "github.com/BSNDA/bsn-sdk-crypto/common"
	"github.com/tjfoc/gmsm/sm2"
	"github.com/tjfoc/gmsm/sm3"
)

var (
	default_uid = []byte{0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38}
)

type PrivateKey struct {
	*sm2.PrivateKey
} // = sm2.PrivateKey

type PublicKey struct {
	*sm2.PublicKey
} // = sm2.PublicKey

func GenerateKey() (*PrivateKey, error) {
	k, err := sm2.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return &PrivateKey{
		k,
	}, nil
}

func Sm2Sign(priv *PrivateKey, msg []byte) (r, s *big.Int, err error) {
	return sm2.Sm2Sign(priv.PrivateKey, msg, default_uid,rand.Reader)
}

func Sm2Verify(pub *PublicKey, msg []byte, r, s *big.Int) bool {
	return sm2.Sm2Verify(pub.PublicKey, msg, default_uid, r, s)
}

func SignDigitToSignData(r, s *big.Int) ([]byte, error) {
	return sm2.SignDigitToSignData(r, s)
}

func SignDataToSignDigit(sign []byte) (*big.Int, *big.Int, error) {
	return sm2.SignDataToSignDigit(sign)
}

func ReadPrivateKeyFromMem(data []byte, pwd []byte) (*PrivateKey, error) {
	k, err := x509.ReadPrivateKeyFromPem(data, pwd)
	if err != nil {
		return nil, err
	}
	return &PrivateKey{
		k,
	}, nil
}
func WritePrivateKeytoMem(key *PrivateKey, pwd []byte) ([]byte, error) {
	return x509.WritePrivateKeyToPem(key.PrivateKey, pwd)
}

func ReadPublicKeyFromMem(data []byte, _ []byte) (*PublicKey, error) {
	puk, err := x509.ReadPublicKeyFromPem(data)
	if err != nil {
		return nil, err
	}
	return &PublicKey{
		puk,
	}, nil
}
func ParseCertificate(asn1Data []byte) (*x509.Certificate, error) {
	return x509.ParseCertificate(asn1Data)
}

func ParseSm2PublicKey(der []byte) (*PublicKey, error) {
	puk, err := x509.ParseSm2PublicKey(der)
	if err != nil {
		return nil, err
	}
	return &PublicKey{
		puk,
	}, nil
}

func WritePublicKeytoMem(key *PublicKey, _ []byte) ([]byte, error) {
	return x509.WritePublicKeyToPem(key.PublicKey)
}

func FromECDSAPub(pub *sm2.PublicKey) []byte {

	if pub == nil || pub.X == nil || pub.Y == nil {
		return nil
	}
	return elliptic.Marshal(pub.Curve, pub.X, pub.Y)
}

func FromECDSA(priv *sm2.PrivateKey) []byte {
	if priv == nil {
		return nil
	}
	return math.PaddedBigBytes(priv.D, priv.Params().BitSize/8)
}

func SignData(key *sm2.PrivateKey, digest []byte) (r, s, pub *big.Int, err error) {

	r, s, err = sm2.Sm2Sign(key, digest, default_uid,rand.Reader)

	if err != nil {
		return
	}

	pb := FromECDSAPub(&key.PublicKey)

	pub = new(big.Int).SetBytes(pb[1:])

	return

}

func SignDataCita(key *sm2.PrivateKey, digest []byte) (r, s, pub *big.Int, err error) {

	h := sm3.New()
	h.Write(digest)
	hash := h.Sum(nil)

	r, s, err = sm2.Sm2Sign(key, hash, default_uid,rand.Reader)

	if err != nil {
		return
	}

	pb := FromECDSAPub(&key.PublicKey)

	pub = new(big.Int).SetBytes(pb[1:])

	return

}

func ConvertSMPublicKey(pubkey string) (*ecdsa.PublicKey, error) {
	puk, err := x509.ReadPublicKeyFromPem([]byte(pubkey))
	if err != nil {
		return nil, err
	}
	var key = &ecdsa.PublicKey{}
	key.Y = puk.Y
	key.X = puk.X
	key.Curve = puk.Curve
	return key, err
}

func ConvertSMPrivateKey(prikey string) (*ecdsa.PrivateKey, error) {
	pkey, err := x509.ReadPrivateKeyFromPem([]byte(prikey), nil)
	if err != nil {
		return nil, err
	}
	var key = &ecdsa.PrivateKey{}
	key.Y = pkey.Y
	key.X = pkey.X
	key.Curve = pkey.Curve
	key.D = pkey.D
	return key, err
}
