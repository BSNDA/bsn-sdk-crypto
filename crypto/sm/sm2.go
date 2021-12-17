package sm

import (
	"crypto/elliptic"
	"math/big"

	"github.com/tjfoc/gmsm/sm2"
	"github.com/tjfoc/gmsm/sm3"
)

func FromECDSAPub(pub *sm2.PublicKey) []byte {

	if pub == nil || pub.X == nil || pub.Y == nil {
		return nil
	}
	return elliptic.Marshal(pub.Curve, pub.X, pub.Y)
}

//func FromECDSA(priv *sm2.PrivateKey) []byte {
//	if priv == nil {
//		return nil
//	}
//	return math.PaddedBigBytes(priv.D, priv.Params().BitSize/8)
//}

func SignData(key *sm2.PrivateKey, digest []byte) (r, s, pub *big.Int, err error) {

	r, s, err = sm2.Sm2Sign(key, digest, default_uid)

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

	r, s, err = sm2.Sm2Sign(key, hash, default_uid)

	if err != nil {
		return
	}

	pb := FromECDSAPub(&key.PublicKey)

	pub = new(big.Int).SetBytes(pb[1:])

	return

}
