package key

import (
	"crypto/sha256"
	"github.com/tjfoc/gmsm/sm3"
)

type SM3Hash struct{}

func (e *SM3Hash) Hash(msg []byte) []byte {

	h := sm3.New()

	h.Write(msg)
	hash := h.Sum(nil)

	return hash
}

type SHA256Hash struct{}

func (e *SHA256Hash) Hash(msg []byte) []byte {

	h := sha256.New()

	h.Write(msg)
	hash := h.Sum(nil)

	return hash
}
