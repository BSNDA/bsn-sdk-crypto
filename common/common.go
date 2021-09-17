package common

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/big"

	"github.com/BSNDA/bsn-sdk-crypto/errors"
)

const (
	// NonceSize is the default NonceSize
	NonceSize = 24
)

// GetRandomBytes returns len random looking bytes
func GetRandomBytes(len int) ([]byte, error) {
	key := make([]byte, len)

	_, err := rand.Read(key)
	if err != nil {
		return nil, errors.New("error getting random bytes")
	}

	return key, nil
}

// GetRandomNonce returns a random byte array of length NonceSize
func GetRandomNonce() ([]byte, error) {
	return GetRandomBytes(NonceSize)
}

// GetRandomBigInt returns a random big int
func GetRandomBigInt() (*big.Int, error) {
	//b, err := GetRandomBytes(32)
	//if err != nil {
	//	return nil, err
	//}
	//return new(big.Int).SetBytes(b), nil

	// generate random Nonce between 0 - 2^250 - 1
	max := new(big.Int)
	max.Exp(big.NewInt(2), big.NewInt(250), nil).Sub(max, big.NewInt(1))
	//Generate cryptographically strong pseudo-random between 0 - max
	nonce, err := rand.Int(rand.Reader, max)
	if err != nil {
		//error handling
		return nil, fmt.Errorf("failed to generate nonce: %v", err)
	}

	return nonce, nil

}

func ComputeTxnID(nonce, creator []byte) (string, error) {
	h := sha256.New()
	b := append(nonce, creator...)
	_, err := h.Write(b)
	if err != nil {
		return "", err
	}
	digest := h.Sum(nil)
	id := hex.EncodeToString(digest)
	return id, nil
}

// GetHash return sha256 hash
func GetHash(data []byte) ([]byte, error) {
	h := sha256.New()
	_, err := h.Write(data)
	if err != nil {
		return nil, err
	}
	digest := h.Sum(nil)
	return digest, nil
}
