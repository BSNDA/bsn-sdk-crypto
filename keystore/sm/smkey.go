package sm

import (
	"crypto/elliptic"
	"crypto/sha256"
	"fmt"

	"github.com/BSNDA/bsn-sdk-crypto/errors"
	"github.com/BSNDA/bsn-sdk-crypto/keystore/key"
	"github.com/tjfoc/gmsm/sm2"
)

func NewSMPrivateKey(privKey *sm2.PrivateKey) *SMPrivateKey {

	return &SMPrivateKey{privKey: privKey}
}

type SMPrivateKey struct {
	privKey *sm2.PrivateKey
}

func (k *SMPrivateKey) GetPrivateKey() *sm2.PrivateKey {
	return k.privKey
}

// Bytes converts this key to its byte representation,
// if this operation is allowed.
func (k *SMPrivateKey) Bytes() ([]byte, error) {
	return nil, errors.New("Not supported.")
}

// SKI returns the subject key identifier of this key.
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

// Symmetric returns true if this key is a symmetric key,
// false if this key is asymmetric
func (k *SMPrivateKey) Symmetric() bool {
	return false
}

// Private returns true if this key is a private key,
// false otherwise.
func (k *SMPrivateKey) Private() bool {
	return true
}

// PublicKey returns the corresponding public key part of an asymmetric public/private key pair.
// This method returns an error in symmetric key schemes.
func (k *SMPrivateKey) PublicKey() (key.Key, error) {
	return &SMPublicKey{&k.privKey.PublicKey}, nil
}

func NewSMPublicKey(pubKey *sm2.PublicKey) *SMPublicKey {

	return &SMPublicKey{pubKey: pubKey}
}

type SMPublicKey struct {
	pubKey *sm2.PublicKey
}

func (k *SMPublicKey) GetPublicKey() *sm2.PublicKey {
	return k.pubKey
}

// Bytes converts this key to its byte representation,
// if this operation is allowed.
func (k *SMPublicKey) Bytes() (raw []byte, err error) {
	raw, err = sm2.MarshalPKIXPublicKey(k.pubKey)
	if err != nil {
		return nil, fmt.Errorf("Failed marshalling key [%s]", err)
	}
	return
}

// SKI returns the subject key identifier of this key.
func (k *SMPublicKey) SKI() []byte {
	if k.pubKey == nil {
		return nil
	}

	// Marshall the public key
	raw := elliptic.Marshal(k.pubKey.Curve, k.pubKey.X, k.pubKey.Y)

	// Hash it
	hash := sha256.New()
	hash.Write(raw)
	return hash.Sum(nil)
}

// Symmetric returns true if this key is a symmetric key,
// false if this key is asymmetric
func (k *SMPublicKey) Symmetric() bool {
	return false
}

// Private returns true if this key is a private key,
// false otherwise.
func (k *SMPublicKey) Private() bool {
	return false
}

// PublicKey returns the corresponding public key part of an asymmetric public/private key pair.
// This method returns an error in symmetric key schemes.
func (k *SMPublicKey) PublicKey() (key.Key, error) {
	return k, nil
}

func GetSmPrivateKey(key key.Key) *sm2.PrivateKey {
	prk, ok := key.(*SMPrivateKey)
	if ok {
		return prk.privKey
	} else {
		return nil
	}
}
