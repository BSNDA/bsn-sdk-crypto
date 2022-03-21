package sign

import (
	"github.com/BSNDA/bsn-sdk-crypto/key"
	"github.com/pkg/errors"
)

type SignProvider interface {
	PrivateKey() key.PrivateKeyProvider
	PublicKey() key.PublicKeyProvider

	Hash(msg []byte) []byte
	Sign(digest []byte) ([]byte, error)
	Verify(sign, digest []byte) (bool, error)
}

type SignOpertion func(handle *signHandle) error

func WithPrivateKey(k key.PrivateKeyProvider) SignOpertion {
	return func(handle *signHandle) error {
		handle.privateKey = k
		return nil
	}
}

func WithHash(h key.HashProvider) SignOpertion {
	return func(handle *signHandle) error {
		handle.hash = h
		return nil
	}
}

func WithPublicKey(pubKey key.PublicKeyProvider) SignOpertion {
	return func(handle *signHandle) error {
		handle.publicKey = pubKey
		return nil
	}
}

func NewSignProvider(opts ...SignOpertion) (SignProvider, error) {
	s := &signHandle{}

	for _, opt := range opts {
		err := opt(s)
		if err != nil {
			return nil, err
		}
	}

	if s.privateKey == nil {
		return nil, errors.New("private key can not be empty")
	}

	if s.hash == nil {
		s.hash = s.privateKey
	}

	return s, nil

}

type signHandle struct {
	privateKey key.PrivateKeyProvider
	publicKey  key.PublicKeyProvider
	hash       key.HashProvider
}

func (s *signHandle) PrivateKey() key.PrivateKeyProvider {
	return s.privateKey
}

func (s *signHandle) PublicKey() key.PublicKeyProvider {
	return s.publicKey
}

func (s *signHandle) Hash(msg []byte) []byte {
	return s.hash.Hash(msg)
}

func (e *signHandle) Sign(digest []byte) ([]byte, error) {
	return e.privateKey.Sign(digest)

}

func (e *signHandle) Verify(sign, digest []byte) (bool, error) {
	if e.publicKey != nil {
		return e.publicKey.Verify(sign, digest)
	} else {
		return e.privateKey.PublicKey().Verify(sign, digest)
	}
}
