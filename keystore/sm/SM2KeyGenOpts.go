package sm

import (
	"github.com/BSNDA/bsn-sdk-crypto/keystore/key"
)

// ECDSAP256KeyGenOpts contains options for ECDSA key generation with curve P-256.
type SM2KeyGenOpts struct {
	Temporary bool
}

// Algorithm returns the key generation algorithm identifier (to be used).
func (opts *SM2KeyGenOpts) Algorithm() string {
	return key.SM2
}

// Ephemeral returns true if the key to generate has to be ephemeral,
// false otherwise.
func (opts *SM2KeyGenOpts) Ephemeral() bool {
	return opts.Temporary
}
