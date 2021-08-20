package crypto

type SignHandle interface {
	Hash(msg []byte) ([]byte, error)
	Sign(digest []byte) ([]byte, error)
	Verify(sign, digest []byte) (bool, error)
}

type PublicHandle interface {

	// Verify verify sign data
	Verify(sign, digest []byte) (bool, error)

	// FromECDSAPub
	FromECDSAPub() []byte
}
