package keymgr

type KeyMgr interface {
	PEM() (string, error)

	SKI() []byte

	Hash(msg []byte) ([]byte, error)

	Sign(digest []byte) ([]byte, error)

	Verify(sign, digest []byte) (bool, error)
}

type PrivateKeyMgr interface {
	PEM() (string, error)

	SKI() []byte

	Hash(msg []byte) ([]byte, error)

	Sign(digest []byte) ([]byte, error)
}

type PublicKeyMgr interface {
	PEM() (string, error)

	SKI() []byte

	Hash(msg []byte) ([]byte, error)

	Verify(sign, digest []byte) (bool, error)
}
