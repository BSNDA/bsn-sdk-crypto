package types

//go:generate stringer -type=KeyType
type KeyType uint8

const (
	SM KeyType = iota
	ECDSA_R1
	ECDSA_K1
)
