package ecdsa

import (
	"fmt"
	"testing"
)

func TestNewSecp256k1Key2(t *testing.T) {

	key, err := NewSecp256k1Key()

	if err != nil {
		t.Fatal(err)
	}

	pemRaw, err := PrivateKeyToPEM(key)
	if err != nil {
		t.Fatal(err)
	}

	fmt.Println(string(pemRaw))

	pukRaw, err := PublicKeyToPEM(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}

	fmt.Println(string(pukRaw))
}

func TestNewSecp256r1Key2(t *testing.T) {

	key, err := NewSecp256r1Key()

	if err != nil {
		t.Fatal(err)
	}

	pemRaw, err := PrivateKeyToPEM(key)
	if err != nil {
		t.Fatal(err)
	}

	fmt.Println(string(pemRaw))

	pukRaw, err := PublicKeyToPEM(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}

	fmt.Println(string(pukRaw))
}
