package ecdsa

import (
	"fmt"
	"reflect"
	"testing"
)

func TestNewSecp256r1Key(t *testing.T) {
	key, err := NewSecp256r1Key()

	if err != nil {
		t.Fatal(err)
	}

	by, err := PrivateKeyToPEM(key)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println(string(by))
}

func TestLoadPrivateKeyByPEMR1(t *testing.T) {
	key := `-----BEGIN PRIVATE KEY-----
MIGEAgEAMBAGByqGSM49AgEGBSuBBAAKBG0wawIBAQQgBRw81edeAQkDKGheQ2m4
uLc8GJcBC9lZbzQWBUuzCfOhRANCAARVOC8n42NOQUh26dHveWpxD97qljABZeXh
TrGMiVrKdTOdpuDcTRhYPN5zapA5qGgfZo/ufkxCU8vKFOXPJ0w2
-----END PRIVATE KEY-----`

	k, err := LoadPrivateKeyByPEM(key)
	if err != nil {
		t.Fatal(err)
	}

	fmt.Println(reflect.TypeOf(k.Curve))
}

func TestNewSecp256k1Key(t *testing.T) {
	key, err := NewSecp256k1Key()

	if err != nil {
		t.Fatal(err)
	}

	by, err := PrivateKeyToPEM(key)
	if err != nil {
		t.Fatal(err)
	}

	fmt.Println(string(by))

}

func TestLoadPrivateKeyByPEMK1(t *testing.T) {
	key := `-----BEGIN PRIVATE KEY-----
MIGEAgEAMBAGByqGSM49AgEGBSuBBAAKBG0wawIBAQQgxJiT0fO+1dx8AlUzb8m2
dwENOBDdRZ9wmMLtdTaezmihRANCAATQKpzl1E0Va1p5cLp2W29ACOay3IhbPuA0
iOyBrmquTbmyHutE5dmK5UYBxZ8eOMB6SOHukPxK6t9+KQlOyzi3
-----END PRIVATE KEY-----`

	k, err := LoadPrivateKeyByPEM(key)
	if err != nil {
		t.Fatal(err)
	}

	fmt.Println(reflect.TypeOf(k.Curve))
}
