package secp256r1

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"testing"

	"github.com/BSNDA/bsn-sdk-crypto/utils"
)

func TestNewPuk(t *testing.T) {

	curve := elliptic.P256()
	privKey, err := ecdsa.GenerateKey(curve, rand.Reader)

	if err != nil {
		t.Fatal(err)
	}

	rawKey, _ := utils.PrivateKeyToPEM(privKey, nil)

	fmt.Println(string(rawKey))

	puk, _ := utils.PublicKeyToPEM(privKey.Public(), nil)

	fmt.Println(string(puk))

	data := []byte("123456")

	fmt.Println(string(data))

	h := sha256.New()

	h.Write([]byte(data))
	hash := h.Sum(nil)

	prk, _ := LoadPrivateKey(string(rawKey))

	sign, _ := SignECDSA(prk, hash)

	fmt.Println(base64.StdEncoding.EncodeToString(sign))

}
