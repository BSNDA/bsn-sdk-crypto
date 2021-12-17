package secp256k1

import (
	"encoding/base64"
	"fmt"
	"github.com/BSNDA/bsn-sdk-crypto/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
	"math/big"
	"testing"
)

func TestNewSecp256k1Key(t *testing.T) {

	pk, err := NewSecp256k1Key()

	if err != nil {
		t.Fatal(err)
	}

	pkpem, err := PrivateKeyToPEM(pk)
	fmt.Println(string(pkpem))

	puk := pk.PublicKey

	pukpem, err := PublicKeyToPEM(&puk)

	if err != nil {
		t.Fatal(err)
	}
	fmt.Println(string(pukpem))

	add := crypto.PubkeyToAddress(puk).String()
	fmt.Println(add)

	common.WriteFile(pkpem, fmt.Sprintf("./%s.pem", add), false)

}

func TestSign(t *testing.T) {

	privk := `-----BEGIN PRIVATE KEY-----
MIGEAgEAMBAGByqGSM49AgEGBSuBBAAKBG0wawIBAQQgseEExMPXTcSpExzejzYZ
wcLWikQtoZ3BRhWergMR2LGhRANCAATCEQFr8dEbUI6ZYChl4+pE3UopdpWknZiv
rK7WWNymFHQQyIN15nsq5ZZat8G+iPNLtCdRSaU3h769ObArmgvB
-----END PRIVATE KEY-----`

	data := []byte("abc123")

	pk, err := LoadPrivateKey([]byte(privk))

	ecdsa := &ecdsaK1Handle{
		pubKey: &pk.PublicKey,
		priKey: pk,
	}

	dis, _ := ecdsa.Hash(data)

	sign, err := ecdsa.Sign(dis)
	if err != nil {
		t.Fatal(err)
	}

	fmt.Println(base64.StdEncoding.EncodeToString(sign))

}

//-----BEGIN PUBLIC KEY-----
//MFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAEGg4fBBN0XCRvoV9ft7TL/UlAUqUQpNaV
//YCIJuMBBUsXcDwhjt+DBn4iSEbOI0GdnEWq5SUSsf3Q+Yp0Xn8gyqQ==
//-----END PUBLIC KEY-----

func TestAddress(t *testing.T) {

	//0x04288cf7d3f37c51ae28d0364e825ead7fc3ad7f
	privk := `-----BEGIN PRIVATE KEY-----
MIGEAgEAMBAGByqGSM49AgEGBSuBBAAKBG0wawIBAQQgp25K/dmpdOq+Zgl7CUHj
6+bTet00kxJ+0N0oZaFle56hRANCAATQJi0Wdec5HkuZwHQM192v6lqZl1BL/mp6
HAzqbBoGaG7qSM5rdZjGdcbX3zVrvUPflwvath5ZC57RL94kuXJv
-----END PRIVATE KEY-----`
	//	privk :=`-----BEGIN PRIVATE KEY-----
	//MIGTAgEAMBMGByqGSM49AgEGCCqBHM9VAYItBHkwdwIBAQQgo6TydHi3OPuvEjQO
	//szKnohJuNG0OKIVAhS79/23/wjagCgYIKoEcz1UBgi2hRANCAAQBoVz533V8xYVD
	//CWwwc2/pWCU1tqx1sY0LBLnTPaOBCXwwZm8JdurfE6WOmicOq/OwiduwOYeLoTH2
	//Ln3SEX2r
	//-----END PRIVATE KEY-----`

	//	puk :=`-----BEGIN PUBLIC KEY-----
	//MFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAEKIz30/N8Ua4o0DZOgl6tf8Otf2VORgug
	//hAU6vDxHlMqp4AiQjdIJH0VNSBJrrALCBiW9339nEEb2EwanIrJr+Q==
	//-----END PUBLIC KEY-----`

	pk, err := LoadPrivateKey([]byte(privk))

	if err != nil {
		t.Fatal(err)
	}
	fmt.Println(hexutil.Encode(pk.D.Bytes()))
	//0xa76e4afdd9a974eabe66097b0941e3ebe6d37add3493127ed0dd2865a1657b9e
	fmt.Println(crypto.PubkeyToAddress(pk.PublicKey).String())
	//0xAe9a823B2b6dE897cad309Eec21636F81f10023F
}

func TestNewKey(t *testing.T) {

	KB, _ := hexutil.Decode("0x0fb49039f736aca91075d33dae5df6d856e696023e886ece1bdb8c6596e7d8c4")

	k := new(big.Int).SetBytes(KB)
	pk, err := NewKey(k)

	if err != nil {
		t.Fatal(err)
	}
	fmt.Println(hexutil.Encode(pk.D.Bytes()))
	//0xa76e4afdd9a974eabe66097b0941e3ebe6d37add3493127ed0dd2865a1657b9e
	fmt.Println(crypto.PubkeyToAddress(pk.PublicKey).String())
	//0xAe9a823B2b6dE897cad309Eec21636F81f10023F
}

func TestSMK(t *testing.T) {

	KB, _ := hexutil.Decode("0xf44c00538f62153c38db88e341285f7c7a2631fe83d5b83592cfe3467185a2a7")

	k := new(big.Int).SetBytes(KB)
	pk, err := NewKey(k)

	if err != nil {
		t.Fatal(err)
	}

	ecdsa := &ecdsaK1Handle{
		pubKey: &pk.PublicKey,
		priKey: pk,
	}

	data := []byte("abc123")

	sign, err := ecdsa.Sign(data)
	if err != nil {
		t.Fatal(err)
	}

	v, err := ecdsa.Verify(sign, data)
	fmt.Println(v)

}
