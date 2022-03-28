package key

import (
	"encoding/base64"
	"fmt"
	"github.com/BSNDA/bsn-sdk-crypto/types"
	"github.com/cloudflare/cfssl/csr"
	"testing"
)

func TestNewSMOrR1PrivateKey(t *testing.T) {

	key, err := NewPrivateKeyByGen(types.SM)

	if err != nil {
		t.Fatal(err)
	}
	fmt.Println(key.Algorithm().String())

	pemBytes, err := key.KeyPEM()

	if err != nil {
		t.Fatal(err)
	}

	fmt.Println(string(pemBytes))

	pubBytes, err := key.PublicKey().KeyPEM()

	if err != nil {
		t.Fatal(err)
	}

	fmt.Println(string(pubBytes))

	csrReq := &csr.CertificateRequest{}
	csrReq.CN = "test"
	csrReq.Names = append(csrReq.Names, csr.Name{
		OU: "client",
		O:  "Bsn",
	})

	csrBytes, err := key.GenCSR(csrReq)

	if err != nil {
		t.Fatal(err)
	}

	fmt.Println(string(csrBytes))

}

func TestSM(t *testing.T) {
	privKey := `-----BEGIN PRIVATE KEY-----
MIGTAgEAMBMGByqGSM49AgEGCCqBHM9VAYItBHkwdwIBAQQgx0co92s16WJUCBLm
RU2gTV2c+D5O+9KWm2ZIQUz7rJigCgYIKoEcz1UBgi2hRANCAAQzP2/FhudZaTWO
WthN4vDM7oxZIyX+Ni/vD0BxbNDlX2QzZL5hPWMav6p/oCqx8Kh/LFg/h0GWylRK
dP/3ofLg
-----END PRIVATE KEY-----`

	key, err := NewPrivateKeyProvider(types.SM, privKey)
	if err != nil {
		t.Fatal(err)
	}

	data := []byte("abc123")

	digest := key.Hash(data)

	sign, _ := key.Sign(digest)

	fmt.Println(base64.StdEncoding.EncodeToString(sign))

	fmt.Println(key.PublicKey().Verify(sign, digest))

}
