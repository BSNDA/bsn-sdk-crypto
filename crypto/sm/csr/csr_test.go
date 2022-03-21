package csr

import (
	"fmt"
	"github.com/cloudflare/cfssl/csr"
	"github.com/tjfoc/gmsm/sm2"
	"testing"
)

func TestCSR(t *testing.T) {

	key, err := sm2.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}

	cr := &csr.CertificateRequest{}
	cr.CN = "test"
	cr.Names = append(cr.Names, csr.Name{
		OU: "client",
		O:  "Bsn",
	})

	csrRaw, err := GenerateSM2CSR(key, cr)
	if err != nil {
		t.Fatal(err)
	}

	fmt.Println(string(csrRaw))
}
