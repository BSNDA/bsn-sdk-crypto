package aes

import (
	"encoding/hex"
	"fmt"
	"testing"
)

func TestAESCBCPKCS7Decrypt(t *testing.T) {

	data := []byte("abc")
	key := []byte("123456")

	key = Pkcs7PaddingKey(key)
	cr, err := AESCBCPKCS7Encrypt(key, data)
	if err != nil {
		t.Fatal(err)
	}

	fmt.Println("Encrypt：", hex.EncodeToString(cr))

	data, err = AESCBCPKCS7Decrypt(key, cr)
	if err != nil {
		t.Fatal(err)
	}

	fmt.Println("Decrypt：", string(data))

}
