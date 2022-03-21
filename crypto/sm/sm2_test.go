package sm

import (
	"encoding/hex"
	"fmt"
	"math/big"
	"testing"
)

func TestKey(t *testing.T) {
	key, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}

	fmt.Println(hex.EncodeToString(FromECDSAPub(&key.PublicKey)[1:]))

	publicKeyStr := fmt.Sprintf("%s%s", fillStr64(String16(key.X)), fillStr64(String16(key.Y)))
	fmt.Println(publicKeyStr)
}

func fillStr64(str string) string {
	if len(str) >= 64 {
		return str
	} else {
		s := fmt.Sprintf("%064s", str)
		return s
	}
}

func String16(x *big.Int) string {
	return x.Text(16)
}
