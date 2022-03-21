package ecdsa

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"github.com/ethereum/go-ethereum/crypto/secp256k1"
	"github.com/pkg/errors"
	"math/big"
)

func NewSecp256r1Key() (*ecdsa.PrivateKey, error) {
	curve := elliptic.P256()
	return ecdsa.GenerateKey(curve, rand.Reader)
}

func NewSecp256k1Key() (*ecdsa.PrivateKey, error) {
	curve := secp256k1.S256()
	return ecdsa.GenerateKey(curve, rand.Reader)
}

// PrivateKeyToPEM converts the private key to PEM format.
func PrivateKeyToPEM(k *ecdsa.PrivateKey) ([]byte, error) {
	if k == nil {
		return nil, errors.New("Invalid ecdsa private key. It must be different from nil.")
	}

	// get the oid for the curve
	oidNamedCurve, ok := oidFromNamedCurve(k.Curve)
	if !ok {
		return nil, errors.New("unknown elliptic curve")
	}

	// based on https://golang.org/src/crypto/x509/sec1.go
	privateKeyBytes := k.D.Bytes()
	paddedPrivateKey := make([]byte, (k.Curve.Params().N.BitLen()+7)/8)
	copy(paddedPrivateKey[len(paddedPrivateKey)-len(privateKeyBytes):], privateKeyBytes)
	// omit NamedCurveOID for compatibility as it's optional
	asn1Bytes, err := asn1.Marshal(ecPrivateKey{
		Version:    1,
		PrivateKey: paddedPrivateKey,
		PublicKey:  asn1.BitString{Bytes: elliptic.Marshal(k.Curve, k.X, k.Y)},
	})

	if err != nil {
		return nil, fmt.Errorf("error marshaling EC key to asn1 [%s]", err)
	}

	var pkcs8Key pkcs8Info
	pkcs8Key.Version = 0
	pkcs8Key.PrivateKeyAlgorithm = make([]asn1.ObjectIdentifier, 2)
	pkcs8Key.PrivateKeyAlgorithm[0] = oidPublicKeyECDSA
	pkcs8Key.PrivateKeyAlgorithm[1] = oidNamedCurve
	pkcs8Key.PrivateKey = asn1Bytes

	pkcs8Bytes, err := asn1.Marshal(pkcs8Key)
	if err != nil {
		return nil, fmt.Errorf("error marshaling EC key to asn1 [%s]", err)
	}
	return pem.EncodeToMemory(
		&pem.Block{
			Type:  "PRIVATE KEY",
			Bytes: pkcs8Bytes,
		},
	), nil
}

// PublicKeyToPEM marshals a public key to the pem format
func PublicKeyToPEM(k *ecdsa.PublicKey) ([]byte, error) {

	PubASN1, err := MarshalPKIXPublicKey(k)
	if err != nil {
		return nil, err
	}

	return pem.EncodeToMemory(
		&pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: PubASN1,
		},
	), nil
}

func MarshalPKIXPublicKey(pub *ecdsa.PublicKey) ([]byte, error) {
	var publicKeyBytes []byte
	var publicKeyAlgorithm pkix.AlgorithmIdentifier
	var err error

	if publicKeyBytes, publicKeyAlgorithm, err = marshalPublicKey(pub); err != nil {
		return nil, err
	}

	pukix := pkixPublicKey{
		Algo: publicKeyAlgorithm,
		BitString: asn1.BitString{
			Bytes:     publicKeyBytes,
			BitLength: 8 * len(publicKeyBytes),
		},
	}

	ret, _ := asn1.Marshal(pukix)
	return ret, nil
}

func marshalPublicKey(pub *ecdsa.PublicKey) (publicKeyBytes []byte, publicKeyAlgorithm pkix.AlgorithmIdentifier, err error) {
	publicKeyBytes = elliptic.Marshal(pub.Curve, pub.X, pub.Y)
	oid, ok := oidFromNamedCurve(pub.Curve)
	if !ok {
		return nil, pkix.AlgorithmIdentifier{}, errors.New("x509: unsupported elliptic curve")
	}
	publicKeyAlgorithm.Algorithm = oidPublicKeyECDSA
	var paramBytes []byte
	paramBytes, err = asn1.Marshal(oid)
	if err != nil {
		return
	}
	publicKeyAlgorithm.Parameters.FullBytes = paramBytes

	return publicKeyBytes, publicKeyAlgorithm, nil
}

func LoadPrivateKeyByPEM(privateKey string) (*ecdsa.PrivateKey, error) {

	bl, _ := pem.Decode([]byte(privateKey))
	if bl == nil {
		return nil, errors.New("failed to decode PEM block from PrivateKey")
	}
	key, err := ParsePKCS8PrivateKey(bl.Bytes)
	if err != nil {
		return nil, errors.New("failed to parse private key from PrivateKey")
	}
	return key.(*ecdsa.PrivateKey), nil
}

func ParsePKCS8PrivateKey(der []byte) (key interface{}, err error) {
	var privKey pkcs8
	if _, err := asn1.Unmarshal(der, &privKey); err != nil {
		return nil, err
	}
	bytes := privKey.Algo.Parameters.FullBytes
	namedCurveOID := new(asn1.ObjectIdentifier)
	if _, err := asn1.Unmarshal(bytes, namedCurveOID); err != nil {
		namedCurveOID = nil
	}
	key, err = parseECPrivateKey(namedCurveOID, privKey.PrivateKey)
	if err != nil {
		return nil, errors.New("x509: failed to parse EC private key embedded in PKCS#8: " + err.Error())
	}
	return key, nil
}

func parseECPrivateKey(namedCurveOID *asn1.ObjectIdentifier, der []byte) (key *ecdsa.PrivateKey, err error) {
	var privKey ecPrivateKey
	if _, err := asn1.Unmarshal(der, &privKey); err != nil {
		return nil, errors.New("x509: failed to parse EC private key: " + err.Error())
	}
	if privKey.Version != ecPrivKeyVersion {
		return nil, fmt.Errorf("x509: unknown EC private key version %d", privKey.Version)
	}

	var curve elliptic.Curve
	if namedCurveOID != nil {
		curve = namedCurveFromOID(*namedCurveOID)
	} else {
		curve = namedCurveFromOID(privKey.NamedCurveOID)
	}
	if curve == nil {
		return nil, errors.New("x509: unknown elliptic curve")
	}

	k := new(big.Int).SetBytes(privKey.PrivateKey)
	curveOrder := curve.Params().N
	if k.Cmp(curveOrder) >= 0 {
		return nil, errors.New("x509: invalid elliptic curve private key value")
	}
	priv := new(ecdsa.PrivateKey)
	priv.Curve = curve
	priv.D = k

	privateKey := make([]byte, (curveOrder.BitLen()+7)/8)

	// Some private keys have leading zero padding. This is invalid
	// according to [SEC1], but this code will ignore it.
	for len(privKey.PrivateKey) > len(privateKey) {
		if privKey.PrivateKey[0] != 0 {
			return nil, errors.New("x509: invalid private key length")
		}
		privKey.PrivateKey = privKey.PrivateKey[1:]
	}

	// Some private keys remove all leading zeros, this is also invalid
	// according to [SEC1] but since OpenSSL used to do this, we ignore
	// this too.
	copy(privateKey[len(privateKey)-len(privKey.PrivateKey):], privKey.PrivateKey)
	priv.X, priv.Y = curve.ScalarBaseMult(privateKey)

	return priv, nil
}

func LoadPublicKeyByPEM(pub string) (*ecdsa.PublicKey, error) {
	bl, _ := pem.Decode([]byte(pub))
	if bl == nil {
		return nil, errors.New("failed to decode PEM block from Certificate")
	}

	key, err := ParsePKIXPublicKey(bl.Bytes)

	if err != nil {
		return nil, errors.New("failed to parse private key from PrivateKey")
	}

	return key.(*ecdsa.PublicKey), nil
}

func ParsePKIXPublicKey(derBytes []byte) (pub interface{}, err error) {
	var pki publicKeyInfo
	if rest, err := asn1.Unmarshal(derBytes, &pki); err != nil {
		return nil, err
	} else if len(rest) != 0 {
		return nil, errors.New("x509: trailing data after ASN.1 of public-key")
	}
	return parsePublicKey(&pki)
}

func parsePublicKey(keyData *publicKeyInfo) (interface{}, error) {
	asn1Data := keyData.PublicKey.RightAlign()
	paramsData := keyData.Algorithm.Parameters.FullBytes
	namedCurveOID := new(asn1.ObjectIdentifier)
	rest, err := asn1.Unmarshal(paramsData, namedCurveOID)
	if err != nil {
		return nil, err
	}
	if len(rest) != 0 {
		return nil, errors.New("x509: trailing data after ECDSA parameters")
	}
	namedCurve := namedCurveFromOID(*namedCurveOID)
	if namedCurve == nil {
		return nil, errors.New("x509: unsupported elliptic curve")
	}
	x, y := elliptic.Unmarshal(namedCurve, asn1Data)
	if x == nil {
		return nil, errors.New("x509: failed to unmarshal elliptic curve point")
	}
	pub := &ecdsa.PublicKey{
		Curve: namedCurve,
		X:     x,
		Y:     y,
	}
	return pub, nil
}

func LoadPublicKeyByCertPem(cert string) (*ecdsa.PublicKey, error) {

	bl, _ := pem.Decode([]byte(cert))
	if bl == nil {
		return nil, errors.New("failed to decode PEM block from Certificate")
	}

	key, err := ParsePublicKeyByCert(bl.Bytes)

	if err != nil {
		return nil, errors.New("failed to parse private key from PrivateKey")
	}

	return key.(*ecdsa.PublicKey), nil
}

func ParsePublicKeyByCert(certBytes []byte) (pub interface{}, err error) {
	var cert certificate
	rest, err := asn1.Unmarshal(certBytes, &cert)
	if err != nil {
		return nil, err
	}
	if len(rest) > 0 {
		return nil, asn1.SyntaxError{Msg: "trailing data"}
	}

	publicKey, err := parsePublicKey(&cert.TBSCertificate.PublicKey)

	return publicKey, err
}
