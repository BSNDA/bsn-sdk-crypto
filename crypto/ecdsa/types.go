package ecdsa

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"time"
)

type ECDSASignature struct {
	R, S *big.Int
}

type pkcs8Info struct {
	Version             int
	PrivateKeyAlgorithm []asn1.ObjectIdentifier
	PrivateKey          []byte
}

type pkcs8 struct {
	Version    int
	Algo       pkix.AlgorithmIdentifier
	PrivateKey []byte
	// optional attributes omitted.
}

type ecPrivateKey struct {
	Version       int
	PrivateKey    []byte
	NamedCurveOID asn1.ObjectIdentifier `asn1:"optional,explicit,tag:0"`
	PublicKey     asn1.BitString        `asn1:"optional,explicit,tag:1"`
}

type pkixPublicKey struct {
	Algo      pkix.AlgorithmIdentifier
	BitString asn1.BitString
}

type certificate struct {
	Raw                asn1.RawContent
	TBSCertificate     tbsCertificate
	SignatureAlgorithm pkix.AlgorithmIdentifier
	SignatureValue     asn1.BitString
}

type tbsCertificate struct {
	Raw                asn1.RawContent
	Version            int `asn1:"optional,explicit,default:0,tag:0"`
	SerialNumber       *big.Int
	SignatureAlgorithm pkix.AlgorithmIdentifier
	Issuer             asn1.RawValue
	Validity           validity
	Subject            asn1.RawValue
	PublicKey          publicKeyInfo
	UniqueId           asn1.BitString   `asn1:"optional,tag:1"`
	SubjectUniqueId    asn1.BitString   `asn1:"optional,tag:2"`
	Extensions         []pkix.Extension `asn1:"optional,explicit,tag:3"`
}

type validity struct {
	NotBefore, NotAfter time.Time
}

type publicKeyInfo struct {
	Raw       asn1.RawContent
	Algorithm pkix.AlgorithmIdentifier
	PublicKey asn1.BitString
}
