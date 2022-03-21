package signing

import (
	"crypto/ecdsa"
	"crypto/x509"
	"github.com/cloudflare/cfssl/config"
	"github.com/cloudflare/cfssl/signer/local"
	"time"
)

var (
	// Default root CA certificate expiration is 15 years (in hours).
	defaultRootCACertificateExpiration = "131400h"
	// Default intermediate CA certificate expiration is 5 years (in hours).
	defaultIntermediateCACertificateExpiration = parseDuration("43800h")
	// Default issued certificate expiration is 1 year (in hours).
	defaultIssuedCertificateExpiration = parseDuration("8760h") //8760
)

func parseDuration(str string) time.Duration {
	d, err := time.ParseDuration(str)
	if err != nil {
		panic(err)
	}
	return d
}

func NewSigner(key *ecdsa.PrivateKey) (*local.Signer, error) {
	return local.NewSigner(key, nil, x509.ECDSAWithSHA256, NewCASigning())
}

func NewCASigning() *config.Signing {

	var policy *config.Signing
	policy = &config.Signing{
		Profiles: map[string]*config.SigningProfile{},
		Default:  &config.SigningProfile{}, //config.DefaultConfig(),
	}

	caProfile := policy.Profiles["ca"]

	initSigningProfile(&caProfile,
		defaultIntermediateCACertificateExpiration,
		true)
	policy.Profiles["ca"] = caProfile

	initSigningProfile(
		&policy.Default,
		defaultIssuedCertificateExpiration,
		false)
	tlsProfile := policy.Profiles["tls"]
	initSigningProfile(&tlsProfile,
		defaultIssuedCertificateExpiration,
		false)
	policy.Profiles["tls"] = tlsProfile

	return policy
}

var AttrOIDString = "1.2.3.4.5.6.7.8.1"

func initSigningProfile(spp **config.SigningProfile, expiry time.Duration, isCA bool) {
	sp := *spp
	if sp == nil {
		sp = &config.SigningProfile{CAConstraint: config.CAConstraint{IsCA: isCA}}
		*spp = sp
	}
	if sp.Usage == nil {
		sp.Usage = []string{"cert sign", "crl sign"}
	}
	if sp.Expiry == 0 {
		sp.Expiry = expiry
	}
	if sp.ExtensionWhitelist == nil {
		sp.ExtensionWhitelist = map[string]bool{}
	}
	// This is set so that all profiles permit an attribute extension in CFSSL
	sp.ExtensionWhitelist[AttrOIDString] = true
}
