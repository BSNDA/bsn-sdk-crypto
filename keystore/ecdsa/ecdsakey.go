/*
Copyright IBM Corp. 2016 All Rights Reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

		 http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
/*
Notice: This file has been modified for Hyperledger Fabric SDK Go usage.
Please review third_party pinning scripts and patches for more details.
*/
package ecdsa

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"fmt"
	"github.com/BSNDA/bsn-sdk-crypto/keystore/key"
)

func NewEcdsaPrivateKey(privKey *ecdsa.PrivateKey) *EcdsaPrivateKey {

	return &EcdsaPrivateKey{
		privKey: privKey,
	}
}

type EcdsaPrivateKey struct {
	privKey *ecdsa.PrivateKey
}

func (k *EcdsaPrivateKey) GetPrivateKey() *ecdsa.PrivateKey {

	return k.privKey
}

// Bytes converts this key to its byte representation,
// if this operation is allowed.
func (k *EcdsaPrivateKey) Bytes() ([]byte, error) {

	return nil, errors.New("Not supported.")
}

// SKI returns the subject key identifier of this key.
func (k *EcdsaPrivateKey) SKI() []byte {
	if k.privKey == nil {
		return nil
	}

	// Marshall the public key
	raw := elliptic.Marshal(k.privKey.Curve, k.privKey.PublicKey.X, k.privKey.PublicKey.Y)

	// Hash it
	hash := sha256.New()
	hash.Write(raw)
	return hash.Sum(nil)
}

// Symmetric returns true if this key is a symmetric key,
// false if this key is asymmetric
func (k *EcdsaPrivateKey) Symmetric() bool {
	return false
}

// Private returns true if this key is a private key,
// false otherwise.
func (k *EcdsaPrivateKey) Private() bool {
	return true
}

// PublicKey returns the corresponding public key part of an asymmetric public/private key pair.
// This method returns an error in symmetric key schemes.
func (k *EcdsaPrivateKey) PublicKey() (key.Key, error) {
	return &EcdsaPublicKey{&k.privKey.PublicKey}, nil
}

func NewEcdsaPublicKey(pubKey *ecdsa.PublicKey) *EcdsaPublicKey {

	return &EcdsaPublicKey{pubKey: pubKey}
}

type EcdsaPublicKey struct {
	pubKey *ecdsa.PublicKey
}

func (k *EcdsaPublicKey) GetPublicKey() *ecdsa.PublicKey {
	return k.pubKey
}

// Bytes converts this key to its byte representation,
// if this operation is allowed.
func (k *EcdsaPublicKey) Bytes() (raw []byte, err error) {
	raw, err = x509.MarshalPKIXPublicKey(k.pubKey)
	if err != nil {
		return nil, fmt.Errorf("Failed marshalling key [%s]", err)
	}
	return
}

// SKI returns the subject key identifier of this key.
func (k *EcdsaPublicKey) SKI() []byte {
	if k.pubKey == nil {
		return nil
	}

	// Marshall the public key
	raw := elliptic.Marshal(k.pubKey.Curve, k.pubKey.X, k.pubKey.Y)

	// Hash it
	hash := sha256.New()
	hash.Write(raw)
	return hash.Sum(nil)
}

// Symmetric returns true if this key is a symmetric key,
// false if this key is asymmetric
func (k *EcdsaPublicKey) Symmetric() bool {
	return false
}

// Private returns true if this key is a private key,
// false otherwise.
func (k *EcdsaPublicKey) Private() bool {
	return false
}

// PublicKey returns the corresponding public key part of an asymmetric public/private key pair.
// This method returns an error in symmetric key schemes.
func (k *EcdsaPublicKey) PublicKey() (key.Key, error) {
	return k, nil
}

func GetECDSAPrivateKey(key key.Key) *ecdsa.PrivateKey {
	prk, ok := key.(*EcdsaPrivateKey)
	if ok {
		return prk.privKey
	} else {
		return nil
	}
}
