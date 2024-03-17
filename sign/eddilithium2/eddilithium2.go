package eddilithium2

import (
	"github.com/cloudflare/circl/sign/eddilithium2"
)

const (
	PublicKeySize  = eddilithium2.PublicKeySize
	PrivateKeySize = eddilithium2.PrivateKeySize
	SignatureSize  = eddilithium2.SignatureSize
)

func Generate() (*eddilithium2.PublicKey, *eddilithium2.PrivateKey) {
	pubKey, privKey, err := eddilithium2.GenerateKey(nil)

	if err != nil {
		panic(err)
	}

	return pubKey, privKey
}

func Sign(privKey *eddilithium2.PrivateKey, msg []byte) []byte {
	var signature []byte
	eddilithium2.SignTo(privKey, msg, signature)
	return signature
}

func Verify(pubKey *eddilithium2.PublicKey, msg []byte, signature []byte) bool {
	return eddilithium2.Verify(pubKey, msg, signature)
}
