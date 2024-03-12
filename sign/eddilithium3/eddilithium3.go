package eddilithium3

import (
	"github.com/cloudflare/circl/sign/eddilithium3"
)

func Generate() (*eddilithium3.PublicKey, *eddilithium3.PrivateKey) {
	pubKey, privKey, err := eddilithium3.GenerateKey(nil)

	if err != nil {
		panic(err)
	}

	return pubKey, privKey
}

func Sign(privKey *eddilithium3.PrivateKey, msg []byte) []byte {
	var signature []byte
	eddilithium3.SignTo(privKey, msg, signature)
	return signature
}

func Verify(pubKey *eddilithium3.PublicKey, msg []byte, signature []byte) bool {
	return eddilithium3.Verify(pubKey, msg, signature)
}
