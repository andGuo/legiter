package dilithium3

import (
	"github.com/cloudflare/circl/sign/dilithium/mode3"
)

const (
	PublicKeySize  = mode3.PublicKeySize
	PrivateKeySize = mode3.PrivateKeySize
	SignatureSize  = mode3.SignatureSize
)

func Generate() (*mode3.PublicKey, *mode3.PrivateKey) {
	pubKey, privKey, err := mode3.GenerateKey(nil)

	if err != nil {
		panic(err)
	}

	return pubKey, privKey
}

func Sign(privKey *mode3.PrivateKey, msg []byte) []byte {
	var signature []byte
	mode3.SignTo(privKey, msg, signature)
	return signature
}

func Verify(pubKey *mode3.PublicKey, msg []byte, signature []byte) bool {
	return mode3.Verify(pubKey, msg, signature)
}
