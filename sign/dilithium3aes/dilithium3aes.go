package dilithium3aes

import (
	"github.com/cloudflare/circl/sign/dilithium/mode3aes"
)

func Generate() (*mode3aes.PublicKey, *mode3aes.PrivateKey) {
	pubKey, privKey, err := mode3aes.GenerateKey(nil)

	if err != nil {
		panic(err)
	}

	return pubKey, privKey
}

func Sign(privKey *mode3aes.PrivateKey, msg []byte) []byte {
	var signature []byte
	mode3aes.SignTo(privKey, msg, signature)
	return signature
}

func Verify(pubKey *mode3aes.PublicKey, msg []byte, signature []byte) bool {
	return mode3aes.Verify(pubKey, msg, signature)
}
