package dilithium2aes

import (
	"github.com/cloudflare/circl/sign/dilithium/mode2aes"
)

const (
	PublicKeySize  = mode2aes.PublicKeySize
	PrivateKeySize = mode2aes.PrivateKeySize
	SignatureSize  = mode2aes.SignatureSize
)

func Generate() (*mode2aes.PublicKey, *mode2aes.PrivateKey) {
	pubKey, privKey, err := mode2aes.GenerateKey(nil)

	if err != nil {
		panic(err)
	}

	return pubKey, privKey
}

func Sign(privKey *mode2aes.PrivateKey, msg []byte) []byte {
	var signature []byte
	mode2aes.SignTo(privKey, msg, signature)
	return signature
}

func Verify(pubKey *mode2aes.PublicKey, msg []byte, signature []byte) bool {
	return mode2aes.Verify(pubKey, msg, signature)
}
