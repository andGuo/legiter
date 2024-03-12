package dilithium2

import (
	"github.com/cloudflare/circl/sign/dilithium/mode2"
)

func Generate() (*mode2.PublicKey, *mode2.PrivateKey) {
	pubKey, privKey, err := mode2.GenerateKey(nil)

	if err != nil {
		panic(err)
	}

	return pubKey, privKey
}

func Sign(privKey *mode2.PrivateKey, msg []byte) []byte {
	var signature []byte
	mode2.SignTo(privKey, msg, signature)
	return signature
}

func Verify(pubKey *mode2.PublicKey, msg []byte, signature []byte) bool {
	return mode2.Verify(pubKey, msg, signature)
}
