package ed25519

import (
	"github.com/cloudflare/circl/sign/ed25519"
)

func Generate() (ed25519.PublicKey, ed25519.PrivateKey) {
	pubKey, privKey, err := ed25519.GenerateKey(nil)

	if err != nil {
		panic(err)
	}

	return pubKey, privKey
}

func Sign(privKey ed25519.PrivateKey, msg []byte) []byte {
	return ed25519.Sign(privKey, msg)
}

func Verify(pubKey ed25519.PublicKey, msg []byte, signature []byte) bool {
	return ed25519.Verify(pubKey, msg, signature)
}
