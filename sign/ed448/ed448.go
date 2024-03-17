package ed448

import (
	"github.com/cloudflare/circl/sign/ed448"
)

const (
	PublicKeySize  = ed448.PublicKeySize
	PrivateKeySize = ed448.PrivateKeySize
	SignatureSize  = ed448.SignatureSize
)

func Generate() (ed448.PublicKey, ed448.PrivateKey) {
	pubKey, privKey, err := ed448.GenerateKey(nil)

	if err != nil {
		panic(err)
	}

	return pubKey, privKey
}

func Sign(privKey ed448.PrivateKey, msg []byte) []byte {
	return ed448.Sign(privKey, msg, "")
}

func Verify(pubKey ed448.PublicKey, msg []byte, signature []byte) bool {
	return ed448.Verify(pubKey, msg, signature, "")
}
