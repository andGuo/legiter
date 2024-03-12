package ed448

import (
	"github.com/cloudflare/circl/sign/ed448"
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

func SignPh(privKey ed448.PrivateKey, msg []byte, ctx string) []byte {
	return ed448.SignPh(privKey, msg, ctx)
}

func Verify(pubKey ed448.PublicKey, msg []byte, signature []byte) bool {
	return ed448.Verify(pubKey, msg, signature, "")
}

func VerifyPh(pubKey ed448.PublicKey, msg []byte, signature []byte, ctx string) bool {
	return ed448.VerifyPh(pubKey, msg, signature, ctx)
}
