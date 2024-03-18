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

func Sign(privKey *ed448.PrivateKey, msg []byte) []byte {
	return ed448.Sign(*privKey, msg, "")
}

func Verify(pubKey *ed448.PublicKey, msg []byte, signature []byte) bool {
	return ed448.Verify(*pubKey, msg, signature, "")
}

func BytesToPrivateKey(b []byte) (*ed448.PrivateKey, error) {
	privKey := ed448.PrivateKey(b)
	return &privKey, nil
}

func BytesToPublicKey(b []byte) (*ed448.PublicKey, error) {
	pubKey := ed448.PublicKey(b)
	return &pubKey, nil
}
