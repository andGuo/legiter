package dilithium3

import (
	"github.com/cloudflare/circl/sign/dilithium/mode3"
)

func Generate() (*mode3.PublicKey, *mode3.PrivateKey) {
	pubKey, privKey, err := mode3.GenerateKey(nil)

	if err != nil {
		panic(err)
	}

	return pubKey, privKey
}

func Sign(privKey *mode3.PrivateKey, msg []byte) []byte {
	signature := make([]byte, mode3.SignatureSize)
	mode3.SignTo(privKey, msg, signature)
	return signature
}

func Verify(pubKey *mode3.PublicKey, msg []byte, signature []byte) bool {
	return mode3.Verify(pubKey, msg, signature)
}

func BytesToPrivateKey(b []byte) (*mode3.PrivateKey, error) {
	var privKey mode3.PrivateKey
	err := privKey.UnmarshalBinary(b)
	if err != nil {
		return nil, err
	}
	return &privKey, nil
}

func BytesToPublicKey(b []byte) (*mode3.PublicKey, error) {
	var pubKey mode3.PublicKey
	err := pubKey.UnmarshalBinary(b)
	if err != nil {
		return nil, err
	}
	return &pubKey, nil
}
