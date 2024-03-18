package dilithium2aes

import (
	"github.com/cloudflare/circl/sign/dilithium/mode2aes"
)

func Generate() (*mode2aes.PublicKey, *mode2aes.PrivateKey) {
	pubKey, privKey, err := mode2aes.GenerateKey(nil)

	if err != nil {
		panic(err)
	}

	return pubKey, privKey
}

func Sign(privKey *mode2aes.PrivateKey, msg []byte) []byte {
	signature := make([]byte, mode2aes.SignatureSize)
	mode2aes.SignTo(privKey, msg, signature)
	return signature
}

func Verify(pubKey *mode2aes.PublicKey, msg []byte, signature []byte) bool {
	return mode2aes.Verify(pubKey, msg, signature)
}

func BytesToPrivateKey(b []byte) (*mode2aes.PrivateKey, error) {
	var privKey mode2aes.PrivateKey
	err := privKey.UnmarshalBinary(b)
	if err != nil {
		return nil, err
	}
	return &privKey, nil
}

func BytesToPublicKey(b []byte) (*mode2aes.PublicKey, error) {
	var pubKey mode2aes.PublicKey
	err := pubKey.UnmarshalBinary(b)
	if err != nil {
		return nil, err
	}
	return &pubKey, nil
}
