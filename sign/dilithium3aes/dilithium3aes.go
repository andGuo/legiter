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
	signature := make([]byte, mode3aes.SignatureSize)
	mode3aes.SignTo(privKey, msg, signature)
	return signature
}

func Verify(pubKey *mode3aes.PublicKey, msg []byte, signature []byte) bool {
	return mode3aes.Verify(pubKey, msg, signature)
}

func BytesToPrivateKey(b []byte) (*mode3aes.PrivateKey, error) {
	var privKey mode3aes.PrivateKey
	err := privKey.UnmarshalBinary(b)
	if err != nil {
		return nil, err
	}
	return &privKey, nil
}

func BytesToPublicKey(b []byte) (*mode3aes.PublicKey, error) {
	var pubKey mode3aes.PublicKey
	err := pubKey.UnmarshalBinary(b)
	if err != nil {
		return nil, err
	}
	return &pubKey, nil
}
