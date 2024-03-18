package eddilithium2

import (
	"github.com/cloudflare/circl/sign/eddilithium2"
)

func Generate() (*eddilithium2.PublicKey, *eddilithium2.PrivateKey) {
	pubKey, privKey, err := eddilithium2.GenerateKey(nil)

	if err != nil {
		panic(err)
	}

	return pubKey, privKey
}

func Sign(privKey *eddilithium2.PrivateKey, msg []byte) []byte {
	signature := make([]byte, eddilithium2.SignatureSize)
	eddilithium2.SignTo(privKey, msg, signature)
	return signature
}

func Verify(pubKey *eddilithium2.PublicKey, msg []byte, signature []byte) bool {
	return eddilithium2.Verify(pubKey, msg, signature)
}

func BytesToPrivateKey(b []byte) (*eddilithium2.PrivateKey, error) {
	var privKey eddilithium2.PrivateKey
	err := privKey.UnmarshalBinary(b)
	if err != nil {
		return nil, err
	}
	return &privKey, nil
}

func BytesToPublicKey(b []byte) (*eddilithium2.PublicKey, error) {
	var pubKey eddilithium2.PublicKey
	err := pubKey.UnmarshalBinary(b)
	if err != nil {
		return nil, err
	}
	return &pubKey, nil
}
