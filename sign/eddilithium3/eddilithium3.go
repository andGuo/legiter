package eddilithium3

import (
	"legiter/signer"

	"github.com/cloudflare/circl/sign/eddilithium3"
)

// Implement the Signer interface
type Eddilithium3 struct{}

func Signer() signer.Signer {
	return &Eddilithium3{}
}

func (*Eddilithium3) Name() string {
	return "ed448_dilithium3"
}

func (*Eddilithium3) Generate() ([]byte, []byte) {
	pub, priv := Generate()
	return pub.Bytes(), priv.Bytes()
}

func (*Eddilithium3) Sign(privateKey interface{}, fileBytes []byte) []byte {
	privKey := privateKey.(*eddilithium3.PrivateKey)
	return Sign(privKey, fileBytes)
}

func (*Eddilithium3) Verify(publicKey interface{}, fileBytes []byte, signature []byte) bool {
	pubKey := publicKey.(*eddilithium3.PublicKey)
	return Verify(pubKey, fileBytes, signature)
}

func (*Eddilithium3) BytesToPrivateKey(keyBytes []byte) (interface{}, error) {
	return BytesToPrivateKey(keyBytes)
}

func (*Eddilithium3) BytesToPublicKey(keyBytes []byte) (interface{}, error) {
	return BytesToPublicKey(keyBytes)
}

func Generate() (*eddilithium3.PublicKey, *eddilithium3.PrivateKey) {
	pubKey, privKey, err := eddilithium3.GenerateKey(nil)

	if err != nil {
		panic(err)
	}

	return pubKey, privKey
}

func Sign(privKey *eddilithium3.PrivateKey, msg []byte) []byte {
	signature := make([]byte, eddilithium3.SignatureSize)
	eddilithium3.SignTo(privKey, msg, signature)
	return signature
}

func Verify(pubKey *eddilithium3.PublicKey, msg []byte, signature []byte) bool {
	return eddilithium3.Verify(pubKey, msg, signature)
}

func BytesToPrivateKey(b []byte) (*eddilithium3.PrivateKey, error) {
	var privKey eddilithium3.PrivateKey
	err := privKey.UnmarshalBinary(b)
	if err != nil {
		return nil, err
	}
	return &privKey, nil
}

func BytesToPublicKey(b []byte) (*eddilithium3.PublicKey, error) {
	var pubKey eddilithium3.PublicKey
	err := pubKey.UnmarshalBinary(b)
	if err != nil {
		return nil, err
	}
	return &pubKey, nil
}
