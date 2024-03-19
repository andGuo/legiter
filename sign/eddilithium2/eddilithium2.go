package eddilithium2

import (
	"legiter/signer"

	"github.com/cloudflare/circl/sign/eddilithium2"
)

// Implement the Signer interface
type Eddilithium2 struct{}

func Signer() signer.Signer {
	return &Eddilithium2{}
}

func (*Eddilithium2) Name() string {
	return "ed488_dilithium2"
}

func (*Eddilithium2) Generate() ([]byte, []byte) {
	pub, priv := Generate()
	return pub.Bytes(), priv.Bytes()
}

func (*Eddilithium2) Sign(privateKey interface{}, fileBytes []byte) []byte {
	privKey := privateKey.(*eddilithium2.PrivateKey)
	return Sign(privKey, fileBytes)
}

func (*Eddilithium2) Verify(publicKey interface{}, fileBytes []byte, signature []byte) bool {
	pubKey := publicKey.(*eddilithium2.PublicKey)
	return Verify(pubKey, fileBytes, signature)
}

func (*Eddilithium2) BytesToPrivateKey(keyBytes []byte) (interface{}, error) {
	return BytesToPrivateKey(keyBytes)
}

func (*Eddilithium2) BytesToPublicKey(keyBytes []byte) (interface{}, error) {
	return BytesToPublicKey(keyBytes)
}

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
