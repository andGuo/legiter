package dilithium2

import (
	"legiter/signer"

	"github.com/cloudflare/circl/sign/dilithium/mode2"
)

// Implement the Signer interface
type Dilithium2 struct{}

func Signer() signer.Signer {
	return &Dilithium2{}
}

func (*Dilithium2) Name() string {
	return "dilithium2"
}

func (*Dilithium2) Generate() ([]byte, []byte) {
	pub, priv := Generate()
	return pub.Bytes(), priv.Bytes()
}

func (*Dilithium2) Sign(privateKey interface{}, fileBytes []byte) []byte {
	privKey := privateKey.(*mode2.PrivateKey)
	return Sign(privKey, fileBytes)
}

func (*Dilithium2) Verify(publicKey interface{}, fileBytes []byte, signature []byte) bool {
	pubKey := publicKey.(*mode2.PublicKey)
	return Verify(pubKey, fileBytes, signature)
}

func (*Dilithium2) BytesToPrivateKey(keyBytes []byte) (interface{}, error) {
	return BytesToPrivateKey(keyBytes)
}

func (*Dilithium2) BytesToPublicKey(keyBytes []byte) (interface{}, error) {
	return BytesToPublicKey(keyBytes)
}

func Generate() (*mode2.PublicKey, *mode2.PrivateKey) {
	pubKey, privKey, err := mode2.GenerateKey(nil)

	if err != nil {
		panic(err)
	}

	return pubKey, privKey
}

func Sign(privKey *mode2.PrivateKey, msg []byte) []byte {
	signature := make([]byte, mode2.SignatureSize)
	mode2.SignTo(privKey, msg, signature)
	return signature
}

func Verify(pubKey *mode2.PublicKey, msg []byte, signature []byte) bool {
	return mode2.Verify(pubKey, msg, signature)
}

func BytesToPrivateKey(b []byte) (*mode2.PrivateKey, error) {
	var privKey mode2.PrivateKey
	err := privKey.UnmarshalBinary(b)
	if err != nil {
		return nil, err
	}
	return &privKey, nil
}

func BytesToPublicKey(b []byte) (*mode2.PublicKey, error) {
	var pubKey mode2.PublicKey
	err := pubKey.UnmarshalBinary(b)
	if err != nil {
		return nil, err
	}
	return &pubKey, nil
}
