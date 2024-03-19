package dilithium3

import (
	"legiter/signer"

	"github.com/cloudflare/circl/sign/dilithium/mode3"
)

// Implement the Signer interface
type Dilithium3 struct{}

func Signer() signer.Signer {
	return &Dilithium3{}
}

func (*Dilithium3) Name() string {
	return "dilithium3"
}

func (*Dilithium3) Generate() ([]byte, []byte) {
	pub, priv := Generate()
	return pub.Bytes(), priv.Bytes()
}

func (*Dilithium3) Sign(privateKey interface{}, fileBytes []byte) []byte {
	privKey := privateKey.(*mode3.PrivateKey)
	return Sign(privKey, fileBytes)
}

func (*Dilithium3) Verify(publicKey interface{}, fileBytes []byte, signature []byte) bool {
	pubKey := publicKey.(*mode3.PublicKey)
	return Verify(pubKey, fileBytes, signature)
}

func (*Dilithium3) BytesToPrivateKey(keyBytes []byte) (interface{}, error) {
	return BytesToPrivateKey(keyBytes)
}

func (*Dilithium3) BytesToPublicKey(keyBytes []byte) (interface{}, error) {
	return BytesToPublicKey(keyBytes)
}

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
