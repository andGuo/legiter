package dilithium3aes

import (
	"legiter/signer"

	"github.com/cloudflare/circl/sign/dilithium/mode3aes"
)

// Implement the Signer interface
type Dilithium3aes struct{}

func Signer() signer.Signer {
	return &Dilithium3aes{}
}

func (*Dilithium3aes) Name() string {
	return "dilithium3_aes"
}

func (*Dilithium3aes) Generate() ([]byte, []byte) {
	pub, priv := Generate()
	return pub.Bytes(), priv.Bytes()
}

func (*Dilithium3aes) Sign(privateKey interface{}, fileBytes []byte) []byte {
	privKey := privateKey.(*mode3aes.PrivateKey)
	return Sign(privKey, fileBytes)
}

func (*Dilithium3aes) Verify(publicKey interface{}, fileBytes []byte, signature []byte) bool {
	pubKey := publicKey.(*mode3aes.PublicKey)
	return Verify(pubKey, fileBytes, signature)
}

func (*Dilithium3aes) BytesToPrivateKey(keyBytes []byte) (interface{}, error) {
	return BytesToPrivateKey(keyBytes)
}

func (*Dilithium3aes) BytesToPublicKey(keyBytes []byte) (interface{}, error) {
	return BytesToPublicKey(keyBytes)
}

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
