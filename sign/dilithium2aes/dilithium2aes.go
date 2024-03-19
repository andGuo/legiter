package dilithium2aes

import (
	"legiter/signer"

	"github.com/cloudflare/circl/sign/dilithium/mode2aes"
)

// Implement the Signer interface
type Dilithium2aes struct{}

func Signer() signer.Signer {
	return &Dilithium2aes{}
}

func (*Dilithium2aes) Name() string {
	return "dilithium2_aes"
}

func (*Dilithium2aes) Generate() ([]byte, []byte) {
	pub, priv := Generate()
	return pub.Bytes(), priv.Bytes()
}

func (*Dilithium2aes) Sign(privateKey interface{}, fileBytes []byte) []byte {
	privKey := privateKey.(*mode2aes.PrivateKey)
	return Sign(privKey, fileBytes)
}

func (*Dilithium2aes) Verify(publicKey interface{}, fileBytes []byte, signature []byte) bool {
	pubKey := publicKey.(*mode2aes.PublicKey)
	return Verify(pubKey, fileBytes, signature)
}

func (*Dilithium2aes) BytesToPrivateKey(keyBytes []byte) (interface{}, error) {
	return BytesToPrivateKey(keyBytes)
}

func (*Dilithium2aes) BytesToPublicKey(keyBytes []byte) (interface{}, error) {
	return BytesToPublicKey(keyBytes)
}

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
