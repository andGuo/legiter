package ed448

import (
	"legiter/signer"

	"github.com/cloudflare/circl/sign/ed448"
)

// Implement the Signer interface
type Ed448 struct{}

func Signer() signer.Signer {
	return &Ed448{}
}

func (*Ed448) Name() string {
	return "ed448"
}

func (*Ed448) Generate() ([]byte, []byte) {
	pub, priv := Generate()
	return pub, priv
}

func (*Ed448) Sign(privateKey interface{}, fileBytes []byte) []byte {
	privKey := privateKey.(*ed448.PrivateKey)
	return Sign(privKey, fileBytes)
}

func (*Ed448) Verify(publicKey interface{}, fileBytes []byte, signature []byte) bool {
	pubKey := publicKey.(*ed448.PublicKey)
	return Verify(pubKey, fileBytes, signature)
}

func (*Ed448) BytesToPrivateKey(keyBytes []byte) (interface{}, error) {
	return BytesToPrivateKey(keyBytes)
}

func (*Ed448) BytesToPublicKey(keyBytes []byte) (interface{}, error) {
	return BytesToPublicKey(keyBytes)
}

func Generate() (ed448.PublicKey, ed448.PrivateKey) {
	pubKey, privKey, err := ed448.GenerateKey(nil)

	if err != nil {
		panic(err)
	}

	return pubKey, privKey
}

func Sign(privKey *ed448.PrivateKey, msg []byte) []byte {
	return ed448.Sign(*privKey, msg, "")
}

func Verify(pubKey *ed448.PublicKey, msg []byte, signature []byte) bool {
	return ed448.Verify(*pubKey, msg, signature, "")
}

func BytesToPrivateKey(b []byte) (*ed448.PrivateKey, error) {
	privKey := ed448.PrivateKey(b)
	return &privKey, nil
}

func BytesToPublicKey(b []byte) (*ed448.PublicKey, error) {
	pubKey := ed448.PublicKey(b)
	return &pubKey, nil
}
