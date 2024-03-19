package ed25519

import (
	"legiter/signer"

	"github.com/cloudflare/circl/sign/ed25519"
)

// Implement the Signer interface
type Ed25519 struct{}

func Signer() signer.Signer {
	return &Ed25519{}
}

func (*Ed25519) Name() string {
	return "ed25519"
}

func (*Ed25519) Generate() ([]byte, []byte) {
	pub, priv := Generate()
	return pub, priv
}

func (*Ed25519) Sign(privateKey interface{}, fileBytes []byte) []byte {
	privKey := privateKey.(*ed25519.PrivateKey)
	return Sign(privKey, fileBytes)
}

func (*Ed25519) Verify(publicKey interface{}, fileBytes []byte, signature []byte) bool {
	pubKey := publicKey.(*ed25519.PublicKey)
	return Verify(pubKey, fileBytes, signature)
}

func (*Ed25519) BytesToPrivateKey(keyBytes []byte) (interface{}, error) {
	return BytesToPrivateKey(keyBytes)
}

func (*Ed25519) BytesToPublicKey(keyBytes []byte) (interface{}, error) {
	return BytesToPublicKey(keyBytes)
}

func Generate() (ed25519.PublicKey, ed25519.PrivateKey) {
	pubKey, privKey, err := ed25519.GenerateKey(nil)

	if err != nil {
		panic(err)
	}

	return pubKey, privKey
}

func Sign(privKey *ed25519.PrivateKey, msg []byte) []byte {
	return ed25519.Sign(*privKey, msg)
}

func Verify(pubKey *ed25519.PublicKey, msg []byte, signature []byte) bool {
	return ed25519.Verify(*pubKey, msg, signature)
}

func BytesToPrivateKey(b []byte) (*ed25519.PrivateKey, error) {
	privKey := ed25519.PrivateKey(b)
	return &privKey, nil
}

func BytesToPublicKey(b []byte) (*ed25519.PublicKey, error) {
	pubKey := ed25519.PublicKey(b)
	return &pubKey, nil
}
