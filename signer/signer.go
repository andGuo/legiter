package signer

type Signer interface {
	Generate() ([]byte, []byte)
	Sign(privKey interface{}, msg []byte) []byte
	Verify(pubKey interface{}, msg []byte, signature []byte) bool
	BytesToPrivateKey(b []byte) (interface{}, error)
	BytesToPublicKey(b []byte) (interface{}, error)
	Name() string
}
