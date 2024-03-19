package sign

import (
	"fmt"
	"legiter/sign/dilithium2"
	"legiter/sign/dilithium2aes"
	"legiter/sign/dilithium3"
	"legiter/sign/dilithium3aes"
	"legiter/sign/ed25519"
	"legiter/sign/ed448"
	"legiter/sign/eddilithium2"
	"legiter/sign/eddilithium3"
	"legiter/signer"
)

func GetSigner(keyType string) (signer.Signer, error) {
	switch keyType {
	case "ed25519":
		return ed25519.Signer(), nil
	case "ed448":
		return ed448.Signer(), nil
	case "dilithium2":
		return dilithium2.Signer(), nil
	case "dilithium3":
		return dilithium3.Signer(), nil
	case "dilithium2_aes":
		return dilithium2aes.Signer(), nil
	case "dilithium3_aes":
		return dilithium3aes.Signer(), nil
	case "ed25519_dilithium2":
		return eddilithium2.Signer(), nil
	case "ed448_dilithium3":
		return eddilithium3.Signer(), nil
	default:
		return nil, fmt.Errorf("Unsupported algorithm: %s", keyType)
	}
}
