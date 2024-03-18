package sign

import (
	"encoding/pem"
	"fmt"
	"os"
	"strings"
)

func readPemKey(pemBytes []byte) ([]byte, string) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, ""
	}
	return block.Bytes, block.Type
}

func GetPubKey(filepath string) ([]byte, string, error) {
	return nil, "", fmt.Errorf("not implemented")
}

func GetPrivKey(filepath string) ([]byte, string, error) {
	pemBytes, err := os.ReadFile(filepath)
	if err != nil {
		return nil, "", err
	}

	keyBytes, pemType := readPemKey(pemBytes)
	if keyBytes == nil {
		return nil, "", fmt.Errorf("failed to decode PEM")
	}

	if !strings.Contains(pemType, "PRIVATE KEY") {
		return nil, "", fmt.Errorf("key type is not PRIVATE KEY")
	}

	keyType, found := strings.CutSuffix(pemType, "PRIVATE KEY")
	if !found {
		return nil, "", fmt.Errorf("failed to parse key type")
	}

	keyType = strings.TrimSpace(keyType)

	return keyBytes, keyType, nil
}

func ReadFile(filepath string) ([]byte, error) {
	return os.ReadFile(filepath)
}
