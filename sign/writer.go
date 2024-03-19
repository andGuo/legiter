package sign

import (
	"encoding/pem"
	"fmt"
	"os"
	"path"
	"strings"
)

func genPemPubKey(pubKey []byte, algorithm string) []byte {
	typeString := fmt.Sprintf("%s PUBLIC KEY", strings.ToUpper(algorithm))
	return pem.EncodeToMemory(&pem.Block{
		Type:  typeString,
		Bytes: pubKey,
	})
}

func genPemPrivKey(privKey []byte, algorithm string) []byte {
	typeString := fmt.Sprintf("%s PRIVATE KEY", strings.ToUpper(algorithm))
	return pem.EncodeToMemory(&pem.Block{
		Type:  typeString,
		Bytes: privKey,
	})
}

func getFilepath(filename string, defaultStr string) (string, error) {
	fpath, fname := path.Split(filename)

	if fname == "" {
		fname = defaultStr
	}

	if fpath != "" {
		if _, err := os.Stat(fpath); os.IsNotExist(err) {
			err := os.MkdirAll(fpath, 0700)
			if err != nil {
				return "", err
			}
		}
	} else {
		fpath = "."
	}

	return fpath + "/" + fname, nil
}

func WriteKeyPairToFile(pubKey []byte, privKey []byte, filename string, algorithm string) error {
	path, err := getFilepath(filename, algorithm)
	if err != nil {
		return err
	}

	err = os.WriteFile(path+".pem", genPemPubKey(pubKey, algorithm), 0644)
	if err != nil {
		return err
	}

	err = os.WriteFile(path+".key", genPemPrivKey(privKey, algorithm), 0644)
	if err != nil {
		return err
	}

	return nil
}

func WriteSignatureToFile(signature []byte, filename string) error {
	err := os.WriteFile(filename+".sig", signature, 0644)
	if err != nil {
		return err
	}

	return nil
}
