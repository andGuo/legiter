/*
Copyright © 2024 NAME HERE <EMAIL ADDRESS>
*/
package cmd

import (
	"fmt"
	"strings"

	"legiter/sign"

	"github.com/spf13/cobra"
)

// verifyCmd represents the verify command
var verifyCmd = &cobra.Command{
	Use:   "verify <filename>",
	Short: "Verifies a file using a digital signature algorithm and a public key",
	Long: `
	Verifies a file using a digital signature algorithm and a public key. The digital signature of the file must be provided using the --signature (-s) flag. The public key to use for verification must be provided using the --key (-k) flag.
	
	The supported algorithms are:
	- ed25519
	- ed448
	- dilithium2
	- dilithium3
	- dilithium2_aes
	- dilithium3_aes
	- ed25519_dilithium2
	- ed448_dilithium3
`,
	Args: cobra.ExactArgs(1),
	Run:  verifying,
}

func verifying(cmd *cobra.Command, args []string) {
	fmt.Printf("Verifying file (%s) using public key (%s)\n", args[0], pubKeyFilename)

	keyBytes, keyType, err := sign.GetPubKey(pubKeyFilename)
	if err != nil {
		fmt.Println("Error reading public key:", err)
		return
	}

	signer, err := sign.GetSigner(strings.ToLower(keyType))
	if err != nil {
		fmt.Println("Error:", err)
		cmd.Help()
		return
	}

	pubKey, err := signer.BytesToPublicKey(keyBytes)
	if err != nil {
		fmt.Println("Error converting public key:", err)
	}
	fileBytes, err := sign.ReadFile(args[0])
	if err != nil {
		fmt.Println("Error reading file:", err)
		return
	}
	sigBytes, err := sign.ReadFile(signatureFilename)
	if err != nil {
		fmt.Println("Error reading signature file:", err)
		return
	}
	isLegit := signer.Verify(pubKey, fileBytes, sigBytes)
	if isLegit {
		fmt.Println("The file is legitimate ✅")
	} else {
		fmt.Println("The file is not legitimate 🚫; The file and/or the public key do not correspond to the given digital signature.")
	}
}

var signatureFilename string
var pubKeyFilename string

func init() {
	rootCmd.AddCommand(verifyCmd)

	verifyCmd.Flags().StringVarP(&pubKeyFilename, "key", "k", "", "The file of the public key to use for verification")
	verifyCmd.MarkFlagRequired("key")
	verifyCmd.Flags().StringVarP(&signatureFilename, "signature", "s", "", "The digital signature of the file")
	verifyCmd.MarkFlagRequired("signature")
}
