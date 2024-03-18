/*
Copyright © 2024 NAME HERE <EMAIL ADDRESS>
*/
package cmd

import (
	"fmt"
	"legiter/sign"
	"legiter/sign/dilithium2"
	"legiter/sign/dilithium2aes"
	"legiter/sign/dilithium3"
	"legiter/sign/dilithium3aes"
	"legiter/sign/ed25519"
	"legiter/sign/ed448"
	"legiter/sign/eddilithium2"
	"legiter/sign/eddilithium3"
	"strings"

	"github.com/spf13/cobra"
)

// verifyCmd represents the verify command
var verifyCmd = &cobra.Command{
	Use:   "verify <filename>",
	Short: "Verifies a file using a digital signature algorithm and a public key",
	Long: `
	Verifies a file using a digital signature algorithm and a public key. The digital signature of the file must be provided using the --signature (-s) flag. The public key to use for verification must be provided using the --key (-k) flag. The supported algorithms are:
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
	Run:  verifier,
}

// TODO: Refactor this using interfaces
func verifier(cmd *cobra.Command, args []string) {
	fmt.Printf("Verifying file (%s) using public key (%s)\n", args[0], pubKeyFilename)

	keyBytes, keyType, err := sign.GetPubKey(pubKeyFilename)
	if err != nil {
		fmt.Println("Error reading public key:", err)
		return
	}

	switch strings.ToLower(keyType) {
	case "ed25519":
		pubKey, err := ed25519.BytesToPublicKey(keyBytes)
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
		isLegit := ed25519.Verify(pubKey, fileBytes, sigBytes)
		if isLegit {
			fmt.Println("The file is legitimate ✅")
		} else {
			fmt.Println("The file is not legitimate 🚫")
		}
	case "ed448":
		pubKey, err := ed448.BytesToPublicKey(keyBytes)
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
		isLegit := ed448.Verify(pubKey, fileBytes, sigBytes)
		if isLegit {
			fmt.Println("The file is legitimate ✅")
		} else {
			fmt.Println("The file is not legitimate 🚫")
		}
	case "dilithium2":
		pubKey, err := dilithium2.BytesToPublicKey(keyBytes)
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
		isLegit := dilithium2.Verify(pubKey, fileBytes, sigBytes)
		if isLegit {
			fmt.Println("The file is legitimate ✅")
		} else {
			fmt.Println("The file is not legitimate 🚫")
		}
	case "dilithium3":
		pubKey, err := dilithium3.BytesToPublicKey(keyBytes)
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
		isLegit := dilithium3.Verify(pubKey, fileBytes, sigBytes)
		if isLegit {
			fmt.Println("The file is legitimate ✅")
		} else {
			fmt.Println("The file is not legitimate 🚫")
		}
	case "dilithium2_aes":
		pubKey, err := dilithium2aes.BytesToPublicKey(keyBytes)
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
		isLegit := dilithium2aes.Verify(pubKey, fileBytes, sigBytes)
		if isLegit {
			fmt.Println("The file is legitimate ✅")
		} else {
			fmt.Println("The file is not legitimate 🚫")
		}
	case "dilithium3_aes":
		pubKey, err := dilithium3aes.BytesToPublicKey(keyBytes)
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
		isLegit := dilithium3aes.Verify(pubKey, fileBytes, sigBytes)
		if isLegit {
			fmt.Println("The file is legitimate ✅")
		} else {
			fmt.Println("The file is not legitimate 🚫")
		}
	case "ed25519_dilithium2":
		pubKey, err := eddilithium2.BytesToPublicKey(keyBytes)
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
		isLegit := eddilithium2.Verify(pubKey, fileBytes, sigBytes)
		if isLegit {
			fmt.Println("The file is legitimate ✅")
		} else {
			fmt.Println("The file is not legitimate 🚫")
		}
	case "ed448_dilithium3":
		pubKey, err := eddilithium3.BytesToPublicKey(keyBytes)
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
		isLegit := eddilithium3.Verify(pubKey, fileBytes, sigBytes)
		if isLegit {
			fmt.Println("The file is legitimate ✅")
		} else {
			fmt.Println("The file is not legitimate 🚫")
		}
	default:
		fmt.Println("ERROR - Unsupported algorithm:", keyType)
		cmd.Help()
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

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// verifyCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// verifyCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}
