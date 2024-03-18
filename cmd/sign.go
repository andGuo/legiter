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

// signCmd represents the sign command
var signCmd = &cobra.Command{
	Use:   "sign <filename>",
	Short: "Signs a file using a digital signature algorithm and a private key",
	Long: `
	Signs a file using a digital signature algorithm and a private key. The supported algorithms are:
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
	Run:  signer,
}

// TODO: Refactor this using interfaces
func signer(cmd *cobra.Command, args []string) {
	fmt.Printf("Signing file (%s) using private key (%s)\n", args[0], privKeyFilename)

	keyBytes, keyType, err := sign.GetPrivKey(privKeyFilename)
	if err != nil {
		fmt.Println("Error reading private key:", err)
		return
	}

	switch strings.ToLower(keyType) {
	case "ed25519":
		privKey, err := ed25519.BytesToPrivateKey(keyBytes)
		if err != nil {
			fmt.Println("Error converting private key:", err)
		}
		fileBytes, err := sign.ReadFile(args[0])
		if err != nil {
			fmt.Println("Error reading file:", err)
			return
		}
		signature := ed25519.Sign(privKey, fileBytes)
		err = sign.WriteSignatureToFile(signature, args[0])
		if err != nil {
			fmt.Println("Error writing signature to file:", err)
		}
	case "ed448":
		privKey, err := ed448.BytesToPrivateKey(keyBytes)
		if err != nil {
			fmt.Println("Error converting private key:", err)
		}
		fileBytes, err := sign.ReadFile(args[0])
		if err != nil {
			fmt.Println("Error reading file:", err)
			return
		}
		signature := ed448.Sign(privKey, fileBytes)
		err = sign.WriteSignatureToFile(signature, args[0])
		if err != nil {
			fmt.Println("Error writing signature to file:", err)
		}
	case "dilithium2":
		privKey, err := dilithium2.BytesToPrivateKey(keyBytes)
		if err != nil {
			fmt.Println("Error converting private key:", err)
		}
		fileBytes, err := sign.ReadFile(args[0])
		if err != nil {
			fmt.Println("Error reading file:", err)
			return
		}
		signature := dilithium2.Sign(privKey, fileBytes)
		err = sign.WriteSignatureToFile(signature, args[0])
		if err != nil {
			fmt.Println("Error writing signature to file:", err)
		}
	case "dilithium3":
		privKey, err := dilithium3.BytesToPrivateKey(keyBytes)
		if err != nil {
			fmt.Println("Error converting private key:", err)
		}
		fileBytes, err := sign.ReadFile(args[0])
		if err != nil {
			fmt.Println("Error reading file:", err)
			return
		}
		signature := dilithium3.Sign(privKey, fileBytes)
		err = sign.WriteSignatureToFile(signature, args[0])
		if err != nil {
			fmt.Println("Error writing signature to file:", err)
		}
	case "dilithium2_aes":
		privKey, err := dilithium2aes.BytesToPrivateKey(keyBytes)
		if err != nil {
			fmt.Println("Error converting private key:", err)
		}
		fileBytes, err := sign.ReadFile(args[0])
		if err != nil {
			fmt.Println("Error reading file:", err)
			return
		}
		signature := dilithium2aes.Sign(privKey, fileBytes)
		err = sign.WriteSignatureToFile(signature, args[0])
		if err != nil {
			fmt.Println("Error writing signature to file:", err)
		}
	case "dilithium3_aes":
		privKey, err := dilithium3aes.BytesToPrivateKey(keyBytes)
		if err != nil {
			fmt.Println("Error converting private key:", err)
		}
		fileBytes, err := sign.ReadFile(args[0])
		if err != nil {
			fmt.Println("Error reading file:", err)
			return
		}
		signature := dilithium3aes.Sign(privKey, fileBytes)
		err = sign.WriteSignatureToFile(signature, args[0])
		if err != nil {
			fmt.Println("Error writing signature to file:", err)
		}
	case "ed25519_dilithium2":
		privKey, err := eddilithium2.BytesToPrivateKey(keyBytes)
		if err != nil {
			fmt.Println("Error converting private key:", err)
		}
		fileBytes, err := sign.ReadFile(args[0])
		if err != nil {
			fmt.Println("Error reading file:", err)
			return
		}
		signature := eddilithium2.Sign(privKey, fileBytes)
		err = sign.WriteSignatureToFile(signature, args[0])
		if err != nil {
			fmt.Println("Error writing signature to file:", err)
		}
	case "ed448_dilithium3":
		privKey, err := eddilithium3.BytesToPrivateKey(keyBytes)
		if err != nil {
			fmt.Println("Error converting private key:", err)
		}
		fileBytes, err := sign.ReadFile(args[0])
		if err != nil {
			fmt.Println("Error reading file:", err)
			return
		}
		signature := eddilithium3.Sign(privKey, fileBytes)
		err = sign.WriteSignatureToFile(signature, args[0])
		if err != nil {
			fmt.Println("Error writing signature to file:", err)
		}
	default:
		fmt.Println("ERROR - Unsupported algorithm:", keyType)
		cmd.Help()
	}
}

var privKeyFilename string

func init() {
	rootCmd.AddCommand(signCmd)

	signCmd.Flags().StringVarP(&privKeyFilename, "key", "k", "", "The file of the private key to use for signing")
	signCmd.MarkFlagRequired("key")
	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// signCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// signCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}
