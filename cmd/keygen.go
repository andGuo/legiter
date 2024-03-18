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

	"github.com/spf13/cobra"
)

// keygenCmd represents the keygen command
var keygenCmd = &cobra.Command{
	Use:   "keygen",
	Short: "Generate a public/private key pair for a specified digital signature algorithm",
	Long: `
	Generate a public/private key pair for a specified digital signature algorithm.
	The key pair will be written to a file specified by the --filename (-f) flag.

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
	Run: keygen,
}

func checkKeygenError(err error) {
	if err != nil {
		fmt.Println("Error writing key pair to file:", err)
	}
}

func keygen(cmd *cobra.Command, args []string) {
	switch algorithm {
	case "ed25519":
		fmt.Println("Generating Ed25519 key pair")
		pubKey, privKey := ed25519.Generate()
		err := sign.WriteKeyPairToFile(pubKey, privKey, filename, "ed25519")
		checkKeygenError(err)
	case "ed448":
		fmt.Println("Generating Ed448 key pair")
		pubKey, privKey := ed448.Generate()
		err := sign.WriteKeyPairToFile(pubKey, privKey, filename, "ed448")
		checkKeygenError(err)
	case "dilithium2":
		fmt.Println("Generating Dilithium2 key pair")
		pubKey, privKey := dilithium2.Generate()
		err := sign.WriteKeyPairToFile(pubKey.Bytes(), privKey.Bytes(), filename, "dilithium2")
		checkKeygenError(err)
	case "dilithium3":
		fmt.Println("Generating Dilithium3 key pair")
		pubKey, privKey := dilithium3.Generate()
		err := sign.WriteKeyPairToFile(pubKey.Bytes(), privKey.Bytes(), filename, "dilithium3")
		checkKeygenError(err)
	case "dilithium2_aes":
		fmt.Println("Generating Dilithium2-AES key pair")
		pubKey, privKey := dilithium2aes.Generate()
		err := sign.WriteKeyPairToFile(pubKey.Bytes(), privKey.Bytes(), filename, "dilithium2_aes")
		checkKeygenError(err)
	case "dilithium3_aes":
		fmt.Println("Generating Dilithium3-AES key pair")
		pubKey, privKey := dilithium3aes.Generate()
		err := sign.WriteKeyPairToFile(pubKey.Bytes(), privKey.Bytes(), filename, "dilithium3_aes")
		checkKeygenError(err)
	case "ed25519_dilithium2":
		fmt.Println("Generating Ed25519-Dilithium2 key pair")
		pubKey, privKey := eddilithium2.Generate()
		err := sign.WriteKeyPairToFile(pubKey.Bytes(), privKey.Bytes(), filename, "ed25519_dilithium2")
		checkKeygenError(err)
	case "ed448_dilithium3":
		fmt.Println("Generating Ed448-Dilithium3 key pair")
		pubKey, privKey := eddilithium3.Generate()
		err := sign.WriteKeyPairToFile(pubKey.Bytes(), privKey.Bytes(), filename, "ed448_dilithium3")
		checkKeygenError(err)
	default:
		fmt.Println("ERROR - Unsupported algorithm:", algorithm)
		cmd.Help()
	}
}

func init() {
	rootCmd.AddCommand(keygenCmd)

	keygenCmd.Flags().StringVarP(&filename, "filename", "f", "", "The name of the file to write the public/private key pair to")
	keygenCmd.Flags().StringVarP(&algorithm, "algorithm", "a", "ed448_dilithium3", "The type of digital signature algorithm to use")
	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// keygenCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// keygenCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}
