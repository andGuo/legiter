/*
Copyright © 2024 NAME HERE <EMAIL ADDRESS>
*/
package cmd

import (
	"fmt"

	"legiter/sign"

	"github.com/spf13/cobra"
)

// keygenCmd represents the keygen command
var keygenCmd = &cobra.Command{
	Use:   "keygen",
	Short: "Generate a public/private key pair for a specified digital signature algorithm",
	Long: `
	Generate a public/private key pair for a specified digital signature algorithm.
	The key pair will be written to a file specified by the --output (-o) flag.

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
	signer, err := sign.GetSigner(algorithm)
	if err != nil {
		fmt.Println("Error:", err)
		_ = cmd.Help()
		return
	}

	fmt.Printf("Generating key pair using algorithm: %s\n", signer.Name())
	pubKey, privKey := signer.Generate()
	err = sign.WriteKeyPairToFile(pubKey, privKey, output, algorithm)
	checkKeygenError(err)
}

var output string
var algorithm string

func init() {
	rootCmd.AddCommand(keygenCmd)

	keygenCmd.Flags().StringVarP(&output, "output", "o", "", "The name of the output file(s) to write the public/private key pair to")
	_ = keygenCmd.MarkFlagRequired("output")
	keygenCmd.Flags().StringVarP(&algorithm, "algorithm", "a", "ed448_dilithium3", "The type of digital signature algorithm to use")
}
