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
	signer, err := sign.GetSigner(algorithm)
	if err != nil {
		fmt.Println("Error:", err)
		cmd.Help()
		return
	}

	pubKey, privKey := signer.Generate()
	err = sign.WriteKeyPairToFile(pubKey, privKey, filename, algorithm)
	checkKeygenError(err)
}

var filename string
var algorithm string

func init() {
	rootCmd.AddCommand(keygenCmd)

	keygenCmd.Flags().StringVarP(&filename, "filename", "f", "", "The name of the file to write the public/private key pair to")
	keygenCmd.Flags().StringVarP(&algorithm, "algorithm", "a", "", "The type of digital signature algorithm to use")
	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// keygenCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// keygenCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}
