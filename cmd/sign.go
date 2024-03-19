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
	Run:  signing,
}

func signing(cmd *cobra.Command, args []string) {
	fmt.Printf("Signing file (%s) using private key (%s)\n", args[0], privKeyFilename)

	keyBytes, keyType, err := sign.GetPrivKey(privKeyFilename)
	if err != nil {
		fmt.Println("Error reading private key:", err)
		return
	}

	signer, err := sign.GetSigner(strings.ToLower(keyType))
	if err != nil {
		fmt.Println("Error:", err)
		cmd.Help()
		return
	}

	privKey, err := signer.BytesToPrivateKey(keyBytes)
	if err != nil {
		fmt.Println("Error converting private key:", err)
		return
	}

	fileBytes, err := sign.ReadFile(args[0])
	if err != nil {
		fmt.Println("Error reading file:", err)
		return
	}

	signature := signer.Sign(privKey, fileBytes)

	err = sign.WriteSignatureToFile(signature, args[0])
	if err != nil {
		fmt.Println("Error writing signature to file:", err)
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
