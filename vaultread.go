package main

import (
	"fmt"
	"io/ioutil"
	"log"
	"os"

	"github.com/hashicorp/vault/api"
)

// requires a token at ~/.vault-token
// requires a secret at secret/path/to/secret
// requires vault endpoint in env var, VAULT_ADDR
func main() {
	vaultAddr := os.Getenv("VAULT_ADDR")
	keyName := "secret/path/to/secret"
	homeDir, err := os.UserHomeDir()
	if err != nil {
		log.Fatalf("unable to detect home directory", err)
	}

	data, err := ioutil.ReadFile(homeDir + "/.vault-token")
	if err != nil {
		log.Fatalf("file reading error", err)
	}
	token := string(data)

	client, err := api.NewClient(&api.Config{
		Address: vaultAddr,
	})
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(client)

	client.SetToken(token)

	secretValues, err := client.Logical().Read(keyName)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("secret %s -> %v", keyName, secretValues)
}
