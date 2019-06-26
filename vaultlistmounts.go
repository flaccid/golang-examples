package main

import (
	"fmt"
	"io/ioutil"
	"log"
	"os"

	"github.com/hashicorp/vault/api"
)

// requires a token at ~/.vault-token
// requires vault endpoint in env var, VAULT_ADDR
func main() {
	vaultAddr := os.Getenv("VAULT_ADDR")
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

	mountsList, err := client.Sys().ListMounts()
	if err != nil {
		log.Fatal(err)
	}

	for k, v := range mountsList {
		log.Printf("%v %v\n", k, v)
	}
}
