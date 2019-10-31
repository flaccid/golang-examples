package main

import (
	"fmt"
	"log"
	"os"

	"github.com/hashicorp/vault/api"
)

// requires vault token in env var, VAULT_TOKEN
// requires vault endpoint in env var, VAULT_ADDR
func main() {
	vaultAddr := os.Getenv("VAULT_ADDR")
	vaultToken := os.Getenv("VAULT_TOKEN")

	client, err := api.NewClient(&api.Config{
		Address: vaultAddr,
	})
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(client)
	client.SetToken(vaultToken)

	res, err := client.Logical().Write("/secret/data/foo",
		map[string]interface{}{
			"data": map[string]interface{}{
				"foo": "bar",
			},
		},
	)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("secret written", res)
}
