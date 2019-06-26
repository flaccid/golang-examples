package main

import (
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"strings"
	"time"

	"github.com/davecgh/go-spew/spew"
	"github.com/hashicorp/vault/api"
)

var (
	prefix      = "/secret"
	secretCount = 0
)

func listSecrets(client *api.Client, path string) {
	secretsList, err := client.Logical().List(path)
	if err != nil {
		log.Fatal(err)
	}

	for _, v := range secretsList.Data["keys"].([]interface{}) {
		secret, err := client.Logical().Read(path + v.(string))
		if err != nil {
			log.Fatal(err)
		}

		if !strings.HasSuffix(v.(string), "/") {
			secretPath := strings.Replace(path+"/"+v.(string), "//", "/", -1)
			log.Println(secretPath)
			spew.Dump(secret)
			secretCount++
		} else {
			listSecrets(client, path+"/"+v.(string))
		}
	}
}

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

	start := time.Now()
	log.Println("starting from " + prefix)
	listSecrets(client, prefix)
	elapsed := time.Since(start)
	log.Printf("dumped %v secrets in %s", secretCount, elapsed)
}
