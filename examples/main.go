package main

import (
	"fmt"
	"net/http"

	"github.com/hashicorp/vault/api"

	hlpr "github.com/petems/vault-cert-helpers"
)

func createVaultClient() *api.Client {

	// Create an HTTP client and inject our transport
	client := &http.Client{}

	// Create Vault client with vcr'd http.Client
	vaultClient, err := api.NewClient(&api.Config{Address: "http://127.0.0.1:8200", HttpClient: client})
	if err != nil {
		panic("Failed to get new Vault client")
	}

	// We're using VAULT_DEV_ROOT_TOKEN_ID=ROOT with a vault server -dev
	vaultClient.SetToken("ROOT")

	return vaultClient
}

func main() {

	vaultClient := createVaultClient()

	// Get list of certs from /pki endpoint
	listOfCertsSecret, err := hlpr.GetListOfCerts(vaultClient, "pki")

	if err != nil {
		panic(err)
	}

	arrayOfCerts, err := hlpr.GetArrayOfCertsFromVault(vaultClient, listOfCertsSecret, "pki")

	if err != nil {
		panic(err)
	}

	fmt.Printf("First cert CN is: %s\n", arrayOfCerts[0].Subject.CommonName)
	fmt.Printf("Second cert CN is: %s\n", arrayOfCerts[1].Subject.CommonName)

}
