package vaultcerthelper

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"

	"github.com/hashicorp/vault/api"
)

// GetListOfCerts fetches the list of certs from a given pki backend
//   listOfCerts, err := GetListOfCerts(client, "pki")
func GetListOfCerts(client *api.Client, pkiPath string) (*api.Secret, error) {

	listOfCerts, err := client.Logical().List(fmt.Sprintf("%s/certs/", pkiPath))

	if err != nil {
		return nil, err
	}

	if listOfCerts == nil {
		return nil, fmt.Errorf("No certs found at %s/certs/", pkiPath)
	}

	return listOfCerts, nil
}

// GetArrayOfCertsFromVault iterates through a given list of keys from a vault secret
// and returns a slice of *x509.Certificate's from the PEM data
// 		arrayOfCerts, err := GetArrayOfCertsFromVault(client, secret, "pki")
func GetArrayOfCertsFromVault(client *api.Client, secret *api.Secret, pkiPath string) (arrayOfCerts []*x509.Certificate, err error) {

	if secret == nil {
		return nil, fmt.Errorf("Secret given was nil")
	}

	keys, ok := secret.Data["keys"].([]interface{})

	if !ok {
		return nil, fmt.Errorf("No keys data found in secret")
	}

	var certArray = []*x509.Certificate{}

	for _, key := range keys {
		secret, err := client.Logical().Read(fmt.Sprintf("%s/cert/%s", pkiPath, key))
		if err != nil {
			return nil, err
		}

		certParse, err := ParseCertFromVaultSecret(secret)

		if err != nil {
			return nil, err
		}

		certArray = append(certArray, certParse)

	}

	return certArray, err
}

// ParseCertFromVaultSecret parses the value from the "certificate" field
// in cert data from vault and returns a *x509.Certificate
// 	cert, err := ParseCertFromVaultSecret(secret)
func ParseCertFromVaultSecret(secret *api.Secret) (*x509.Certificate, error) {

	if secret == nil {
		return nil, fmt.Errorf("Secret is nil")
	}

	rawCert, ok := secret.Data["certificate"].(string)

	if !ok {
		return nil, fmt.Errorf("No certificate data found in secret")
	}

	block, _ := pem.Decode([]byte(rawCert))

	if block == nil {
		return nil, fmt.Errorf("failed to parse certificate PEM")
	}

	cert, err := x509.ParseCertificate(block.Bytes)

	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate from bytes")
	}

	return cert, nil
}
