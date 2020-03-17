package vaultcerthelper

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"os"
	"testing"

	"github.com/dnaeon/go-vcr/recorder"
	"github.com/hashicorp/vault/api"
	"github.com/stretchr/testify/assert"
)

func getVCRRecorder(t *testing.T, cassetteName string) *recorder.Recorder {

	// Set recording responses with env variable RECORDING
	envRecording, ok := os.LookupEnv("RECORDING")

	mode := recorder.ModeReplaying

	if ok {
		switch envRecording {
		case "false":
			t.Logf("[VCR] - Replay mode enabled")
			mode = recorder.ModeReplaying
		case "disabled", "disable":
			t.Logf("[VCR] - VCR disabled")
			mode = recorder.ModeDisabled
		case "true":
			t.Logf("[VCR] - Recording enabled")
			mode = recorder.ModeRecording
		default:
			t.Logf("[VCR] - Recording enabled")
			mode = recorder.ModeRecording
		}
	}

	filename := fmt.Sprintf("fixtures/%s", cassetteName)

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	rec, err := recorder.NewAsMode(
		filename,
		mode,
		transport,
	)
	if err != nil {
		t.Fatal(err)
	}
	return rec
}

func createVaultClient(t *testing.T, r *recorder.Recorder) *api.Client {

	// Create an HTTP client and inject our transport
	client := &http.Client{
		Transport: r, // Inject as transport!
	}

	// Create Vault client with vcr'd http.Client
	vaultClient, err := api.NewClient(&api.Config{Address: "http://127.0.0.1:8200", HttpClient: client})
	if err != nil {
		t.Fatalf("Failed to get new Vault client: %s", err)
	}

	// We're using VAULT_DEV_ROOT_TOKEN_ID=ROOT with a vault server -dev
	vaultClient.SetToken("ROOT")

	return vaultClient
}

func TestGetListOfCerts_TwoCerts(t *testing.T) {

	rec := getVCRRecorder(t, "pki_enabled_2_certs_exist")
	defer rec.Stop()

	vaultClient := createVaultClient(t, rec)

	listOfCertsSecret, err := GetListOfCerts(vaultClient, "pki")

	assert.NoError(t, err, "listOfCerts returned an error")

	if listOfCertsSecret == nil {
		t.Fatal("listOfCerts returned nil")
	}

	listOfCerts := listOfCertsSecret.Data["keys"].([]interface{})

	assert.Len(t, listOfCerts, 2)
	assert.Equal(t, "17-8d-25-c3-66-37-81-eb-64-c6-84-5c-46-5b-42-8b-fd-12-bf-1d", listOfCerts[0])
	assert.Equal(t, "2e-88-a1-89-5a-df-e1-e6-dd-57-e9-47-78-e1-74-24-73-a3-38-c2", listOfCerts[1])
}

func TestGetListOfCerts_NoCerts(t *testing.T) {

	rec := getVCRRecorder(t, "pki_enabled_no_certs")
	defer rec.Stop()

	vaultClient := createVaultClient(t, rec)

	_, err := GetListOfCerts(vaultClient, "pki_no_certs")

	assert.EqualError(t, err, "No certs found at pki_no_certs/certs/")
}

func TestGetArrayOfCertsFromVault_TwoCerts(t *testing.T) {

	rec := getVCRRecorder(t, "pki_enabled_2_certs_exist")
	defer rec.Stop()

	vaultClient := createVaultClient(t, rec)

	listOfCerts, err := vaultClient.Logical().List(fmt.Sprintf("%s/certs/", "pki"))

	assert.NoError(t, err, "vaultClient.Logical().List(\"pki/certs/\") returned an error")

	assert.NotNil(t, listOfCerts, "vaultClient.Logical().List(\"pki/certs/\") returned nil")

	arrayOfCerts, err := GetArrayOfCertsFromVault(vaultClient, listOfCerts, "pki")

	assert.NoErrorf(t, err, "arrayOfCerts returned an error: %s")

	assert.NotNil(t, arrayOfCerts)

	assert.Len(t, arrayOfCerts, 2)

	if len(arrayOfCerts) == 0 {
		t.Fatalf("arrayOfCerts is empty")
	}

	firstCert := arrayOfCerts[0]
	secondCert := arrayOfCerts[1]

	assert.Equal(t, "example.com", firstCert.Subject.CommonName)
	assert.Equal(t, "2020-03-19 19:38:57 +0000 UTC", firstCert.NotBefore.String())
	assert.Equal(t, "134454482447451618610371535730452651545868812061", firstCert.SerialNumber.String())

	assert.Equal(t, "vch.example.com", secondCert.Subject.CommonName)
	assert.Equal(t, "2020-03-19 19:38:57 +0000 UTC", secondCert.NotBefore.String())
	assert.Equal(t, "265660548622409048083489437369719820564690057410", secondCert.SerialNumber.String())
}
func TestGetArrayOfCertsFromVaultPKIEnabled_NoCerts(t *testing.T) {

	rec := getVCRRecorder(t, "pki_enabled_no_certs")
	defer rec.Stop()

	vaultClient := createVaultClient(t, rec)

	nilSecret, err := vaultClient.Logical().List(fmt.Sprintf("%s/certs/", "pki_no_certs"))

	if err != nil {
		t.Fatalf("Listing certs gave an unexpected error: %s", err)
	}

	_, err = GetArrayOfCertsFromVault(vaultClient, nilSecret, "pki_no_certs")

	assert.EqualError(t, err, "Secret given was nil")
}

func TestGetArrayOfCertsFromVaultPKIEnabled_SecretHasNoKeys(t *testing.T) {

	dataFilepath := "fixtures/secret_no_cert.json"

	dataFile, err := os.Open(dataFilepath)

	if err != nil {
		t.Fatalf("Error when reading fixture: %s", err)
	}

	jsonSecret, err := api.ParseSecret(dataFile)

	if err != nil {
		t.Fatalf("Error when parsing fixture as secret: %s", err)
	}

	_, err = GetArrayOfCertsFromVault(nil, jsonSecret, "pki")

	assert.EqualError(t, err, "No keys data found in secret")
}

func TestParseCertFromVaultSecret_TwoCerts(t *testing.T) {

	rec := getVCRRecorder(t, "pki_enabled_2_certs_exist")
	defer rec.Stop()

	vaultClient := createVaultClient(t, rec)

	certLookup, err := vaultClient.Logical().Read("pki/cert/17-8d-25-c3-66-37-81-eb-64-c6-84-5c-46-5b-42-8b-fd-12-bf-1d")

	assert.NoError(t, err, "vaultClient.Logical().List(\"pki/certs/\") returned an error")

	certParse, err := ParseCertFromVaultSecret(certLookup)

	assert.NoError(t, err)

	if certParse == nil {
		t.Fatalf("Cert from lookup was nil")
	}

	assert.Equal(t, "example.com", certParse.Subject.CommonName)
	assert.Equal(t, "2020-03-19 19:38:57 +0000 UTC", certParse.NotBefore.String())
	assert.Equal(t, "134454482447451618610371535730452651545868812061", certParse.SerialNumber.String())

}

func TestParseCertFromVaultSecret_ValidCert(t *testing.T) {

	dataFilepath := "fixtures/cert_secret.json"

	dataFile, err := os.Open(dataFilepath)

	if err != nil {
		t.Fatalf("Error when reading fixture: %s", err)
	}

	jsonSecret, err := api.ParseSecret(dataFile)

	if err != nil {
		t.Fatalf("Error when parsing fixture as secret: %s", err)
	}

	certParse, err := ParseCertFromVaultSecret(jsonSecret)

	assert.NoError(t, err)

	assert.Equal(t, "example.com", certParse.Subject.CommonName)
	assert.Equal(t, "2020-03-19 19:38:57 +0000 UTC", certParse.NotBefore.String())
	assert.Equal(t, "134454482447451618610371535730452651545868812061", certParse.SerialNumber.String())
}

func TestParseCertFromVaultSecret_InvalidCert(t *testing.T) {

	dataFilepath := "fixtures/cert_secret_invalid_cert_data.json"

	dataFile, err := os.Open(dataFilepath)

	if err != nil {
		t.Fatalf("Error when reading fixture: %s", err)
	}

	jsonSecret, err := api.ParseSecret(dataFile)

	if err != nil {
		t.Fatalf("Error when parsing fixture as secret: %s", err)
	}

	_, err = ParseCertFromVaultSecret(jsonSecret)

	assert.EqualError(t, err, "failed to parse certificate PEM")
}

func TestParseCertFromVaultSecret_NilSecret(t *testing.T) {

	_, err := ParseCertFromVaultSecret(nil)

	assert.EqualError(t, err, "Secret is nil")
}

func TestParseCertFromVaultSecret_NonCertSecret(t *testing.T) {

	dataFilepath := "fixtures/secret_no_cert.json"

	dataFile, err := os.Open(dataFilepath)

	if err != nil {
		t.Fatalf("Error when reading fixture: %s", err)
	}

	jsonSecret, err := api.ParseSecret(dataFile)

	if err != nil {
		t.Fatalf("Error when parsing fixture as secret: %s", err)
	}

	_, err = ParseCertFromVaultSecret(jsonSecret)

	assert.EqualError(t, err, "No certificate data found in secret")
}
