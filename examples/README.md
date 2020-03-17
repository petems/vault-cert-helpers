# example

## What are we doing

Enabling the PKI secrets engine, creating two certs, then iterating through the list of certs and returning their values.

## Pre-reqs

Run Vault with:

```
docker run -p 8200:8200 --name='vault_test_server' -d --cap-add=IPC_LOCK -e 'VAULT_DEV_ROOT_TOKEN_ID=ROOT' vault
```

Or

```
VAULT_DEV_ROOT_TOKEN_ID=ROOT vault server -dev &
```

Then create some certs:

```
VAULT_TOKEN=ROOT VAULT_ADDR=http://127.0.0.1:8200 vault secrets enable pki
VAULT_TOKEN=ROOT VAULT_ADDR=http://127.0.0.1:8200 vault secrets enable --path='pki_no_certs/' pki
VAULT_TOKEN=ROOT VAULT_ADDR=http://127.0.0.1:8200 vault write -field=certificate pki/root/generate/internal common_name="example.com"
VAULT_TOKEN=ROOT VAULT_ADDR=http://127.0.0.1:8200 vault write pki/roles/example-dot-com allowed_domains=example.com allow_subdomains=true max_ttl=72h
VAULT_TOKEN=ROOT VAULT_ADDR=http://127.0.0.1:8200 vault write pki/issue/example-dot-com common_name=vch.example.com
```

## Run the code

Then run the code in this folder:

```
go run main.go
```

You should see something like:

```
First cert CN is: example.com
Second cert CN is: vch.example.com
```