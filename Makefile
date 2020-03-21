# Setup name variables for the package/tool
NAME := vault-cert-helpers
PKG := github.com/petems/$(NAME)

.PHONY: all
all: fmt lint test

.PHONY: fmt
fmt: ## Verifies all files have men `gofmt`ed
	@echo "+ $@"
	@gofmt -s -l . | grep -v '.pb.go:' | grep -v vendor | tee /dev/stderr

.PHONY: lint
lint: ## Verifies `golangci-lint` passes
	@echo "+ $@"
	@golangci-lint run ./... 

.PHONY: cover
cover: ## Runs go test with coverage
	@go test -race -coverprofile=profile.out -covermode=atomic

.PHONY: cover_html
cover_html: cover ## Runs go test with coverage
	@go tool cover -html=profile.out

.PHONY: test
test: ## Runs the go tests
	@echo "+ $@"
	@go test ./...

.PHONY: docker_dev_vault_server
docker_dev_vault_server: 
	@docker run -p 8200:8200 --name='vault_test_server' -d --cap-add=IPC_LOCK -e 'VAULT_DEV_ROOT_TOKEN_ID=ROOT' vault
	@sleep 2
	@VAULT_TOKEN=ROOT VAULT_ADDR=http://127.0.0.1:8200 vault secrets enable pki
	@VAULT_TOKEN=ROOT VAULT_ADDR=http://127.0.0.1:8200 vault secrets enable --path='pki_no_certs/' pki
	@VAULT_TOKEN=ROOT VAULT_ADDR=http://127.0.0.1:8200 vault write -field=certificate pki/root/generate/internal common_name="example.com"
	@VAULT_TOKEN=ROOT VAULT_ADDR=http://127.0.0.1:8200 vault write pki/roles/example-dot-com allowed_domains=example.com allow_subdomains=true max_ttl=72h
	@VAULT_TOKEN=ROOT VAULT_ADDR=http://127.0.0.1:8200 vault write pki/issue/example-dot-com common_name=vch.example.com

.PHONY: kill_docker_server
kill_docker_server: 
	@docker rm -f 'vault_test_server'