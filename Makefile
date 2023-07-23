# Ensure Make is run with bash shell as some syntax below is bash-specific
SHELL=/bin/bash -o pipefail

.DEFAULT_GOAL:=help
GOPATH  := $(shell go env GOPATH)
GOARCH  := $(shell go env GOARCH)
GOOS    := $(shell go env GOOS)
GOPROXY := $(shell go env GOPROXY)
ifeq ($(GOPROXY),)
GOPROXY := https://proxy.golang.org
endif
export GOPROXY
GO ?= go
DOCKER ?= docker


.PHONY: install
install:
	helm repo add gadget https://inspektor-gadget.github.io/charts
	helm repo update
	helm install gadget gadget/gadget --namespace=gadget --create-namespace -f ig/values.yaml

.PHONY: upgrade
upgrade:
	helm repo add gadget https://inspektor-gadget.github.io/charts
	helm repo update
	helm upgrade gadget gadget/gadget --namespace=gadget -f ig/values.yaml

.PHONY: linux-amd64
linux-amd64:
	$(GO) mod download
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 $(GO) build -o ig .
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 $(GO) build -o gadgettracermanager ./tracemanager

.PHONY: build
build: linux-amd64
	$(DOCKER) build --force-rm --no-cache -t ig:latest .

.PHONY: build-and-deploy
build-and-deploy:
	#az acr login --name emilgelmantest
	make build
	docker tag ig emilgelmantest.azurecr.io/ig:latest
	docker push emilgelmantest.azurecr.io/ig:latest
	kubectl rollout restart daemonset gadget -n gadget