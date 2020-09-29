SHELL := /bin/bash

ROOT := $(shell git rev-parse --show-toplevel)

BINARY := $(ROOT)/extra-cilium-metrics

.PHONY: build
build:
	GOARCH=amd64 GOOS=linux go build -o $(BINARY) -v main.go

.PHONY: run
run: CILIUM_NAMESPACE ?= kube-system
run: build
	@hack/run.sh $(CILIUM_NAMESPACE) $(BINARY)
