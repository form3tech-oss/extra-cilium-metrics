SHELL := /bin/bash

ROOT := $(shell git rev-parse --show-toplevel)

BINARY := $(ROOT)/extra-cilium-metrics

VERSION ?= $(shell git describe --dirty="-dev")

DOCKER_IMG ?= form3tech/extra-cilium-metrics
DOCKER_TAG ?= $(VERSION)

.PHONY: build
build: TARGET ?= $(BINARY)
build:
	GOARCH=amd64 GOOS=linux go build -ldflags="-s -w -X github.com/form3tech-oss/extra-cilium-metrics/version.Version=$(VERSION)" -o $(TARGET) -v main.go

.PHONY: docker.build
docker.build:
	docker build -t $(DOCKER_IMG):$(DOCKER_TAG) $(ROOT)

.PHONY: docker.push
docker.push: docker.build
	echo "$(DOCKER_PASSWORD)" | docker login -u "$(DOCKER_USERNAME)" --password-stdin
	docker push $(DOCKER_IMG):$(DOCKER_TAG)

.PHONY: run
run: CILIUM_NAMESPACE ?= kube-system
run: build
	@hack/run.sh $(CILIUM_NAMESPACE) $(BINARY)
