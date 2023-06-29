# Variables
GOCMD = go
GOBUILD_ENVS = CGO_ENABLED=0 GOOS=linux GOARCH=amd64
GOBUILD = $(GOCMD) build
GOCLEAN = $(GOCMD) clean
GOTEST = $(GOCMD) test
GOGET = $(GOCMD) get
BINARY_NAME = kubescape-network-scanner
GOFILES = $(shell find . -type f -name '*.go')

all: test build

build: $(GOFILES)
	$(GOBUILD_ENVS) $(GOBUILD) -v -o $(BINARY_NAME) .

test: 
	$(GOTEST) -v ./...

clean: 
	$(GOCLEAN)
	rm -f $(BINARY_NAME)

run: build
	./$(BINARY_NAME)

deps:
	$(GOGET) -v -d ./...
