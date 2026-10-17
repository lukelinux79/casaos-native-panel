.PHONY: deps build run test vet

APP_NAME=casaos-native-panel

all: build

deps:
	go mod download

build:
	go build -o bin/$(APP_NAME) ./cmd/server

run:
	go run ./cmd/server

test:
	go test ./...

vet:
	go vet ./...
