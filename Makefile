.PHONY: up down build test vet fmt tidy

up:
	docker compose up --build

down:
	docker compose down

build:
	go build -o bin/api ./cmd/api

test:
	go test ./...

vet:
	go vet ./...

fmt:
	gofmt -w .

tidy:
	go mod tidy
