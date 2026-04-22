.PHONY: up down build test vet fmt tidy

# Local dev: starts just the app. DATABASE_URL must be set in .env
# (or the shell env) and must point at Supabase — there is no local DB.
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
