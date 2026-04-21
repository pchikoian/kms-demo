.PHONY: help build build-go build-all up down logs clean test test-go test-all integration-test-go integration-test-java integration-test

help:
	@echo "Usage: make <target>"
	@echo ""
	@echo "Targets:"
	@echo "  build      Build the Java s3-proxy image"
	@echo "  build-go   Build the Go s3-proxy-go image"
	@echo "  build-all  Build both images"
	@echo "  up         Start all services"
	@echo "  down       Stop all services"
	@echo "  logs       Follow logs for all services"
	@echo "  clean      Stop services and remove volumes"
	@echo "  test       Smoke test the Java proxy  (port 8080)"
	@echo "  test-go    Unit tests + smoke test the Go proxy (port 8081)"
	@echo "  test-all              Smoke test both proxies"
	@echo "  integration-test-go   Integration tests against Go proxy   (port 8081)"
	@echo "  integration-test-java Integration tests against Java proxy (port 8080)"
	@echo "  integration-test      Integration tests against both proxies"

build:
	docker compose build s3-proxy

build-go:
	docker compose build s3-proxy-go

build-all:
	docker compose build s3-proxy s3-proxy-go

up:
	docker compose up -d

down:
	docker compose down

logs:
	docker compose logs -f

clean:
	docker compose down -v

test:
	@echo "==> Java proxy (port 8080)"
	curl -sf -X PUT http://localhost:8080/demo-bucket/hello-java.txt \
		-H "Content-Type: text/plain" \
		--data "hello from java proxy"
	@echo ""
	curl -sf http://localhost:8080/demo-bucket/hello-java.txt
	@echo ""

test-go:
	@echo "==> Go unit tests"
	docker run --rm -v $(CURDIR)/s3-proxy-go:/app -w /app golang:1.22-alpine \
		sh -c "go mod tidy && go test ./... -v"
	@echo "==> Go proxy smoke test (port 8081)"
	curl -sf -X PUT http://localhost:8081/demo-bucket/hello-go.txt \
		-H "Content-Type: text/plain" \
		--data "hello from go proxy"
	@echo ""
	curl -sf http://localhost:8081/demo-bucket/hello-go.txt
	@echo ""

test-all: test test-go

integration-test-go:
	@echo "==> Integration tests against Go proxy (port 8081)"
	docker run --rm --network host \
		-v $(CURDIR)/integration-tests:/app -w /app \
		-e PROXY_URL=http://localhost:8081 \
		golang:1.22-alpine sh -c "go test ./... -v -count=1"

integration-test-java:
	@echo "==> Integration tests against Java proxy (port 8080)"
	docker run --rm --network host \
		-v $(CURDIR)/integration-tests:/app -w /app \
		-e PROXY_URL=http://localhost:8080 \
		golang:1.22-alpine sh -c "go test ./... -v -count=1"

integration-test: integration-test-go integration-test-java
