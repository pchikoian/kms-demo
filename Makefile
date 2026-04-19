.PHONY: help build up down logs clean test

help:
	@echo "Usage: make <target>"
	@echo ""
	@echo "Targets:"
	@echo "  build   Build the s3-proxy Docker image"
	@echo "  up      Start all services"
	@echo "  down    Stop all services"
	@echo "  logs    Follow logs for all services"
	@echo "  clean   Stop services and remove volumes"
	@echo "  test    Run a quick smoke test (PUT + GET)"

build:
	docker compose build s3-proxy

up:
	docker compose up -d

down:
	docker compose down

logs:
	docker compose logs -f

clean:
	docker compose down -v

test:
	@echo "Uploading test object..."
	curl -sf -X PUT http://localhost:8080/demo-bucket/hello.txt \
		-H "Content-Type: text/plain" \
		--data "hello world"
	@echo ""
	@echo "Downloading test object..."
	curl -sf http://localhost:8080/demo-bucket/hello.txt
	@echo ""
