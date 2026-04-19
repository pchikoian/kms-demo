# kms-demo

Demonstrates transparent client-side envelope encryption for S3-compatible object storage using HashiCorp Vault Transit as a KMS. Provided in two implementations — Java and Go — that share the same wire format and are fully interoperable.

## How it works

```
Client          S3 Proxy (Java or Go)         Vault Transit         MinIO
  |                      |                          |                  |
  |-- PUT /bucket/key -->|                          |                  |
  |                      |-- datakey/plaintext -->  |                  |
  |                      |<-- DEK (plain+wrapped) --|                  |
  |                      |-- AES-256-GCM encrypt    |                  |
  |                      |-- PutObject (ciphertext, encrypted-dek) --> |
  |<-- 200 OK -----------|                          |                  |
  |                      |                          |                  |
  |-- GET /bucket/key -->|                          |                  |
  |                      |-- StatObject + GetObject -----------------> |
  |                      |-- decrypt/unwrap DEK --> |                  |
  |                      |-- AES-256-GCM decrypt    |                  |
  |<-- plaintext --------|                          |                  |
```

Each object is encrypted with a unique DEK (data encryption key). The DEK is wrapped by Vault's Transit engine (KEK) and stored in the object's metadata. Vault never sees the plaintext data.

## Encryption format

Wire format is identical across both implementations:

```
[ 12-byte nonce ][ ciphertext + 16-byte GCM tag ]
```

Object metadata:
- `X-Amz-Meta-Encrypted-Dek` — Vault-wrapped DEK (`vault:v1:…`)
- `X-Amz-Meta-Original-Content-Type` — original `Content-Type` header

## Implementations

| | Java | Go |
|---|---|---|
| Directory | `s3-proxy/` | `s3-proxy-go/` |
| Port | `8080` | `8081` |
| Runtime | Java 21, Spring Boot | Go 1.22 |
| Encryption | `AesGcm.java` | `crypto.go` |

Both proxies intercept `PUT` and `GET` for object paths and forward everything else (bucket ops, list, delete, head) directly to MinIO.

## Prerequisites

- Docker and Docker Compose

All builds and tests run inside Docker — no local Go or Java toolchain required.

## Quick start

```bash
# Build images
make build-all

# Start Vault, MinIO, and both proxies
make up

# Smoke test
make test-all
```

## Make targets

| Target | Description |
|--------|-------------|
| `make build` | Build Java proxy image |
| `make build-go` | Build Go proxy image |
| `make build-all` | Build both images |
| `make up` | Start full stack |
| `make down` | Stop stack |
| `make clean` | Stop stack and remove volumes |
| `make test` | Smoke test Java proxy (`:8080`) |
| `make test-go` | Smoke test Go proxy (`:8081`) |
| `make test-all` | Smoke test both |

## Services

| Service | Port | Purpose |
|---------|------|---------|
| Vault | `8200` | Transit KMS (dev mode, token: `root`) |
| MinIO | `9000` | S3-compatible object storage |
| MinIO Console | `9001` | Web UI |
| Java proxy | `8080` | Encrypting S3 proxy |
| Go proxy | `8081` | Encrypting S3 proxy |

## Manual testing

```bash
# PUT an object through the Go proxy
curl -X PUT http://localhost:8081/demo-bucket/hello.txt \
  -H "Content-Type: text/plain" \
  --data "hello world"

# GET it back (decrypted transparently)
curl http://localhost:8081/demo-bucket/hello.txt

# Verify the raw object in MinIO is ciphertext
curl http://localhost:9000/demo-bucket/hello.txt
```

## Interoperability

Objects written by either proxy can be read by either proxy — they share the same encryption format and Vault key (`demo-kek`).

```bash
# Write via Java, read via Go
curl -X PUT http://localhost:8080/demo-bucket/cross.txt --data "from java"
curl http://localhost:8081/demo-bucket/cross.txt
```

## Security notes

This is a **demo**. Production hardening checklist:

- Use a non-root Vault token with a scoped policy (policy is created by `vault-init` but the `root` token is used for Vault itself)
- Enable Vault audit logging
- Rotate the Transit KEK periodically (`vault write -f transit/keys/demo-kek/rotate`)
- Add TLS between all components
- Set a maximum object size in the proxy to avoid unbounded memory reads
