# kms-demo — Architecture

## Runtime Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                          CLIENT LAYER                                │
│                                                                       │
│   curl / AWS CLI / boto3 / AWS SDK                                   │
│   S3-compatible HTTP (PUT, GET, DELETE, LIST)                        │
└────────────────┬────────────────────┬────────────────────────────────┘
                 │                    │
          port 8080             port 8081
                 │                    │
                 ▼                    ▼
┌────────────────────┐   ┌────────────────────────────────────────────┐
│   Java Proxy        │   │   Go Proxy                                  │
│                    │   │                                              │
│  gaul/s3proxy      │   │  net/http                                   │
│  (embedded S3 srv) │   │                                              │
│        │           │   │  ┌────────────┐  ┌──────────┐              │
│        ▼           │   │  │  handler   │  │ passthru │              │
│  VaultTransit      │   │  │ (put/get/  │  │ (reverse │              │
│  Encrypting        │   │  │  delete)   │  │  proxy)  │              │
│  BlobStore         │   │  └─────┬──────┘  └────┬─────┘              │
│  (Forwarding       │   │        │               │                    │
│   BlobStore)       │   │  ┌─────┴──────┐        │                   │
│        │           │   │  │vaultService│        │                   │
│        │           │   │  │(interface) │        │                   │
│        │           │   │  └────────────┘        │                   │
└────┬───┴───────────┘   └──────────┬─────────────┴───────────────────┘
     │                              │
     │   ┌──────────────────────────┘
     │   │
     │   │  Vault Transit API (HTTP)
     ▼   ▼
┌────────────────────────────────────┐
│   HashiCorp Vault (port 8200)       │
│                                    │
│   Transit Secrets Engine           │
│   ┌────────────────────────────┐   │
│   │  KEK: demo-kek             │   │
│   │  (AES-256, stored in Vault)│   │
│   │                            │   │
│   │  datakey/plaintext  ───────────────> returns DEK plaintext + wrapped DEK
│   │  decrypt            <───────────────  unwraps DEK from wrapped ciphertext
│   └────────────────────────────┘   │
│                                    │
│   Policy: s3-proxy-policy          │
│   (transit/datakey, transit/decrypt│
│    on demo-kek only)               │
└────────────────────────────────────┘

     │   │
     │   │  S3 API (HTTP)
     ▼   ▼
┌────────────────────────────────────┐
│   MinIO (port 9000)                 │
│   Console (port 9001)               │
│                                    │
│   Stores:                          │
│   ┌────────────────────────────┐   │
│   │  Object body:              │   │
│   │  [12B nonce][ciphertext]   │   │
│   │  [16B GCM auth tag]        │   │
│   │                            │   │
│   │  Object metadata:          │   │
│   │  x-amz-meta-encrypted-dek  │   │
│   │    → vault:v1:AbCdEf…      │   │
│   │  x-amz-meta-original-      │   │
│   │    content-type: text/plain│   │
│   └────────────────────────────┘   │
└────────────────────────────────────┘
```

---

## Envelope Encryption Data Flow

### PUT (write path)

```
PUT /bucket/key (plaintext body)
         │
         ▼
  ┌─────────────┐
  │    Proxy    │
  │             │
  │  1. POST /v1/transit/datakey/plaintext/demo-kek
  │     ◄─────────────────────────────────────────────── Vault
  │     returns: DEK plaintext (32 bytes, base64)
  │              DEK wrapped   (vault:v1:…)
  │                            │
  │  2. AES-256-GCM encrypt(body, DEK plaintext)
  │     nonce ← crypto/rand (12 bytes)
  │     ciphertext = GCM seal(nonce, plaintext)
  │     wire: [nonce 12B][ciphertext][tag 16B]
  │                            │
  │  3. PutObject to MinIO ────────────────────────────► MinIO
  │     body    = wire format above
  │     metadata["encrypted-dek"] = vault:v1:…
  │     metadata["original-content-type"] = …
  │                            │
  │  4. DEK plaintext zeroed / discarded
  └─────────────┘
```

### GET (read path)

```
GET /bucket/key
         │
         ▼
  ┌─────────────┐
  │    Proxy    │
  │             │
  │  1. GetObject from MinIO ──────────────────────────► MinIO
  │     returns: wire format body + metadata
  │                            │
  │  2. POST /v1/transit/decrypt/demo-kek
  │     { ciphertext: metadata["encrypted-dek"] }
  │     ◄─────────────────────────────────────────────── Vault
  │     returns: DEK plaintext (base64)
  │                            │
  │  3. AES-256-GCM decrypt(body, DEK plaintext)
  │     split wire: nonce[0:12], ciphertext[12:]
  │     plaintext = GCM open(nonce, ciphertext)
  │                            │
  │  4. Return plaintext to client
  └─────────────┘
```

---

## Wire Format

```
┌─────────────────┬──────────────────────────────────────┐
│  12-byte nonce  │  ciphertext  +  16-byte GCM auth tag  │
└─────────────────┴──────────────────────────────────────┘
```

Object metadata keys stored in MinIO:

| Key | Value |
|-----|-------|
| `x-amz-meta-encrypted-dek` | Vault-wrapped DEK (`vault:v1:…`) |
| `x-amz-meta-original-content-type` | Original `Content-Type` |

---

## Key Custody

```
┌──────────────────────────────────────────────────────────────┐
│  SECRET                WHERE              NEVER LEAVES         │
├──────────────────────────────────────────────────────────────┤
│  KEK (master key)      Vault Transit      Vault memory        │
│  DEK plaintext         Proxy RAM only     Proxy RAM (zeroed)  │
│  DEK wrapped           MinIO metadata     Not sensitive alone │
│  Object plaintext      Client / Proxy     MinIO sees cipher   │
└──────────────────────────────────────────────────────────────┘
```

Vault is used **only as a key manager** — it wraps/unwraps DEKs via the Transit engine. All AES-256-GCM encryption and decryption happens locally inside the proxy. Vault never sees object data.

---

## Build / Project Structure

```
kms-demo/
│
├── s3proxy-upstream/          ← git submodule (gaul/s3proxy source)
│   └── pom.xml                   pinned tag ~3.1.0 / 3.2.0-SNAPSHOT
│
├── s3-proxy/                  ← Java proxy (Maven module)
│   ├── Dockerfile             ← builds from root context
│   │   │  stage 1 (maven:3-eclipse-temurin-17)
│   │   │    git init (satisfies git-commit-id plugin)
│   │   │    mvn install -pl s3proxy-upstream  (→ local .m2)
│   │   │    mvn package -pl s3-proxy
│   │   └  stage 2 (eclipse-temurin:17-jre)
│   │        COPY s3-proxy.jar
│   │
│   └── src/.../
│       ├── Main.java                   env config + wiring
│       ├── VaultTransitEncryptingBlobStore.java   ForwardingBlobStore
│       ├── VaultTransitClient.java     Vault HTTP client
│       ├── VaultTransitConstants.java  property key constants
│       └── AesGcm.java                AES-256-GCM helpers
│
├── s3-proxy-go/               ← Go proxy (single binary)
│   ├── Dockerfile             ← go build inside container
│   ├── main.go                env config + server startup
│   ├── proxy.go               HTTP handler + minioClient interface
│   ├── vault.go               vaultService interface + impl
│   ├── crypto.go              AES-256-GCM helpers
│   └── passthru.go            reverse proxy (non-object ops)
│
├── docker-compose.yml         ← full stack (vault, minio, both proxies)
├── Makefile                   ← build-all / up / test-all / logs
└── README.md
```

---

## Component Dependency Graph

```
            ┌──────────────────────────────────┐
            │         docker-compose            │
            │  vault-init ──► vault             │
            │  minio                            │
            │  s3-proxy  (Java, port 8080)      │
            │  s3-proxy-go (Go,  port 8081)     │
            └──────────────────────────────────┘

Java proxy deps (compile-time):
  s3proxy-upstream (submodule) ──► local .m2 ──► s3-proxy/pom.xml
                                                    │
                                         gaul/s3proxy 3.2.0-SNAPSHOT
                                         jclouds 2.7.0
                                         aws-sdk-java-v2 2.42.31
                                         slf4j-simple 2.0.12

Go proxy deps (go.mod):
  github.com/minio/minio-go/v7
  github.com/aws/aws-sdk-go-v2/...   (SigV4 signing in passthru)
  stdlib: net/http, crypto/aes, crypto/cipher, encoding/json
```
