# KMS Demo — Vault + S3-Proxy + MinIO with Envelope Encryption

## Project Overview

This project demonstrates end-to-end envelope encryption for object storage:

- **KMS**: HashiCorp Vault (Transit secrets engine) — generates and manages Data Encryption Keys (DEKs)
- **Auto-encryption layer**: `s3-proxy` — intercepts S3 API calls, applies envelope encryption transparently
- **Storage backend**: MinIO — S3-compatible object store that holds only ciphertext
- **Pattern**: Envelope encryption — each object is encrypted with a unique DEK; the DEK itself is encrypted by a Key Encryption Key (KEK) stored in Vault

```
Client
  │  (plain S3 API calls)
  ▼
s3-proxy  ──► Vault Transit (KEK: encrypt/decrypt DEK)
  │              ▲
  │  wraps DEK   │ unwraps DEK
  ▼
MinIO  (stores: ciphertext + encrypted DEK in object metadata)
```

## Envelope Encryption Pattern

1. **Encrypt path** (PUT object):
   - s3-proxy generates a random DEK (AES-256)
   - s3-proxy calls Vault `transit/encrypt/<key-name>` to wrap (encrypt) the DEK → produces `encrypted_DEK`
   - s3-proxy encrypts the object body with the DEK
   - s3-proxy stores `{ ciphertext, encrypted_DEK }` in MinIO (encrypted DEK goes in object metadata or a sidecar)

2. **Decrypt path** (GET object):
   - s3-proxy retrieves ciphertext + `encrypted_DEK` from MinIO
   - s3-proxy calls Vault `transit/decrypt/<key-name>` to unwrap the DEK
   - s3-proxy decrypts the object body with the DEK
   - s3-proxy returns plaintext to the client

The plaintext DEK is **never persisted**; it exists only in memory during the request.

## Repository Structure (planned)

```
kms-demo/
├── CLAUDE.md                  # this file
├── docker-compose.yml         # orchestrates Vault, MinIO, s3-proxy
├── vault/
│   ├── config.hcl             # Vault dev-mode config
│   └── init.sh                # enable Transit engine, create KEK, create policy + token
├── minio/
│   └── init.sh                # create bucket via mc
├── s3-proxy/
│   ├── Dockerfile             # build s3-proxy image (or use upstream)
│   ├── config.yaml            # s3-proxy routes, Vault addr, key name
│   └── main.go                # custom proxy if writing from scratch
├── demo/
│   ├── put_object.sh          # curl PUT through s3-proxy
│   ├── get_object.sh          # curl GET through s3-proxy
│   └── verify_minio.sh        # show raw (encrypted) bytes in MinIO directly
└── tests/
    └── e2e_test.sh            # full round-trip smoke test
```

## Services and Ports

| Service   | Port  | Notes                              |
|-----------|-------|------------------------------------|
| Vault     | 8200  | dev mode, root token in env        |
| MinIO API | 9000  | S3-compatible endpoint             |
| MinIO UI  | 9001  | console                            |
| s3-proxy  | 8080  | client-facing S3 endpoint          |

## Key Configuration Values

- Vault Transit key name: `demo-kek`
- Vault policy: `s3-proxy-policy` (allow `transit/encrypt/demo-kek`, `transit/decrypt/demo-kek`)
- MinIO bucket: `demo-bucket`
- s3-proxy upstream: `http://minio:9000`
- s3-proxy Vault address: `http://vault:8200`

## Environment Variables

```bash
# Vault
VAULT_ADDR=http://localhost:8200
VAULT_TOKEN=root                  # dev mode root token

# MinIO
MINIO_ROOT_USER=minioadmin
MINIO_ROOT_PASSWORD=minioadmin
MINIO_ENDPOINT=http://localhost:9000

# s3-proxy
S3PROXY_LISTEN=:8080
S3PROXY_VAULT_ADDR=http://vault:8200
S3PROXY_VAULT_TOKEN=<s3-proxy-token>
S3PROXY_VAULT_KEY=demo-kek
S3PROXY_MINIO_ENDPOINT=http://minio:9000
S3PROXY_MINIO_ACCESS_KEY=minioadmin
S3PROXY_MINIO_SECRET_KEY=minioadmin
```

## Running the Demo

```bash
# 1. Start all services
docker compose up -d

# 2. Initialize Vault (enable Transit, create KEK + token)
bash vault/init.sh

# 3. Initialize MinIO (create bucket)
bash minio/init.sh

# 4. PUT an object through s3-proxy (auto-encrypted)
bash demo/put_object.sh

# 5. GET the object back (auto-decrypted)
bash demo/get_object.sh

# 6. Verify MinIO stores only ciphertext (prove encryption)
bash demo/verify_minio.sh
```

## Implementation Notes

### Vault Transit Engine

- Use `type=aes256-gcm96` (default) for the KEK — provides authenticated encryption
- The Transit engine **never exposes the KEK**; it only performs encrypt/decrypt operations
- Vault wraps/unwraps DEKs using the `transit/encrypt` and `transit/decrypt` endpoints
- Key rotation: `vault write -f transit/keys/demo-kek/rotate` — old ciphertext still decryptable; new encryptions use new key version

### s3-proxy Design Choices

- Intercept at the HTTP layer (S3 REST API: `PUT /bucket/key`, `GET /bucket/key`)
- Use AES-256-GCM for DEK-based object encryption (provides integrity + confidentiality)
- Store `encrypted_DEK` as S3 object metadata (`x-amz-meta-encrypted-dek`) alongside the ciphertext object
- Keep the proxy stateless — all state lives in MinIO metadata + Vault

### MinIO

- Acts as a dumb ciphertext store; has no knowledge of encryption
- Raw GET from MinIO returns unintelligible ciphertext
- This demonstrates that storage-layer compromise alone is insufficient to read data

## Security Considerations

- In production: replace Vault dev mode with a hardened Vault cluster (TLS, HA, audit logs)
- s3-proxy Vault token should use a narrowly scoped policy (only transit encrypt/decrypt for the specific key)
- Rotate the KEK regularly; Vault Transit key rotation is non-disruptive
- Enable Vault audit logging to track all key usage
- Consider Vault's `transit/datakey` endpoint as an alternative DEK generation path (Vault generates the DEK, returns plaintext + ciphertext; proxy uses plaintext DEK then discards it)

## Useful Vault Commands

```bash
# Enable Transit engine
vault secrets enable transit

# Create KEK
vault write -f transit/keys/demo-kek

# Encrypt a DEK (base64-encoded plaintext)
vault write transit/encrypt/demo-kek plaintext=$(echo -n "my-dek-bytes" | base64)

# Decrypt an encrypted DEK
vault write transit/decrypt/demo-kek ciphertext="vault:v1:..."

# Use datakey endpoint (recommended for high-throughput)
vault write transit/datakey/plaintext/demo-kek bits=256
# returns: plaintext (DEK, base64) + ciphertext (encrypted DEK to store)
```

## Testing Strategy

- **Unit**: test encrypt/decrypt round-trip in s3-proxy logic with a mock Vault client
- **Integration**: docker-compose up → PUT → GET → assert plaintext matches original
- **Negative**: GET directly from MinIO → assert result is not plaintext
- **Key rotation**: rotate KEK → decrypt old object → assert still works (Vault handles versioned decryption)
