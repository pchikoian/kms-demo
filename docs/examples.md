# Usage Examples

Practical examples for interacting with the kms-demo encryption proxies.  
All examples assume the full stack is running (`make up`).

| Proxy | Endpoint |
|-------|----------|
| Java  | `http://localhost:8080` |
| Go    | `http://localhost:8081` |
| MinIO (direct, no encryption) | `http://localhost:9000` |

---

## Table of contents

1. [curl](#1-curl)
2. [AWS CLI](#2-aws-cli)
3. [Python (boto3)](#3-python-boto3)
4. [Go](#4-go)
5. [Java (AWS SDK v2)](#5-java-aws-sdk-v2)
6. [Verify encryption](#6-verify-encryption)
7. [Cross-proxy interoperability](#7-cross-proxy-interoperability)
8. [Vault key rotation](#8-vault-key-rotation)

---

## 1. curl

### PUT an object

```bash
curl -X PUT http://localhost:8080/demo-bucket/hello.txt \
  -H "Content-Type: text/plain" \
  --data "hello world"
```

### GET an object

```bash
curl http://localhost:8080/demo-bucket/hello.txt
# → hello world
```

### PUT a JSON document

```bash
curl -X PUT http://localhost:8080/demo-bucket/config.json \
  -H "Content-Type: application/json" \
  -d '{"env":"prod","version":"1.0"}'
```

### GET a JSON document

```bash
curl http://localhost:8080/demo-bucket/config.json
# → {"env":"prod","version":"1.0"}
```

### PUT a binary file

```bash
curl -X PUT http://localhost:8080/demo-bucket/photo.jpg \
  -H "Content-Type: image/jpeg" \
  --data-binary @/path/to/photo.jpg
```

### GET a binary file

```bash
curl -o downloaded.jpg http://localhost:8080/demo-bucket/photo.jpg
```

### DELETE an object

```bash
curl -X DELETE http://localhost:8080/demo-bucket/hello.txt
```

### List objects in a bucket

```bash
curl "http://localhost:8080/demo-bucket/?list-type=2"
```

### HEAD — inspect metadata without downloading

```bash
curl -I http://localhost:8080/demo-bucket/hello.txt
```

---

## 2. AWS CLI

### Configure a profile

```bash
aws configure --profile kms-demo
# AWS Access Key ID:     minioadmin
# AWS Secret Access Key: minioadmin
# Default region:        us-east-1
# Default output format: json
```

Set a shell alias to avoid repeating the flags:

```bash
alias s3p='aws s3 --endpoint-url http://localhost:8080 --profile kms-demo'
alias s3ap='aws s3api --endpoint-url http://localhost:8080 --profile kms-demo'
```

### Upload a file

```bash
aws s3 cp notes.txt s3://demo-bucket/notes.txt \
  --endpoint-url http://localhost:8080 --profile kms-demo

# With content-type
aws s3 cp data.json s3://demo-bucket/data.json \
  --content-type application/json \
  --endpoint-url http://localhost:8080 --profile kms-demo
```

### Download a file

```bash
aws s3 cp s3://demo-bucket/notes.txt ./notes-out.txt \
  --endpoint-url http://localhost:8080 --profile kms-demo
```

### Upload an entire folder

```bash
aws s3 sync ./my-folder s3://demo-bucket/my-folder/ \
  --endpoint-url http://localhost:8080 --profile kms-demo
```

### Download an entire folder

```bash
aws s3 sync s3://demo-bucket/my-folder/ ./my-folder-out/ \
  --endpoint-url http://localhost:8080 --profile kms-demo
```

### List objects

```bash
aws s3 ls s3://demo-bucket/ \
  --endpoint-url http://localhost:8080 --profile kms-demo
```

### Delete an object

```bash
aws s3 rm s3://demo-bucket/notes.txt \
  --endpoint-url http://localhost:8080 --profile kms-demo
```

### Inspect raw metadata (shows encrypted DEK)

```bash
aws s3api head-object \
  --bucket demo-bucket --key notes.txt \
  --endpoint-url http://localhost:8080 --profile kms-demo
```

Output:

```json
{
    "ContentType": "text/plain",
    "Metadata": {
        "encrypted-dek": "vault:v1:AbCdEf...",
        "original-content-type": "text/plain"
    }
}
```

---

## 3. Python (boto3)

```python
import boto3

# Point boto3 at the proxy instead of AWS
s3 = boto3.client(
    "s3",
    endpoint_url="http://localhost:8080",
    aws_access_key_id="minioadmin",
    aws_secret_access_key="minioadmin",
    region_name="us-east-1",
)

BUCKET = "demo-bucket"

# ── Upload a string ──────────────────────────────────────────────────────────
s3.put_object(
    Bucket=BUCKET,
    Key="greeting.txt",
    Body=b"hello from python",
    ContentType="text/plain",
)

# ── Download and print ───────────────────────────────────────────────────────
response = s3.get_object(Bucket=BUCKET, Key="greeting.txt")
print(response["Body"].read().decode())
# → hello from python

# ── Upload a local file ──────────────────────────────────────────────────────
s3.upload_file("/tmp/data.csv", BUCKET, "data.csv",
               ExtraArgs={"ContentType": "text/csv"})

# ── Download to a local file ─────────────────────────────────────────────────
s3.download_file(BUCKET, "data.csv", "/tmp/data-out.csv")

# ── List objects ─────────────────────────────────────────────────────────────
paginator = s3.get_paginator("list_objects_v2")
for page in paginator.paginate(Bucket=BUCKET):
    for obj in page.get("Contents", []):
        print(obj["Key"], obj["Size"])

# ── Delete ───────────────────────────────────────────────────────────────────
s3.delete_object(Bucket=BUCKET, Key="greeting.txt")

# ── Check the encrypted DEK stored in metadata ───────────────────────────────
head = s3.head_object(Bucket=BUCKET, Key="data.csv")
print(head["Metadata"].get("encrypted-dek"))
# → vault:v1:...
```

### Upload / download with streaming (large files)

```python
import boto3
from boto3.s3.transfer import TransferConfig

s3 = boto3.client(
    "s3",
    endpoint_url="http://localhost:8080",
    aws_access_key_id="minioadmin",
    aws_secret_access_key="minioadmin",
    region_name="us-east-1",
)

config = TransferConfig(multipart_threshold=10 * 1024 * 1024)  # 10 MB

s3.upload_file("/path/to/large.bin", "demo-bucket", "large.bin",
               Config=config)

s3.download_file("demo-bucket", "large.bin", "/tmp/large-out.bin",
                 Config=config)
```

---

## 4. Go

```go
package main

import (
    "bytes"
    "context"
    "fmt"
    "io"
    "log"

    "github.com/aws/aws-sdk-go-v2/aws"
    "github.com/aws/aws-sdk-go-v2/config"
    "github.com/aws/aws-sdk-go-v2/credentials"
    "github.com/aws/aws-sdk-go-v2/service/s3"
)

func main() {
    // Point the SDK at the proxy.
    cfg, err := config.LoadDefaultConfig(context.Background(),
        config.WithRegion("us-east-1"),
        config.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(
            "minioadmin", "minioadmin", "",
        )),
    )
    if err != nil {
        log.Fatal(err)
    }

    client := s3.NewFromConfig(cfg, func(o *s3.Options) {
        o.BaseEndpoint = aws.String("http://localhost:8080")
        o.UsePathStyle = true
    })

    ctx := context.Background()
    bucket := "demo-bucket"

    // ── PUT ─────────────────────────────────────────────────────────────────
    body := []byte("hello from go client")
    _, err = client.PutObject(ctx, &s3.PutObjectInput{
        Bucket:      aws.String(bucket),
        Key:         aws.String("hello-go.txt"),
        Body:        bytes.NewReader(body),
        ContentType: aws.String("text/plain"),
    })
    if err != nil {
        log.Fatal(err)
    }
    fmt.Println("uploaded hello-go.txt")

    // ── GET ─────────────────────────────────────────────────────────────────
    out, err := client.GetObject(ctx, &s3.GetObjectInput{
        Bucket: aws.String(bucket),
        Key:    aws.String("hello-go.txt"),
    })
    if err != nil {
        log.Fatal(err)
    }
    defer out.Body.Close()

    data, _ := io.ReadAll(out.Body)
    fmt.Println("downloaded:", string(data))
    // → hello from go client

    // ── HEAD (inspect encrypted DEK) ────────────────────────────────────────
    head, err := client.HeadObject(ctx, &s3.HeadObjectInput{
        Bucket: aws.String(bucket),
        Key:    aws.String("hello-go.txt"),
    })
    if err != nil {
        log.Fatal(err)
    }
    fmt.Println("encrypted-dek:", head.Metadata["encrypted-dek"])

    // ── DELETE ──────────────────────────────────────────────────────────────
    _, err = client.DeleteObject(ctx, &s3.DeleteObjectInput{
        Bucket: aws.String(bucket),
        Key:    aws.String("hello-go.txt"),
    })
    if err != nil {
        log.Fatal(err)
    }
    fmt.Println("deleted hello-go.txt")
}
```

---

## 5. Java (AWS SDK v2)

```java
import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider;
import software.amazon.awssdk.core.sync.RequestBody;
import software.amazon.awssdk.core.sync.ResponseTransformer;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.model.*;

import java.net.URI;
import java.nio.charset.StandardCharsets;

public class ProxyExample {

    public static void main(String[] args) {
        // Point the SDK at the proxy.
        S3Client s3 = S3Client.builder()
                .endpointOverride(URI.create("http://localhost:8080"))
                .forcePathStyle(true)
                .region(Region.US_EAST_1)
                .credentialsProvider(StaticCredentialsProvider.create(
                        AwsBasicCredentials.create("minioadmin", "minioadmin")))
                .build();

        String bucket = "demo-bucket";

        // ── PUT ─────────────────────────────────────────────────────────────
        byte[] data = "hello from java client".getBytes(StandardCharsets.UTF_8);
        s3.putObject(
                PutObjectRequest.builder()
                        .bucket(bucket)
                        .key("hello-java.txt")
                        .contentType("text/plain")
                        .build(),
                RequestBody.fromBytes(data));
        System.out.println("uploaded hello-java.txt");

        // ── GET ─────────────────────────────────────────────────────────────
        byte[] downloaded = s3.getObjectAsBytes(
                GetObjectRequest.builder()
                        .bucket(bucket)
                        .key("hello-java.txt")
                        .build()
        ).asByteArray();
        System.out.println("downloaded: " + new String(downloaded, StandardCharsets.UTF_8));
        // → hello from java client

        // ── HEAD (inspect encrypted DEK) ────────────────────────────────────
        HeadObjectResponse head = s3.headObject(
                HeadObjectRequest.builder()
                        .bucket(bucket)
                        .key("hello-java.txt")
                        .build());
        System.out.println("encrypted-dek: " + head.metadata().get("encrypted-dek"));

        // ── LIST ────────────────────────────────────────────────────────────
        ListObjectsV2Response list = s3.listObjectsV2(
                ListObjectsV2Request.builder().bucket(bucket).build());
        list.contents().forEach(o ->
                System.out.println(o.key() + " (" + o.size() + " bytes)"));

        // ── DELETE ──────────────────────────────────────────────────────────
        s3.deleteObject(DeleteObjectRequest.builder()
                .bucket(bucket)
                .key("hello-java.txt")
                .build());
        System.out.println("deleted hello-java.txt");

        s3.close();
    }
}
```

---

## 6. Verify encryption

These steps confirm data is encrypted at rest and the DEK is stored in object metadata.

### Confirm ciphertext in MinIO

```bash
# Write through the proxy
curl -X PUT http://localhost:8080/demo-bucket/secret.txt \
  -H "Content-Type: text/plain" \
  --data "top secret"

# Read back through proxy — plaintext
curl http://localhost:8080/demo-bucket/secret.txt
# → top secret

# Read directly from MinIO — binary ciphertext
curl -s http://localhost:9000/demo-bucket/secret.txt | xxd | head -3
# 00000000: 3f8a c1d2 e4f5 ...   (not "top secret")
```

### Inspect the wrapped DEK

```bash
curl -sI http://localhost:9000/demo-bucket/secret.txt \
  | grep -i "x-amz-meta"
# x-amz-meta-encrypted-dek: vault:v1:AbCdEf...
# x-amz-meta-original-content-type: text/plain
```

### Manually decrypt with Vault + openssl

```bash
# 1. Get the wrapped DEK from metadata
ENCRYPTED_DEK=$(curl -sI http://localhost:9000/demo-bucket/secret.txt \
  | grep -i "x-amz-meta-encrypted-dek" | awk '{print $2}' | tr -d '\r')

# 2. Unwrap DEK via Vault
PLAINTEXT_DEK_B64=$(curl -s \
  -H "X-Vault-Token: root" \
  -d "{\"ciphertext\":\"$ENCRYPTED_DEK\"}" \
  http://localhost:8200/v1/transit/decrypt/demo-kek \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['data']['plaintext'])")

echo "DEK (base64): $PLAINTEXT_DEK_B64"

# 3. Download the raw ciphertext blob
curl -s http://localhost:9000/demo-bucket/secret.txt -o /tmp/blob.bin

# 4. Split nonce (first 12 bytes) and ciphertext
dd if=/tmp/blob.bin bs=1 count=12 of=/tmp/nonce.bin 2>/dev/null
dd if=/tmp/blob.bin bs=1 skip=12 of=/tmp/cipher.bin 2>/dev/null

# 5. Decrypt with openssl
echo "$PLAINTEXT_DEK_B64" | base64 -d > /tmp/dek.bin
openssl enc -d -aes-256-gcm \
  -K $(xxd -p -c 32 /tmp/dek.bin) \
  -iv $(xxd -p -c 12 /tmp/nonce.bin) \
  -in /tmp/cipher.bin
# → top secret
```

---

## 7. Cross-proxy interoperability

Objects are interoperable because both proxies use the same encryption format and the same Vault KEK.

```bash
# Write via Java proxy
curl -X PUT http://localhost:8080/demo-bucket/shared.txt \
  -H "Content-Type: text/plain" \
  --data "written by java"

# Read via Go proxy — works
curl http://localhost:8081/demo-bucket/shared.txt
# → written by java

# Write via Go proxy
curl -X PUT http://localhost:8081/demo-bucket/shared2.txt \
  -H "Content-Type: text/plain" \
  --data "written by go"

# Read via Java proxy — works
curl http://localhost:8080/demo-bucket/shared2.txt
# → written by go
```

---

## 8. Vault key rotation

Rotation produces a new key version. New objects are encrypted with the new version; old objects still decrypt because Vault keeps all previous versions.

### Rotate the KEK

```bash
curl -s \
  -H "X-Vault-Token: root" \
  -X POST \
  http://localhost:8200/v1/transit/keys/demo-kek/rotate
```

### Confirm the version bumped

```bash
curl -s -H "X-Vault-Token: root" \
  http://localhost:8200/v1/transit/keys/demo-kek \
  | python3 -c "import sys,json; d=json.load(sys.stdin)['data']; print('latest:', d['latest_version'], '/ min_decryption:', d['min_decryption_version'])"
# → latest: 2 / min_decryption: 1
```

### Verify old objects still decrypt

```bash
# Object written before rotation
curl http://localhost:8080/demo-bucket/secret.txt
# → top secret   (still works, Vault decrypts with v1 key)

# New object uses v2 key
curl -X PUT http://localhost:8080/demo-bucket/new.txt --data "after rotation"
curl -sI http://localhost:9000/demo-bucket/new.txt | grep encrypted-dek
# x-amz-meta-encrypted-dek: vault:v2:...   ← note v2
```

### Rewrap an old object's DEK to the latest key version

```bash
OLD_DEK=$(curl -sI http://localhost:9000/demo-bucket/secret.txt \
  | grep -i "x-amz-meta-encrypted-dek" | awk '{print $2}' | tr -d '\r')

curl -s \
  -H "X-Vault-Token: root" \
  -d "{\"ciphertext\":\"$OLD_DEK\"}" \
  http://localhost:8200/v1/transit/rewrap/demo-kek \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['data']['ciphertext'])"
# → vault:v2:...   (new wrapped DEK, safe to store back in metadata)
```
