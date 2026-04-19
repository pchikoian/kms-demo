# ── build stage ───────────────────────────────────────────────────────────────
FROM golang:1.22-alpine AS builder

WORKDIR /app

COPY go.mod *.go ./
RUN go mod tidy && \
    CGO_ENABLED=0 GOOS=linux go build -trimpath -o s3proxy .

# ── runtime stage ─────────────────────────────────────────────────────────────
FROM alpine:3.19

RUN apk add --no-cache ca-certificates

WORKDIR /app
COPY --from=builder /app/s3proxy .

EXPOSE 8080
ENTRYPOINT ["./s3proxy"]
