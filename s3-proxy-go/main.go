package main

import (
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strings"
)

func main() {
	cfg, err := configFromEnv()
	if err != nil {
		slog.Error("config", "err", err)
		os.Exit(1)
	}

	slog.Info("starting s3-proxy-go",
		"vault", cfg.VaultAddr,
		"key", cfg.VaultKey,
		"minio", cfg.MinioEndpoint,
		"listen", cfg.Listen,
	)

	vault := newVaultClient(cfg.VaultAddr, cfg.VaultToken, cfg.VaultKey)

	h, err := newHandler(cfg, vault)
	if err != nil {
		slog.Error("init handler", "err", err)
		os.Exit(1)
	}

	slog.Info("ready", "addr", cfg.Listen)
	if err := http.ListenAndServe(cfg.Listen, h); err != nil {
		slog.Error("serve", "err", err)
		os.Exit(1)
	}
}

// ── Config ────────────────────────────────────────────────────────────────────

type config struct {
	Listen         string
	VaultAddr      string
	VaultToken     string
	VaultKey       string
	MinioEndpoint  string
	MinioAccessKey string
	MinioSecretKey string
}

func configFromEnv() (config, error) {
	token := getenv("S3PROXY_VAULT_TOKEN", "")
	if token == "" {
		data, err := os.ReadFile("/shared/s3proxy-token")
		if err == nil {
			token = strings.TrimSpace(string(data))
		}
	}
	if token == "" {
		return config{}, fmt.Errorf(
			"no Vault token: set S3PROXY_VAULT_TOKEN or write to /shared/s3proxy-token")
	}
	return config{
		Listen:         getenv("S3PROXY_LISTEN", ":8080"),
		VaultAddr:      getenv("S3PROXY_VAULT_ADDR", "http://vault:8200"),
		VaultToken:     token,
		VaultKey:       getenv("S3PROXY_VAULT_KEY", "demo-kek"),
		MinioEndpoint:  getenv("S3PROXY_MINIO_ENDPOINT", "http://minio:9000"),
		MinioAccessKey: getenv("S3PROXY_MINIO_ACCESS_KEY", "minioadmin"),
		MinioSecretKey: getenv("S3PROXY_MINIO_SECRET_KEY", "minioadmin"),
	}, nil
}

func getenv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
