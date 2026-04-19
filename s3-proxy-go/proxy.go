package main

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
)

// Metadata keys stored alongside every encrypted object.
// Must match the Java implementation (EncryptingBlobStore.java).
const (
	metaKeyDEK         = "encrypted-dek"
	metaKeyContentType = "original-content-type"
)

// handler is the core HTTP handler. It intercepts PUT and GET for object
// paths to apply transparent AES-256-GCM encryption, and forwards everything
// else (bucket ops, list, delete, head) directly to MinIO.
type handler struct {
	mc       *minio.Client
	vault    *vaultClient
	passthru http.Handler
}

func newHandler(cfg config, vault *vaultClient) (*handler, error) {
	u, err := url.Parse(cfg.MinioEndpoint)
	if err != nil {
		return nil, fmt.Errorf("parse MinIO endpoint: %w", err)
	}

	mc, err := minio.New(u.Host, &minio.Options{
		Creds:  credentials.NewStaticV4(cfg.MinioAccessKey, cfg.MinioSecretKey, ""),
		Secure: u.Scheme == "https",
	})
	if err != nil {
		return nil, fmt.Errorf("minio client: %w", err)
	}

	return &handler{
		mc:       mc,
		vault:    vault,
		passthru: newPassthru(u, cfg.MinioAccessKey, cfg.MinioSecretKey),
	}, nil
}

func (h *handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	bucket, key := parsePath(r.URL.Path)

	switch {
	case key != "" && r.Method == http.MethodPut:
		h.putObject(w, r, bucket, key)
	case key != "" && r.Method == http.MethodGet:
		h.getObject(w, r, bucket, key)
	default:
		h.passthru.ServeHTTP(w, r)
	}
}

// ── PUT: encrypt then store ───────────────────────────────────────────────────

func (h *handler) putObject(w http.ResponseWriter, r *http.Request, bucket, key string) {
	plaintext, err := io.ReadAll(r.Body)
	if err != nil {
		httpErr(w, "read body", err, http.StatusBadRequest)
		return
	}

	dk, err := h.vault.generateDataKey()
	if err != nil {
		httpErr(w, "generate DEK", err, http.StatusInternalServerError)
		return
	}

	ciphertext, err := aesGcmEncrypt(dk.Plaintext, plaintext)
	if err != nil {
		httpErr(w, "encrypt", err, http.StatusInternalServerError)
		return
	}

	meta := map[string]string{metaKeyDEK: dk.Ciphertext}
	if ct := r.Header.Get("Content-Type"); ct != "" {
		meta[metaKeyContentType] = ct
	}

	_, err = h.mc.PutObject(context.Background(), bucket, key,
		bytes.NewReader(ciphertext), int64(len(ciphertext)),
		minio.PutObjectOptions{
			ContentType:  "application/octet-stream",
			UserMetadata: meta,
		},
	)
	if err != nil {
		httpErr(w, "store object", err, http.StatusInternalServerError)
		return
	}

	slog.Info("PUT", "bucket", bucket, "key", key,
		"plaintext_bytes", len(plaintext), "ciphertext_bytes", len(ciphertext))
	w.WriteHeader(http.StatusOK)
}

// ── GET: fetch then decrypt ───────────────────────────────────────────────────

func (h *handler) getObject(w http.ResponseWriter, r *http.Request, bucket, key string) {
	info, err := h.mc.StatObject(context.Background(), bucket, key, minio.StatObjectOptions{})
	if err != nil {
		httpErr(w, "stat object", err, http.StatusNotFound)
		return
	}

	obj, err := h.mc.GetObject(context.Background(), bucket, key, minio.GetObjectOptions{})
	if err != nil {
		httpErr(w, "get object", err, http.StatusInternalServerError)
		return
	}
	defer obj.Close()

	ciphertext, err := io.ReadAll(obj)
	if err != nil {
		httpErr(w, "read object body", err, http.StatusInternalServerError)
		return
	}

	encDEK := getUserMeta(info.UserMetadata, metaKeyDEK)
	if encDEK == "" {
		// Object not written through this proxy — return as-is.
		slog.Warn("no DEK metadata, returning raw object", "bucket", bucket, "key", key)
		w.Header().Set("Content-Type", info.ContentType)
		_, _ = w.Write(ciphertext)
		return
	}

	dek, err := h.vault.decryptDataKey(encDEK)
	if err != nil {
		httpErr(w, "decrypt DEK", err, http.StatusInternalServerError)
		return
	}

	plaintext, err := aesGcmDecrypt(dek, ciphertext)
	if err != nil {
		httpErr(w, "decrypt object", err, http.StatusInternalServerError)
		return
	}

	ct := getUserMeta(info.UserMetadata, metaKeyContentType)
	if ct == "" {
		ct = "application/octet-stream"
	}

	slog.Info("GET", "bucket", bucket, "key", key,
		"ciphertext_bytes", len(ciphertext), "plaintext_bytes", len(plaintext))
	w.Header().Set("Content-Type", ct)
	_, _ = w.Write(plaintext)
}

// ── helpers ───────────────────────────────────────────────────────────────────

// parsePath splits /bucket/key into its two components.
func parsePath(path string) (bucket, key string) {
	parts := strings.SplitN(strings.TrimPrefix(path, "/"), "/", 2)
	if len(parts) == 0 || parts[0] == "" {
		return "", ""
	}
	bucket = parts[0]
	if len(parts) > 1 {
		key = parts[1]
	}
	return
}

// getUserMeta does a case-insensitive lookup in the minio-go user metadata map.
// minio-go returns keys in canonical HTTP header form (e.g. "Encrypted-Dek"),
// so we normalise both sides to lower-case for safety.
func getUserMeta(meta map[string]string, key string) string {
	keyLower := strings.ToLower(key)
	for k, v := range meta {
		if strings.ToLower(k) == keyLower {
			return v
		}
	}
	return ""
}

func httpErr(w http.ResponseWriter, msg string, err error, code int) {
	slog.Error(msg, "err", err)
	http.Error(w, msg+": "+err.Error(), code)
}
