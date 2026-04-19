package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// vaultService is the interface the handler depends on.
// Using an interface instead of the concrete type allows testing with a fake.
type vaultService interface {
	generateDataKey(ctx context.Context) (dataKey, error)
	decryptDataKey(ctx context.Context, encryptedDek string) ([]byte, error)
}

type vaultClient struct {
	addr    string
	token   string
	keyName string
	http    *http.Client
}

type dataKey struct {
	Plaintext  []byte // raw DEK bytes — never persisted
	Ciphertext string // vault:v1:… — stored in object metadata
}

func newVaultClient(addr, token, keyName string) *vaultClient {
	return &vaultClient{
		addr:    addr,
		token:   token,
		keyName: keyName,
		http:    &http.Client{Timeout: 10 * time.Second},
	}
}

// generateDataKey calls transit/datakey/plaintext/<key> to obtain a fresh AES-256 DEK.
func (v *vaultClient) generateDataKey(ctx context.Context) (dataKey, error) {
	url := fmt.Sprintf("%s/v1/transit/datakey/plaintext/%s", v.addr, v.keyName)
	body, err := v.post(ctx, url, map[string]any{"bits": 256})
	if err != nil {
		return dataKey{}, err
	}

	var resp struct {
		Data struct {
			Plaintext  string `json:"plaintext"`
			Ciphertext string `json:"ciphertext"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return dataKey{}, fmt.Errorf("parse vault datakey response: %w", err)
	}

	pt, err := base64.StdEncoding.DecodeString(resp.Data.Plaintext)
	if err != nil {
		return dataKey{}, fmt.Errorf("decode DEK plaintext: %w", err)
	}
	return dataKey{Plaintext: pt, Ciphertext: resp.Data.Ciphertext}, nil
}

// decryptDataKey calls transit/decrypt/<key> to unwrap a stored encrypted DEK.
func (v *vaultClient) decryptDataKey(ctx context.Context, encryptedDek string) ([]byte, error) {
	url := fmt.Sprintf("%s/v1/transit/decrypt/%s", v.addr, v.keyName)
	body, err := v.post(ctx, url, map[string]any{"ciphertext": encryptedDek})
	if err != nil {
		return nil, err
	}

	var resp struct {
		Data struct {
			Plaintext string `json:"plaintext"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("parse vault decrypt response: %w", err)
	}

	return base64.StdEncoding.DecodeString(resp.Data.Plaintext)
}

func (v *vaultClient) post(ctx context.Context, url string, payload any) ([]byte, error) {
	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(payload); err != nil {
		return nil, fmt.Errorf("encode request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, &buf)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-Vault-Token", v.token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := v.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("vault request to %s: %w", url, err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("vault returned %d: %s", resp.StatusCode, respBody)
	}
	return respBody, nil
}
