package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

type vaultClient struct {
	addr    string
	token   string
	keyName string
}

type dataKey struct {
	Plaintext  []byte // raw DEK bytes — never persisted
	Ciphertext string // vault:v1:… — stored in object metadata
}

func newVaultClient(addr, token, keyName string) *vaultClient {
	return &vaultClient{addr: addr, token: token, keyName: keyName}
}

// generateDataKey calls transit/datakey/plaintext/<key> to obtain a fresh AES-256 DEK.
func (v *vaultClient) generateDataKey() (dataKey, error) {
	url := fmt.Sprintf("%s/v1/transit/datakey/plaintext/%s", v.addr, v.keyName)
	body, err := v.post(url, `{"bits":256}`)
	if err != nil {
		return dataKey{}, err
	}

	var resp struct {
		Data struct {
			Plaintext  string `json:"plaintext"`
			Ciphertext string `json:"ciphertext"`
		} `json:"data"`
	}
	if err := json.Unmarshal([]byte(body), &resp); err != nil {
		return dataKey{}, fmt.Errorf("parse vault datakey response: %w", err)
	}

	pt, err := base64.StdEncoding.DecodeString(resp.Data.Plaintext)
	if err != nil {
		return dataKey{}, fmt.Errorf("decode DEK plaintext: %w", err)
	}
	return dataKey{Plaintext: pt, Ciphertext: resp.Data.Ciphertext}, nil
}

// decryptDataKey calls transit/decrypt/<key> to unwrap a stored encrypted DEK.
func (v *vaultClient) decryptDataKey(encryptedDek string) ([]byte, error) {
	url := fmt.Sprintf("%s/v1/transit/decrypt/%s", v.addr, v.keyName)
	body, err := v.post(url, fmt.Sprintf(`{"ciphertext":%q}`, encryptedDek))
	if err != nil {
		return nil, err
	}

	var resp struct {
		Data struct {
			Plaintext string `json:"plaintext"`
		} `json:"data"`
	}
	if err := json.Unmarshal([]byte(body), &resp); err != nil {
		return nil, fmt.Errorf("parse vault decrypt response: %w", err)
	}

	return base64.StdEncoding.DecodeString(resp.Data.Plaintext)
}

func (v *vaultClient) post(url, reqBody string) (string, error) {
	req, err := http.NewRequest(http.MethodPost, url, strings.NewReader(reqBody))
	if err != nil {
		return "", err
	}
	req.Header.Set("X-Vault-Token", v.token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("vault request to %s: %w", url, err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("vault returned %d: %s", resp.StatusCode, respBody)
	}
	return string(respBody), nil
}
