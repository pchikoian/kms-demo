package main

import (
	"bytes"
	"testing"
)

func dek32() []byte {
	k := make([]byte, 32)
	for i := range k {
		k[i] = byte(i + 1)
	}
	return k
}

func TestAesGcmRoundTrip(t *testing.T) {
	dek := dek32()
	plain := []byte("the quick brown fox jumps over the lazy dog")

	ct, err := aesGcmEncrypt(dek, plain)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if bytes.Equal(ct, plain) {
		t.Error("ciphertext must differ from plaintext")
	}

	got, err := aesGcmDecrypt(dek, ct)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if !bytes.Equal(got, plain) {
		t.Errorf("round-trip mismatch: want %q, got %q", plain, got)
	}
}

func TestAesGcmEmptyPlaintext(t *testing.T) {
	dek := dek32()
	ct, err := aesGcmEncrypt(dek, []byte{})
	if err != nil {
		t.Fatalf("encrypt empty: %v", err)
	}
	got, err := aesGcmDecrypt(dek, ct)
	if err != nil {
		t.Fatalf("decrypt empty: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("want empty plaintext, got %d bytes", len(got))
	}
}

// Each call must produce a different ciphertext (random nonce).
func TestAesGcmRandomNonce(t *testing.T) {
	dek := dek32()
	plain := []byte("same input")
	ct1, _ := aesGcmEncrypt(dek, plain)
	ct2, _ := aesGcmEncrypt(dek, plain)
	if bytes.Equal(ct1, ct2) {
		t.Error("same plaintext produced identical ciphertexts — nonce must be random")
	}
}

func TestAesGcmEncryptRejectsShortKey(t *testing.T) {
	_, err := aesGcmEncrypt(make([]byte, 16), []byte("data"))
	if err == nil {
		t.Error("expected error for 16-byte key")
	}
}

func TestAesGcmDecryptRejectsShortKey(t *testing.T) {
	_, err := aesGcmDecrypt(make([]byte, 16), make([]byte, 64))
	if err == nil {
		t.Error("expected error for 16-byte key")
	}
}

func TestAesGcmDecryptTooShort(t *testing.T) {
	// Exactly nonceSize bytes — no room for ciphertext+tag.
	_, err := aesGcmDecrypt(dek32(), make([]byte, nonceSize))
	if err == nil {
		t.Error("expected error: ciphertext too short")
	}
}

func TestAesGcmDecryptTamperedTag(t *testing.T) {
	dek := dek32()
	ct, _ := aesGcmEncrypt(dek, []byte("secret"))
	ct[len(ct)-1] ^= 0xFF // flip last byte of GCM auth tag
	_, err := aesGcmDecrypt(dek, ct)
	if err == nil {
		t.Error("expected authentication error for tampered ciphertext")
	}
}

func TestAesGcmDecryptTamperedNonce(t *testing.T) {
	dek := dek32()
	ct, _ := aesGcmEncrypt(dek, []byte("secret"))
	ct[0] ^= 0xFF // flip first byte of nonce
	_, err := aesGcmDecrypt(dek, ct)
	if err == nil {
		t.Error("expected authentication error for tampered nonce")
	}
}

func TestAesGcmDecryptWrongKey(t *testing.T) {
	dek1 := dek32()
	dek2 := make([]byte, 32)
	for i := range dek2 {
		dek2[i] = 0xFF
	}
	ct, _ := aesGcmEncrypt(dek1, []byte("secret"))
	_, err := aesGcmDecrypt(dek2, ct)
	if err == nil {
		t.Error("expected error when decrypting with wrong key")
	}
}
