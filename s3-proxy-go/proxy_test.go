package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/minio/minio-go/v7"
)

// ── fakes ─────────────────────────────────────────────────────────────────────

type fakeVault struct {
	dek    dataKey
	genErr error
	decErr error
	decFn  func(string) ([]byte, error)
}

func (f *fakeVault) generateDataKey(_ context.Context) (dataKey, error) {
	return f.dek, f.genErr
}

func (f *fakeVault) decryptDataKey(_ context.Context, enc string) ([]byte, error) {
	if f.decFn != nil {
		return f.decFn(enc)
	}
	return f.dek.Plaintext, f.decErr
}

type fakeObj struct {
	data []byte
	meta map[string]string
	ct   string
}

type fakeStore struct {
	objects map[string]fakeObj
	putErr  error
	statErr error
	getErr  error
}

func newFakeStore() *fakeStore {
	return &fakeStore{objects: make(map[string]fakeObj)}
}

func (s *fakeStore) PutObject(_ context.Context, bucket, key string, r io.Reader, _ int64, opts minio.PutObjectOptions) (minio.UploadInfo, error) {
	if s.putErr != nil {
		return minio.UploadInfo{}, s.putErr
	}
	data, _ := io.ReadAll(r)
	s.objects[bucket+"/"+key] = fakeObj{data: data, meta: opts.UserMetadata, ct: opts.ContentType}
	return minio.UploadInfo{}, nil
}

func (s *fakeStore) StatObject(_ context.Context, bucket, key string, _ minio.StatObjectOptions) (minio.ObjectInfo, error) {
	if s.statErr != nil {
		return minio.ObjectInfo{}, s.statErr
	}
	obj, ok := s.objects[bucket+"/"+key]
	if !ok {
		return minio.ObjectInfo{}, errors.New("object not found")
	}
	return minio.ObjectInfo{
		UserMetadata: obj.meta,
		ContentType:  obj.ct,
		Size:         int64(len(obj.data)),
	}, nil
}

func (s *fakeStore) GetObject(_ context.Context, bucket, key string, _ minio.GetObjectOptions) (io.ReadCloser, error) {
	if s.getErr != nil {
		return nil, s.getErr
	}
	obj, ok := s.objects[bucket+"/"+key]
	if !ok {
		return nil, errors.New("object not found")
	}
	return io.NopCloser(bytes.NewReader(obj.data)), nil
}

// captureHandler records whether a request reached passthru and replies with
// a distinctive 418 so tests can assert routing.
type captureHandler struct{ received *http.Request }

func (c *captureHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	c.received = r
	w.WriteHeader(http.StatusTeapot)
}

// ── helpers ───────────────────────────────────────────────────────────────────

func testHandler(vault vaultService, store minioClient, passthru http.Handler) *handler {
	if passthru == nil {
		passthru = http.NotFoundHandler()
	}
	return &handler{mc: store, vault: vault, passthru: passthru}
}

func fixedDEK() []byte {
	k := make([]byte, 32)
	for i := range k {
		k[i] = byte(i + 1)
	}
	return k
}

// storeEncrypted pre-populates the fake store with an already-encrypted object.
func storeEncrypted(t *testing.T, store *fakeStore, bucket, key string, plain, dek []byte, contentType string) {
	t.Helper()
	ct, err := aesGcmEncrypt(dek, plain)
	if err != nil {
		t.Fatalf("pre-encrypt: %v", err)
	}
	meta := map[string]string{metaKeyDEK: "vault:v1:enc"}
	if contentType != "" {
		meta[metaKeyContentType] = contentType
	}
	store.objects[bucket+"/"+key] = fakeObj{data: ct, meta: meta}
}

// ── parsePath ─────────────────────────────────────────────────────────────────

func TestParsePath(t *testing.T) {
	cases := []struct {
		path       string
		wantBucket string
		wantKey    string
	}{
		{"", "", ""},
		{"/", "", ""},
		{"/bucket", "bucket", ""},
		{"/bucket/", "bucket", ""},
		{"/bucket/key", "bucket", "key"},
		{"/bucket/dir/sub/file.txt", "bucket", "dir/sub/file.txt"},
	}
	for _, tc := range cases {
		b, k := parsePath(tc.path)
		if b != tc.wantBucket || k != tc.wantKey {
			t.Errorf("parsePath(%q) = (%q, %q), want (%q, %q)",
				tc.path, b, k, tc.wantBucket, tc.wantKey)
		}
	}
}

// ── getUserMeta ───────────────────────────────────────────────────────────────

func TestGetUserMeta(t *testing.T) {
	meta := map[string]string{
		"Encrypted-Dek":         "vault:v1:abc",
		"Original-Content-Type": "text/html",
	}
	cases := []struct {
		key  string
		want string
	}{
		{"encrypted-dek", "vault:v1:abc"},
		{"ENCRYPTED-DEK", "vault:v1:abc"},
		{"Encrypted-Dek", "vault:v1:abc"},
		{"original-content-type", "text/html"},
		{"missing-key", ""},
	}
	for _, tc := range cases {
		if got := getUserMeta(meta, tc.key); got != tc.want {
			t.Errorf("getUserMeta(%q) = %q, want %q", tc.key, got, tc.want)
		}
	}
	if got := getUserMeta(nil, "any"); got != "" {
		t.Errorf("nil map: want empty, got %q", got)
	}
}

// ── PUT object ────────────────────────────────────────────────────────────────

func TestPutObject_Success(t *testing.T) {
	dek := fixedDEK()
	vault := &fakeVault{dek: dataKey{Plaintext: dek, Ciphertext: "vault:v1:enc"}}
	store := newFakeStore()
	h := testHandler(vault, store, nil)

	plain := []byte("hello, world!")
	req := httptest.NewRequest(http.MethodPut, "/mybucket/mykey", bytes.NewReader(plain))
	req.Header.Set("Content-Type", "text/plain")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", rec.Code, rec.Body)
	}
	obj, ok := store.objects["mybucket/mykey"]
	if !ok {
		t.Fatal("object not stored in fake store")
	}
	if bytes.Equal(obj.data, plain) {
		t.Error("stored data should be ciphertext, not plaintext")
	}
	if obj.meta[metaKeyDEK] != "vault:v1:enc" {
		t.Errorf("DEK metadata wrong: %v", obj.meta)
	}
	if obj.meta[metaKeyContentType] != "text/plain" {
		t.Errorf("content-type metadata wrong: %v", obj.meta)
	}
}

func TestPutObject_NoContentTypeHeader(t *testing.T) {
	dek := fixedDEK()
	vault := &fakeVault{dek: dataKey{Plaintext: dek, Ciphertext: "x"}}
	store := newFakeStore()
	h := testHandler(vault, store, nil)

	req := httptest.NewRequest(http.MethodPut, "/b/k", strings.NewReader("data"))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", rec.Code)
	}
	obj := store.objects["b/k"]
	if _, has := obj.meta[metaKeyContentType]; has {
		t.Error("content-type metadata should be absent when request header not set")
	}
}

func TestPutObject_VaultError(t *testing.T) {
	vault := &fakeVault{genErr: errors.New("vault sealed")}
	h := testHandler(vault, newFakeStore(), nil)

	req := httptest.NewRequest(http.MethodPut, "/b/k", strings.NewReader("data"))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Errorf("want 500, got %d", rec.Code)
	}
}

func TestPutObject_MinioError(t *testing.T) {
	dek := fixedDEK()
	vault := &fakeVault{dek: dataKey{Plaintext: dek, Ciphertext: "x"}}
	store := newFakeStore()
	store.putErr = errors.New("disk full")
	h := testHandler(vault, store, nil)

	req := httptest.NewRequest(http.MethodPut, "/b/k", strings.NewReader("data"))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Errorf("want 500, got %d", rec.Code)
	}
}

// ── GET object ────────────────────────────────────────────────────────────────

func TestGetObject_Success(t *testing.T) {
	dek := fixedDEK()
	store := newFakeStore()
	storeEncrypted(t, store, "bkt", "obj", []byte("secret content"), dek, "text/plain")

	h := testHandler(&fakeVault{dek: dataKey{Plaintext: dek}}, store, nil)

	req := httptest.NewRequest(http.MethodGet, "/bkt/obj", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", rec.Code, rec.Body)
	}
	if got := rec.Body.String(); got != "secret content" {
		t.Errorf("want %q, got %q", "secret content", got)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "text/plain" {
		t.Errorf("want content-type text/plain, got %q", ct)
	}
}

func TestGetObject_DefaultContentType(t *testing.T) {
	dek := fixedDEK()
	store := newFakeStore()
	// storeEncrypted with empty contentType — no metaKeyContentType in metadata.
	storeEncrypted(t, store, "b", "k", []byte("data"), dek, "")

	h := testHandler(&fakeVault{dek: dataKey{Plaintext: dek}}, store, nil)

	req := httptest.NewRequest(http.MethodGet, "/b/k", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/octet-stream" {
		t.Errorf("want application/octet-stream default, got %q", ct)
	}
}

func TestGetObject_NoDEKMetadata(t *testing.T) {
	// Object stored without the proxy — returned raw, no decryption attempted.
	rawBody := []byte("unencrypted legacy object")
	store := newFakeStore()
	store.objects["bkt/raw"] = fakeObj{data: rawBody, meta: map[string]string{}, ct: "image/png"}

	h := testHandler(&fakeVault{}, store, nil)

	req := httptest.NewRequest(http.MethodGet, "/bkt/raw", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", rec.Code)
	}
	if !bytes.Equal(rec.Body.Bytes(), rawBody) {
		t.Error("raw body should be returned as-is when DEK metadata is absent")
	}
	if ct := rec.Header().Get("Content-Type"); ct != "image/png" {
		t.Errorf("want image/png from ObjectInfo, got %q", ct)
	}
}

func TestGetObject_StatError(t *testing.T) {
	store := newFakeStore()
	store.statErr = errors.New("key not found")
	h := testHandler(&fakeVault{}, store, nil)

	req := httptest.NewRequest(http.MethodGet, "/b/missing", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Errorf("want 404, got %d", rec.Code)
	}
}

func TestGetObject_GetError(t *testing.T) {
	dek := fixedDEK()
	store := newFakeStore()
	// StatObject succeeds (object in map) but GetObject fails.
	store.objects["b/k"] = fakeObj{data: []byte("x"), meta: map[string]string{metaKeyDEK: "y"}}
	store.getErr = errors.New("network error")
	h := testHandler(&fakeVault{dek: dataKey{Plaintext: dek}}, store, nil)

	req := httptest.NewRequest(http.MethodGet, "/b/k", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Errorf("want 500, got %d", rec.Code)
	}
}

func TestGetObject_VaultDecryptError(t *testing.T) {
	dek := fixedDEK()
	store := newFakeStore()
	storeEncrypted(t, store, "b", "k", []byte("secret"), dek, "")

	vault := &fakeVault{decErr: errors.New("vault sealed")}
	h := testHandler(vault, store, nil)

	req := httptest.NewRequest(http.MethodGet, "/b/k", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Errorf("want 500, got %d", rec.Code)
	}
}

func TestGetObject_TamperedCiphertext(t *testing.T) {
	dek := fixedDEK()
	ct, _ := aesGcmEncrypt(dek, []byte("secret"))
	ct[len(ct)-1] ^= 0xFF // corrupt auth tag

	store := newFakeStore()
	store.objects["b/k"] = fakeObj{data: ct, meta: map[string]string{metaKeyDEK: "x"}}

	h := testHandler(&fakeVault{dek: dataKey{Plaintext: dek}}, store, nil)

	req := httptest.NewRequest(http.MethodGet, "/b/k", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Errorf("want 500 on tampered ciphertext, got %d", rec.Code)
	}
}

// ── PUT → GET round-trip ──────────────────────────────────────────────────────

func TestRoundTrip(t *testing.T) {
	dek := fixedDEK()
	vault := &fakeVault{dek: dataKey{Plaintext: dek, Ciphertext: "vault:v1:enc"}}
	store := newFakeStore()
	h := testHandler(vault, store, nil)

	cases := []struct {
		name  string
		key   string
		plain string
		ct    string
	}{
		{"text", "docs/readme.txt", "hello world", "text/plain"},
		{"json", "cfg/config.json", `{"k":"v"}`, "application/json"},
		{"binary", "img/photo.jpg", "\x00\xFF\xFE\xFD", "image/jpeg"},
		{"empty", "empty/file", "", "application/octet-stream"},
		{"nested", "a/b/c/d/e.dat", "deep path", "application/octet-stream"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			putReq := httptest.NewRequest(http.MethodPut, "/bkt/"+tc.key, strings.NewReader(tc.plain))
			putReq.Header.Set("Content-Type", tc.ct)
			putRec := httptest.NewRecorder()
			h.ServeHTTP(putRec, putReq)
			if putRec.Code != http.StatusOK {
				t.Fatalf("PUT: want 200, got %d", putRec.Code)
			}

			getReq := httptest.NewRequest(http.MethodGet, "/bkt/"+tc.key, nil)
			getRec := httptest.NewRecorder()
			h.ServeHTTP(getRec, getReq)
			if getRec.Code != http.StatusOK {
				t.Fatalf("GET: want 200, got %d: %s", getRec.Code, getRec.Body)
			}
			if got := getRec.Body.String(); got != tc.plain {
				t.Errorf("round-trip: want %q, got %q", tc.plain, got)
			}
			if got := getRec.Header().Get("Content-Type"); got != tc.ct {
				t.Errorf("content-type: want %q, got %q", tc.ct, got)
			}
		})
	}
}

// ── passthru routing ──────────────────────────────────────────────────────────

func TestPassthru_DeleteObject(t *testing.T) {
	cap := &captureHandler{}
	h := testHandler(&fakeVault{}, newFakeStore(), cap)

	req := httptest.NewRequest(http.MethodDelete, "/bucket/key", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusTeapot {
		t.Errorf("DELETE /bucket/key: want passthru (418), got %d", rec.Code)
	}
	if cap.received == nil {
		t.Error("request did not reach passthru handler")
	}
}

func TestPassthru_HeadObject(t *testing.T) {
	cap := &captureHandler{}
	h := testHandler(&fakeVault{}, newFakeStore(), cap)

	req := httptest.NewRequest(http.MethodHead, "/bucket/key", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusTeapot {
		t.Errorf("HEAD /bucket/key: want passthru (418), got %d", rec.Code)
	}
}

func TestPassthru_ListObjects(t *testing.T) {
	cap := &captureHandler{}
	h := testHandler(&fakeVault{}, newFakeStore(), cap)

	// GET /bucket (no object key) — list operation
	req := httptest.NewRequest(http.MethodGet, "/bucket", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusTeapot {
		t.Errorf("GET /bucket: want passthru (418), got %d", rec.Code)
	}
}

func TestPassthru_CreateBucket(t *testing.T) {
	cap := &captureHandler{}
	h := testHandler(&fakeVault{}, newFakeStore(), cap)

	req := httptest.NewRequest(http.MethodPut, "/newbucket", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusTeapot {
		t.Errorf("PUT /newbucket: want passthru (418), got %d", rec.Code)
	}
}

func TestPassthru_DeleteBucket(t *testing.T) {
	cap := &captureHandler{}
	h := testHandler(&fakeVault{}, newFakeStore(), cap)

	req := httptest.NewRequest(http.MethodDelete, "/bucket", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusTeapot {
		t.Errorf("DELETE /bucket: want passthru (418), got %d", rec.Code)
	}
}

func TestPassthru_RootListBuckets(t *testing.T) {
	cap := &captureHandler{}
	h := testHandler(&fakeVault{}, newFakeStore(), cap)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusTeapot {
		t.Errorf("GET /: want passthru (418), got %d", rec.Code)
	}
}
