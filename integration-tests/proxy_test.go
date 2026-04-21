// Integration tests for the s3-proxy (Java or Go).
// Run against either proxy by setting PROXY_URL:
//
//	PROXY_URL=http://localhost:8081 go test ./... -v   # Go proxy
//	PROXY_URL=http://localhost:8080 go test ./... -v   # Java proxy
//
// Requires the full stack to be running (make up).
package integration

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"
)

const testBucket = "demo-bucket"

var httpClient = &http.Client{Timeout: 15 * time.Second}

func proxyURL() string {
	if u := os.Getenv("PROXY_URL"); u != "" {
		return strings.TrimRight(u, "/")
	}
	return "http://localhost:8081"
}

func objURL(key string) string {
	return fmt.Sprintf("%s/%s/%s", proxyURL(), testBucket, key)
}

// uniqueKey returns a key scoped under a per-test prefix so parallel runs
// and repeated runs don't collide.
func uniqueKey(t *testing.T) string {
	t.Helper()
	safe := strings.NewReplacer(" ", "-", "/", "-").Replace(t.Name())
	return fmt.Sprintf("it/%s/%d", safe, time.Now().UnixNano())
}

// ── HTTP helpers ──────────────────────────────────────────────────────────────

func doPut(t *testing.T, rawURL, ct string, body []byte) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodPut, rawURL, bytes.NewReader(body))
	if err != nil {
		t.Fatalf("PUT build request: %v", err)
	}
	if ct != "" {
		req.Header.Set("Content-Type", ct)
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		t.Fatalf("PUT %s: %v", rawURL, err)
	}
	return resp
}

func doGet(t *testing.T, rawURL string) *http.Response {
	t.Helper()
	resp, err := httpClient.Get(rawURL)
	if err != nil {
		t.Fatalf("GET %s: %v", rawURL, err)
	}
	return resp
}

func doDelete(t *testing.T, rawURL string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodDelete, rawURL, nil)
	if err != nil {
		t.Fatalf("DELETE build request: %v", err)
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		t.Fatalf("DELETE %s: %v", rawURL, err)
	}
	return resp
}

func doHead(t *testing.T, rawURL string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodHead, rawURL, nil)
	if err != nil {
		t.Fatalf("HEAD build request: %v", err)
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		t.Fatalf("HEAD %s: %v", rawURL, err)
	}
	return resp
}

func readBody(t *testing.T, resp *http.Response) []byte {
	t.Helper()
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	return b
}

// ── TestMain ──────────────────────────────────────────────────────────────────

// TestMain confirms the proxy is reachable before any test runs.
func TestMain(m *testing.M) {
	resp, err := httpClient.Get(fmt.Sprintf("%s/%s", proxyURL(), testBucket))
	if err != nil {
		fmt.Fprintf(os.Stderr,
			"proxy not reachable at %s: %v\nStart services with: make up\n",
			proxyURL(), err)
		os.Exit(1)
	}
	resp.Body.Close()
	os.Exit(m.Run())
}

// ── tests ─────────────────────────────────────────────────────────────────────

func TestPutAndGet(t *testing.T) {
	u := objURL(uniqueKey(t))
	t.Cleanup(func() { doDelete(t, u).Body.Close() })

	want := []byte("hello from integration test")
	resp := doPut(t, u, "text/plain", want)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("PUT: want 200, got %d", resp.StatusCode)
	}

	resp2 := doGet(t, u)
	got := readBody(t, resp2)
	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("GET: want 200, got %d", resp2.StatusCode)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("body mismatch: want %q, got %q", want, got)
	}
}

func TestContentTypePreserved(t *testing.T) {
	cases := []struct{ ct, body string }{
		{"text/plain", "plain text"},
		{"application/json", `{"key":"value"}`},
		{"image/png", "\x89PNG\r\n\x1a\n"},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.ct, func(t *testing.T) {
			u := objURL(uniqueKey(t))
			t.Cleanup(func() { doDelete(t, u).Body.Close() })

			doPut(t, u, tc.ct, []byte(tc.body)).Body.Close()

			resp := doGet(t, u)
			readBody(t, resp)
			if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, tc.ct) {
				t.Errorf("want Content-Type %q, got %q", tc.ct, ct)
			}
		})
	}
}

func TestGetNonExistent(t *testing.T) {
	u := objURL(fmt.Sprintf("it/no-such-key/%d", time.Now().UnixNano()))
	resp := doGet(t, u)
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("want 404, got %d", resp.StatusCode)
	}
}

func TestDeleteObject(t *testing.T) {
	u := objURL(uniqueKey(t))

	doPut(t, u, "text/plain", []byte("temporary")).Body.Close()

	delResp := doDelete(t, u)
	delResp.Body.Close()
	if delResp.StatusCode != http.StatusNoContent && delResp.StatusCode != http.StatusOK {
		t.Fatalf("DELETE: want 200 or 204, got %d", delResp.StatusCode)
	}

	resp := doGet(t, u)
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("GET after DELETE: want 404, got %d", resp.StatusCode)
	}
}

func TestHeadObject(t *testing.T) {
	u := objURL(uniqueKey(t))
	t.Cleanup(func() { doDelete(t, u).Body.Close() })

	body := bytes.Repeat([]byte("x"), 512)
	doPut(t, u, "application/octet-stream", body).Body.Close()

	resp := doHead(t, u)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("HEAD: want 200, got %d", resp.StatusCode)
	}
	if resp.ContentLength <= 0 {
		t.Error("HEAD: Content-Length should be positive")
	}
}

func TestEmptyObject(t *testing.T) {
	u := objURL(uniqueKey(t))
	t.Cleanup(func() { doDelete(t, u).Body.Close() })

	doPut(t, u, "application/octet-stream", []byte{}).Body.Close()

	resp := doGet(t, u)
	got := readBody(t, resp)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET empty: want 200, got %d", resp.StatusCode)
	}
	if len(got) != 0 {
		t.Errorf("want empty body, got %d bytes", len(got))
	}
}

func TestBinaryData(t *testing.T) {
	u := objURL(uniqueKey(t))
	t.Cleanup(func() { doDelete(t, u).Body.Close() })

	binary := make([]byte, 256)
	for i := range binary {
		binary[i] = byte(i)
	}
	doPut(t, u, "application/octet-stream", binary).Body.Close()

	resp := doGet(t, u)
	got := readBody(t, resp)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET binary: want 200, got %d", resp.StatusCode)
	}
	if !bytes.Equal(got, binary) {
		t.Error("binary data round-trip mismatch")
	}
}

func TestOverwriteObject(t *testing.T) {
	u := objURL(uniqueKey(t))
	t.Cleanup(func() { doDelete(t, u).Body.Close() })

	doPut(t, u, "text/plain", []byte("version 1")).Body.Close()
	doPut(t, u, "text/plain", []byte("version 2")).Body.Close()

	resp := doGet(t, u)
	got := readBody(t, resp)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET after overwrite: want 200, got %d", resp.StatusCode)
	}
	if !bytes.Equal(got, []byte("version 2")) {
		t.Errorf("want %q after overwrite, got %q", "version 2", got)
	}
}

func TestMultipleObjects(t *testing.T) {
	base := uniqueKey(t)
	suffixes := []string{"a.txt", "b.txt", "c.txt"}

	for _, s := range suffixes {
		key := base + "/" + s
		u := objURL(key)
		t.Cleanup(func() { doDelete(t, u).Body.Close() })
		doPut(t, u, "text/plain", []byte("content:"+key)).Body.Close()
	}

	for _, s := range suffixes {
		key := base + "/" + s
		resp := doGet(t, objURL(key))
		got := readBody(t, resp)
		if resp.StatusCode != http.StatusOK {
			t.Errorf("GET %s: want 200, got %d", key, resp.StatusCode)
			continue
		}
		want := []byte("content:" + key)
		if !bytes.Equal(got, want) {
			t.Errorf("GET %s: want %q, got %q", key, want, got)
		}
	}
}

func TestListObjects(t *testing.T) {
	base := uniqueKey(t)
	keys := []string{base + "/x", base + "/y", base + "/z"}

	for _, k := range keys {
		u := objURL(k)
		t.Cleanup(func() { doDelete(t, u).Body.Close() })
		doPut(t, u, "text/plain", []byte("list-test")).Body.Close()
	}

	// Use raw slashes — url.QueryEscape would encode "/" as "%2F", which
	// SignV4 then double-encodes to "%252F", causing a signature mismatch.
	listURL := fmt.Sprintf("%s/%s?prefix=%s/", proxyURL(), testBucket, base)
	resp := doGet(t, listURL)
	body := readBody(t, resp)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("list: want 200, got %d: %s", resp.StatusCode, body)
	}
	for _, k := range keys {
		if !bytes.Contains(body, []byte(k)) {
			t.Errorf("list response missing key %q", k)
		}
	}
}

func TestLargeObject(t *testing.T) {
	u := objURL(uniqueKey(t))
	t.Cleanup(func() { doDelete(t, u).Body.Close() })

	// 1 MiB of patterned data
	large := make([]byte, 1<<20)
	for i := range large {
		large[i] = byte(i % 251)
	}
	putResp := doPut(t, u, "application/octet-stream", large)
	putResp.Body.Close()
	if putResp.StatusCode != http.StatusOK {
		t.Fatalf("PUT large: want 200, got %d", putResp.StatusCode)
	}

	resp := doGet(t, u)
	got := readBody(t, resp)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET large: want 200, got %d", resp.StatusCode)
	}
	if !bytes.Equal(got, large) {
		t.Errorf("large object round-trip mismatch (%d bytes)", len(large))
	}
}
