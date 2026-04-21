package main

import (
	"net/http"
	"net/http/httputil"
	"net/url"

	"github.com/minio/minio-go/v7/pkg/credentials"
	"github.com/minio/minio-go/v7/pkg/signer"
)

// newPassthru returns an httputil.ReverseProxy that forwards requests to MinIO
// and re-signs them with the provided credentials (AWS Signature V4).
// Used for all non-object operations: bucket create/list/delete, object list,
// object head/delete, etc.
func newPassthru(target *url.URL, accessKey, secretKey string) http.Handler {
	creds := credentials.NewStaticV4(accessKey, secretKey, "")

	rp := httputil.NewSingleHostReverseProxy(target)

	// Strip incoming auth headers in the Director so they are absent when
	// the transport signs the outgoing request.
	originalDirector := rp.Director
	rp.Director = func(r *http.Request) {
		originalDirector(r)
		r.Header.Del("Authorization")
		r.Header.Del("X-Amz-Security-Token")
	}

	// Signing in the Transport runs after httputil.ReverseProxy has finished
	// all its header modifications (X-Forwarded-For, hop-by-hop removal, etc.),
	// so the signed canonical request exactly matches what MinIO receives.
	// Clearing req.Host forces both the signer and the HTTP client to use
	// req.URL.Host (minio:9000) instead of the original client Host header.
	rp.Transport = &v4Transport{base: http.DefaultTransport, creds: creds}

	return rp
}

type v4Transport struct {
	base  http.RoundTripper
	creds *credentials.Credentials
}

func (t *v4Transport) RoundTrip(req *http.Request) (*http.Response, error) {
	req = req.Clone(req.Context())
	req.Host = "" // use req.URL.Host (minio:9000) for both signing and Host header
	v, _ := t.creds.Get()
	return t.base.RoundTrip(signer.SignV4(*req, v.AccessKeyID, v.SecretAccessKey, v.SessionToken, "us-east-1"))
}
