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
	originalDirector := rp.Director

	rp.Director = func(r *http.Request) {
		originalDirector(r)

		// Strip any incoming Authorization header before re-signing.
		r.Header.Del("Authorization")
		r.Header.Del("X-Amz-Security-Token")

		v, _ := creds.Get()
		*r = *signer.SignV4(*r, v.AccessKeyID, v.SecretAccessKey, v.SessionToken, "us-east-1")
	}

	return rp
}
