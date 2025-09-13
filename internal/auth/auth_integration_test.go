//go:build integration

package auth_integration

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"

	"github.com/slavasuhoveev/shelf-auth/internal/auth/jwks"
	"github.com/slavasuhoveev/shelf-auth/internal/auth/signer"
	"github.com/slavasuhoveev/shelf-auth/internal/tokens"
)

func TestEndToEnd_SignAndVerifyViaJWKS(t *testing.T) {
	tmp := t.TempDir()
	const kid = "k-int-1"

	// write PEM
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	path := filepath.Join(tmp, kid+".pem")
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("create pem: %v", err)
	}
	defer f.Close()
	if err := pem.Encode(f, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}); err != nil {
		t.Fatalf("pem encode: %v", err)
	}

	// init signer and jwks
	ttl := 5 * time.Minute
	iss, aud := "shelf-auth", "shelf-api"
	s := signer.New(tmp, kid, "RS256", ttl, iss, aud)
	p := jwks.NewProvider(tmp, "RS256", 60*time.Second)

	// sign
	cl := tokens.AccessClaims{UserID: 7, Email: "u7@example.com"}
	token, _, err := s.SignAccess(cl, ttl)
	if err != nil {
		t.Fatalf("SignAccess: %v", err)
	}

	// build jwk.Set from provider body
	body, _, _ := p.Current()
	set, err := jwk.Parse(body)
	if err != nil {
		t.Fatalf("parse jwks: %v", err)
	}

	// verify
	parsed, err := jwt.ParseString(token, jwt.WithKeySet(set), jwt.WithValidate(true))
	if err != nil {
		t.Fatalf("verify jwt with jwks: %v", err)
	}
	if got, _ := parsed.Get("uid"); toInt64(got) != int64(7) {
		t.Fatalf("uid claim mismatch: %v", got)
	}
	if got, _ := parsed.Get("email"); got != "u7@example.com" {
		t.Fatalf("email claim mismatch: %v", got)
	}

	// just for sanity: token must be valid "now"
	if err := jwt.Validate(parsed, jwt.WithAcceptableSkew(0)); err != nil {
		t.Fatalf("validate now: %v", err)
	}

	// demonstrate provider auto-refresh works (optional)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go p.StartAutoRefresh(ctx, 50*time.Millisecond)
	time.Sleep(120 * time.Millisecond) // let it tick at least once
}

func toInt64(v any) int64 {
	switch x := v.(type) {
	case int64:
		return x
	case int:
		return int64(x)
	case float64:
		return int64(x)
	case json.Number:
		if n, err := x.Int64(); err == nil {
			return n
		}
	}
	if s, ok := v.(string); ok {
		if n, err := strconv.ParseInt(s, 10, 64); err == nil {
			return n
		}
	}
	return 0
}
