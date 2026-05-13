//go:build unit

package signer

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/lestrrat-go/jwx/v2/jwt"

	"github.com/slavasuhoveev/shelf-auth/internal/tokens"
)

func writeTestKey(t *testing.T, dir, kid string) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	path := filepath.Join(dir, kid+".pem")
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("create pem: %v", err)
	}
	defer f.Close()
	if err := pem.Encode(f, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}); err != nil {
		t.Fatalf("pem encode: %v", err)
	}
}

func TestSigner_SignAccess_BasicClaims(t *testing.T) {
	tmp := t.TempDir()
	const kid = "k-test-1"
	writeTestKey(t, tmp, kid)

	ttl := 15 * time.Minute
	iss := "shelf-auth"
	aud := "shelf-api"

	s := New(tmp, kid, "RS256", ttl, iss, aud)

	cl := tokens.AccessClaims{
		UserID: uuid.NewString(),
		Email:  "user@example.com",
	}

	token, exp, err := s.SignAccess(cl, ttl)
	if err != nil {
		t.Fatalf("SignAccess: %v", err)
	}
	if token == "" {
		t.Fatalf("empty token")
	}
	if exp.Sub(time.Now().UTC()) > ttl+time.Minute || exp.Sub(time.Now().UTC()) < ttl-time.Minute {
		t.Fatalf("unexpected exp vs ttl: exp=%v ttl=%v", exp, ttl)
	}

	// Parse without verification to inspect claims quickly
	parsed, err := jwt.ParseString(token, jwt.WithVerify(false))
	if err != nil {
		t.Fatalf("parse jwt (no verify): %v", err)
	}

	// Check standard claims
	if got, _ := parsed.Get(jwt.IssuerKey); got != iss {
		t.Fatalf("iss mismatch: %v", got)
	}
	if got, _ := parsed.Get(jwt.AudienceKey); gotStr(got) != aud {
		t.Fatalf("aud mismatch: %v", got)
	}
	if got, _ := parsed.Get(jwt.SubjectKey); got != cl.UserID {
		t.Fatalf("sub mismatch: %v", got)
	}

	// Check custom claims
	if got, _ := parsed.Get("email"); got != cl.Email {
		t.Fatalf("email mismatch: %v", got)
	}
	if got, _ := parsed.Get("uid"); got != cl.UserID {
		t.Fatalf("uid mismatch: %v", got)
	}
}

func TestSigner_SignAccess_UnknownKID(t *testing.T) {
	tmp := t.TempDir()
	// intentionally do NOT write a key for kid
	s := New(tmp, "missing-kid", "RS256", 15*time.Minute, "iss", "aud")

	_, _, err := s.SignAccess(tokens.AccessClaims{UserID: uuid.NewString(), Email: "e@x"}, 15*time.Minute)
	if err == nil || !strings.Contains(err.Error(), "signing key not found") {
		t.Fatalf("expected signing key not found error, got: %v", err)
	}
}

func gotStr(audAny any) string {
	// jwx stores audience as []string
	if s, ok := audAny.(string); ok {
		return s
	}
	if sl, ok := audAny.([]string); ok && len(sl) > 0 {
		return sl[0]
	}
	return ""
}
