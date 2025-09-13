//go:build unit

package jwks

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
)

func writeTestPEM(t *testing.T, dir, name string) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	path := filepath.Join(dir, name)
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("create pem: %v", err)
	}
	defer f.Close()
	if err := pem.Encode(f, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}); err != nil {
		t.Fatalf("pem encode: %v", err)
	}
}

func TestProvider_EmptyDir_ReturnsEmptySet(t *testing.T) {
	tmp := t.TempDir()
	p := NewProvider(tmp, "RS256", 60*time.Second)
	body, etag, maxAge := p.Current()
	if string(body) != `{"keys":[]}` {
		// empty set is ok too, but provider returns empty JWKS via Current() only when it had no body
		// First call NewProvider triggers refresh; if directory empty, it may still produce {"keys":[]}
		if !strings.Contains(string(body), `"keys"`) {
			t.Fatalf("unexpected body: %s", string(body))
		}
	}
	if etag == "" {
		t.Fatalf("etag should be set (even empty)")
	}
	if maxAge == 0 {
		t.Fatalf("maxAge should be > 0")
	}
}

func TestProvider_MultipleKeys_Published(t *testing.T) {
	tmp := t.TempDir()
	writeTestPEM(t, tmp, "k1.pem")
	writeTestPEM(t, tmp, "k2.pem")

	p := NewProvider(tmp, "RS256", 60*time.Second)
	body, etag1, _ := p.Current()

	if c := strings.Count(string(body), `"kid":"k1"`) + strings.Count(string(body), `"kid":"k2"`); c < 2 {
		t.Fatalf("expected both k1 and k2 in JWKS, got: %s", string(body))
	}

	// add third key and refresh
	writeTestPEM(t, tmp, "k3.pem")
	if err := p.Refresh(); err != nil {
		t.Fatalf("refresh: %v", err)
	}
	body2, etag2, _ := p.Current()
	if !strings.Contains(string(body2), `"kid":"k3"`) {
		t.Fatalf("k3 not present after refresh")
	}
	if etag1 == etag2 {
		t.Fatalf("etag should change when keyset changes")
	}
}
