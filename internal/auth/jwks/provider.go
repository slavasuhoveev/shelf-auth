package jwks

import (
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
)

// Provider builds and serves JWKS from private key files on disk.
// It exposes only public key material (n/e) with proper kid/alg/use.
type Provider struct {
	keysDir string
	alg     jwa.SignatureAlgorithm
	maxAge  time.Duration

	mu     sync.RWMutex
	body   []byte // serialized JWKS
	etag   string // weak ETag computed from body
	loaded time.Time
}

// NewProvider creates a JWKS provider backed by private key files in keysDir.
// Only RSA private keys (PKCS#1/PKCS#8) are supported for RS256.
func NewProvider(keysDir string, alg string, maxAge time.Duration) *Provider {
	p := &Provider{
		keysDir: strings.TrimSpace(keysDir),
		alg:     jwa.SignatureAlgorithm(alg),
		maxAge:  maxAge,
	}
	_ = p.refresh() // initial load (ignore error to keep server up; will return empty set)
	return p
}

// Current returns the serialized JWKS, ETag, and cache max-age.
func (p *Provider) Current() ([]byte, string, time.Duration) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if len(p.body) == 0 {
		// Always return a valid JWKS object even if empty.
		return []byte(`{"keys":[]}`), `W/"jwks-empty"`, p.maxAge
	}
	return p.body, p.etag, p.maxAge
}

// refresh scans the directory, builds a jwk.Set, and caches the serialized JSON.
// It is safe to call multiple times (e.g., from a file watcher or cron).
func (p *Provider) refresh() error {
	pubKeys, err := p.loadPublicJWKs()
	if err != nil {
		// On error, keep previous body if present.
		return err
	}
	set := jwk.NewSet()
	for _, k := range pubKeys {
		set.AddKey(k)
	}
	payload, err := json.Marshal(set)
	if err != nil {
		return err
	}

	etag := weakETag(payload)

	p.mu.Lock()
	p.body = payload
	p.etag = etag
	p.loaded = time.Now()
	p.mu.Unlock()

	return nil
}

func (p *Provider) loadPublicJWKs() ([]jwk.Key, error) {
	if p.keysDir == "" {
		return nil, errors.New("keys dir is empty")
	}
	var jwks []jwk.Key

	err := filepath.WalkDir(p.keysDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			// Skip unreadable entries but continue walking.
			return nil
		}
		if d.IsDir() {
			return nil
		}
		// Consider only .pem files
		if !strings.HasSuffix(strings.ToLower(d.Name()), ".pem") {
			return nil
		}
		// kid is derived from filename without extension (e.g., k1-2025-08-25.pem)
		kid := strings.TrimSuffix(d.Name(), filepath.Ext(d.Name()))

		priv, perr := loadRSAPrivateKeyPEM(path)
		if perr != nil {
			return nil // skip malformed key; do not fail whole set
		}
		pub := &priv.PublicKey
		jwkKey, jerr := jwk.FromRaw(pub)
		if jerr != nil {
			return nil
		}
		_ = jwkKey.Set(jwk.KeyIDKey, kid)
		_ = jwkKey.Set(jwk.KeyUsageKey, "sig")
		_ = jwkKey.Set(jwk.AlgorithmKey, p.alg)
		jwks = append(jwks, jwkKey)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return jwks, nil
}

func loadRSAPrivateKeyPEM(path string) (*rsa.PrivateKey, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(b)
	if block == nil {
		return nil, errors.New("no PEM block found")
	}
	// Try PKCS#1 first.
	if k, e := x509.ParsePKCS1PrivateKey(block.Bytes); e == nil {
		return k, nil
	}
	// Fallback to PKCS#8.
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	rsaKey, ok := key.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("not an RSA private key")
	}
	return rsaKey, nil
}

func weakETag(b []byte) string {
	h := sha256.Sum256(b)
	// Use first 16 bytes to keep ETag short.
	return `W/"` + hex.EncodeToString(h[:16]) + `"`
}
