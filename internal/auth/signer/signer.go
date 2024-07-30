package signer

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

// Signer signs access tokens with RS256 using a selected private key (by kid).
// It loads all PEM keys from keysDir and keeps them in memory.
type Signer struct {
	keysDir string
	alg     jwa.SignatureAlgorithm
	kid     string
	ttl     time.Duration

	mu    sync.RWMutex
	keys  map[string]*rsa.PrivateKey // kid -> private key
	ready bool
}

// New creates a Signer that uses keys in keysDir and signs with the provided kid.
// alg must be "RS256".
func New(keysDir, kid, alg string, ttl time.Duration) *Signer {
	s := &Signer{
		keysDir: keysDir,
		alg:     jwa.SignatureAlgorithm(alg),
		kid:     kid,
		ttl:     ttl,
		keys:    make(map[string]*rsa.PrivateKey),
	}
	_ = s.reload()
	return s
}

// reload scans keysDir for .pem files and populates the key map.
func (s *Signer) reload() error {
	files, err := os.ReadDir(s.keysDir)
	if err != nil {
		return err
	}
	tmp := make(map[string]*rsa.PrivateKey)
	for _, f := range files {
		if f.IsDir() {
			continue
		}
		if !strings.HasSuffix(strings.ToLower(f.Name()), ".pem") {
			continue
		}
		kid := strings.TrimSuffix(f.Name(), filepath.Ext(f.Name()))
		priv, err := loadRSAPrivate(filepath.Join(s.keysDir, f.Name()))
		if err != nil {
			continue // skip malformed
		}
		tmp[kid] = priv
	}

	s.mu.Lock()
	s.keys = tmp
	s.ready = len(tmp) > 0
	s.mu.Unlock()
	return nil
}

// SignAccess issues a signed JWT with standard and custom claims.
// roles is optional and may be empty.
func (s *Signer) SignAccess(sub, iss, aud string, roles []string) (string, error) {
	s.mu.RLock()
	priv, ok := s.keys[s.kid]
	alg := s.alg
	ttl := s.ttl
	s.mu.RUnlock()

	if !ok {
		return "", fmt.Errorf("signing key not found: kid=%s", s.kid)
	}

	now := time.Now()
	t := jwt.New()
	_ = t.Set(jwt.IssuerKey, iss)
	_ = t.Set(jwt.AudienceKey, aud)
	_ = t.Set(jwt.SubjectKey, sub)
	_ = t.Set(jwt.IssuedAtKey, now)
	_ = t.Set(jwt.ExpirationKey, now.Add(ttl))
	if len(roles) > 0 {
		_ = t.Set("roles", roles)
	}

	// Attach protected header with kid and alg.
	hdr := jws.NewHeaders()
	_ = hdr.Set(jws.KeyIDKey, s.kid)
	_ = hdr.Set(jws.AlgorithmKey, alg)

	b, err := jwt.Sign(t, jwt.WithKey(alg, priv, jws.WithProtectedHeaders(hdr)))
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func loadRSAPrivate(path string) (*rsa.PrivateKey, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(b)
	if block == nil {
		return nil, errors.New("no PEM block")
	}
	if k, e := x509.ParsePKCS1PrivateKey(block.Bytes); e == nil {
		return k, nil
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	rsaKey, ok := key.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("not RSA private key")
	}
	return rsaKey, nil
}
