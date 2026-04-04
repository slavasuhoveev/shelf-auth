package signer

import (
	"context"
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
	"github.com/slavasuhoveev/shelf-auth/internal/tokens"
)

// Signer signs access tokens with RS256 using a selected private key (by kid).
// It loads all PEM keys from keysDir and keeps them in memory.
type Signer struct {
	keysDir  string
	alg      jwa.SignatureAlgorithm
	kid      string
	ttl      time.Duration
	issuer   string
	audience string

	mu    sync.RWMutex
	keys  map[string]*rsa.PrivateKey // kid -> private key
	ready bool
}

// New loads all PEM keys from keysDir and signs with the provided active kid.
func New(keysDir, kid, alg string, ttl time.Duration, issuer, audience string) *Signer {
	s := &Signer{
		keysDir:  keysDir,
		alg:      jwa.SignatureAlgorithm(alg),
		kid:      kid,
		ttl:      ttl,
		issuer:   issuer,
		audience: audience,
		keys:     make(map[string]*rsa.PrivateKey),
	}
	_ = s.reload()
	return s
}

// SetActiveKid switches the active kid at runtime if it exists in memory.
// If the PEM file was just added, call Reload() first.
func (s *Signer) SetActiveKid(kid string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.keys[kid]; !ok {
		return fmt.Errorf("kid not loaded: %s", kid)
	}
	s.kid = kid
	return nil
}

// Reload rescans keysDir for .pem files and reloads the in-memory map.
func (s *Signer) Reload() error {
	return s.reload()
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

// StartAutoReload periodically reloads the keys from keysDir.
func (s *Signer) StartAutoReload(ctx context.Context, interval time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			_ = s.reload()
		}
	}
}

func (s *Signer) SignAccess(claims tokens.AccessClaims, ttl time.Duration) (string, time.Time, error) {
	s.mu.RLock()
	priv, ok := s.keys[s.kid]
	alg := s.alg
	iss := s.issuer
	aud := s.audience
	s.mu.RUnlock()

	if !ok {
		return "", time.Time{}, fmt.Errorf("signing key not found: kid=%s", s.kid)
	}

	now := time.Now().UTC()
	exp := now.Add(ttl)

	t := jwt.New()
	_ = t.Set(jwt.IssuerKey, iss)
	_ = t.Set(jwt.AudienceKey, aud)
	_ = t.Set(jwt.IssuedAtKey, now)
	_ = t.Set(jwt.NotBeforeKey, now)
	_ = t.Set(jwt.ExpirationKey, exp)

	// subject = user id as string
	_ = t.Set(jwt.SubjectKey, claims.UserID)

	// custom claims
	if claims.Email != "" {
		_ = t.Set("email", claims.Email)
	}
	_ = t.Set("uid", claims.UserID)

	hdr := jws.NewHeaders()
	_ = hdr.Set(jws.KeyIDKey, s.kid)
	_ = hdr.Set(jws.AlgorithmKey, alg)

	signed, err := jwt.Sign(t, jwt.WithKey(alg, priv, jws.WithProtectedHeaders(hdr)))
	if err != nil {
		return "", time.Time{}, err
	}
	return string(signed), exp, nil
}

func (s *Signer) VerifyAccess(tokenStr string) (*tokens.AccessClaims, error) {
	msg, err := jws.Parse([]byte(tokenStr))
	if err != nil {
		return nil, err
	}

	if len(msg.Signatures()) == 0 {
		return nil, fmt.Errorf("no signatures")
	}

	hdr := msg.Signatures()[0].ProtectedHeaders()

	kid, ok := hdr.Get(jws.KeyIDKey)
	if !ok {
		return nil, fmt.Errorf("missing kid")
	}

	kidStr, ok := kid.(string)
	if !ok {
		return nil, fmt.Errorf("invalid kid type")
	}

	s.mu.RLock()
	priv, ok := s.keys[kidStr]
	s.mu.RUnlock()

	if !ok {
		return nil, fmt.Errorf("unknown kid: %s", kidStr)
	}

	tok, err := jwt.Parse(
		[]byte(tokenStr),
		jwt.WithKey(jwa.RS256, &priv.PublicKey),
	)
	if err != nil {
		return nil, err
	}

	if err := jwt.Validate(
		tok,
		jwt.WithIssuer(s.issuer),
		jwt.WithAudience(s.audience),
		jwt.WithAcceptableSkew(5*time.Second),
	); err != nil {
		return nil, err
	}

	sub, ok := tok.Get(jwt.SubjectKey)
	if !ok {
		return nil, fmt.Errorf("missing sub")
	}

	userID, ok := sub.(string)
	if !ok || userID == "" {
		return nil, fmt.Errorf("invalid sub")
	}

	emailVal, _ := tok.Get("email")
	email, _ := emailVal.(string)

	return &tokens.AccessClaims{
		UserID: userID,
		Email:  email,
	}, nil
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
