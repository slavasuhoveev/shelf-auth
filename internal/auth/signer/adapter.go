package signer

import (
	"crypto/rsa"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/slavasuhoveev/shelf-auth/internal/tokens"
)

type AccessSigner struct {
	privateKey *rsa.PrivateKey
	kid        string
	issuer     string
	audience   string
}

func NewAccessSigner(priv *rsa.PrivateKey, kid, issuer, audience string) *AccessSigner {
	return &AccessSigner{
		privateKey: priv,
		kid:        kid,
		issuer:     issuer,
		audience:   audience,
	}
}

func (s *AccessSigner) SignAccess(c tokens.AccessClaims, ttl time.Duration) (string, time.Time, error) {
	now := time.Now().UTC()
	exp := now.Add(ttl)

	claims := jwt.MapClaims{
		"sub":   c.UserID,
		"email": c.Email,
		"iss":   s.issuer,
		"aud":   s.audience,
		"iat":   now.Unix(),
		"nbf":   now.Unix(),
		"exp":   exp.Unix(),
	}
	t := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	t.Header["kid"] = s.kid
	signed, err := t.SignedString(s.privateKey)
	if err != nil {
		return "", time.Time{}, err
	}
	return signed, exp, nil
}
