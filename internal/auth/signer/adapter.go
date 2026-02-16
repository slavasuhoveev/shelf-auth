package signer

import (
	"crypto/rsa"
	"encoding/json"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/slavasuhoveev/shelf-auth/internal/domain"
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

func isExpired(claims jwt.MapClaims) bool {
	expVal, ok := claims["exp"]
	if !ok {
		return true
	}

	var exp int64

	switch v := expVal.(type) {
	case float64:
		exp = int64(v)
	case int64:
		exp = v
	case json.Number:
		n, err := v.Int64()
		if err != nil {
			return true
		}
		exp = n
	default:
		return true
	}

	return time.Now().Unix() > exp
}

func (s *AccessSigner) VerifyAccess(tokenStr string) (*tokens.AccessClaims, error) {
	t, err := jwt.Parse(tokenStr, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, domain.ErrInvalidAccessToken
		}

		kid, ok := t.Header["kid"].(string)
		if !ok || kid == "" || kid != s.kid {
			return nil, domain.ErrInvalidAccessToken
		}

		return &s.privateKey.PublicKey, nil
	})

	if err != nil {
		return nil, domain.ErrInvalidAccessToken
	}

	if !t.Valid {
		return nil, domain.ErrInvalidAccessToken
	}

	claims, ok := t.Claims.(jwt.MapClaims)
	if !ok {
		return nil, domain.ErrInvalidAccessToken
	}

	// issuer
	if iss, _ := claims["iss"].(string); iss != s.issuer {
		return nil, domain.ErrInvalidAccessToken
	}

	// audience
	if aud, _ := claims["aud"].(string); aud != s.audience {
		return nil, domain.ErrInvalidAccessToken
	}

	// expiration
	if isExpired(claims) {
		return nil, domain.ErrExpiredAccessToken
	}

	sub, ok := claims["sub"].(string)
	if !ok || sub == "" {
		return nil, domain.ErrInvalidAccessToken
	}

	email, _ := claims["email"].(string)

	return &tokens.AccessClaims{
		UserID: sub,
		Email:  email,
	}, nil
}
