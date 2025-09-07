// internal/tokens/tokens.go
package tokens

import "time"

type AccessClaims struct {
	UserID int64
	Email  string
}

type Signer interface {
	SignAccess(claims AccessClaims, ttl time.Duration) (token string, exp time.Time, err error)
}
