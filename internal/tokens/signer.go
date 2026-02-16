package tokens

import "time"

type Signer interface {
	SignAccess(claims AccessClaims, ttl time.Duration) (token string, exp time.Time, err error)
}
