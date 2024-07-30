package httpserver

import "time"

// emptyJWKS is a no-op JWKS provider used before real keys are wired.
type emptyJWKS struct{}

// NewEmptyJWKS returns a provider that always serves an empty JWKS set.
func NewEmptyJWKS() JWKSProvider { return emptyJWKS{} }

// Current returns a valid (but empty) JWKS document with cache headers.
func (emptyJWKS) Current() ([]byte, string, time.Duration) {
	return []byte(`{"keys":[]}`), `W/"jwks-empty-0"`, 5 * time.Minute
}
