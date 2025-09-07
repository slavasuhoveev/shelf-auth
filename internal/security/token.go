package security

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
)

// GenerateOpaqueToken returns a URL-safe random token of nBytes entropy.
// nBytes 32..48 is a good range (256..384 bits).
func GenerateOpaqueToken(nBytes int) (string, error) {
	buf := make([]byte, nBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	// URL-safe, no padding to keep it compact.
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

// HashSHA256Hex returns hex-encoded SHA-256 of the given string.
// Use for storing refresh token hashes in DB (never store raw tokens).
func HashSHA256Hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}
