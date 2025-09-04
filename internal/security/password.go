package security

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"unicode"

	"golang.org/x/crypto/bcrypt"
)

// DefaultBcryptCost is a good starting point for dev. For prod, consider 12-14.
// Tune based on your hardware and latency SLOs.
const DefaultBcryptCost = 12

// Policy defines password strength requirements.
type Policy struct {
	MinLength     int  // minimum length in runes
	RequireLower  bool // at least one lowercase letter
	RequireUpper  bool // at least one uppercase letter
	RequireDigit  bool // at least one decimal digit
	RequireSymbol bool // at least one punctuation/symbol
	DisallowSpace bool // forbid any whitespace (space, tabs, newlines)
}

// DefaultPolicy returns sane defaults that balance UX and security.
func DefaultPolicy() Policy {
	return Policy{
		MinLength:     8,
		RequireLower:  true,
		RequireUpper:  false, // set true if your product demands it
		RequireDigit:  true,
		RequireSymbol: false, // set true if your product demands it
		DisallowSpace: true,
	}
}

// ValidatePassword checks the given password against the provided policy.
// It returns the first violation found (simple and predictable).
func ValidatePassword(p Policy, pw string) error {
	if pw == "" {
		return ErrEmptyPassword
	}

	var (
		hasLower  bool
		hasUpper  bool
		hasDigit  bool
		hasSymbol bool
		length    int
	)

	for _, r := range pw {
		length++
		switch {
		case unicode.IsLower(r):
			hasLower = true
		case unicode.IsUpper(r):
			hasUpper = true
		case unicode.IsDigit(r):
			hasDigit = true
		case unicode.IsPunct(r) || unicode.IsSymbol(r):
			hasSymbol = true
		case unicode.IsSpace(r):
			if p.DisallowSpace {
				return ErrPasswordHasSpace
			}
		}
	}

	if length < p.MinLength {
		return ErrPasswordTooShort
	}
	if p.RequireLower && !hasLower {
		return ErrPasswordNoLower
	}
	if p.RequireUpper && !hasUpper {
		return ErrPasswordNoUpper
	}
	if p.RequireDigit && !hasDigit {
		return ErrPasswordNoDigit
	}
	if p.RequireSymbol && !hasSymbol {
		return ErrPasswordNoSymbol
	}
	return nil
}

// Options control hashing behavior.
type Options struct {
	// BcryptCost controls the work factor; higher = slower = stronger.
	// If zero, DefaultBcryptCost is used.
	BcryptCost int
	// Pepper is an optional application-wide secret. If non-empty,
	// we apply HMAC-SHA256 with this pepper before bcrypt.
	// Store pepper in a secret manager or ENV, NOT in the database.
	Pepper []byte
}

// DefaultOptions returns recommended defaults for hashing.
func DefaultOptions() Options {
	return Options{
		BcryptCost: DefaultBcryptCost,
		Pepper:     nil,
	}
}

// HashPassword hashes the given plaintext password using a two-step KDF:
//  1. Pre-KDF: SHA-256(password) OR HMAC-SHA256(pepper, password) if pepper is provided
//  2. bcrypt on the pre-KDF output (hex-encoded), with configurable cost
//
// Rationale:
// - bcrypt truncates inputs > 72 bytes; pre-hashing avoids silent truncation.
// - HMAC with pepper prevents offline rainbow-table reuse if DB is leaked.
func HashPassword(plain string, opt Options) (string, error) {
	if plain == "" {
		return "", ErrEmptyPassword
	}
	if opt.BcryptCost <= 0 {
		opt.BcryptCost = DefaultBcryptCost
	}
	pre := preKDF(plain, opt.Pepper)
	// We hex-encode the digest to get stable ASCII; bcrypt input is treated as bytes.
	hashed, err := bcrypt.GenerateFromPassword(pre, opt.BcryptCost)
	if err != nil {
		return "", err
	}
	return string(hashed), nil
}

// CheckPassword verifies a plaintext password against a bcrypt hash.
// It uses the same pre-KDF (SHA-256 or HMAC-SHA256 with pepper) before bcrypt comparison.
func CheckPassword(hash, plain string, opt Options) error {
	if hash == "" {
		return ErrEmptyPasswordHash
	}
	if plain == "" {
		return ErrEmptyPassword
	}
	pre := preKDF(plain, opt.Pepper)
	return bcrypt.CompareHashAndPassword([]byte(hash), pre)
}

// preKDF normalizes the password for bcrypt by applying SHA-256 or HMAC-SHA256.
// We return hex-encoded digest bytes to keep bcrypt input ASCII-stable.
func preKDF(plain string, pepper []byte) []byte {
	var sum []byte
	if len(pepper) > 0 {
		h := hmac.New(sha256.New, pepper)
		h.Write([]byte(plain))
		sum = h.Sum(nil)
	} else {
		h := sha256.Sum256([]byte(plain))
		sum = h[:]
	}
	hexed := make([]byte, hex.EncodedLen(len(sum)))
	hex.Encode(hexed, sum)
	return hexed
}
