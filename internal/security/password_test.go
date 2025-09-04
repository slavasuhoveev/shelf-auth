//go:build unit
// +build unit

package security

import (
	"testing"
)

func TestValidatePassword_DefaultPolicy_OK(t *testing.T) {
	p := DefaultPolicy() // min=8, lower+digit required
	cases := []string{
		"abc12345",  // lower+digit
		"passw0rd!", // lower+digit(+symbol)
		"x9xxxxxx",  // exactly 8 with digit
	}
	for _, pw := range cases {
		if err := ValidatePassword(p, pw); err != nil {
			t.Fatalf("password %q should pass: %v", pw, err)
		}
	}
}

func TestValidatePassword_DefaultPolicy_Errors(t *testing.T) {
	p := DefaultPolicy()
	tests := []struct {
		pw   string
		want error
	}{
		{"", ErrEmptyPassword},
		{"short7", ErrPasswordTooShort},   // len 7
		{"abcdefgh", ErrPasswordNoDigit},  // no digit
		{"ABC12345", ErrPasswordNoLower},  // no lower
		{"abc 1234", ErrPasswordHasSpace}, // space forbidden by default
	}
	for _, tt := range tests {
		if err := ValidatePassword(p, tt.pw); err != tt.want {
			t.Fatalf("password %q: got %v, want %v", tt.pw, err, tt.want)
		}
	}
}

func TestValidatePassword_StrictPolicy(t *testing.T) {
	p := Policy{
		MinLength:     10,
		RequireLower:  true,
		RequireUpper:  true,
		RequireDigit:  true,
		RequireSymbol: true,
		DisallowSpace: true,
	}
	if err := ValidatePassword(p, "Aa1!aaaaaa"); err != nil {
		t.Fatalf("strict policy should pass: %v", err)
	}
	if err := ValidatePassword(p, "Aa1aaaaaaa"); err != ErrPasswordNoSymbol {
		t.Fatalf("expected ErrPasswordNoSymbol, got %v", err)
	}
}

func TestHashAndCheck_Roundtrip_NoPepper(t *testing.T) {
	opts := DefaultOptions()
	hash, err := HashPassword("abc12345", opts)
	if err != nil {
		t.Fatalf("hash error: %v", err)
	}
	if err := CheckPassword(hash, "abc12345", opts); err != nil {
		t.Fatalf("check error: %v", err)
	}
	// wrong password must fail
	if err := CheckPassword(hash, "abc12346", opts); err == nil {
		t.Fatal("expected check to fail for wrong password")
	}
}

func TestHashAndCheck_Roundtrip_WithPepper(t *testing.T) {
	opts := DefaultOptions()
	opts.Pepper = []byte("super-secret-pepper")
	hash, err := HashPassword("abc12345", opts)
	if err != nil {
		t.Fatalf("hash error: %v", err)
	}
	// must succeed with same pepper
	if err := CheckPassword(hash, "abc12345", opts); err != nil {
		t.Fatalf("check error: %v", err)
	}
	// must fail with different pepper
	optsBad := DefaultOptions()
	optsBad.Pepper = []byte("another-pepper")
	if err := CheckPassword(hash, "abc12345", optsBad); err == nil {
		t.Fatal("expected check to fail with different pepper")
	}
}

func TestHash_IsRandomizedPerCall(t *testing.T) {
	opts := DefaultOptions()
	const pw = "abc12345"
	h1, err := HashPassword(pw, opts)
	if err != nil {
		t.Fatalf("hash1 error: %v", err)
	}
	h2, err := HashPassword(pw, opts)
	if err != nil {
		t.Fatalf("hash2 error: %v", err)
	}
	if h1 == h2 {
		t.Fatal("bcrypt hashes for same password should differ due to salt")
	}
}

func TestPreKDF_AvoidsBcrypt72ByteTruncation(t *testing.T) {
	// Construct a very long password (>72 bytes). Our preKDF (SHA256/HMAC) ensures
	// bcrypt input length is fixed and no silent truncation happens.
	long := make([]byte, 200)
	for i := range long {
		long[i] = 'a' + byte(i%26)
	}
	pw := string(long)

	opts := DefaultOptions()
	h1, err := HashPassword(pw, opts)
	if err != nil {
		t.Fatalf("hash long pw error: %v", err)
	}
	// must verify ok
	if err := CheckPassword(h1, pw, opts); err != nil {
		t.Fatalf("check error for long pw: %v", err)
	}
	// wrong tail must fail (proves we didn't silently truncate)
	if err := CheckPassword(h1, pw+"x", opts); err == nil {
		t.Fatal("expected mismatch for altered long password")
	}
}

func TestHashPassword_EmptyInput(t *testing.T) {
	_, err := HashPassword("", DefaultOptions())
	if err != ErrEmptyPassword {
		t.Fatalf("expected ErrEmptyPassword, got %v", err)
	}
}

func TestCheckPassword_EmptyInputs(t *testing.T) {
	if err := CheckPassword("", "pw", DefaultOptions()); err != ErrEmptyPasswordHash {
		t.Fatalf("expected ErrEmptyPasswordHash, got %v", err)
	}
	if err := CheckPassword("$2y$12$somehash", "", DefaultOptions()); err != ErrEmptyPassword {
		t.Fatalf("expected ErrEmptyPassword, got %v", err)
	}
}
