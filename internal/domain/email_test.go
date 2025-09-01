//go:build unit
// +build unit

package domain

import "testing"

func TestParseEmail_Valid(t *testing.T) {
	e, err := ParseEmail(" user@example.com ")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got, want := e.String(), "user@example.com"; got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestParseEmail_Invalid(t *testing.T) {
	tests := []string{"", "not-an-email", "foo@bar@baz"}
	for _, input := range tests {
		if _, err := ParseEmail(input); err == nil {
			t.Errorf("expected error for input %q", input)
		}
	}
}
