package security

import "errors"

var (
	ErrPasswordTooShort  = errors.New("password too short")
	ErrPasswordNoLower   = errors.New("password must contain at least one lowercase letter")
	ErrPasswordNoUpper   = errors.New("password must contain at least one uppercase letter")
	ErrPasswordNoDigit   = errors.New("password must contain at least one digit")
	ErrPasswordNoSymbol  = errors.New("password must contain at least one symbol")
	ErrPasswordHasSpace  = errors.New("password must not contain spaces")
	ErrEmptyPassword     = errors.New("password is empty")
	ErrEmptyPasswordHash = errors.New("password hash is empty")
)
