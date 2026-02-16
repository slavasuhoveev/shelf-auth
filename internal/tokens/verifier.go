package tokens

type Verifier interface {
	VerifyAccess(token string) (*AccessClaims, error)
}
