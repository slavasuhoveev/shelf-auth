package tokens

type AccessClaims struct {
	UserID string `json:"sub"`
	Email  string `json:"email"`
}
