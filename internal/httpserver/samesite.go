package httpserver

import "net/http"

func ParseSameSite(v string) http.SameSite {
	switch v {
	case "Strict", "strict":
		return http.SameSiteStrictMode
	case "None", "none":
		// NOTE: browsers require Secure=true when SameSite=None
		return http.SameSiteNoneMode
	default:
		return http.SameSiteLaxMode
	}
}
