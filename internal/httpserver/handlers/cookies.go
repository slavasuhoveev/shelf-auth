package handlers

import (
	"net/http"
	"time"
)

type CookieCfg struct {
	Secure   bool
	SameSite http.SameSite
	Domain   string
}

func setRefreshCookie(w http.ResponseWriter, value string, exp time.Time, cfg CookieCfg) {
	c := &http.Cookie{
		Name:     "refresh_token",
		Value:    value,
		Path:     "/",
		HttpOnly: true,
		Secure:   cfg.Secure,
		SameSite: cfg.SameSite,
		Expires:  exp,
		MaxAge:   int(time.Until(exp).Seconds()),
	}
	if cfg.Domain != "" {
		c.Domain = cfg.Domain
	}
	http.SetCookie(w, c)
}

func clearRefreshCookie(w http.ResponseWriter, cfg CookieCfg) {
	c := &http.Cookie{
		Name:     "refresh_token",
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   cfg.Secure,
		SameSite: cfg.SameSite,
		MaxAge:   0,
		Expires:  time.Unix(0, 0).UTC(),
	}
	if cfg.Domain != "" {
		c.Domain = cfg.Domain
	}
	http.SetCookie(w, c)
}
