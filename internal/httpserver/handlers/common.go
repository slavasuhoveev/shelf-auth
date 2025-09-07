package handlers

import (
	"encoding/json"
	"net/http"
)

type apiError struct {
	Error string `json:"error"`
	Code  string `json:"code,omitempty"`
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeAPIError(w http.ResponseWriter, status int, code, msg string) {
	writeJSON(w, status, apiError{Error: msg, Code: code})
}
