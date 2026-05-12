package service

import "strings"

// nonEmpty validates a string is not empty after trimming.
func nonEmpty(s string) bool { return strings.TrimSpace(s) != "" }
