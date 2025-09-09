package service

// nonEmpty validates a string is not empty after trimming.
func nonEmpty(s string) bool { return len(s) > 0 }
