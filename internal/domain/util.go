package domain

import "time"

// Now returns UTC time to enforce consistent timestamps in the domain layer.
func Now() time.Time { return time.Now().UTC() }

// ptrTime returns pointer to a time.Time (handy for optional timestamps).
func ptrTime(t time.Time) *time.Time { return &t }

// nonEmpty validates a string is not empty after trimming.
func nonEmpty(s string) bool { return len(s) > 0 }
