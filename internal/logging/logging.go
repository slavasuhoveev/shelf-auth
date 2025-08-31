package logging

import (
	"os"
	"strings"
	"time"

	"github.com/rs/zerolog"
)

// New creates a zerolog.Logger configured with JSON output and the given level.
func New(level string) zerolog.Logger {
	lvl := parseLevel(level)
	logger := zerolog.New(os.Stdout).
		With().
		Timestamp().
		Caller().
		Logger().
		Level(lvl)

	// Human-friendly time format (optional).
	zerolog.TimeFieldFormat = time.RFC3339
	return logger
}

func parseLevel(s string) zerolog.Level {
	switch strings.ToLower(s) {
	case "debug":
		return zerolog.DebugLevel
	case "warn", "warning":
		return zerolog.WarnLevel
	case "error":
		return zerolog.ErrorLevel
	case "info", "":
		return zerolog.InfoLevel
	default:
		return zerolog.InfoLevel
	}
}
