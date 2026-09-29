// Package config reads the NATRIUM_TOKEN_EXCHANGE_* environment variables of the command. No other package reads the
// environment. Load parses them into a server.Config, validates it and names the variable in every error.
package config

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strconv"
	"time"

	"github.com/SchwarzDigits/natrium-token-exchange/internal/allow"
	"github.com/SchwarzDigits/natrium-token-exchange/server"
)

// Environment variable names.
const (
	EnvPort       = "NATRIUM_TOKEN_EXCHANGE_PORT"
	EnvLogLevel   = "NATRIUM_TOKEN_EXCHANGE_LOG_LEVEL"
	EnvWireAPIURL = "NATRIUM_TOKEN_EXCHANGE_WIRE_API_URL"
	EnvIssuer     = "NATRIUM_TOKEN_EXCHANGE_ISSUER"
	EnvAudience   = "NATRIUM_TOKEN_EXCHANGE_AUDIENCE"
	// EnvTokenTTL is a Go duration, e.g. 1h or 30m.
	EnvTokenTTL = "NATRIUM_TOKEN_EXCHANGE_TOKEN_TTL"
	// EnvSigningKeys is a comma-separated list of <key ID>:<base64url seed>. It is a secret.
	EnvSigningKeys  = "NATRIUM_TOKEN_EXCHANGE_SIGNING_KEYS"
	EnvCurrentKeyID = "NATRIUM_TOKEN_EXCHANGE_CURRENT_KEY_ID"
	// EnvAllowedTeams and EnvDeniedTeams are comma-separated lists of team UUIDs, or "*".
	EnvAllowedTeams = "NATRIUM_TOKEN_EXCHANGE_ALLOWED_TEAMS"
	EnvDeniedTeams  = "NATRIUM_TOKEN_EXCHANGE_DENIED_TEAMS"
	// EnvAllowedUsers and EnvDeniedUsers are comma-separated lists of qualified user IDs, <uuid>@<domain>, or "*".
	EnvAllowedUsers = "NATRIUM_TOKEN_EXCHANGE_ALLOWED_USERS"
	EnvDeniedUsers  = "NATRIUM_TOKEN_EXCHANGE_DENIED_USERS"
	// EnvTokenLimit and EnvKeyLimit have the form <n>/<window>, e.g. 60/1h.
	EnvTokenLimit              = "NATRIUM_TOKEN_EXCHANGE_TOKEN_LIMIT"
	EnvKeyLimit                = "NATRIUM_TOKEN_EXCHANGE_KEY_LIMIT"
	EnvMaxConcurrentWireChecks = "NATRIUM_TOKEN_EXCHANGE_MAX_CONCURRENT_WIRE_CHECKS"
)

const defaultPort = 8080

// envOf maps the fields of server.Config to the variables that set them, for error messages.
var envOf = map[string]string{
	"Addr":         EnvPort,
	"WireAPIURL":   EnvWireAPIURL,
	"Issuer":       EnvIssuer,
	"Audience":     EnvAudience,
	"TokenTTL":     EnvTokenTTL,
	"SigningKeys":  EnvSigningKeys,
	"CurrentKeyID": EnvCurrentKeyID,
	"AllowedTeams": EnvAllowedTeams,
	"DeniedTeams":  EnvDeniedTeams,
	"AllowedUsers": EnvAllowedUsers,
	"DeniedUsers":  EnvDeniedUsers,

	"TokenLimit":              EnvTokenLimit,
	"KeyLimit":                EnvKeyLimit,
	"MaxConcurrentWireChecks": EnvMaxConcurrentWireChecks,
}

// Config is the configuration of the command.
type Config struct {
	Server   server.Config
	LogLevel slog.Level
}

// Load reads and validates the environment variables.
func Load() (Config, error) {
	cfg := Config{Server: server.DefaultConfig(), LogLevel: slog.LevelInfo}
	s := &cfg.Server

	port := defaultPort
	if v := os.Getenv(EnvPort); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > 65535 {
			return Config{}, fmt.Errorf("%s: must be a port from 1 to 65535, got %q", EnvPort, v)
		}
		port = n
	}
	s.Addr = fmt.Sprintf(":%d", port)

	if v := os.Getenv(EnvLogLevel); v != "" {
		if err := cfg.LogLevel.UnmarshalText([]byte(v)); err != nil {
			return Config{}, fmt.Errorf("%s: %w", EnvLogLevel, err)
		}
	}

	s.WireAPIURL = os.Getenv(EnvWireAPIURL)
	s.Issuer = os.Getenv(EnvIssuer)
	s.Audience = os.Getenv(EnvAudience)
	if v := os.Getenv(EnvTokenTTL); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil {
			return Config{}, fmt.Errorf("%s: must be a duration such as 1h or 30m, got %q", EnvTokenTTL, v)
		}
		s.TokenTTL = d
	}
	if v := os.Getenv(EnvSigningKeys); v != "" {
		keys, err := server.ParseSigningKeys(v)
		if err != nil {
			return Config{}, fmt.Errorf("%s: %w", EnvSigningKeys, err)
		}
		s.SigningKeys = keys
	}
	s.CurrentKeyID = os.Getenv(EnvCurrentKeyID)
	s.AllowedTeams = allow.Split(os.Getenv(EnvAllowedTeams))
	s.DeniedTeams = allow.Split(os.Getenv(EnvDeniedTeams))
	s.AllowedUsers = allow.Split(os.Getenv(EnvAllowedUsers))
	s.DeniedUsers = allow.Split(os.Getenv(EnvDeniedUsers))
	for _, v := range []struct {
		name  string
		limit *server.Limit
	}{{EnvTokenLimit, &s.TokenLimit}, {EnvKeyLimit, &s.KeyLimit}} {
		if raw := os.Getenv(v.name); raw != "" {
			l, err := server.ParseLimit(raw)
			if err != nil {
				return Config{}, fmt.Errorf("%s: %w", v.name, err)
			}
			*v.limit = l
		}
	}
	if v := os.Getenv(EnvMaxConcurrentWireChecks); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil {
			return Config{}, fmt.Errorf("%s: must be a number, got %q", EnvMaxConcurrentWireChecks, v)
		}
		s.MaxConcurrentWireChecks = n
	}

	if err := s.Validate(); err != nil {
		return Config{}, Named(err)
	}
	return cfg, nil
}

// Named replaces the field name in a *server.ConfigError with the variable that sets the field. Other errors, and
// nil, are returned unchanged.
func Named(err error) error {
	var invalid *server.ConfigError
	if errors.As(err, &invalid) {
		if name, ok := envOf[invalid.Field]; ok {
			return fmt.Errorf("%s: %s", name, invalid.Problem)
		}
	}
	return err
}
