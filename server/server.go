// Package server runs the token exchange of Natrium: it exchanges a Wire access token for a short-lived token that a
// storage server accepts, bound to the client's Ed25519 key, for the users its admission lists allow. It
// serves the API, the key set, the health probes and the metrics on one address.
//
// Programs that read their configuration their own way build a Config, starting from DefaultConfig, and call Run.
// The command in cmd/natrium-token-exchange reads it from NATRIUM_TOKEN_EXCHANGE_* environment variables.
package server

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"slices"
	"time"

	"github.com/SchwarzDigits/natrium-token-exchange/internal/allow"
	"github.com/SchwarzDigits/natrium-token-exchange/internal/httpapi"
	"github.com/SchwarzDigits/natrium-token-exchange/internal/platform"
	"github.com/SchwarzDigits/natrium-token-exchange/internal/signing"
	"github.com/SchwarzDigits/natrium-token-exchange/internal/wireauth"
)

// Paths served on Config.Addr.
const (
	PathToken   = httpapi.PathToken
	PathJWKS    = httpapi.PathJWKS
	PathLive    = platform.PathLive
	PathReady   = platform.PathReady
	PathMetrics = platform.PathMetrics
)

// Bounds and default of Config.TokenTTL.
const (
	DefaultTokenTTL = time.Hour
	MinTokenTTL     = time.Minute
	MaxTokenTTL     = 24 * time.Hour
)

// maxClaimLength bounds Issuer and Audience.
const maxClaimLength = 256

// SigningKey is a key that signs tokens: its key ID and its secret Ed25519 seed. cmd/new-signing-key creates one.
type SigningKey = signing.Key

// ParseSigningKeys reads comma-separated keys of the form <key ID>:<base64url seed>, as cmd/new-signing-key prints
// them.
func ParseSigningKeys(s string) ([]SigningKey, error) {
	return signing.ParseKeys(s)
}

// Config configures Run. Start from DefaultConfig: its zero value is not valid.
type Config struct {
	// Addr is the TCP address to listen on, e.g. ":8080". Required.
	Addr string
	// WireAPIURL is the base URL of the Wire API including the API version, e.g.
	// https://nginz-https.wire.example/v15. The server checks every access token with GET /self there. Required.
	WireAPIURL string

	// Issuer is the iss claim of the tokens, e.g. https://token.example. The storage server expects it. Required.
	Issuer string
	// Audience is the aud claim of the tokens: the storage server, e.g. wss://vfs.example/v1/ws. Required.
	Audience string
	// TokenTTL is the lifetime of a token, from MinTokenTTL to MaxTokenTTL.
	TokenTTL time.Duration

	// SigningKeys are the keys in the key set. Required.
	SigningKeys []SigningKey
	// CurrentKeyID names the key among SigningKeys that signs new tokens. Required.
	CurrentKeyID string

	// AllowedTeams, DeniedTeams, AllowedUsers and DeniedUsers decide who gets a token. The team lists hold team
	// UUIDs, the user lists qualified IDs <uuid>@<domain>, and each may hold "*" for all. The most specific matching
	// entry decides, a denial wins over an admission of the same specificity, and a user no entry matches is denied;
	// see docs/protocol.md. At least one allowed team or user is required.
	AllowedTeams []string
	DeniedTeams  []string
	AllowedUsers []string
	DeniedUsers  []string
}

// rules returns the admission lists of c.
func (c Config) rules() allow.Rules {
	return allow.Rules{
		AllowedTeams: c.AllowedTeams,
		DeniedTeams:  c.DeniedTeams,
		AllowedUsers: c.AllowedUsers,
		DeniedUsers:  c.DeniedUsers,
	}
}

// DefaultConfig returns the default token lifetime of one hour. The other required fields are left to the caller.
func DefaultConfig() Config {
	return Config{TokenTTL: DefaultTokenTTL}
}

// ConfigError reports an invalid field of Config. Field is the Go field name, so that a caller that reads the
// configuration from its own sources can name its own setting in the message.
type ConfigError struct {
	Field   string
	Problem string
}

func (e *ConfigError) Error() string {
	return e.Field + ": " + e.Problem
}

func invalid(field, format string, args ...any) error {
	return &ConfigError{Field: field, Problem: fmt.Sprintf(format, args...)}
}

// Validate checks the configuration. It returns a *ConfigError for the first invalid field.
func (c Config) Validate() error {
	switch {
	case c.Addr == "":
		return invalid("Addr", "is required")
	case c.WireAPIURL == "":
		return invalid("WireAPIURL", "is required, e.g. https://nginz-https.wire.example/v15")
	}
	if err := wireauth.CheckAPIURL(c.WireAPIURL); err != nil {
		return invalid("WireAPIURL", "%v", err)
	}
	if err := checkClaim(c.Issuer); err != nil {
		return invalid("Issuer", "%v, e.g. https://token.example", err)
	}
	if err := checkClaim(c.Audience); err != nil {
		return invalid("Audience", "%v, e.g. wss://vfs.example/v1/ws", err)
	}
	if c.TokenTTL < MinTokenTTL || c.TokenTTL > MaxTokenTTL || c.TokenTTL%time.Second != 0 {
		return invalid("TokenTTL", "must be whole seconds from %s to %s, got %s", MinTokenTTL, MaxTokenTTL, c.TokenTTL)
	}
	switch {
	case len(c.SigningKeys) == 0:
		return invalid("SigningKeys", "at least one key is required")
	case c.CurrentKeyID == "":
		return invalid("CurrentKeyID", "is required")
	case !slices.ContainsFunc(c.SigningKeys, func(k SigningKey) bool { return k.ID == c.CurrentKeyID }):
		return invalid("CurrentKeyID", "must be one of the key IDs in SigningKeys, got %q", c.CurrentKeyID)
	}
	if err := signing.CheckKeys(c.SigningKeys, c.CurrentKeyID); err != nil {
		return invalid("SigningKeys", "%v", err)
	}
	for _, list := range []struct {
		field string
		check func([]string) error
		value []string
	}{
		{"AllowedTeams", allow.CheckTeams, c.AllowedTeams},
		{"DeniedTeams", allow.CheckTeams, c.DeniedTeams},
		{"AllowedUsers", allow.CheckUsers, c.AllowedUsers},
		{"DeniedUsers", allow.CheckUsers, c.DeniedUsers},
	} {
		if err := list.check(list.value); err != nil {
			return invalid(list.field, "%v", err)
		}
	}
	if _, err := allow.New(c.rules()); err != nil {
		return invalid("AllowedTeams", "%v; set AllowedTeams or AllowedUsers", err)
	}
	return nil
}

// checkClaim reports whether s can be a claim: 1 to 256 printable ASCII characters without spaces.
func checkClaim(s string) error {
	if s == "" || len(s) > maxClaimLength {
		return fmt.Errorf("must have 1 to %d characters", maxClaimLength)
	}
	for _, c := range []byte(s) {
		if c < 0x21 || c > 0x7e {
			return fmt.Errorf("must be printable ASCII without spaces")
		}
	}
	return nil
}

// Run validates the configuration and serves until ctx is canceled. It then waits for running requests and returns
// after the shutdown.
func Run(ctx context.Context, cfg Config, log *slog.Logger) error {
	return run(ctx, cfg, log, dependencies{})
}

// dependencies are what tests replace.
type dependencies struct {
	// wireHTTP is the HTTP client for the Wire backend. nil uses a client of its own.
	wireHTTP *http.Client
}

func run(ctx context.Context, cfg Config, log *slog.Logger, deps dependencies) error {
	if err := cfg.Validate(); err != nil {
		return err
	}
	wire, err := wireauth.New(cfg.WireAPIURL, deps.wireHTTP)
	if err != nil {
		return invalid("WireAPIURL", "%v", err)
	}
	signer, err := signing.New(cfg.SigningKeys, cfg.CurrentKeyID, signing.Options{
		Issuer:   cfg.Issuer,
		Audience: cfg.Audience,
		TTL:      cfg.TokenTTL,
	})
	if err != nil {
		return invalid("SigningKeys", "%v", err)
	}
	list, err := allow.New(cfg.rules())
	if err != nil {
		return invalid("AllowedTeams", "%v", err)
	}

	registry := platform.NewRegistry()
	mux := http.NewServeMux()
	httpapi.New(httpapi.Options{
		Auth:    wire,
		Allow:   list,
		Signer:  signer,
		Log:     log,
		Metrics: registry,
	}).Register(mux)
	mux.Handle("GET "+PathLive, platform.OKHandler())
	mux.Handle("GET "+PathReady, platform.ReadyHandler())
	mux.Handle("GET "+PathMetrics, platform.MetricsHandler(registry))

	log.Info("starting server", append([]any{"addr", cfg.Addr, "wire_api_url", cfg.WireAPIURL, "issuer", cfg.Issuer,
		"audience", cfg.Audience, "token_ttl", cfg.TokenTTL.String(), "signing_keys", len(cfg.SigningKeys),
		"current_key_id", cfg.CurrentKeyID}, list.LogAttrs()...)...)
	return platform.Serve(ctx, log, cfg.Addr, platform.Recover(log, mux))
}
