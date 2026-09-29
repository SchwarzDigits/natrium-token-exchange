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

	"github.com/prometheus/client_golang/prometheus"

	"github.com/SchwarzDigits/natrium-token-exchange/internal/allow"
	"github.com/SchwarzDigits/natrium-token-exchange/internal/httpapi"
	"github.com/SchwarzDigits/natrium-token-exchange/internal/limits"
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

// Bounds and defaults of the token lifetimes.
const (
	DefaultStorageTokenTTL = time.Hour
	DefaultPinTokenTTL     = 10 * time.Minute
	MinTokenTTL            = time.Minute
	MaxTokenTTL            = 24 * time.Hour
)

// Names of the audiences in requests.
const (
	AudienceStorage = "storage"
	AudiencePin     = "pin"
)

// maxClaimLength bounds Issuer and the audiences.
const maxClaimLength = 256

// sweepInterval is the interval at which users are forgotten whose limits have run out of their windows.
const sweepInterval = time.Minute

// Defaults of the limits.
var (
	DefaultTokenLimit              = Limit{N: 60, Window: time.Hour}
	DefaultKeyLimit                = Limit{N: 10, Window: 24 * time.Hour}
	DefaultMaxConcurrentWireChecks = 64
)

// Limit allows N within Window.
type Limit = limits.Limit

// ParseLimit reads a limit of the form <n>/<window>, e.g. 60/1h.
func ParseLimit(s string) (Limit, error) {
	return limits.ParseLimit(s)
}

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

	// Issuer is the iss claim of the tokens, e.g. https://token.example. The servers that accept the tokens expect
	// it. Required.
	Issuer string
	// StorageAudience is the aud claim of the tokens for the storage server, e.g. wss://vfs.example/v1/ws. A request
	// for them names the audience "storage" and carries the client's public key. Required.
	StorageAudience string
	// StorageTokenTTL is the lifetime of a storage token, from MinTokenTTL to MaxTokenTTL.
	StorageTokenTTL time.Duration
	// PinAudience is the aud claim of the tokens for the PIN service, e.g. https://pin.example. A request for them
	// names the audience "pin" and carries no key: a browser that restores its key file has no key yet. Empty: the
	// service issues no PIN tokens. It must differ from StorageAudience, so that neither server accepts the other's
	// tokens.
	PinAudience string
	// PinTokenTTL is the lifetime of a PIN token, from MinTokenTTL to MaxTokenTTL.
	PinTokenTTL time.Duration

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

	// TokenLimit bounds the tokens one user gets from one instance within the window.
	TokenLimit Limit
	// KeyLimit bounds the distinct client keys one user has in use at one instance: a key is in use from its last
	// token until the window has passed.
	KeyLimit Limit
	// MaxConcurrentWireChecks bounds the token checks with Wire that run at once. A request beyond it is refused with
	// 503 without asking Wire.
	MaxConcurrentWireChecks int
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

// DefaultConfig returns the default token lifetimes and limits. The other required fields are
// left to the caller.
func DefaultConfig() Config {
	return Config{
		StorageTokenTTL:         DefaultStorageTokenTTL,
		PinTokenTTL:             DefaultPinTokenTTL,
		TokenLimit:              DefaultTokenLimit,
		KeyLimit:                DefaultKeyLimit,
		MaxConcurrentWireChecks: DefaultMaxConcurrentWireChecks,
	}
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
	if err := checkClaim(c.StorageAudience); err != nil {
		return invalid("StorageAudience", "%v, e.g. wss://vfs.example/v1/ws", err)
	}
	if err := checkTTL(c.StorageTokenTTL); err != nil {
		return invalid("StorageTokenTTL", "%v", err)
	}
	if c.PinAudience != "" {
		if err := checkClaim(c.PinAudience); err != nil {
			return invalid("PinAudience", "%v, e.g. https://pin.example", err)
		}
		if c.PinAudience == c.StorageAudience {
			return invalid("PinAudience", "must differ from StorageAudience")
		}
		if err := checkTTL(c.PinTokenTTL); err != nil {
			return invalid("PinTokenTTL", "%v", err)
		}
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
	if err := c.TokenLimit.Check(); err != nil {
		return invalid("TokenLimit", "%v", err)
	}
	if err := c.KeyLimit.Check(); err != nil {
		return invalid("KeyLimit", "%v", err)
	}
	if c.MaxConcurrentWireChecks < 1 {
		return invalid("MaxConcurrentWireChecks", "must be at least 1, got %d", c.MaxConcurrentWireChecks)
	}
	return nil
}

// checkTTL reports whether d is whole seconds from MinTokenTTL to MaxTokenTTL.
func checkTTL(d time.Duration) error {
	if d < MinTokenTTL || d > MaxTokenTTL || d%time.Second != 0 {
		return fmt.Errorf("must be whole seconds from %s to %s, got %s", MinTokenTTL, MaxTokenTTL, d)
	}
	return nil
}

// audiences returns the kinds of token c configures.
func (c Config) audiences() map[string]httpapi.Audience {
	a := map[string]httpapi.Audience{
		AudienceStorage: {Aud: c.StorageAudience, TTL: c.StorageTokenTTL, Key: true},
	}
	if c.PinAudience != "" {
		a[AudiencePin] = httpapi.Audience{Aud: c.PinAudience, TTL: c.PinTokenTTL}
	}
	return a
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
//
// Run makes the process not dumpable and turns off core dumps (on Linux), because the signing keys are in its memory
// and its environment.
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
	if err := platform.ProtectProcess(); err != nil {
		return err
	}
	wire, err := wireauth.New(cfg.WireAPIURL, deps.wireHTTP)
	if err != nil {
		return invalid("WireAPIURL", "%v", err)
	}
	signer, err := signing.New(cfg.SigningKeys, cfg.CurrentKeyID, signing.Options{Issuer: cfg.Issuer})
	if err != nil {
		return invalid("SigningKeys", "%v", err)
	}
	list, err := allow.New(cfg.rules())
	if err != nil {
		return invalid("AllowedTeams", "%v", err)
	}

	limiter, err := limits.New(cfg.TokenLimit, cfg.KeyLimit)
	if err != nil {
		return invalid("TokenLimit", "%v", err)
	}
	sweepCtx, stopSweep := context.WithCancel(ctx)
	sweepDone := make(chan struct{})
	go func() {
		defer close(sweepDone)
		limiter.Run(sweepCtx, sweepInterval)
	}()
	defer func() {
		stopSweep()
		<-sweepDone
	}()

	registry := platform.NewRegistry()
	registry.MustRegister(prometheus.NewGaugeFunc(prometheus.GaugeOpts{
		Name: "natrium_token_exchange_limited_users",
		Help: "Number of users whose tokens or keys are being counted against the limits.",
	}, func() float64 { return float64(limiter.Users()) }))
	mux := http.NewServeMux()
	httpapi.New(httpapi.Options{
		Auth:                wire,
		Allow:               list,
		Signer:              signer,
		Limits:              limiter,
		Audiences:           cfg.audiences(),
		MaxConcurrentChecks: cfg.MaxConcurrentWireChecks,
		Log:                 log,
		Metrics:             registry,
	}).Register(mux)
	mux.Handle("GET "+PathLive, platform.OKHandler())
	mux.Handle("GET "+PathReady, platform.ReadyHandler())
	mux.Handle("GET "+PathMetrics, platform.MetricsHandler(registry))

	log.Info("starting server", append([]any{"addr", cfg.Addr, "wire_api_url", cfg.WireAPIURL, "issuer", cfg.Issuer,
		"storage_audience", cfg.StorageAudience, "storage_token_ttl", cfg.StorageTokenTTL.String(),
		"pin_audience", cfg.PinAudience, "pin_token_ttl", cfg.PinTokenTTL.String(),
		"signing_keys", len(cfg.SigningKeys),
		"current_key_id", cfg.CurrentKeyID, "token_limit", cfg.TokenLimit.String(), "key_limit", cfg.KeyLimit.String(),
		"max_concurrent_wire_checks", cfg.MaxConcurrentWireChecks}, list.LogAttrs()...)...)
	return platform.Serve(ctx, log, cfg.Addr, platform.Recover(log, mux))
}
