package server

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/require"
)

const (
	aliceID = "39b7f597-dfd1-4dff-86f5-fe1b79cb70a0"
	team    = "8b3c1a2e-0f4d-4e5a-9b6c-7d8e9f0a1b2c"
)

func seed(fill byte) []byte {
	return bytes.Repeat([]byte{fill}, 32)
}

func valid() Config {
	cfg := DefaultConfig()
	cfg.Addr = ":8080"
	cfg.WireAPIURL = "https://nginz-https.wire.example/v15"
	cfg.Issuer = "https://token.example"
	cfg.StorageAudience = "wss://vfs.example/v1/ws"
	cfg.PinAudience = "https://pin.example"
	cfg.SigningKeys = []SigningKey{{ID: "k1", Seed: seed(1)}}
	cfg.CurrentKeyID = "k1"
	cfg.AllowedTeams = []string{team}
	return cfg
}

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()
	require.Equal(t, time.Hour, cfg.StorageTokenTTL)
	require.Equal(t, 10*time.Minute, cfg.PinTokenTTL)
	require.Equal(t, Limit{N: 60, Window: time.Hour}, cfg.TokenLimit)
	require.Equal(t, Limit{N: 10, Window: 24 * time.Hour}, cfg.KeyLimit)
	require.Equal(t, 64, cfg.MaxConcurrentWireChecks)
	require.NoError(t, valid().Validate())
}

func TestValidateNamesTheField(t *testing.T) {
	for _, tc := range []struct {
		field  string
		change func(*Config)
	}{
		{"Addr", func(c *Config) { c.Addr = "" }},
		{"WireAPIURL", func(c *Config) { c.WireAPIURL = "" }},
		{"WireAPIURL", func(c *Config) { c.WireAPIURL = "http://nginz-https.wire.example/v15" }},
		{"Issuer", func(c *Config) { c.Issuer = "" }},
		{"Issuer", func(c *Config) { c.Issuer = "with space" }},
		{"StorageAudience", func(c *Config) { c.StorageAudience = "" }},
		{"StorageAudience", func(c *Config) { c.StorageAudience = strings.Repeat("a", maxClaimLength+1) }},
		{"StorageTokenTTL", func(c *Config) { c.StorageTokenTTL = 0 }},
		{"StorageTokenTTL", func(c *Config) { c.StorageTokenTTL = 59 * time.Second }},
		{"StorageTokenTTL", func(c *Config) { c.StorageTokenTTL = 25 * time.Hour }},
		{"StorageTokenTTL", func(c *Config) { c.StorageTokenTTL = time.Hour + time.Millisecond }},
		{"PinAudience", func(c *Config) { c.PinAudience = "with space" }},
		{"PinAudience", func(c *Config) { c.PinAudience = c.StorageAudience }},
		{"PinTokenTTL", func(c *Config) { c.PinTokenTTL = 30 * time.Second }},
		{"SigningKeys", func(c *Config) { c.SigningKeys = nil }},
		{"SigningKeys", func(c *Config) { c.SigningKeys = []SigningKey{{ID: "k1", Seed: []byte{1}}} }},
		{"SigningKeys", func(c *Config) {
			c.SigningKeys = []SigningKey{{ID: "k1", Seed: seed(1)}, {ID: "k1", Seed: seed(2)}}
		}},
		{"CurrentKeyID", func(c *Config) { c.CurrentKeyID = "" }},
		{"CurrentKeyID", func(c *Config) { c.CurrentKeyID = "k2" }},
		{"AllowedTeams", func(c *Config) { c.AllowedTeams = nil }},
		{"AllowedTeams", func(c *Config) { c.AllowedTeams = []string{"sales"} }},
		{"AllowedTeams", func(c *Config) { c.AllowedTeams, c.DeniedTeams = nil, []string{"*"} }},
		{"DeniedTeams", func(c *Config) { c.DeniedTeams = []string{"sales"} }},
		{"AllowedUsers", func(c *Config) { c.AllowedUsers = []string{"alice"} }},
		{"DeniedUsers", func(c *Config) { c.DeniedUsers = []string{"bob"} }},
		{"TokenLimit", func(c *Config) { c.TokenLimit = Limit{} }},
		{"KeyLimit", func(c *Config) { c.KeyLimit = Limit{N: 1, Window: time.Millisecond} }},
		{"MaxConcurrentWireChecks", func(c *Config) { c.MaxConcurrentWireChecks = 0 }},
	} {
		cfg := valid()
		tc.change(&cfg)
		err := cfg.Validate()
		var ce *ConfigError
		require.ErrorAs(t, err, &ce, tc.field)
		require.Equal(t, tc.field, ce.Field, err.Error())
	}
}

func TestPinAudienceIsOptional(t *testing.T) {
	cfg := valid()
	cfg.PinAudience = ""
	cfg.PinTokenTTL = 0
	require.NoError(t, cfg.Validate(), "without a PIN audience its lifetime does not matter")
	require.NotContains(t, cfg.audiences(), AudiencePin)
	require.Contains(t, valid().audiences(), AudiencePin)
	require.Equal(t, []string{valid().PinAudience, valid().StorageAudience}, valid().audiences()[AudiencePin].Aud,
		"a PIN token also names the storage server, for the slot lookup")
	require.Equal(t, []string{valid().StorageAudience}, valid().audiences()[AudienceStorage].Aud)
}

func TestValidAdmissionLists(t *testing.T) {
	cfg := valid()
	cfg.AllowedTeams = nil
	cfg.AllowedUsers = []string{aliceID + "@wire.example"}
	require.NoError(t, cfg.Validate())

	cfg = valid()
	cfg.AllowedTeams, cfg.DeniedTeams = []string{"*"}, []string{team}
	cfg.DeniedUsers = []string{"*"}
	require.NoError(t, cfg.Validate())
}

func TestParseSigningKeys(t *testing.T) {
	keys, err := ParseSigningKeys("k1:" + base64.RawURLEncoding.EncodeToString(seed(3)))
	require.NoError(t, err)
	require.Equal(t, []SigningKey{{ID: "k1", Seed: seed(3)}}, keys)
}

// freeAddr returns a local address that nothing listens on yet.
func freeAddr(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	addr := listener.Addr().String()
	require.NoError(t, listener.Close())
	return addr
}

// The whole service against a fake Wire backend: a token for an admitted user, the key set that verifies it, the
// probes, the metrics and the shutdown.
func TestRunExchangesATokenEndToEnd(t *testing.T) {
	wire := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/v15/self", r.URL.Path)
		if r.Header.Get("Authorization") != "Bearer wire-token" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"qualified_id":{"domain":"wire.example","id":"` + aliceID + `"},"team":"` + team + `"}`))
	}))
	defer wire.Close()

	cfg := valid()
	cfg.Addr = freeAddr(t)
	cfg.WireAPIURL = wire.URL + "/v15"
	cfg.SigningKeys = []SigningKey{{ID: "old", Seed: seed(1)}, {ID: "new", Seed: seed(2)}}
	cfg.CurrentKeyID = "new"

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	var logs bytes.Buffer
	go func() {
		done <- run(ctx, cfg, slog.New(slog.NewJSONHandler(&logs, nil)), dependencies{wireHTTP: wire.Client()})
	}()
	base := "http://" + cfg.Addr
	require.Eventually(t, func() bool {
		resp, err := http.Get(base + PathLive)
		if err != nil {
			return false
		}
		_ = resp.Body.Close()
		return resp.StatusCode == http.StatusOK
	}, 5*time.Second, 20*time.Millisecond)

	client, _, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)
	req, err := http.NewRequest(http.MethodPost, base+PathToken,
		strings.NewReader(`{"audience":"storage","publicKey":"`+base64.RawURLEncoding.EncodeToString(client)+`"}`))
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer wire-token")
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	var issued struct {
		Token string `json:"token"`
	}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&issued))
	_ = resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	// Verify the way the storage server does: fetch the key set, pick the key by kid.
	resp, err = http.Get(base + PathJWKS)
	require.NoError(t, err)
	var set struct {
		Keys []struct {
			Kid string `json:"kid"`
			X   string `json:"x"`
		} `json:"keys"`
	}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&set))
	_ = resp.Body.Close()
	require.Len(t, set.Keys, 2)
	parsed, err := jwt.Parse(issued.Token, func(tok *jwt.Token) (any, error) {
		for _, k := range set.Keys {
			if k.Kid == tok.Header["kid"] {
				x, err := base64.RawURLEncoding.DecodeString(k.X)
				return ed25519.PublicKey(x), err
			}
		}
		return nil, errors.New("unknown kid")
	}, jwt.WithValidMethods([]string{"EdDSA"}), jwt.WithIssuer(cfg.Issuer), jwt.WithAudience(cfg.StorageAudience))
	require.NoError(t, err)
	require.Equal(t, "new", parsed.Header["kid"])
	require.Equal(t, aliceID+"@wire.example", parsed.Claims.(jwt.MapClaims)["sub"])

	for _, path := range []string{PathReady, PathMetrics} {
		resp, err := http.Get(base + path)
		require.NoError(t, err)
		b, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		require.Equal(t, http.StatusOK, resp.StatusCode, path)
		if path == PathMetrics {
			require.Contains(t, string(b), `natrium_token_exchange_requests_total{result="ok"} 1`)
			require.Contains(t, string(b), `natrium_token_exchange_limited_users 1`)
		}
	}

	cancel()
	require.NoError(t, <-done)
	require.Contains(t, logs.String(), "starting server")
	require.NotContains(t, logs.String(), "wire-token")
	require.NotContains(t, logs.String(), issued.Token)
	require.NotContains(t, logs.String(), base64.RawURLEncoding.EncodeToString(seed(2)))
}

func TestRunRejectsInvalidConfig(t *testing.T) {
	cfg := valid()
	cfg.Issuer = ""
	err := Run(context.Background(), cfg, slog.New(slog.NewJSONHandler(io.Discard, nil)))
	var ce *ConfigError
	require.ErrorAs(t, err, &ce)
	require.Equal(t, "Issuer", ce.Field)
}
