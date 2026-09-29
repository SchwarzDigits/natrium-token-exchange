package config

import (
	"bytes"
	"encoding/base64"
	"errors"
	"log/slog"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/SchwarzDigits/natrium-token-exchange/server"
)

const (
	team  = "8b3c1a2e-0f4d-4e5a-9b6c-7d8e9f0a1b2c"
	alice = "39b7f597-dfd1-4dff-86f5-fe1b79cb70a0@wire.example"
)

var seed = base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{9}, 32))

func setValid(t *testing.T) {
	t.Helper()
	t.Setenv(EnvWireAPIURL, "https://nginz-https.wire.example/v15")
	t.Setenv(EnvIssuer, "https://token.example")
	t.Setenv(EnvAudience, "wss://vfs.example/v1/ws")
	t.Setenv(EnvSigningKeys, "k1:"+seed)
	t.Setenv(EnvCurrentKeyID, "k1")
	t.Setenv(EnvAllowedTeams, team)
	for _, name := range []string{EnvPort, EnvLogLevel, EnvTokenTTL, EnvDeniedTeams, EnvAllowedUsers, EnvDeniedUsers} {
		t.Setenv(name, "")
	}
}

func TestLoadDefaults(t *testing.T) {
	setValid(t)
	cfg, err := Load()
	require.NoError(t, err)
	require.Equal(t, ":8080", cfg.Server.Addr)
	require.Equal(t, slog.LevelInfo, cfg.LogLevel)
	require.Equal(t, time.Hour, cfg.Server.TokenTTL)
	require.Equal(t, []string{team}, cfg.Server.AllowedTeams)
	require.Nil(t, cfg.Server.AllowedUsers)
	require.Equal(t, "k1", cfg.Server.CurrentKeyID)
	require.Len(t, cfg.Server.SigningKeys, 1)
}

func TestLoadAll(t *testing.T) {
	setValid(t)
	t.Setenv(EnvPort, "9090")
	t.Setenv(EnvLogLevel, "debug")
	t.Setenv(EnvTokenTTL, "30m")
	t.Setenv(EnvAllowedTeams, "*")
	t.Setenv(EnvDeniedTeams, team)
	t.Setenv(EnvAllowedUsers, alice+", "+alice)
	t.Setenv(EnvDeniedUsers, "*")
	cfg, err := Load()
	require.NoError(t, err)
	require.Equal(t, ":9090", cfg.Server.Addr)
	require.Equal(t, slog.LevelDebug, cfg.LogLevel)
	require.Equal(t, 30*time.Minute, cfg.Server.TokenTTL)
	require.Equal(t, []string{"*"}, cfg.Server.AllowedTeams)
	require.Equal(t, []string{team}, cfg.Server.DeniedTeams)
	require.Equal(t, []string{alice, alice}, cfg.Server.AllowedUsers)
	require.Equal(t, []string{"*"}, cfg.Server.DeniedUsers)
}

func TestLoadNamesTheVariable(t *testing.T) {
	for name, value := range map[string]string{
		EnvPort:         "http",
		EnvLogLevel:     "loud",
		EnvWireAPIURL:   "http://nginz-https.wire.example/v15",
		EnvIssuer:       "",
		EnvAudience:     "",
		EnvTokenTTL:     "an hour",
		EnvSigningKeys:  "k1",
		EnvCurrentKeyID: "k2",
		EnvAllowedTeams: "sales",
		EnvDeniedTeams:  "sales",
		EnvAllowedUsers: "alice",
		EnvDeniedUsers:  "bob",
	} {
		setValid(t)
		t.Setenv(name, value)
		_, err := Load()
		require.Error(t, err, name)
		require.Contains(t, err.Error(), name)
		require.NotContains(t, err.Error(), seed)
	}
}

func TestLoadRequiresTeamsOrUsers(t *testing.T) {
	setValid(t)
	t.Setenv(EnvAllowedTeams, " , ")
	_, err := Load()
	require.ErrorContains(t, err, EnvAllowedTeams)
}

func TestNamed(t *testing.T) {
	require.NoError(t, Named(nil))
	other := errors.New("other")
	require.Equal(t, other, Named(other))
	require.EqualError(t, Named(&server.ConfigError{Field: "Issuer", Problem: "is required"}),
		EnvIssuer+": is required")
	require.EqualError(t, Named(&server.ConfigError{Field: "Unknown", Problem: "x"}), "Unknown: x")
}
