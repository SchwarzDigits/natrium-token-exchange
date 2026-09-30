package config_test

import (
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/SchwarzDigits/natrium-token-exchange/config"
)

func TestLoadFromReadsThroughTheGivenFunction(t *testing.T) {
	vars := map[string]string{
		config.EnvPort:            "9001",
		config.EnvWireAPIURL:      "https://wire.example/v15",
		config.EnvIssuer:          "https://token.example",
		config.EnvStorageAudience: "wss://vfs.example/v1/ws",
		config.EnvSigningKeys:     "k1:" + base64.RawURLEncoding.EncodeToString(make([]byte, 32)),
		config.EnvCurrentKeyID:    "k1",
		config.EnvAllowedTeams:    "8b3c1a2e-0f4d-4e5a-9b6c-7d8e9f0a1b2c",
	}
	cfg, err := config.LoadFrom(func(name string) string { return vars[name] })
	require.NoError(t, err)
	require.Equal(t, ":9001", cfg.Server.Addr)
	require.Equal(t, "https://token.example", cfg.Server.Issuer)

	delete(vars, config.EnvIssuer)
	_, err = config.LoadFrom(func(name string) string { return vars[name] })
	require.ErrorContains(t, err, config.EnvIssuer)
}
