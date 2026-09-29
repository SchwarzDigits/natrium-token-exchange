package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"net"
	"net/http"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/SchwarzDigits/natrium-token-exchange/internal/config"
	"github.com/SchwarzDigits/natrium-token-exchange/server"
)

// lockedBuffer collects log output written from several goroutines.
type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// The command started with only its environment variables serves the probes, the key set and the metrics, logs JSON
// and stops when its context is canceled.
func TestRunServesWithEnvironmentVariables(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	port := listener.Addr().(*net.TCPAddr).Port
	require.NoError(t, listener.Close())

	seed := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{5}, 32))
	t.Setenv(config.EnvPort, strconv.Itoa(port))
	t.Setenv(config.EnvLogLevel, "info")
	t.Setenv(config.EnvWireAPIURL, "https://127.0.0.1:1/v15")
	t.Setenv(config.EnvIssuer, "https://token.example")
	t.Setenv(config.EnvAudience, "wss://vfs.example/v1/ws")
	t.Setenv(config.EnvTokenTTL, "")
	t.Setenv(config.EnvSigningKeys, "k1:"+seed)
	t.Setenv(config.EnvCurrentKeyID, "k1")
	t.Setenv(config.EnvAllowedTeams, "8b3c1a2e-0f4d-4e5a-9b6c-7d8e9f0a1b2c")
	t.Setenv(config.EnvDeniedTeams, "")
	t.Setenv(config.EnvAllowedUsers, "")
	t.Setenv(config.EnvDeniedUsers, "")
	t.Setenv(config.EnvTokenLimit, "")
	t.Setenv(config.EnvKeyLimit, "")
	t.Setenv(config.EnvMaxConcurrentWireChecks, "")

	ctx, cancel := context.WithCancel(context.Background())
	var logs lockedBuffer
	done := make(chan error, 1)
	go func() { done <- run(ctx, &logs) }()

	base := "http://127.0.0.1:" + strconv.Itoa(port)
	require.Eventually(t, func() bool {
		resp, err := http.Get(base + server.PathLive)
		if err != nil {
			return false
		}
		_ = resp.Body.Close()
		return resp.StatusCode == http.StatusOK
	}, 5*time.Second, 20*time.Millisecond)
	for _, path := range []string{server.PathReady, server.PathJWKS, server.PathMetrics} {
		resp, err := http.Get(base + path)
		require.NoError(t, err)
		_ = resp.Body.Close()
		require.Equal(t, http.StatusOK, resp.StatusCode, path)
	}

	cancel()
	require.NoError(t, <-done)
	require.Contains(t, logs.String(), `"msg":"starting server"`)
	require.NotContains(t, logs.String(), seed)
}

func TestRunNamesTheVariable(t *testing.T) {
	t.Setenv(config.EnvIssuer, "")
	err := run(context.Background(), &bytes.Buffer{})
	require.Error(t, err)
	require.Contains(t, err.Error(), "NATRIUM_TOKEN_EXCHANGE_")
}
