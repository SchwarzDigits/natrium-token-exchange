// Command natrium-token-exchange runs the token exchange of Natrium. It reads its configuration from
// NATRIUM_TOKEN_EXCHANGE_* environment variables, logs JSON to stdout and shuts down gracefully on SIGINT and SIGTERM.
package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"

	"github.com/SchwarzDigits/natrium-token-exchange/config"
	"github.com/SchwarzDigits/natrium-token-exchange/internal/platform"
	"github.com/SchwarzDigits/natrium-token-exchange/server"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "natrium-token-exchange:", err)
		os.Exit(1)
	}
}

// run reads the configuration and serves until ctx is canceled. Logs go to out.
func run(ctx context.Context, out io.Writer) error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	return config.Named(server.Run(ctx, cfg.Server, platform.NewLogger(out, cfg.LogLevel)))
}
