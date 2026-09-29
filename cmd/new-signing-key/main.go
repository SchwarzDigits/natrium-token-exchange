// Command new-signing-key creates a signing key for natrium-token-exchange. It prints only the entry for
// NATRIUM_TOKEN_EXCHANGE_SIGNING_KEYS, <key ID>:<base64url seed>, on stdout. The entry is a secret: store it where the
// deployment keeps its secrets, not in a file next to the configuration.
//
//	new-signing-key -key-id 2026-09
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/SchwarzDigits/natrium-token-exchange/internal/signing"
)

func main() {
	err := run(os.Args[1:], os.Stdout, os.Stderr)
	switch {
	case errors.Is(err, flag.ErrHelp):
		os.Exit(0)
	case err != nil:
		fmt.Fprintln(os.Stderr, "new-signing-key:", err)
		os.Exit(1)
	}
}

// run parses args, creates the key and writes its entry to out. Usage goes to errOut.
func run(args []string, out, errOut io.Writer) error {
	flags := flag.NewFlagSet("new-signing-key", flag.ContinueOnError)
	flags.SetOutput(errOut)
	keyID := flags.String("key-id", "", "ID of the new key, as tokens name it in their kid header (required; "+
		"A-Z, a-z, 0-9, '-' and '_')")
	if err := flags.Parse(args); err != nil {
		return err
	}
	switch {
	case flags.NArg() > 0:
		return fmt.Errorf("unexpected argument %q", flags.Arg(0))
	case *keyID == "":
		return errors.New("-key-id is required")
	}
	key, err := signing.NewKey(*keyID)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintln(out, key.Entry())
	return err
}
