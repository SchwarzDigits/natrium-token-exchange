package main

import (
	"bytes"
	"errors"
	"flag"
	"io"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/SchwarzDigits/natrium-token-exchange/server"
)

func TestPrintsAnEntryTheServerLoads(t *testing.T) {
	var out bytes.Buffer
	require.NoError(t, run([]string{"-key-id", "2026-09"}, &out, io.Discard))
	line := strings.TrimSuffix(out.String(), "\n")
	require.NotContains(t, line, "\n", "only the entry is printed")
	keys, err := server.ParseSigningKeys(line)
	require.NoError(t, err)
	require.Len(t, keys, 1)
	require.Equal(t, "2026-09", keys[0].ID)

	var again bytes.Buffer
	require.NoError(t, run([]string{"-key-id", "2026-09"}, &again, io.Discard))
	require.NotEqual(t, out.String(), again.String(), "every key has a new seed")
}

func TestRejectsBadArguments(t *testing.T) {
	for _, args := range [][]string{
		nil,
		{"-key-id", ""},
		{"-key-id", "with space"},
		{"-key-id", "a", "extra"},
		{"-unknown"},
	} {
		var out bytes.Buffer
		require.Error(t, run(args, &out, io.Discard), args)
		require.Empty(t, out.String(), args)
	}
	require.True(t, errors.Is(run([]string{"-h"}, io.Discard, io.Discard), flag.ErrHelp))
}
