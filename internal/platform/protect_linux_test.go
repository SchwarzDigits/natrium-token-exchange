package platform

import (
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

func TestProtectProcess(t *testing.T) {
	require.NoError(t, ProtectProcess())
	dumpable, err := unix.PrctlRetInt(unix.PR_GET_DUMPABLE, 0, 0, 0, 0)
	require.NoError(t, err)
	require.Zero(t, dumpable)
	var core unix.Rlimit
	require.NoError(t, unix.Getrlimit(unix.RLIMIT_CORE, &core))
	require.Zero(t, core.Cur)
}
