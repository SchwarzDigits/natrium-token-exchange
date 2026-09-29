package platform

import (
	"fmt"

	"golang.org/x/sys/unix"
)

// ProtectProcess makes the process not dumpable and turns off core dumps: another process of the same user cannot
// attach a debugger or read the process's memory and environment through /proc, and a crash writes no memory to disk.
// The signing keys are in both.
func ProtectProcess() error {
	if err := unix.Prctl(unix.PR_SET_DUMPABLE, 0, 0, 0, 0); err != nil {
		return fmt.Errorf("prctl PR_SET_DUMPABLE: %w", err)
	}
	if err := unix.Setrlimit(unix.RLIMIT_CORE, &unix.Rlimit{Cur: 0, Max: 0}); err != nil {
		return fmt.Errorf("setrlimit RLIMIT_CORE: %w", err)
	}
	return nil
}
