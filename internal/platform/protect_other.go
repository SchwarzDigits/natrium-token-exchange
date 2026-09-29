//go:build !linux

package platform

// ProtectProcess does nothing on platforms other than Linux, which the service is not deployed on.
func ProtectProcess() error {
	return nil
}
