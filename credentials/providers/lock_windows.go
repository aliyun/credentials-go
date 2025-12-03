//go:build windows

package providers

// lockFile is a no-op on Windows
func lockFile(fd int) error {
	return nil
}

// unlockFile is a no-op on Windows
func unlockFile(fd int) error {
	return nil
}
