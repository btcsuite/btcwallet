package bwtest

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

// GetBtcdBinary returns the path to the btcd binary.
// It checks if "btcd" is in the PATH.
func GetBtcdBinary() (string, error) {
	// If specific path is needed, we could check env vars here.
	path, err := exec.LookPath("btcd")
	if err != nil {
		return "", fmt.Errorf("failed to find btcd binary: %w", err)
	}

	path, err = filepath.Abs(path)
	if err != nil {
		return "", fmt.Errorf("failed to get absolute path: %w", err)
	}

	return path, nil
}

// GetBitcoindBinary returns the path to the bitcoind binary.
func GetBitcoindBinary() (string, error) {
	path, err := exec.LookPath("bitcoind")
	if err != nil {
		return "", fmt.Errorf("failed to find bitcoind binary: %w", err)
	}

	path, err = filepath.Abs(path)
	if err != nil {
		return "", fmt.Errorf("failed to get absolute path: %w", err)
	}

	return path, nil
}

// ensureLogDir creates the log directory if it doesn't exist.
func ensureLogDir(dir string) error {
	err := os.MkdirAll(dir, logDirPerm)
	if err != nil {
		return fmt.Errorf("mkdir log dir: %w", err)
	}

	return nil
}
