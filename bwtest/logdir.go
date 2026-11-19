package bwtest

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

const (
	// testLogsRootDir is the directory under the itest package where all
	// per-run logs are stored.
	//
	// Note: When running the integration tests with `go test ./itest`, the
	// working directory is `itest`, so logs are written under
	// `itest/test-logs`.
	testLogsRootDir = "test-logs"

	maxLogDirAttempts = 1000
)

// createTestLogDir creates a per-run log directory under `test-logs`.
//
// The directory is named using the format:
//
//	log-<chain>-<db>-YYYYMMDD-HHMMSS
//
// If the directory already exists, a numeric suffix is appended.
func createTestLogDir(t *testing.T, chainBackend, dbBackend string) string {
	t.Helper()

	err := os.MkdirAll(testLogsRootDir, logDirPerm)
	require.NoError(t, err, "unable to create test log root")

	chainBackend = sanitizeLogToken(chainBackend)
	dbBackend = sanitizeLogToken(dbBackend)

	base := fmt.Sprintf(
		"log-%s-%s-%s", chainBackend, dbBackend,
		time.Now().Format("20060102-150405"),
	)

	// Use Mkdir instead of MkdirAll so we can detect collisions and retry
	// with a deterministic numeric suffix.
	for i := range maxLogDirAttempts {
		dir := base
		if i > 0 {
			dir = fmt.Sprintf("%s-%d", base, i)
		}

		fullPath := filepath.Join(testLogsRootDir, dir)

		err := os.Mkdir(fullPath, logDirPerm)
		if err == nil {
			_, _ = fmt.Fprintf(os.Stdout, "itest logs dir: %s\n", fullPath)
			return fullPath
		}

		if os.IsExist(err) {
			continue
		}

		require.NoError(t, err, "unable to create test log dir")
	}

	t.Fatalf(
		"unable to create test log dir: too many collisions (%d)",
		maxLogDirAttempts,
	)

	return ""
}

// sanitizeLogToken converts a string into a safe filename token.
func sanitizeLogToken(token string) string {
	if token == "" {
		return "unknown"
	}

	var b strings.Builder
	for _, r := range token {
		if isSafeLogRune(r) {
			b.WriteRune(r)
			continue
		}

		b.WriteByte('_')
	}

	return b.String()
}

// isSafeLogRune reports whether r can be used in log directory/file names
// without additional escaping.
func isSafeLogRune(r rune) bool {
	switch {
	case r >= 'a' && r <= 'z':
		return true
	case r >= 'A' && r <= 'Z':
		return true
	case r >= '0' && r <= '9':
		return true
	case r == '-' || r == '_':
		return true
	default:
		return false
	}
}

// createOrEnsureLogSubDir creates a named sub-directory under a per-run log
// directory.
func createOrEnsureLogSubDir(t *testing.T, parent, name string) string {
	t.Helper()

	full := filepath.Join(parent, name)
	err := os.MkdirAll(full, logDirPerm)
	require.NoError(t, err, "unable to create log subdir")

	return full
}

// createUniqueLogSubDir creates a uniquely named sub-directory under a per-run
// log directory.
func createUniqueLogSubDir(t *testing.T, parent, prefix string) string {
	t.Helper()

	// Retry with a numeric suffix when a directory name collision occurs.
	for i := range maxLogDirAttempts {
		dir := prefix
		if i > 0 {
			dir = fmt.Sprintf("%s-%d", prefix, i)
		}

		full := filepath.Join(parent, dir)

		err := os.Mkdir(full, logDirPerm)
		if err == nil {
			return full
		}

		if os.IsExist(err) {
			continue
		}

		require.NoError(t, err, "unable to create log subdir")
	}

	t.Fatalf(
		"unable to create log subdir: too many collisions (%d)",
		maxLogDirAttempts,
	)

	return ""
}
