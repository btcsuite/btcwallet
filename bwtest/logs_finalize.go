package bwtest

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
)

const (
	minerLogFilename        = "miner.log"
	chainBackendLogFilename = "chain_backend.log"

	logFilePerm = 0o600
)

// finalizeLogs flattens component logs into the per-run log directory.
func (h *HarnessTest) finalizeLogs() {
	h.Helper()

	// Flatten miner logs.
	minerDst := filepath.Join(h.logDir, minerLogFilename)

	err := flattenBtcdLogs(h.T, h.miner.logPath, minerDst)
	if err != nil {
		h.Logf("failed to flatten miner logs: %v", err)
	}

	chainLogDir := h.Backend.LogDir()

	chainDst := filepath.Join(h.logDir, chainBackendLogFilename)
	if chainLogDir == "" {
		// Some backends (eg. neutrino) do not have an external process log
		// directory. Still create the file for consistent log collection.
		// #nosec G304 -- chainDst is created by the test harness.
		f, err := os.OpenFile(
			chainDst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, logFilePerm,
		)
		if err != nil {
			h.Logf("failed to create chain backend log file: %v", err)
			return
		}

		_ = f.Close()

		return
	}

	switch h.Backend.Name() {
	case backendBtcd:
		err = flattenBtcdLogs(h.T, chainLogDir, chainDst)
		if err != nil {
			h.Logf("failed to flatten btcd backend logs: %v", err)
		}

	case backendBitcoind:
		err = flattenBitcoindLogs(h.T, chainLogDir, chainDst)
		if err != nil {
			h.Logf("failed to flatten bitcoind backend logs: %v", err)
		}

	default:
		// No backend logs to flatten.
	}
}

// flattenBitcoindLogs concatenates bitcoind logs under srcDir into dstFile.
func flattenBitcoindLogs(t *testing.T, srcDir, dstFile string) error {
	t.Helper()

	// Capture process stdout/stderr first, as fatal startup errors might not be
	// present in debug.log.
	prelude := []string{
		filepath.Join(srcDir, "bitcoind.stderr.log"),
		filepath.Join(srcDir, "bitcoind.stdout.log"),
	}

	pattern := filepath.Join(srcDir, "*", "debug.log*")

	matches, err := filepath.Glob(pattern)
	if err != nil {
		return fmt.Errorf("glob bitcoind logs: %w", err)
	}

	files := make([]string, 0, len(prelude)+len(matches))
	files = append(files, prelude...)
	files = append(files, matches...)

	files = filterRegularFiles(files)
	if len(files) == 0 {
		return nil
	}

	// bitcoind rotates debug.log.1, debug.log.2 etc but we don't try too hard
	// ordering here.
	sort.Strings(files)

	// #nosec G304 -- dstFile is created by the test harness.
	f, err := os.OpenFile(dstFile, os.O_CREATE|os.O_WRONLY|os.O_TRUNC,
		logFilePerm)
	if err != nil {
		return fmt.Errorf("open dst log: %w", err)
	}

	defer func() {
		_ = f.Close()
	}()

	for i, p := range files {
		// Keep a blank line between concatenated source files to make the
		// merged output easier to scan when debugging CI failures.
		if i > 0 {
			_, _ = f.WriteString("\n")
		}

		base := filepath.Base(p)
		_, _ = f.WriteString("--- " + base + " ---\n")

		// #nosec G304 -- p is discovered under the harness-controlled log dir.
		src, err := os.Open(p)
		if err != nil {
			return fmt.Errorf("open src log: %w", err)
		}

		_, cpErr := io.Copy(f, src)
		_ = src.Close()

		if cpErr != nil {
			return fmt.Errorf("copy src log: %w", cpErr)
		}
	}

	_ = os.RemoveAll(srcDir)

	return nil
}

// flattenBtcdLogs concatenates btcd logs under srcDir into dstFile.
func flattenBtcdLogs(t *testing.T, srcDir, dstFile string) error {
	t.Helper()

	pattern := filepath.Join(srcDir, "*", "btcd.log*")

	matches, err := filepath.Glob(pattern)
	if err != nil {
		return fmt.Errorf("glob btcd logs: %w", err)
	}

	if len(matches) == 0 {
		return nil
	}

	files := filterRegularFiles(matches)
	if len(files) == 0 {
		return nil
	}

	sortBtcdLogs(files)

	// #nosec G304 -- dstFile is created by the test harness.
	f, err := os.OpenFile(dstFile, os.O_CREATE|os.O_WRONLY|os.O_TRUNC,
		logFilePerm)
	if err != nil {
		return fmt.Errorf("open dst log: %w", err)
	}

	defer func() {
		_ = f.Close()
	}()

	for i, p := range files {
		// Add a small delimiter between rotated files.
		if i > 0 {
			_, _ = f.WriteString("\n")
		}

		base := filepath.Base(p)
		_, _ = f.WriteString("--- " + base + " ---\n")

		// #nosec G304 -- p is discovered under the harness-controlled log dir.
		src, err := os.Open(p)
		if err != nil {
			return fmt.Errorf("open src log: %w", err)
		}

		_, cpErr := io.Copy(f, src)
		_ = src.Close()

		if cpErr != nil {
			return fmt.Errorf("copy src log: %w", cpErr)
		}
	}

	// Best effort cleanup to keep the log dir shallow.
	_ = os.RemoveAll(srcDir)

	return nil
}

// filterRegularFiles filters to existing regular files.
func filterRegularFiles(paths []string) []string {
	files := make([]string, 0, len(paths))
	for _, p := range paths {
		info, err := os.Stat(p)
		if err != nil {
			continue
		}

		if info.Mode().IsRegular() {
			files = append(files, p)
		}
	}

	return files
}

// sortBtcdLogs sorts btcd logs by rotation index so older logs appear first.
func sortBtcdLogs(paths []string) {
	sort.Slice(paths, func(i, j int) bool {
		iBase := filepath.Base(paths[i])
		jBase := filepath.Base(paths[j])

		// Prefer older rotated logs first: btcd.log.N ... btcd.log.1 then
		// btcd.log.
		iN, iOk := btcdLogRotationIndex(iBase)

		jN, jOk := btcdLogRotationIndex(jBase)
		if iOk && jOk {
			// Larger rotation index means an older file. For example,
			// btcd.log.3 is older than btcd.log.1 and should be concatenated
			// first.
			return iN > jN
		}

		if iOk != jOk {
			// Rotated logs before the active log.
			return iOk
		}

		// Fallback to lexicographic ordering.
		return iBase < jBase
	})
}

// btcdLogRotationIndex parses the rotation suffix of btcd log filenames.
func btcdLogRotationIndex(base string) (int, bool) {
	// btcd rotates logs like btcd.log.1, btcd.log.2, ...
	const prefix = "btcd.log."
	if !strings.HasPrefix(base, prefix) {
		return 0, false
	}

	n, err := strconv.Atoi(strings.TrimPrefix(base, prefix))
	if err != nil {
		return 0, false
	}

	return n, true
}
