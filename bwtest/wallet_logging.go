package bwtest

import (
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/btcsuite/btcd/rpcclient"
	"github.com/btcsuite/btclog"
	"github.com/btcsuite/btcwallet/chain"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/btcsuite/btcwallet/wallet"
	"github.com/btcsuite/btcwallet/wtxmgr"
	"github.com/stretchr/testify/require"
)

// walletLogFilePerm is intentionally more restrictive than logDirPerm because
// wallet logs may contain addresses, txids, and operational details that should
// not be readable by other users on a shared machine.
const walletLogFilePerm = 0o600

// setUpWalletLogging configures the btclog-based loggers used by btcwallet to
// write into the provided log file path.
//
// NOTE: This is package-global logger configuration. It should only be used in
// serial integration tests.
func setUpWalletLogging(t *testing.T, logPath string) func() {
	t.Helper()

	// #nosec G304 -- logPath is created by the test harness.
	f, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC,
		walletLogFilePerm)
	require.NoError(t, err, "unable to create wallet log file")

	backend := btclog.NewBackend(f)

	btwl := backend.Logger("BTWL")
	amgr := backend.Logger("AMGR")
	tmgr := backend.Logger("TMGR")
	chio := backend.Logger("CHIO")
	rpcl := backend.Logger("RPCC")

	level, _ := btclog.LevelFromString("debug")
	btwl.SetLevel(level)
	amgr.SetLevel(level)
	tmgr.SetLevel(level)
	chio.SetLevel(level)
	rpcl.SetLevel(level)

	wallet.UseLogger(btwl)
	waddrmgr.UseLogger(amgr)
	wtxmgr.UseLogger(tmgr)
	chain.UseLogger(chio)
	rpcclient.UseLogger(rpcl)

	return func() {
		_ = f.Sync()
		_ = f.Close()
	}
}

// walletLogFileName returns the per-test wallet log filename.
func walletLogFileName(t *testing.T) string {
	t.Helper()

	// Use the leaf subtest name to keep filenames short.
	name := t.Name()

	parts := strings.Split(name, "/")
	if len(parts) > 0 {
		name = parts[len(parts)-1]
	}

	name = sanitizeLogToken(name)

	return fmt.Sprintf("wallet-%s.log", name)
}
