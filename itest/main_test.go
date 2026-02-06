//go:build itest

package itest

import (
	"flag"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/btcsuite/btcwallet/bwtest"
)

var (
	// chainBackend defines the blockchain backend to be used for the
	// integration tests.
	// Options: "btcd" (default), "bitcoind", "neutrino".
	chainBackend = flag.String(
		"chain", "btcd",
		"chain backend to use (btcd, bitcoind, neutrino)",
	)

	// dbBackend defines the database backend to be used for the wallet
	// storage.
	// Options: "kvdb" (default), "sqlite", "postgres".
	//
	// This flag allows verifying that the wallet functions correctly across all
	// supported database drivers.
	dbBackend = flag.String(
		"db", "kvdb",
		"database backend to use (kvdb, sqlite, postgres)",
	)
)

// TestBtcWallet runs the btcwallet integration test suite.
func TestBtcWallet(t *testing.T) {
	if len(allTestCases) == 0 {
		t.Skip("no integration test cases registered")
	}

	harness := bwtest.SetupHarness(t, *chainBackend, *dbBackend)

	for _, tc := range allTestCases {
		if tc == nil {
			continue
		}

		validateTestCaseName(t, tc.Name)

		name := fmt.Sprintf("%s/%s", *chainBackend, tc.Name)

		success := t.Run(name, func(st *testing.T) {
			ht := harness.Subtest(st)
			ht.RunTestCase(tc.Name, tc.TestFunc)
		})
		if !success {
			t.Logf("failure time: %v", time.Now().Format(
				"2006-01-02 15:04:05.000",
			))
			break
		}
	}
}

// validateTestCaseName enforces a consistent naming convention for integration
// test cases.
//
// Names must be in the format "component action" (space separated), and must
// not include underscores.
func validateTestCaseName(t *testing.T, name string) {
	t.Helper()

	if strings.Contains(name, "_") {
		t.Fatalf("invalid test case name %q: underscores are not allowed",
			name)
	}

	words := strings.Fields(name)
	if len(words) < 2 {
		t.Fatalf("invalid test case name %q: want 'component action'",
			name)
	}
}
