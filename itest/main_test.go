//go:build itest

package itest

import (
	"flag"
	"fmt"
	"math/rand"
	"strings"
	"testing"
	"time"

	"github.com/btcsuite/btcd/integration/rpctest"
	"github.com/btcsuite/btcwallet/bwtest"
	"github.com/btcsuite/btcwallet/chain/port"
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

	// shuffleSeedFlag is the source of randomness used to shuffle the test
	// cases. If not specified, the test cases won't be shuffled.
	shuffleSeedFlag = flag.Uint64(
		"shuffleseed", 0,
		"if set, shuffles the test cases using this as the source of "+
			"randomness",
	)
)

func init() {
	// Use system-unique ports for rpctest harnesses so multiple local test runs
	// don't collide.
	rpctest.ListenAddressGenerator = func() (string, string) {
		p2p := fmt.Sprintf(rpctest.ListenerFormat, port.NextAvailablePort())
		rpc := fmt.Sprintf(rpctest.ListenerFormat, port.NextAvailablePort())
		return p2p, rpc
	}
}

// TestBtcWallet runs the btcwallet integration test suite.
func TestBtcWallet(t *testing.T) {
	if len(allTestCases) == 0 {
		t.Skip("no integration test cases registered")
	}

	maybeShuffleTestCases()

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

// maybeShuffleTestCases shuffles the test cases if the flag `shuffleseed` is
// set and not 0.
func maybeShuffleTestCases() {
	// Exit if set to 0.
	if *shuffleSeedFlag == 0 {
		return
	}

	r := rand.New(rand.NewSource(int64(*shuffleSeedFlag)))
	r.Shuffle(len(allTestCases), func(i, j int) {
		allTestCases[i], allTestCases[j] = allTestCases[j], allTestCases[i]
	})
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
