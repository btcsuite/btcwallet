//go:build itest

package itest

import "github.com/btcsuite/btcwallet/bwtest"

// testCase defines a single integration test case.
type testCase struct {
	// Name is the human-readable name of the test case.
	Name string

	// TestFunc executes the test case.
	TestFunc func(t *bwtest.HarnessTest)
}

// allTestCases is the full set of integration test cases.
var allTestCases = []*testCase{
	{
		Name:     "manager create wallet",
		TestFunc: testCreateWallet,
	},
}
