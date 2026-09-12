//go:build itest

package itest

import (
	"testing"

	"github.com/btcsuite/btcwallet/wallet/internal/db/page"
	"github.com/stretchr/testify/require"
)

// uint32Ptr returns a pointer to the given uint32 value.
func uint32Ptr(v uint32) *uint32 {
	return &v
}

// newTestReq constructs a valid pagination request for tests.
func newTestReq[C any](t *testing.T, limit uint32) page.Request[C] {
	t.Helper()

	req, err := page.NewRequest[C](limit)
	require.NoError(t, err)

	return req
}
