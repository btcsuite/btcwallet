package chain

import (
	"errors"
	"testing"

	"github.com/btcsuite/btcd/btcjson"
	"github.com/stretchr/testify/require"
)

// TestBitcoindMapRPCErr checks cluster-limit reasons share the existing chain
// limit category while legacy and unknown reasons retain their classifications.
func TestBitcoindMapRPCErr(t *testing.T) {
	t.Parallel()

	// Arrange both Core call boundaries: acceptance returns a raw reason,
	// while publication returns an RPC error. Controls preserve the older
	// chain-limit spelling and fallback for unknown reasons.
	testCases := []struct {
		name   string
		rpcErr error
		want   error
	}{
		{
			name:   "cluster acceptance rejection",
			rpcErr: errors.New("too-large-cluster"),
			want:   ErrMempoolChainTooLong,
		},
		{
			name: "cluster publication rejection",
			rpcErr: &btcjson.RPCError{
				Code:    btcjson.ErrRPCVerifyRejected,
				Message: "too-large-cluster",
			},
			want: ErrMempoolChainTooLong,
		},
		{
			name:   "legacy chain rejection",
			rpcErr: errors.New("too-long-mempool-chain"),
			want:   ErrMempoolChainTooLong,
		},
		{
			name:   "unknown rejection",
			rpcErr: errors.New("unrecognized rejection"),
			want:   ErrUndefined,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			// Arrange a disconnected client: mapping is pure
			// classification and must not require a live backend.
			client := &BitcoindClient{}

			// Act through the shared acceptance/publication mapper.
			err := client.MapRPCErr(tc.rpcErr)

			// Assert callers can match the policy category through
			// errors.Is, including the unknown fallback's wrapping.
			require.ErrorIs(t, err, tc.want)
		})
	}
}

// TestMatchErrStr checks that `matchErrStr` can correctly replace the dashes
// with spaces and turn title cases into lowercases for a given error and match
// it against the specified string pattern.
func TestMatchErrStr(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name        string
		bitcoindErr error
		matchStr    string
		matched     bool
	}{
		{
			name:        "error without dashes",
			bitcoindErr: errors.New("missing input"),
			matchStr:    "missing input",
			matched:     true,
		},
		{
			name:        "match str without dashes",
			bitcoindErr: errors.New("missing-input"),
			matchStr:    "missing input",
			matched:     true,
		},
		{
			name:        "error with dashes",
			bitcoindErr: errors.New("missing-input"),
			matchStr:    "missing input",
			matched:     true,
		},
		{
			name:        "match str with dashes",
			bitcoindErr: errors.New("missing-input"),
			matchStr:    "missing-input",
			matched:     true,
		},
		{
			name:        "error with title case and dash",
			bitcoindErr: errors.New("Missing-Input"),
			matchStr:    "missing input",
			matched:     true,
		},
		{
			name:        "match str with title case and dash",
			bitcoindErr: errors.New("missing-input"),
			matchStr:    "Missing-Input",
			matched:     true,
		},
		{
			name:        "unmatched error",
			bitcoindErr: errors.New("missing input"),
			matchStr:    "missingorspent",
			matched:     false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			matched := matchErrStr(tc.bitcoindErr, tc.matchStr)
			require.Equal(t, tc.matched, matched)
		})
	}
}

// TestErrorSentinel checks that all defined RPCErr errors are added to the
// method `Error`.
func TestBitcoindErrorSentinel(t *testing.T) {
	t.Parallel()

	rt := require.New(t)

	for i := uint32(0); i < uint32(errSentinel); i++ {
		err := RPCErr(i)
		rt.NotEqualf(err.Error(), "unknown error", "error code %d is "+
			"not defined, make sure to update it inside the Error "+
			"method", i)
	}
}
