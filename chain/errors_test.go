package chain

import (
	"errors"
	"strings"
	"testing"

	"github.com/btcsuite/btcd/btcjson"
	"github.com/btcsuite/btcd/rpcclient"
	"github.com/lightninglabs/neutrino/pushtx"
	"github.com/stretchr/testify/require"
)

// TestBitcoindMapRPCErr checks cluster-limit reasons share the existing chain
// limit category while legacy and unknown reasons retain their classifications.
//
//nolint:err113 // Fixtures reproduce raw backend rejection strings.
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

// TestBtcdMapRPCErr checks input diagnostics take precedence over their
// nested policy causes while output and unknown errors retain their identity.
//
//nolint:err113 // Fixtures reproduce raw backend rejection strings.
func TestBtcdMapRPCErr(t *testing.T) {
	t.Parallel()

	// Arrange a closed SDK client so the unknown-reason version lookup
	// terminates without network I/O; known reasons need no backend lookup.
	rpc, err := rpcclient.New(
		&rpcclient.ConnConfig{
			DisableConnectOnNew: true,
		}, nil,
	)
	require.NoError(t, err)
	rpc.Shutdown()
	rpc.WaitForShutdown()

	// Use diagnostics that embed broad keys in their causes so each
	// assertion checks precedence over unordered table iteration.
	txid := strings.Repeat("a", 64)
	inputContext := txid + ":0 which references output " + txid + ":1 - "
	scripts := " (input witness [], input script bytes 00, " +
		"prev output script bytes 51)"
	nonStandard := "transaction " + txid +
		" has a non-standard input: transaction input #0 has a " +
		"non-standard script form"
	testCases := []struct {
		name   string
		rpcErr error
		want   error
	}{
		{
			name: "input parsing",
			rpcErr: errors.New("failed to parse input " +
				inputContext + "signature script is not push only" +
				scripts),
			want: ErrScriptVerifyFlag,
		},
		{
			name: "input validation",
			rpcErr: errors.New("failed to validate input " +
				inputContext + "invalid transaction version: 1" +
				scripts),
			want: ErrScriptVerifyFlag,
		},
		{
			name: "publication rejection",
			rpcErr: &btcjson.RPCError{
				Code:    btcjson.ErrRPCTxRejected,
				Message: "TX rejected: " + nonStandard,
			},
			want: ErrNonStandardInputs,
		},
		{
			name: "nonstandard output",
			rpcErr: errors.New("transaction " + txid +
				" is not standard: transaction output 0: " +
				"non-standard script form"),
			want: ErrNonStandardScript,
		},
		{
			name:   "unknown rejection",
			rpcErr: errors.New("unrecognized btcd rejection"),
			want:   ErrUndefined,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			// Arrange this mapper with the closed transport so the
			// unknown fallback cannot depend on a live backend.
			client := &RPCClient{
				Client: rpc,
			}

			// Act through the acceptance/publication mapper with the
			// complete backend diagnostic, including any broad cause.
			err := client.MapRPCErr(tc.rpcErr)

			// Assert the caller sees the precise input category or
			// the unchanged output/unknown fallback through errors.Is.
			require.ErrorIs(t, err, tc.want)
		})
	}
}

// TestNeutrinoMapRPCErr checks peer input rejects retain their specificity
// when the shared btcd table also matches the nested script-policy text.
func TestNeutrinoMapRPCErr(t *testing.T) {
	t.Parallel()

	// Arrange the real peer-reject wrapper without a chain service: the
	// mapper only needs the reason preserved by the broadcast path.
	peerErr := &pushtx.BroadcastError{
		Code: pushtx.Invalid,
		Reason: "rejected by peer: transaction " + strings.Repeat("a", 64) +
			" has a non-standard input: transaction input #0 has a " +
			"non-standard script form",
	}
	client := &NeutrinoClient{}

	// Act through the existing second consumer of the btcd error table.
	err := client.MapRPCErr(peerErr)

	// Assert generic script text cannot mask the input-specific rejection
	// just because that generic table entry happens to be visited first.
	require.ErrorIs(t, err, ErrNonStandardInputs)
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
