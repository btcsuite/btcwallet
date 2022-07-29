package waddrmgr

import (
	"testing"

	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/txscript"
	"github.com/stretchr/testify/require"
)

var (
	testPubKey, _ = schnorr.ParsePubKey(hexToBytes(
		"29faddf1254d490d6add49e2b08cf52b561038c72baec0edb3cfacff71" +
			"ff1021",
	))
	testScript = []byte{99, 88, 77, 66, 55, 44}
	testProof  = [32]byte{99, 88, 77, 66}
)

// TestTlvEncodeDecode tests encoding and decoding of taproot script TLV data.
func TestTlvEncodeDecode(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name              string
		given             *Tapscript
		expected          *Tapscript
		expectedErrEncode string
		expectedErrDecode string
	}{{
		name:              "nil",
		expectedErrEncode: "cannot encode nil script",
	}, {
		name:     "empty",
		given:    &Tapscript{},
		expected: &Tapscript{},
	}, {
		name: "no leaves",
		given: &Tapscript{
			Type: TapscriptTypeFullTree,
			ControlBlock: &txscript.ControlBlock{
				InternalKey: testPubKey,
			},
		},
		expected: &Tapscript{
			Type: TapscriptTypeFullTree,
			ControlBlock: &txscript.ControlBlock{
				InternalKey:    testPubKey,
				InclusionProof: []byte{},
			},
		},
	}, {
		name: "no pubkey",
		given: &Tapscript{
			Type:         TapscriptTypeFullTree,
			ControlBlock: &txscript.ControlBlock{},
		},
		expectedErrEncode: "control block is missing internal key",
	}, {
		name: "empty leaf",
		given: &Tapscript{
			Type: TapscriptTypeFullTree,
			ControlBlock: &txscript.ControlBlock{
				InternalKey: testPubKey,
			},
			Leaves: []txscript.TapLeaf{{}},
		},
		expected: &Tapscript{
			Type: TapscriptTypeFullTree,
			ControlBlock: &txscript.ControlBlock{
				InternalKey:    testPubKey,
				InclusionProof: []byte{},
			},
			Leaves: []txscript.TapLeaf{{}},
		},
	}, {
		name: "full key and leaves",
		given: &Tapscript{
			Type: TapscriptTypeFullTree,
			ControlBlock: &txscript.ControlBlock{
				InternalKey: testPubKey,
			},
			Leaves: []txscript.TapLeaf{
				txscript.NewBaseTapLeaf(testScript),
			},
		},
		expected: &Tapscript{
			Type: TapscriptTypeFullTree,
			ControlBlock: &txscript.ControlBlock{
				InternalKey:    testPubKey,
				InclusionProof: []byte{},
			},
			Leaves: []txscript.TapLeaf{
				txscript.NewBaseTapLeaf(testScript),
			},
		},
	}, {
		name: "invalid proof",
		given: &Tapscript{
			Type: TapscriptTypePartialReveal,
			ControlBlock: &txscript.ControlBlock{
				InternalKey:    testPubKey,
				InclusionProof: testScript,
			},
			RevealedScript: testScript,
		},
		expectedErrDecode: "error decoding control block: control " +
			"block proof is not a multiple of 32: 6",
	}, {
		name: "inclusion proof no leaves",
		given: &Tapscript{
			Type: TapscriptTypePartialReveal,
			ControlBlock: &txscript.ControlBlock{
				InternalKey:    testPubKey,
				InclusionProof: testProof[:],
			},
			RevealedScript: testScript,
		},
		expected: &Tapscript{
			Type: TapscriptTypePartialReveal,
			ControlBlock: &txscript.ControlBlock{
				InternalKey:    testPubKey,
				InclusionProof: testProof[:],
			},
			RevealedScript: testScript,
		},
	}, {
		name: "root hash only",
		given: &Tapscript{
			Type: TaprootKeySpendRootHash,
			ControlBlock: &txscript.ControlBlock{
				InternalKey: testPubKey,
			},
			RootHash: testScript,
		},
		expected: &Tapscript{
			Type: TaprootKeySpendRootHash,
			ControlBlock: &txscript.ControlBlock{
				InternalKey:    testPubKey,
				InclusionProof: []byte{},
			},
			RootHash: testScript,
		},
	}, {
		name: "full key only",
		given: &Tapscript{
			Type:          TapscriptTypeFullTree,
			FullOutputKey: testPubKey,
		},
		expected: &Tapscript{
			Type:          TapscriptTypeFullTree,
			FullOutputKey: testPubKey,
		},
	}}

	for _, tc := range testCases {
		tc := tc

		t.Run(tc.name, func(tt *testing.T) {
			data, err := tlvEncodeTaprootScript(tc.given)

			if tc.expectedErrEncode != "" {
				require.Error(tt, err)
				require.Contains(
					tt, err.Error(), tc.expectedErrEncode,
				)

				return
			}

			require.NoError(tt, err)
			require.NotEmpty(tt, data)

			decoded, err := tlvDecodeTaprootTaprootScript(data)
			if tc.expectedErrDecode != "" {
				require.Error(tt, err)
				require.Contains(
					tt, err.Error(), tc.expectedErrDecode,
				)

				return
			}

			require.NoError(tt, err)

			require.Equal(tt, tc.expected, decoded)
		})
	}
}
