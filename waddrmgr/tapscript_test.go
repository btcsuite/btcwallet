package waddrmgr

import (
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/txscript"
	"github.com/stretchr/testify/require"
)

var (
	testInternalKey, _ = btcec.ParsePubKey(hexToBytes(
		"020ef94ee79c07cbd1988fffd6e6aea1e25c3b033a2fd64fe14a9b955e53" +
			"55f0c6",
	))

	testScript1 = hexToBytes(
		"76a914f6c97547d73156abb300ae059905c4acaadd09dd88",
	)
	testScript2 = hexToBytes(
		"200ef94ee79c07cbd1988fffd6e6aea1e25c3b033a2fd64fe14a9b955e53" +
			"55f0c6ac",
	)
	testScript1Proof = hexToBytes(
		"6c2e4bb01e316abaaee288d69c06cc608cedefd6e1a06813786c4ec51b6e" +
			"1d38",
	)

	testTaprootKey = hexToBytes(
		"e15405aab8fd601206a3848b0ec495df75d8a602465d8dbba42a7493bd88" +
			"9b78",
	)
	testTaprootKey2 = hexToBytes(
		"b1ef5fafd9a55b8c4bb3c2eee3fcf033194891ebf89b1d9b666c6306acc3" +
			"a3df",
	)
)

// TestTaprootKey tests that the taproot tweaked key can be calculated correctly
// for both a tree with all leaves known as well as a partially revealed tree
// with an inclusion/merkle proof.
func TestTaprootKey(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name     string
		given    *Tapscript
		expected []byte
	}{{
		name: "full tree",
		given: &Tapscript{
			Type: TapscriptTypeFullTree,
			Leaves: []txscript.TapLeaf{
				txscript.NewBaseTapLeaf(testScript1),
				txscript.NewBaseTapLeaf(testScript2),
			},
			ControlBlock: &txscript.ControlBlock{
				InternalKey: testInternalKey,
				LeafVersion: txscript.BaseLeafVersion,
			},
		},
		expected: testTaprootKey,
	}, {
		name: "partial tree with proof",
		given: &Tapscript{
			Type:           TapscriptTypePartialReveal,
			RevealedScript: testScript2,
			ControlBlock: &txscript.ControlBlock{
				InternalKey:    testInternalKey,
				LeafVersion:    txscript.BaseLeafVersion,
				InclusionProof: testScript1Proof,
			},
		},
		expected: testTaprootKey,
	}, {
		name: "root hash only",
		given: &Tapscript{
			Type: TaprootKeySpendRootHash,
			ControlBlock: &txscript.ControlBlock{
				InternalKey: testInternalKey,
			},
			RootHash: []byte("I could be a root hash"),
		},
		expected: testTaprootKey2,
	}, {
		name: "full key only",
		given: &Tapscript{
			Type:          TaprootFullKeyOnly,
			FullOutputKey: testInternalKey,
		},
		expected: schnorr.SerializePubKey(testInternalKey),
	}}

	for _, tc := range testCases {
		tc := tc

		t.Run(tc.name, func(tt *testing.T) {
			taprootKey, err := tc.given.TaprootKey()
			require.NoError(tt, err)

			require.Equal(
				tt, tc.expected, schnorr.SerializePubKey(
					taprootKey,
				),
			)
		})
	}
}
