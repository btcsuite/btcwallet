package waddrmgr

import (
	"bytes"
	"io"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/txscript/v2"
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

// scriptBufferReader retains the actual destination buffers used to decode
// scripts, so cleanup can be checked after the decoder discards them. It can
// panic while filling a script buffer to exercise decoder-local cleanup.
type scriptBufferReader struct {
	io.Reader

	buffers [][]byte
	panicAt int
}

// Read records buffers receiving the test script and optionally panics before
// returning to the decoder. Partial reads retain the entire allocated buffer.
// It relies on the TLV var-bytes decoder reading directly into an exact-size
// destination buffer; the callers' buffer-count assertions fail if it doesn't.
func (r *scriptBufferReader) Read(p []byte) (int, error) {
	n, err := r.Reader.Read(p)

	script := []byte{0x51, 0x52, 0x53}
	if n > 0 && len(p) == len(script) &&
		bytes.Equal(p[:n], script[:n]) {

		r.buffers = append(r.buffers, p)
		if r.panicAt == len(r.buffers) {
			panic("script decode interrupted")
		}
	}

	return n, err
}

// TestDecodeTaprootScriptClearsFailedBuffers verifies that genuine parsing
// errors clear completed and partially read script allocations, including
// leaves that the nested decoder has not returned to its parent.
func TestDecodeTaprootScriptClearsFailedBuffers(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		encoded []byte
		buffers int

		// controlBlockErr marks cases that must fail control block
		// parsing, after the outer decoder took the scripts.
		controlBlockErr bool
	}{{
		name: "output key parsing fails after revealed script",
		encoded: []byte{
			// Revealed script (type 4, len 3).
			4, 3, 0x51, 0x52, 0x53,
			// Invalid 1-byte full output key (type 6).
			6, 1, 0,
		},
		buffers: 1,
	}, {
		name: "control block parsing fails after revealed script",
		encoded: []byte{
			// Invalid 1-byte control block (type 2).
			2, 1, 0,
			// Revealed script (type 4, len 3).
			4, 3, 0x51, 0x52, 0x53,
		},
		buffers:         1,
		controlBlockErr: true,
	}, {
		name: "outer TLV fails after revealed script",
		encoded: []byte{
			// Revealed script (type 4, len 3).
			4, 3, 0x51, 0x52, 0x53,
			// Duplicate type 4 is rejected by the stream.
			4, 0,
		},
		buffers: 1,
	}, {
		name: "revealed script read is truncated",
		// Revealed script (type 4) claims 3 bytes but has 1.
		encoded: []byte{4, 3, 0x51},
		buffers: 1,
	}, {
		name: "control block parsing fails after completed leaves",
		encoded: []byte{
			// Invalid 1-byte control block (type 2).
			2, 1, 0,
			// Terminal leaves (type 3, len 6) holding one 5-byte
			// leaf with a script (leaf type 2, len 3).
			3, 6, 5, 2, 3, 0x51, 0x52, 0x53,
		},
		buffers:         1,
		controlBlockErr: true,
	}, {
		name: "second leaf fails after allocating its script",
		encoded: []byte{
			// Leaves (type 3, len 14).
			3, 14,
			// First leaf: script (leaf type 2, len 3).
			5, 2, 3, 0x51, 0x52, 0x53,
			// Second leaf: script, then duplicate leaf type 2.
			7, 2, 3, 0x51, 0x52, 0x53, 2, 0,
		},
		buffers: 2,
	}, {
		name: "leaf script read is truncated",
		// Leaf script (leaf type 2) claims 3 bytes but has 1.
		encoded: []byte{3, 6, 5, 2, 3, 0x51},
		buffers: 1,
	}}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			// Arrange: Observe the real decoder's allocations.
			original := bytes.Clone(test.encoded)
			reader := &scriptBufferReader{
				Reader: bytes.NewReader(test.encoded),
			}

			// Act: Fail decoding after script data has been read.
			decoded, err := decodeTaprootScript(reader)

			// Assert: Discarded allocations, not input, are erased.
			require.Error(t, err)
			require.Nil(t, decoded)
			require.Len(t, reader.buffers, test.buffers)

			if test.controlBlockErr {
				var scriptErr txscript.Error
				require.ErrorAs(t, err, &scriptErr)
				require.Equal(
					t, txscript.ErrControlBlockTooSmall,
					scriptErr.ErrorCode,
				)
			}

			for _, buf := range reader.buffers {
				require.Equal(t, make([]byte, len(buf)), buf)
			}

			require.Equal(t, original, test.encoded)
		})
	}
}

// TestDecodeTaprootScriptClearsPanickedBuffers verifies that a panic after
// allocation clears both the current script and any earlier completed leaves.
func TestDecodeTaprootScriptClearsPanickedBuffers(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		encoded []byte
		panicAt int
	}{{
		name:    "revealed script read panics",
		encoded: []byte{4, 3, 0x51, 0x52, 0x53},
		panicAt: 1,
	}, {
		name: "second leaf read panics",
		encoded: []byte{
			3, 12,
			5, 2, 3, 0x51, 0x52, 0x53,
			5, 2, 3, 0x51, 0x52, 0x53,
		},
		panicAt: 2,
	}}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			// Arrange: Panic with actual decoder buffers in flight.
			original := bytes.Clone(test.encoded)
			reader := &scriptBufferReader{
				Reader:  bytes.NewReader(test.encoded),
				panicAt: test.panicAt,
			}

			// Act: Let the panic unwind through decoder cleanup.
			decode := func() {
				_, _ = decodeTaprootScript(reader)
			}
			require.PanicsWithValue(
				t, "script decode interrupted", decode,
			)

			// Assert: Every observed allocation was cleared.
			require.Len(t, reader.buffers, test.panicAt)

			for _, buf := range reader.buffers {
				require.Equal(t, make([]byte, len(buf)), buf)
			}

			require.Equal(t, original, test.encoded)
		})
	}
}
