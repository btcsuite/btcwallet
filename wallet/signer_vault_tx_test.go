package wallet

import (
	"crypto/sha256"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/txscript/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/stretchr/testify/require"
)

// rawSigTx returns a one-input transaction spending prevOut, with its sighash
// cache.
func rawSigTx(prevOut *wire.TxOut) (*wire.MsgTx, *txscript.TxSigHashes) {
	tx := wire.NewMsgTx(2)
	tx.AddTxIn(wire.NewTxIn(&wire.OutPoint{Index: 1}, nil, nil))
	tx.AddTxOut(wire.NewTxOut(prevOut.Value-1_000, prevOut.PkScript))

	fetcher := txscript.NewCannedPrevOutputFetcher(
		prevOut.PkScript, prevOut.Value,
	)

	return tx, txscript.NewTxSigHashes(tx, fetcher)
}

// lndRevocationTweak returns a tweak with both scalars set, shaped like the
// revocation tweak lnd passes to ComputeRawSig.
func lndRevocationTweak(t *testing.T) KeyTweak {
	t.Helper()

	tweak, err := NewMulAddTweak(
		sha256.Sum256([]byte("revocation mul")),
		sha256.Sum256([]byte("revocation add")),
	)
	require.NoError(t, err)

	return tweak
}

// tweakedPrivKey returns a copy of key with tweak applied, as the legacy
// signer tweaked an exported key before signing. It is zeroed when the test
// ends.
func tweakedPrivKey(t *testing.T, key *btcec.PrivateKey,
	tweak KeyTweak) *btcec.PrivateKey {

	t.Helper()

	tweaked, _ := btcec.PrivKeyFromBytes(key.Serialize())
	require.NoError(t, tweak.Apply(tweaked))
	t.Cleanup(tweaked.Zero)

	return tweaked
}

// rawSigP2PKH is a P2PKH script used as the spent output and the signed
// script of the raw-signature tests.
var rawSigP2PKH = []byte{
	txscript.OP_DUP, txscript.OP_HASH160, txscript.OP_DATA_20,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	txscript.OP_EQUALVERIFY, txscript.OP_CHECKSIG,
}

// TestSQLComputeRawSigMatchesLegacy verifies that SQL ComputeRawSig signs a
// legacy, a SegWit v0 and a tapscript input in the vault, with no unsafe vault
// attached, and returns the bytes the legacy signer made from the tweaked
// exported key.
func TestSQLComputeRawSigMatchesLegacy(t *testing.T) {
	t.Parallel()

	// Arrange: Read one key and drop the unsafe vault, then compute the
	// legacy signature of each spend type with the tweaked key.
	w := createSQLiteWallet(t, createTestChain(t))
	path := BIP32Path{
		KeyScope:       waddrmgr.KeyScopeBIP0084,
		DerivationPath: waddrmgr.DerivationPath{Index: 3},
	}
	key := sqlSignerPrivKeys(t, w, path)[0]
	tweak := lndRevocationTweak(t)
	tweaked := tweakedPrivKey(t, key, tweak)

	prevOut := wire.NewTxOut(100_000, rawSigP2PKH)
	tx, sigHashes := rawSigTx(prevOut)
	leaf := txscript.TapLeaf{
		LeafVersion: txscript.BaseLeafVersion,
		Script:      []byte{txscript.OP_TRUE},
	}

	legacySig, err := txscript.RawTxInSignature(
		tx, 0, rawSigP2PKH, txscript.SigHashAll, tweaked,
	)
	require.NoError(t, err)

	segwitSig, err := txscript.RawTxInWitnessSignature(
		tx, sigHashes, 0, prevOut.Value, rawSigP2PKH,
		txscript.SigHashAll, tweaked,
	)
	require.NoError(t, err)

	tapscriptSig, err := txscript.RawTxInTapscriptSignature(
		tx, sigHashes, 0, prevOut.Value, prevOut.PkScript, leaf,
		txscript.SigHashDefault, tweaked,
	)
	require.NoError(t, err)

	tests := []struct {
		name     string
		details  SpendDetails
		hashType txscript.SigHashType
		want     RawSignature
	}{
		{
			name:     "legacy",
			details:  LegacySpendDetails{},
			hashType: txscript.SigHashAll,
			want:     legacySig,
		},
		{
			name: "segwit v0",
			details: SegwitV0SpendDetails{
				WitnessScript: rawSigP2PKH,
			},
			hashType: txscript.SigHashAll,
			want:     segwitSig[:len(segwitSig)-1],
		},
		{
			name: "tapscript",
			details: TaprootSpendDetails{
				SpendPath:     ScriptPathSpend,
				WitnessScript: leaf.Script,
			},
			hashType: txscript.SigHashDefault,
			want:     tapscriptSig,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			// Act: Sign the input through the wallet.
			sig, err := w.ComputeRawSig(t.Context(), &RawSigParams{
				Tx:        tx,
				Output:    prevOut,
				SigHashes: sigHashes,
				HashType:  test.hashType,
				Path:      path,
				Tweak:     tweak,
				Details:   test.details,
			})

			// Assert: The vault's signature equals the legacy one.
			require.NoError(t, err)
			require.Equal(t, test.want, sig)
		})
	}
}

// TestSQLComputeRawSigTaprootKeyPath verifies that a SQL Taproot key-path raw
// signature, made in the vault with no unsafe vault attached, equals the
// legacy signer's for an internal key with an odd Y coordinate, for a script
// root on one with an even Y, and for an lnd tweak, which applies before the
// BIP-341 output tweak.
func TestSQLComputeRawSigTaprootKeyPath(t *testing.T) {
	t.Parallel()

	// Arrange: Read an even and an odd key and drop the unsafe vault, then
	// compute each legacy key-path signature.
	w := createSQLiteWallet(t, createTestChain(t))
	even, odd := parityIndices(t, w, waddrmgr.KeyScopeBIP0084, 0)
	evenPath := BIP32Path{
		KeyScope:       waddrmgr.KeyScopeBIP0084,
		DerivationPath: waddrmgr.DerivationPath{Index: even},
	}
	oddPath := BIP32Path{
		KeyScope:       waddrmgr.KeyScopeBIP0084,
		DerivationPath: waddrmgr.DerivationPath{Index: odd},
	}
	keys := sqlSignerPrivKeys(t, w, evenPath, oddPath)
	tweak := lndRevocationTweak(t)
	tweakedOdd := tweakedPrivKey(t, keys[1], tweak)
	root := sha256.Sum256([]byte("script root"))

	prevOut := wire.NewTxOut(100_000, rawSigP2PKH)
	tx, sigHashes := rawSigTx(prevOut)

	oddSig, err := txscript.RawTxInTaprootSignature(
		tx, sigHashes, 0, prevOut.Value, prevOut.PkScript, nil,
		txscript.SigHashDefault, keys[1],
	)
	require.NoError(t, err)

	rootSig, err := txscript.RawTxInTaprootSignature(
		tx, sigHashes, 0, prevOut.Value, prevOut.PkScript, root[:],
		txscript.SigHashAll, keys[0],
	)
	require.NoError(t, err)

	tweakedSig, err := txscript.RawTxInTaprootSignature(
		tx, sigHashes, 0, prevOut.Value, prevOut.PkScript, nil,
		txscript.SigHashDefault, tweakedOdd,
	)
	require.NoError(t, err)

	tests := []struct {
		name     string
		path     BIP32Path
		tweak    KeyTweak
		root     []byte
		hashType txscript.SigHashType
		want     RawSignature
	}{
		{
			name:     "odd key",
			path:     oddPath,
			hashType: txscript.SigHashDefault,
			want:     oddSig,
		},
		{
			name:     "script root",
			path:     evenPath,
			root:     root[:],
			hashType: txscript.SigHashAll,
			want:     rootSig,
		},
		{
			name:     "lnd tweak",
			path:     oddPath,
			tweak:    tweak,
			hashType: txscript.SigHashDefault,
			want:     tweakedSig,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			// Act: Sign the key-path input through the wallet.
			sig, err := w.ComputeRawSig(t.Context(), &RawSigParams{
				Tx:        tx,
				Output:    prevOut,
				SigHashes: sigHashes,
				HashType:  test.hashType,
				Path:      test.path,
				Tweak:     test.tweak,
				Details: TaprootSpendDetails{
					SpendPath: KeyPathSpend,
					Tweak:     test.root,
				},
			})

			// Assert: The vault's signature equals the legacy one.
			require.NoError(t, err)
			require.Equal(t, test.want, sig)
		})
	}
}
