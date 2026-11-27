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

// sqlUnlockingAddress creates an account in scope and returns one of its
// receive addresses with a previous output paying it.
func sqlUnlockingAddress(t *testing.T, w *Wallet, scope waddrmgr.KeyScope,
	name string) *wire.TxOut {

	t.Helper()

	_, err := w.NewAccount(t.Context(), NewAccountParams{
		Scope: scope, Name: name,
	})
	require.NoError(t, err)

	info, err := w.NewAddress(
		t.Context(), NewAccountSelectorByName(scope, name), false,
	)
	require.NoError(t, err)

	pkScript, err := txscript.PayToAddrScript(info.Addr)
	require.NoError(t, err)

	return wire.NewTxOut(100_000, pkScript)
}

// sqlTaprootParityOutputs creates a BIP-86 account and returns previous
// outputs paying one of its addresses whose internal key has an even Y
// coordinate and one whose internal key has an odd one.
func sqlTaprootParityOutputs(t *testing.T,
	w *Wallet) (*wire.TxOut, *wire.TxOut) {

	t.Helper()

	_, err := w.NewAccount(t.Context(), NewAccountParams{
		Scope: waddrmgr.KeyScopeBIP0086, Name: "taproot",
	})
	require.NoError(t, err)

	infos, err := w.NewBulkAddresses(
		t.Context(), NewAccountSelectorByName(
			waddrmgr.KeyScopeBIP0086, "taproot",
		), false, 16,
	)
	require.NoError(t, err)

	var found [2]*wire.TxOut
	for _, info := range infos {
		parity := info.PubKey.SerializeCompressed()[0] - 0x02
		if found[parity] != nil {
			continue
		}

		pkScript, err := txscript.PayToAddrScript(info.Addr)
		require.NoError(t, err)

		found[parity] = wire.NewTxOut(100_000, pkScript)
	}

	require.NotNil(t, found[0])
	require.NotNil(t, found[1])

	return found[0], found[1]
}

// TestSQLComputeUnlockingScriptVerifies verifies that SQL
// ComputeUnlockingScript signs in the vault, with no unsafe vault attached,
// and that the script engine accepts its result for P2PKH, nested P2WKH, P2WKH
// and BIP-86 P2TR outputs, the last for internal keys of both Y parities.
func TestSQLComputeUnlockingScriptVerifies(t *testing.T) {
	t.Parallel()

	// Arrange: Create an output for every single-key address family, then
	// drop the unsafe vault, which account creation still needs.
	w := createSQLiteWallet(t, createTestChain(t))
	p2pkh := sqlUnlockingAddress(t, w, waddrmgr.KeyScopeBIP0044, "p2pkh")
	np2wkh := sqlUnlockingAddress(
		t, w, waddrmgr.KeyScopeBIP0049Plus, "np2wkh",
	)
	p2wkh := sqlUnlockingAddress(t, w, waddrmgr.KeyScopeBIP0084, "p2wkh")
	evenP2TR, oddP2TR := sqlTaprootParityOutputs(t, w)

	w.unsafeVault = nil

	tests := []struct {
		name    string
		prevOut *wire.TxOut
	}{
		{name: "p2pkh", prevOut: p2pkh},
		{name: "np2wkh", prevOut: np2wkh},
		{name: "p2wkh", prevOut: p2wkh},
		{name: "p2tr even key", prevOut: evenP2TR},
		{name: "p2tr odd key", prevOut: oddP2TR},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			tx, sigHashes := rawSigTx(test.prevOut)

			// Act: Compute and install the unlocking script.
			script, err := w.ComputeUnlockingScript(
				t.Context(), &UnlockingScriptParams{
					Tx:        tx,
					Output:    test.prevOut,
					SigHashes: sigHashes,
					HashType:  txscript.SigHashAll,
				},
			)
			require.NoError(t, err)

			tx.TxIn[0].SignatureScript = script.SigScript
			tx.TxIn[0].Witness = script.Witness

			// Assert: The script engine accepts the spend.
			fetcher := txscript.NewCannedPrevOutputFetcher(
				test.prevOut.PkScript, test.prevOut.Value,
			)
			engine, err := txscript.NewEngine(
				test.prevOut.PkScript, tx, 0,
				txscript.StandardVerifyFlags, nil, sigHashes,
				test.prevOut.Value, fetcher,
			)
			require.NoError(t, err)
			require.NoError(t, engine.Execute())
		})
	}
}
