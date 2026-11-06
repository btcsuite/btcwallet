package wallet

import (
	"crypto/sha256"
	"errors"
	"sync"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/txscript/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/btcsuite/btcwallet/wallet/internal/keyvault"
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

// scalarBytes returns a nonzero 32-byte scalar derived from label.
func scalarBytes(label string) [32]byte {
	return sha256.Sum256([]byte(label))
}

// legacyRawSig is the pre-vault ComputeRawSig result for an exported key: the
// key is tweaked in place, then signed by the txscript helpers the old
// SpendDetails.Sign methods called.
func legacyRawSig(t *testing.T, key *btcec.PrivateKey, tweak KeyTweak,
	params *RawSigParams) RawSignature {

	t.Helper()

	tweaked, _ := btcec.PrivKeyFromBytes(key.Serialize())
	require.NoError(t, tweak.apply(tweaked))

	var (
		sig []byte
		err error
	)

	switch details := params.Details.(type) {
	case LegacySpendDetails:
		script := details.RedeemScript
		if script == nil {
			script = params.Output.PkScript
		}

		sig, err = txscript.RawTxInSignature(
			params.Tx, params.InputIndex, script, params.HashType,
			tweaked,
		)

	case SegwitV0SpendDetails:
		sig, err = txscript.RawTxInWitnessSignature(
			params.Tx, params.SigHashes, params.InputIndex,
			params.Output.Value, details.WitnessScript,
			params.HashType, tweaked,
		)
		sig = sig[:len(sig)-1]

	case TaprootSpendDetails:
		if details.SpendPath == KeyPathSpend {
			sig, err = txscript.RawTxInTaprootSignature(
				params.Tx, params.SigHashes, params.InputIndex,
				params.Output.Value, params.Output.PkScript,
				details.Tweak, params.HashType, tweaked,
			)

			break
		}

		sig, err = txscript.RawTxInTapscriptSignature(
			params.Tx, params.SigHashes, params.InputIndex,
			params.Output.Value, params.Output.PkScript,
			txscript.TapLeaf{
				LeafVersion: txscript.BaseLeafVersion,
				Script:      details.WitnessScript,
			}, params.HashType, tweaked,
		)
	}

	require.NoError(t, err)

	return sig
}

// TestSQLComputeRawSigMatchesLegacy verifies that SQL ComputeRawSig signs in
// the vault and returns the same bytes as the legacy signer for every spend
// type, with the identity, single, revocation and combined lnd tweaks. Keys of
// both Y parities reach the Taproot key path, where the Lightning tweak is
// applied before the BIP-341 output tweak. No private key is decrypted for
// Wallet code until the oracle exports one.
func TestSQLComputeRawSigMatchesLegacy(t *testing.T) {
	t.Parallel()

	// Arrange: Build the tweaks lnd uses and the spend types to sign.
	w, spy := newSQLSignerWallet(t)

	single, err := NewAddTweak(scalarBytes("single"))
	require.NoError(t, err)

	revocation, err := NewMulAddTweak(
		scalarBytes("revocation mul"), scalarBytes("revocation add"),
	)
	require.NoError(t, err)

	var combinedAdd btcec.ModNScalar
	combinedAdd.Set(&revocation.add).Add(&single.add)
	combined, err := NewMulAddTweak(
		revocation.mul.Bytes(), combinedAdd.Bytes(),
	)
	require.NoError(t, err)

	tweaks := map[string]KeyTweak{
		"identity":   {},
		"single":     single,
		"revocation": revocation,
		"combined":   combined,
	}

	root := sha256.Sum256([]byte("script root"))
	leaf := []byte{txscript.OP_TRUE}
	p2pkh := []byte{
		txscript.OP_DUP, txscript.OP_HASH160, txscript.OP_DATA_20,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		txscript.OP_EQUALVERIFY, txscript.OP_CHECKSIG,
	}

	type spend struct {
		name     string
		details  SpendDetails
		hashType txscript.SigHashType
	}

	spends := []spend{
		{"legacy", LegacySpendDetails{}, txscript.SigHashAll},
		{
			"legacy redeem",
			LegacySpendDetails{RedeemScript: p2pkh},
			txscript.SigHashSingle,
		},
		{
			"segwit",
			SegwitV0SpendDetails{WitnessScript: p2pkh},
			txscript.SigHashAll,
		},
		{
			"taproot key bip86",
			TaprootSpendDetails{SpendPath: KeyPathSpend},
			txscript.SigHashDefault,
		},
		{
			"taproot key root",
			TaprootSpendDetails{
				SpendPath: KeyPathSpend, Tweak: root[:],
			},
			txscript.SigHashAll,
		},
		{
			"tapscript",
			TaprootSpendDetails{
				SpendPath: ScriptPathSpend, WitnessScript: leaf,
			},
			txscript.SigHashDefault,
		},
	}

	prevOut := wire.NewTxOut(100_000, p2pkh)
	tx, sigHashes := rawSigTx(prevOut)

	// Act: Sign every combination through the vault for four keys.
	type result struct {
		path    BIP32Path
		tweak   KeyTweak
		params  *RawSigParams
		sig     RawSignature
		keyPath bool
	}

	var results []result

	for index := range uint32(4) {
		path := BIP32Path{
			KeyScope: waddrmgr.KeyScopeBIP0084,
			DerivationPath: waddrmgr.DerivationPath{
				Index: index,
			},
		}

		for _, tweak := range tweaks {
			for _, spend := range spends {
				params := &RawSigParams{
					Tx:        tx,
					Output:    prevOut,
					SigHashes: sigHashes,
					HashType:  spend.hashType,
					Path:      path,
					Tweak:     tweak,
					Details:   spend.details,
				}

				sig, err := w.ComputeRawSig(t.Context(), params)
				require.NoError(t, err, spend.name)

				keyPath := false
				if details, ok := spend.details.(TaprootSpendDetails); ok {
					keyPath = details.SpendPath == KeyPathSpend
				}

				results = append(results, result{
					path, tweak, params, sig, keyPath,
				})
			}
		}
	}

	// Assert: The vault signed without a private-key decrypt.
	require.Zero(t, spy.privateDecrypts.Load())
	require.Equal(t, int32(len(results)), spy.signDigests.Load())

	// Assert: Each signature equals the legacy signature, and the
	// effective internal keys of the key path had both parities.
	parities := make(map[byte]bool)

	for _, res := range results {
		key, err := w.DerivePrivKey(t.Context(), res.path)
		require.NoError(t, err)

		want := legacyRawSig(t, key, res.tweak, res.params)
		require.Equal(t, want, res.sig)

		if res.keyPath {
			internal, err := res.tweak.pubKey(key.PubKey())
			require.NoError(t, err)

			parities[internal.SerializeCompressed()[0]] = true
		}

		key.Zero()
	}

	require.Len(t, parities, 2)
}

// TestSQLComputeRawSigFailures verifies SQL ComputeRawSig failures: malformed
// spend details fail before any vault request, a tweak that cancels the key
// fails in the vault without a signature, and a missing account keeps its
// sentinel.
func TestSQLComputeRawSigFailures(t *testing.T) {
	t.Parallel()

	// Arrange: Export the key whose negation cancels it.
	w, spy := newSQLSignerWallet(t)
	path := BIP32Path{KeyScope: waddrmgr.KeyScopeBIP0084}
	prevOut := wire.NewTxOut(50_000, []byte{txscript.OP_TRUE})
	tx, sigHashes := rawSigTx(prevOut)

	key, err := w.DerivePrivKey(t.Context(), path)
	require.NoError(t, err)

	var negated btcec.ModNScalar
	negated.Set(&key.Key).Negate()
	key.Zero()

	cancel, err := NewAddTweak(negated.Bytes())
	require.NoError(t, err)

	params := func(details SpendDetails, output *wire.TxOut) *RawSigParams {
		return &RawSigParams{
			Tx:        tx,
			Output:    output,
			SigHashes: sigHashes,
			HashType:  txscript.SigHashAll,
			Path:      path,
			Details:   details,
		}
	}

	// Act: Request malformed and failing signatures.
	_, unknownPathErr := w.ComputeRawSig(t.Context(), params(
		TaprootSpendDetails{SpendPath: TaprootSpendPath(99)}, prevOut,
	))
	_, missingOutputErr := w.ComputeRawSig(t.Context(), params(
		SegwitV0SpendDetails{}, nil,
	))
	requests := spy.signDigests.Load()

	cancelParams := params(LegacySpendDetails{}, prevOut)
	cancelParams.Tweak = cancel
	_, cancelErr := w.ComputeRawSig(t.Context(), cancelParams)

	missingParams := params(LegacySpendDetails{}, prevOut)
	missingParams.Path.DerivationPath.InternalAccount = 42
	_, missingErr := w.ComputeRawSig(t.Context(), missingParams)

	// Assert: Malformed requests never reached the vault, and the vault
	// failures keep the legacy sentinels.
	require.ErrorIs(t, unknownPathErr, ErrUnknownSignMethod)
	require.ErrorIs(t, missingOutputErr, ErrNilArguments)
	require.Zero(t, requests)
	require.ErrorIs(t, cancelErr, ErrInvalidSignParam)
	require.ErrorIs(t, cancelErr, keyvault.ErrInvalidKeyTweak)
	require.ErrorIs(t, missingErr, ErrAccountNotInStore)
	require.Equal(t, int32(1), spy.privateDecrypts.Load())
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

// TestSQLComputeUnlockingScriptVerifies verifies that SQL
// ComputeUnlockingScript signs in the vault and that the script engine accepts
// its result for P2PKH, nested P2WKH, P2WKH and BIP-86 P2TR outputs, with no
// private key decrypted for Wallet code.
func TestSQLComputeUnlockingScriptVerifies(t *testing.T) {
	t.Parallel()

	// Arrange: Create an output for every single-key address family.
	w, spy := newSQLSignerWallet(t)

	scopes := map[string]waddrmgr.KeyScope{
		"p2pkh":   waddrmgr.KeyScopeBIP0044,
		"np2wkh":  waddrmgr.KeyScopeBIP0049Plus,
		"p2wkh":   waddrmgr.KeyScopeBIP0084,
		"taproot": waddrmgr.KeyScopeBIP0086,
	}

	prevOuts := make(map[string]*wire.TxOut, len(scopes))
	for name, scope := range scopes {
		prevOuts[name] = sqlUnlockingAddress(t, w, scope, name)
	}

	// Account creation encrypts new account keys, which is outside this
	// change, so count decrypts from here.
	decrypts := spy.privateDecrypts.Load()

	for name, prevOut := range prevOuts {
		tx, sigHashes := rawSigTx(prevOut)

		for _, hashType := range []txscript.SigHashType{
			txscript.SigHashAll, txscript.SigHashSingle,
		} {
			// Act: Compute and install the unlocking script.
			script, err := w.ComputeUnlockingScript(
				t.Context(), &UnlockingScriptParams{
					Tx:        tx,
					Output:    prevOut,
					SigHashes: sigHashes,
					HashType:  hashType,
				},
			)
			require.NoError(t, err, name)

			tx.TxIn[0].SignatureScript = script.SigScript
			tx.TxIn[0].Witness = script.Witness

			// Assert: The script engine accepts the spend.
			engine, err := txscript.NewEngine(
				prevOut.PkScript, tx, 0,
				txscript.StandardVerifyFlags, nil, sigHashes,
				prevOut.Value, txscript.NewCannedPrevOutputFetcher(
					prevOut.PkScript, prevOut.Value,
				),
			)
			require.NoError(t, err, name)
			require.NoError(t, engine.Execute(), name)
		}
	}

	require.Equal(t, decrypts, spy.privateDecrypts.Load())
}

// TestSQLComputeUnlockingScriptTaprootParity verifies BIP-86 key-path spends
// for internal keys of both Y parities, where the vault negates an odd key
// before the output tweak.
func TestSQLComputeUnlockingScriptTaprootParity(t *testing.T) {
	t.Parallel()

	// Arrange: Collect P2TR outputs until both internal-key parities are
	// covered.
	w, _ := newSQLSignerWallet(t)
	selector := NewAccountSelectorByName(waddrmgr.KeyScopeBIP0086, "tr")
	_, err := w.NewAccount(t.Context(), NewAccountParams{
		Scope: waddrmgr.KeyScopeBIP0086, Name: "tr",
	})
	require.NoError(t, err)

	infos, err := w.NewBulkAddresses(t.Context(), selector, false, 16)
	require.NoError(t, err)

	parities := make(map[byte]bool)
	for _, info := range infos {
		parity := info.PubKey.SerializeCompressed()[0]
		if parities[parity] {
			continue
		}

		parities[parity] = true

		pkScript, err := txscript.PayToAddrScript(info.Addr)
		require.NoError(t, err)

		prevOut := wire.NewTxOut(70_000, pkScript)
		tx, sigHashes := rawSigTx(prevOut)

		// Act: Compute the key-path witness.
		script, err := w.ComputeUnlockingScript(
			t.Context(), &UnlockingScriptParams{
				Tx:        tx,
				Output:    prevOut,
				SigHashes: sigHashes,
				HashType:  txscript.SigHashDefault,
			},
		)
		require.NoError(t, err)

		// Assert: The signature verifies under the BIP-86 output key.
		require.Len(t, script.Witness, 1)
		sig, err := schnorr.ParseSignature(script.Witness[0])
		require.NoError(t, err)

		hash, err := txscript.CalcTaprootSignatureHash(
			sigHashes, txscript.SigHashDefault, tx, 0,
			txscript.NewCannedPrevOutputFetcher(
				pkScript, prevOut.Value,
			),
		)
		require.NoError(t, err)

		outputKey := txscript.ComputeTaprootOutputKey(info.PubKey, nil)
		require.True(t, sig.Verify(hash, outputKey))
	}

	require.Len(t, parities, 2)
}

// TestSQLComputeUnlockingScriptConcurrentLock verifies that unlocking scripts
// racing a Lock either verify or fail as locked. Run with -race, it checks
// that Lock and vault signing share state safely.
func TestSQLComputeUnlockingScriptConcurrentLock(t *testing.T) {
	t.Parallel()

	// Arrange: Create one P2WKH output.
	w, _ := newSQLSignerWallet(t)
	prevOut := sqlUnlockingAddress(
		t, w, waddrmgr.KeyScopeBIP0084, "concurrent",
	)

	const signers = 8

	var (
		wg      sync.WaitGroup
		scripts = make([]*UnlockingScript, signers)
		errs    = make([]error, signers)
		txs     = make([]*wire.MsgTx, signers)
		hashes  = make([]*txscript.TxSigHashes, signers)
	)

	// Act: Sign from several goroutines while the wallet locks.
	for i := range signers {
		txs[i], hashes[i] = rawSigTx(prevOut)

		wg.Add(1)

		go func() {
			defer wg.Done()

			scripts[i], errs[i] = w.ComputeUnlockingScript(
				t.Context(), &UnlockingScriptParams{
					Tx:        txs[i],
					Output:    prevOut,
					SigHashes: hashes[i],
					HashType:  txscript.SigHashAll,
				},
			)
		}()
	}

	require.NoError(t, w.Lock(t.Context()))
	wg.Wait()

	// Assert: Each result verifies or fails as locked.
	for i := range signers {
		if errs[i] != nil {
			locked := errors.Is(errs[i], ErrStateForbidden) ||
				errors.Is(errs[i], keyvault.ErrVaultLocked)
			require.True(t, locked, "signer %d: %v", i, errs[i])

			continue
		}

		txs[i].TxIn[0].Witness = scripts[i].Witness

		engine, err := txscript.NewEngine(
			prevOut.PkScript, txs[i], 0, txscript.StandardVerifyFlags,
			nil, hashes[i], prevOut.Value,
			txscript.NewCannedPrevOutputFetcher(
				prevOut.PkScript, prevOut.Value,
			),
		)
		require.NoError(t, err)
		require.NoError(t, engine.Execute())
	}
}
