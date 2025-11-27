package wallet

import (
	"fmt"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/stretchr/testify/require"
)

// BenchmarkDerivePubKey benchmarks the DerivePubKey method across different
// wallet sizes. The benchmark measures the performance of deriving a public
// key from a BIP-32 path, which involves database lookups and cryptographic
// operations.
func BenchmarkDerivePubKey(b *testing.B) {
	const (
		startGrowthIteration = 0
		maxGrowthIteration   = 5
	)

	var (
		// accountGrowth uses linearGrowth to test how performance
		// scales with the number of accounts in the wallet. Key
		// derivation uses the account index in the BIP-32 path, so
		// database lookup time should remain constant due to indexed
		// lookups.
		accountGrowth = mapRange(
			startGrowthIteration, maxGrowthIteration,
			linearGrowth,
		)

		// addressGrowth uses constantGrowth since address count doesn't
		// affect the key derivation's time complexity - it derives from
		// an explicit path without address search.
		addressGrowth = mapRange(
			startGrowthIteration, maxGrowthIteration,
			constantGrowth,
		)

		// utxoGrowth uses constantGrowth since UTXO count doesn't
		// affect the key derivation's time complexity.
		utxoGrowth = mapRange(
			startGrowthIteration, maxGrowthIteration,
			constantGrowth,
		)

		accountGrowthPadding = decimalWidth(
			accountGrowth[len(accountGrowth)-1],
		)

		scopes = []waddrmgr.KeyScope{
			waddrmgr.KeyScopeBIP0084,
			waddrmgr.KeyScopeBIP0086,
		}
	)

	for i := 0; i <= maxGrowthIteration; i++ {
		name := fmt.Sprintf("Accounts-%0*d", accountGrowthPadding,
			accountGrowth[i])

		b.Run(name, func(b *testing.B) {
			w := setupBenchmarkWallet(
				b, benchmarkWalletConfig{
					scopes:       scopes,
					numAccounts:  accountGrowth[i],
					numAddresses: addressGrowth[i],
					numWalletTxs: utxoGrowth[i],
				},
			)

			// Use a path from the middle of the account range
			// for representative performance.
			accountIndex := uint32(accountGrowth[i] / 2)
			path := BIP32Path{
				KeyScope: scopes[0],
				DerivationPath: waddrmgr.DerivationPath{
					InternalAccount: accountIndex,
					Branch:          0,
					Index:           0,
				},
			}

			b.ReportAllocs()
			b.ResetTimer()

			for b.Loop() {
				_, err := w.DerivePubKey(b.Context(), path)
				require.NoError(b, err)
			}
		})
	}
}

// BenchmarkECDH benchmarks the ECDH method across different wallet sizes.
// The benchmark measures the performance of performing an ECDH operation
// between a wallet key and a remote public key.
func BenchmarkECDH(b *testing.B) {
	const (
		startGrowthIteration = 0
		maxGrowthIteration   = 5
	)

	var (
		// accountGrowth uses linearGrowth to test scaling with wallet
		// size. ECDH derives the wallet's private key using the account
		// index in the BIP-32 path for the scalar multiplication.
		accountGrowth = mapRange(
			startGrowthIteration, maxGrowthIteration,
			linearGrowth,
		)

		// addressGrowth uses constantGrowth since address count doesn't
		// the ECDH operation's time complexity. It uses an explicit
		// path.
		addressGrowth = mapRange(
			startGrowthIteration, maxGrowthIteration,
			constantGrowth,
		)

		// utxoGrowth uses constantGrowth since UTXO count doesn't
		// affect the cryptographic operation's time complexity.
		utxoGrowth = mapRange(
			startGrowthIteration, maxGrowthIteration,
			constantGrowth,
		)

		accountGrowthPadding = decimalWidth(
			accountGrowth[len(accountGrowth)-1],
		)

		scopes = []waddrmgr.KeyScope{waddrmgr.KeyScopeBIP0084}
	)

	// Generate a remote public key for ECDH.
	remotePrivKey, err := btcec.NewPrivateKey()
	require.NoError(b, err)

	remotePubKey := remotePrivKey.PubKey()

	for i := 0; i <= maxGrowthIteration; i++ {
		name := fmt.Sprintf("Accounts-%0*d", accountGrowthPadding,
			accountGrowth[i])

		b.Run(name, func(b *testing.B) {
			w := setupBenchmarkWallet(
				b, benchmarkWalletConfig{
					scopes:       scopes,
					numAccounts:  accountGrowth[i],
					numAddresses: addressGrowth[i],
					numWalletTxs: utxoGrowth[i],
				},
			)

			accountIndex := uint32(accountGrowth[i] / 2)
			path := BIP32Path{
				KeyScope: scopes[0],
				DerivationPath: waddrmgr.DerivationPath{
					InternalAccount: accountIndex,
					Branch:          0,
					Index:           0,
				},
			}

			b.ReportAllocs()
			b.ResetTimer()

			for b.Loop() {
				_, err := w.ECDH(
					b.Context(), path, remotePubKey,
				)
				require.NoError(b, err)
			}
		})
	}
}

// BenchmarkSignDigestECDSA benchmarks the SignDigest method for ECDSA
// signatures across different wallet sizes. The benchmark measures the
// performance of signing a digest with ECDSA.
func BenchmarkSignDigestECDSA(b *testing.B) {
	const (
		startGrowthIteration = 0
		maxGrowthIteration   = 5
	)

	var (
		// accountGrowth uses linearGrowth to test scaling with wallet
		// size. Signature operations derive keys using the account
		// index in the BIP-32 path.
		accountGrowth = mapRange(
			startGrowthIteration, maxGrowthIteration,
			linearGrowth,
		)

		// addressGrowth uses constantGrowth since address count doesn't
		// affect the signature generation's time complexity when using
		// an explicit path.
		addressGrowth = mapRange(
			startGrowthIteration, maxGrowthIteration,
			constantGrowth,
		)

		// utxoGrowth uses constantGrowth since UTXO count doesn't
		// affect the signature generation's time complexity.
		utxoGrowth = mapRange(
			startGrowthIteration, maxGrowthIteration,
			constantGrowth,
		)

		accountGrowthPadding = decimalWidth(
			accountGrowth[len(accountGrowth)-1],
		)

		scopes = []waddrmgr.KeyScope{waddrmgr.KeyScopeBIP0084}
	)

	// Create a test digest to sign.
	digest := chainhash.HashB([]byte("test message"))

	for i := 0; i <= maxGrowthIteration; i++ {
		name := fmt.Sprintf("Accounts-%0*d", accountGrowthPadding,
			accountGrowth[i])

		b.Run(name, func(b *testing.B) {
			w := setupBenchmarkWallet(
				b, benchmarkWalletConfig{
					scopes:       scopes,
					numAccounts:  accountGrowth[i],
					numAddresses: addressGrowth[i],
					numWalletTxs: utxoGrowth[i],
				},
			)

			accountIndex := uint32(accountGrowth[i] / 2)
			path := BIP32Path{
				KeyScope: scopes[0],
				DerivationPath: waddrmgr.DerivationPath{
					InternalAccount: accountIndex,
					Branch:          0,
					Index:           0,
				},
			}

			intent := &SignDigestIntent{
				Digest:  digest,
				SigType: SigTypeECDSA,
			}

			b.ReportAllocs()
			b.ResetTimer()

			for b.Loop() {
				sig, err := w.SignDigest(
					b.Context(), path, intent,
				)
				require.NoError(b, err)
				require.NotNil(b, sig)
			}
		})
	}
}

// BenchmarkSignDigestECDSACompact benchmarks the SignDigest method for
// compact ECDSA signatures across different wallet sizes.
func BenchmarkSignDigestECDSACompact(b *testing.B) {
	const (
		startGrowthIteration = 0
		maxGrowthIteration   = 5
	)

	var (
		// accountGrowth uses linearGrowth to test scaling with wallet
		// size. Signature operations derive keys using the account
		// index in the BIP-32 path.
		accountGrowth = mapRange(
			startGrowthIteration, maxGrowthIteration,
			linearGrowth,
		)

		// addressGrowth uses constantGrowth since address count doesn't
		// affect the signature generation's time complexity when using
		// an explicit path.
		addressGrowth = mapRange(
			startGrowthIteration, maxGrowthIteration,
			constantGrowth,
		)

		// utxoGrowth uses constantGrowth since UTXO count doesn't
		// affect the signature generation's time complexity.
		utxoGrowth = mapRange(
			startGrowthIteration, maxGrowthIteration,
			constantGrowth,
		)

		accountGrowthPadding = decimalWidth(
			accountGrowth[len(accountGrowth)-1],
		)

		scopes = []waddrmgr.KeyScope{waddrmgr.KeyScopeBIP0084}
	)

	digest := chainhash.DoubleHashB([]byte("test message"))

	for i := 0; i <= maxGrowthIteration; i++ {
		name := fmt.Sprintf("Accounts-%0*d", accountGrowthPadding,
			accountGrowth[i])

		b.Run(name, func(b *testing.B) {
			w := setupBenchmarkWallet(
				b, benchmarkWalletConfig{
					scopes:       scopes,
					numAccounts:  accountGrowth[i],
					numAddresses: addressGrowth[i],
					numWalletTxs: utxoGrowth[i],
				},
			)

			accountIndex := uint32(accountGrowth[i] / 2)

			path := BIP32Path{
				KeyScope: scopes[0],
				DerivationPath: waddrmgr.DerivationPath{
					InternalAccount: accountIndex,
					Branch:          0,
					Index:           0,
				},
			}

			intent := &SignDigestIntent{
				Digest:     digest,
				SigType:    SigTypeECDSA,
				CompactSig: true,
			}

			b.ReportAllocs()
			b.ResetTimer()

			for b.Loop() {
				sig, err := w.SignDigest(
					b.Context(), path, intent,
				)
				require.NoError(b, err)
				require.NotNil(b, sig)
			}
		})
	}
}

// BenchmarkSignDigestSchnorr benchmarks the SignDigest method for Schnorr
// signatures across different wallet sizes. The benchmark measures the
// performance of signing a digest with Schnorr signatures.
func BenchmarkSignDigestSchnorr(b *testing.B) {
	const (
		startGrowthIteration = 0
		maxGrowthIteration   = 5
	)

	var (
		accountGrowth = mapRange(
			startGrowthIteration, maxGrowthIteration,
			linearGrowth,
		)

		addressGrowth = mapRange(
			startGrowthIteration, maxGrowthIteration,
			constantGrowth,
		)

		utxoGrowth = mapRange(
			startGrowthIteration, maxGrowthIteration,
			constantGrowth,
		)

		accountGrowthPadding = decimalWidth(
			accountGrowth[len(accountGrowth)-1],
		)

		scopes = []waddrmgr.KeyScope{waddrmgr.KeyScopeBIP0086}
	)

	digest := chainhash.TaggedHash(
		[]byte("BIP0340/challenge"), []byte("test message"),
	)

	for i := 0; i <= maxGrowthIteration; i++ {
		name := fmt.Sprintf("Accounts-%0*d", accountGrowthPadding,
			accountGrowth[i])

		b.Run(name, func(b *testing.B) {
			w := setupBenchmarkWallet(
				b, benchmarkWalletConfig{
					scopes:       scopes,
					numAccounts:  accountGrowth[i],
					numAddresses: addressGrowth[i],
					numWalletTxs: utxoGrowth[i],
				},
			)

			accountIndx := uint32(accountGrowth[i] / 2)
			path := BIP32Path{
				KeyScope: scopes[0],
				DerivationPath: waddrmgr.DerivationPath{
					InternalAccount: accountIndx,
					Branch:          0,
					Index:           0,
				},
			}

			intent := &SignDigestIntent{
				Digest:  digest[:],
				SigType: SigTypeSchnorr,
			}

			b.ReportAllocs()
			b.ResetTimer()

			for b.Loop() {
				sig, err := w.SignDigest(
					b.Context(), path, intent,
				)
				require.NoError(b, err)
				require.NotNil(b, sig)
			}
		})
	}
}

// BenchmarkComputeUnlockingScriptP2WKH benchmarks the ComputeUnlockingScript
// method for P2WKH outputs across different wallet sizes and UTXO counts.
func BenchmarkComputeUnlockingScriptP2WKH(b *testing.B) {
	const (
		startGrowthIteration = 0
		maxGrowthIteration   = 5
	)

	var (
		accountGrowth = mapRange(
			startGrowthIteration, maxGrowthIteration,
			linearGrowth,
		)

		addressGrowth = mapRange(
			startGrowthIteration, maxGrowthIteration,
			constantGrowth,
		)

		utxoGrowth = mapRange(
			startGrowthIteration, maxGrowthIteration,
			exponentialGrowth,
		)

		accountGrowthPadding = decimalWidth(
			accountGrowth[len(accountGrowth)-1],
		)

		utxoGrowthPadding = decimalWidth(
			utxoGrowth[len(utxoGrowth)-1],
		)

		scopes = []waddrmgr.KeyScope{waddrmgr.KeyScopeBIP0084}
	)

	for i := 0; i <= maxGrowthIteration; i++ {
		name := fmt.Sprintf("Accounts-%0*d/UTXOs-%0*d",
			accountGrowthPadding, accountGrowth[i],
			utxoGrowthPadding, utxoGrowth[i])

		b.Run(name, func(b *testing.B) {
			bw := setupBenchmarkWallet(
				b, benchmarkWalletConfig{
					scopes:       scopes,
					numAccounts:  accountGrowth[i],
					numAddresses: addressGrowth[i],
					numWalletTxs: utxoGrowth[i],
				},
			)

			// Get a test address and create a P2WKH output.
			testAddr := getTestAddress(
				b, bw.Wallet, accountGrowth[i],
			)
			pkScript, err := txscript.PayToAddrScript(testAddr)
			require.NoError(b, err)

			prevOut := &wire.TxOut{
				Value:    100000,
				PkScript: pkScript,
			}

			// Create a spending transaction.
			tx := wire.NewMsgTx(2)
			tx.AddTxIn(&wire.TxIn{
				PreviousOutPoint: wire.OutPoint{
					Hash:  chainhash.Hash{},
					Index: 0,
				},
			})
			tx.AddTxOut(&wire.TxOut{
				Value:    50000,
				PkScript: pkScript,
			})

			fetcher := txscript.NewCannedPrevOutputFetcher(
				prevOut.PkScript, prevOut.Value,
			)
			sigHashes := txscript.NewTxSigHashes(tx, fetcher)

			params := &UnlockingScriptParams{
				Tx:         tx,
				InputIndex: 0,
				Output:     prevOut,
				SigHashes:  sigHashes,
				HashType:   txscript.SigHashAll,
			}

			b.ReportAllocs()
			b.ResetTimer()

			for b.Loop() {
				unlockScript, err := bw.ComputeUnlockingScript(
					b.Context(), params,
				)
				require.NoError(b, err)
				require.NotNil(b, unlockScript)
			}
		})
	}
}

// BenchmarkComputeUnlockingScriptP2TR benchmarks the ComputeUnlockingScript
// method for P2TR (Taproot) key-path spends across different wallet sizes.
func BenchmarkComputeUnlockingScriptP2TR(b *testing.B) {
	const (
		startGrowthIteration = 0
		maxGrowthIteration   = 5
	)

	var (
		// accountGrowth uses linearGrowth to test scaling with wallet
		// size. ComputeUnlockingScript derives the signing key from the
		// output's address, which requires account lookup.
		accountGrowth = mapRange(
			startGrowthIteration, maxGrowthIteration,
			linearGrowth,
		)

		// addressGrowth uses constantGrowth since we're testing with a
		// single specific output address.
		addressGrowth = mapRange(
			startGrowthIteration, maxGrowthIteration,
			constantGrowth,
		)

		// utxoGrowth uses constantGrowth since UTXO count doesn't
		// affect signing a single input.
		utxoGrowth = mapRange(
			startGrowthIteration, maxGrowthIteration,
			constantGrowth,
		)

		accountGrowthPadding = decimalWidth(
			accountGrowth[len(accountGrowth)-1],
		)

		scopes = []waddrmgr.KeyScope{waddrmgr.KeyScopeBIP0086}
	)

	for i := 0; i <= maxGrowthIteration; i++ {
		name := fmt.Sprintf("Accounts-%0*d", accountGrowthPadding,
			accountGrowth[i])

		b.Run(name, func(b *testing.B) {
			bw := setupBenchmarkWallet(
				b, benchmarkWalletConfig{
					scopes:       scopes,
					numAccounts:  accountGrowth[i],
					numAddresses: addressGrowth[i],
					numWalletTxs: utxoGrowth[i],
				},
			)

			// Get a test Taproot address.
			testAddr := getTestAddress(
				b, bw.Wallet, accountGrowth[i],
			)
			pkScript, err := txscript.PayToAddrScript(testAddr)
			require.NoError(b, err)

			prevOut := &wire.TxOut{
				Value:    100000,
				PkScript: pkScript,
			}

			// Create a spending transaction.
			tx := wire.NewMsgTx(2)
			tx.AddTxIn(&wire.TxIn{
				PreviousOutPoint: wire.OutPoint{
					Hash:  chainhash.Hash{},
					Index: 0,
				},
			})
			tx.AddTxOut(&wire.TxOut{
				Value:    50000,
				PkScript: pkScript,
			})

			fetcher := txscript.NewCannedPrevOutputFetcher(
				prevOut.PkScript, prevOut.Value,
			)
			sigHashes := txscript.NewTxSigHashes(tx, fetcher)

			params := &UnlockingScriptParams{
				Tx:         tx,
				InputIndex: 0,
				Output:     prevOut,
				SigHashes:  sigHashes,
				HashType:   txscript.SigHashDefault,
			}

			b.ReportAllocs()
			b.ResetTimer()

			for b.Loop() {
				unlockScript, err := bw.ComputeUnlockingScript(
					b.Context(), params,
				)
				require.NoError(b, err)
				require.NotNil(b, unlockScript)
			}
		})
	}
}

// BenchmarkComputeRawSigSegwitV0 benchmarks the ComputeRawSig method for
// SegWit v0 inputs.
func BenchmarkComputeRawSigSegwitV0(b *testing.B) {
	const (
		startGrowthIteration = 0
		maxGrowthIteration   = 5
	)

	var (
		// accountGrowth uses constantGrowth to verify that wallet size
		// doesn't affect performance. ComputeRawSig uses an explicit
		// BIP-32 path, so performance should be constant regardless of
		// account count.
		accountGrowth = mapRange(
			startGrowthIteration, maxGrowthIteration,
			constantGrowth,
		)

		// addressGrowth uses constantGrowth since address count doesn't
		// affect the ComputeRawSig operation's time complexity - it
		// uses an explicit BIP-32 path.
		addressGrowth = mapRange(
			startGrowthIteration, maxGrowthIteration,
			constantGrowth,
		)

		// utxoGrowth uses constantGrowth since UTXO count doesn't
		// affect the ComputeRawSig operation's time complexity.
		utxoGrowth = mapRange(
			startGrowthIteration, maxGrowthIteration,
			constantGrowth,
		)

		accountGrowthPadding = decimalWidth(
			accountGrowth[len(accountGrowth)-1],
		)

		scopes = []waddrmgr.KeyScope{waddrmgr.KeyScopeBIP0084}
	)

	for i := 0; i <= maxGrowthIteration; i++ {
		name := fmt.Sprintf("Accounts-%0*d", accountGrowthPadding,
			accountGrowth[i])

		b.Run(name, func(b *testing.B) {
			bw := setupBenchmarkWallet(
				b, benchmarkWalletConfig{
					scopes:       scopes,
					numAccounts:  accountGrowth[i],
					numAddresses: addressGrowth[i],
					numWalletTxs: utxoGrowth[i],
				},
			)

			// Get a test address and create witness script.
			testAddr := getTestAddress(
				b, bw.Wallet, accountGrowth[i],
			)
			witnessPubKeyHash := testAddr.ScriptAddress()
			witnessScript, err := txscript.NewScriptBuilder().
				AddOp(txscript.OP_DUP).
				AddOp(txscript.OP_HASH160).
				AddData(witnessPubKeyHash).
				AddOp(txscript.OP_EQUALVERIFY).
				AddOp(txscript.OP_CHECKSIG).
				Script()
			require.NoError(b, err)

			pkScript, err := txscript.PayToAddrScript(testAddr)
			require.NoError(b, err)

			prevOut := &wire.TxOut{
				Value:    100000,
				PkScript: pkScript,
			}

			// Create a spending transaction.
			tx := wire.NewMsgTx(2)
			tx.AddTxIn(&wire.TxIn{
				PreviousOutPoint: wire.OutPoint{
					Hash:  chainhash.Hash{},
					Index: 0,
				},
			})
			tx.AddTxOut(&wire.TxOut{
				Value:    50000,
				PkScript: pkScript,
			})

			fetcher := txscript.NewCannedPrevOutputFetcher(
				prevOut.PkScript, prevOut.Value,
			)
			sigHashes := txscript.NewTxSigHashes(tx, fetcher)

			accountIndex := uint32(accountGrowth[i] / 2)
			addressIndex := uint32(addressGrowth[i] / 2)
			path := BIP32Path{
				KeyScope: scopes[0],
				DerivationPath: waddrmgr.DerivationPath{
					InternalAccount: accountIndex,
					Branch:          0,
					Index:           addressIndex,
				},
			}

			params := &RawSigParams{
				Tx:         tx,
				InputIndex: 0,
				Output:     prevOut,
				SigHashes:  sigHashes,
				HashType:   txscript.SigHashAll,
				Path:       path,
				Details: SegwitV0SpendDetails{
					WitnessScript: witnessScript,
				},
			}

			b.ReportAllocs()
			b.ResetTimer()

			for b.Loop() {
				sig, err := bw.ComputeRawSig(
					b.Context(), params,
				)
				require.NoError(b, err)
				require.NotNil(b, sig)
			}
		})
	}
}

// BenchmarkComputeRawSigTaproot benchmarks the ComputeRawSig method for
// Taproot key-path spends. Since ComputeRawSig uses an explicit path and
// doesn't search through accounts, wallet size shouldn't affect performance -
// we use constantGrowth to verify performance remains constant regardless of
// wallet size.
func BenchmarkComputeRawSigTaproot(b *testing.B) {
	const (
		startGrowthIteration = 0
		maxGrowthIteration   = 10
	)

	var (
		accountGrowth = mapRange(
			startGrowthIteration, maxGrowthIteration,
			constantGrowth,
		)

		addressGrowth = mapRange(
			startGrowthIteration, maxGrowthIteration,
			constantGrowth,
		)

		utxoGrowth = mapRange(
			startGrowthIteration, maxGrowthIteration,
			constantGrowth,
		)

		accountGrowthPadding = decimalWidth(
			accountGrowth[len(accountGrowth)-1],
		)

		scopes = []waddrmgr.KeyScope{waddrmgr.KeyScopeBIP0086}
	)

	for i := 0; i <= maxGrowthIteration; i++ {
		name := fmt.Sprintf("Accounts-%0*d", accountGrowthPadding,
			accountGrowth[i])

		b.Run(name, func(b *testing.B) {
			bw := setupBenchmarkWallet(
				b, benchmarkWalletConfig{
					scopes:       scopes,
					numAccounts:  accountGrowth[i],
					numAddresses: addressGrowth[i],
					numWalletTxs: utxoGrowth[i],
				},
			)

			// Get a test Taproot address.
			testAddr := getTestAddress(
				b, bw.Wallet, accountGrowth[i],
			)
			pkScript, err := txscript.PayToAddrScript(testAddr)
			require.NoError(b, err)

			prevOut := &wire.TxOut{
				Value:    100000,
				PkScript: pkScript,
			}

			// Create a spending transaction.
			tx := wire.NewMsgTx(2)
			tx.AddTxIn(&wire.TxIn{
				PreviousOutPoint: wire.OutPoint{
					Hash:  chainhash.Hash{},
					Index: 0,
				},
			})
			tx.AddTxOut(&wire.TxOut{
				Value:    50000,
				PkScript: pkScript,
			})

			fetcher := txscript.NewCannedPrevOutputFetcher(
				prevOut.PkScript, prevOut.Value,
			)
			sigHashes := txscript.NewTxSigHashes(tx, fetcher)

			accountIndex := uint32(accountGrowth[i] / 2)
			addressIndex := uint32(addressGrowth[i] / 2)
			path := BIP32Path{
				KeyScope: scopes[0],
				DerivationPath: waddrmgr.DerivationPath{
					InternalAccount: accountIndex,
					Branch:          0,
					Index:           addressIndex,
				},
			}

			params := &RawSigParams{
				Tx:         tx,
				InputIndex: 0,
				Output:     prevOut,
				SigHashes:  sigHashes,
				HashType:   txscript.SigHashDefault,
				Path:       path,
				Details: TaprootSpendDetails{
					SpendPath: KeyPathSpend,
				},
			}

			b.ReportAllocs()
			b.ResetTimer()

			for b.Loop() {
				sig, err := bw.ComputeRawSig(
					b.Context(), params,
				)
				require.NoError(b, err)
				require.NotNil(b, sig)
			}
		})
	}
}

// BenchmarkDerivePrivKey benchmarks the DerivePrivKey method (UnsafeSigner)
// across different wallet sizes. This benchmark measures the performance of
// deriving a private key from a BIP-32 path.
func BenchmarkDerivePrivKey(b *testing.B) {
	const (
		startGrowthIteration = 0
		maxGrowthIteration   = 10
	)

	var (
		// accountGrowth uses linearGrowth to test scaling with wallet
		// size. Signature operations derive keys using the account
		// index in the BIP-32 path.
		accountGrowth = mapRange(
			startGrowthIteration, maxGrowthIteration,
			linearGrowth,
		)

		// addressGrowth uses constantGrowth since address count doesn't
		// affect the signature generation's time complexity when using
		// an explicit path.
		addressGrowth = mapRange(
			startGrowthIteration, maxGrowthIteration,
			constantGrowth,
		)

		// utxoGrowth uses constantGrowth since UTXO count doesn't
		// affect the signature generation's time complexity.
		utxoGrowth = mapRange(
			startGrowthIteration, maxGrowthIteration,
			constantGrowth,
		)

		accountGrowthPadding = decimalWidth(
			accountGrowth[len(accountGrowth)-1],
		)

		scopes = []waddrmgr.KeyScope{waddrmgr.KeyScopeBIP0084}
	)

	for i := 0; i <= maxGrowthIteration; i++ {
		name := fmt.Sprintf("Accounts-%0*d", accountGrowthPadding,
			accountGrowth[i])

		b.Run(name, func(b *testing.B) {
			w := setupBenchmarkWallet(
				b, benchmarkWalletConfig{
					scopes:       scopes,
					numAccounts:  accountGrowth[i],
					numAddresses: addressGrowth[i],
					numWalletTxs: utxoGrowth[i],
				},
			)

			accountIndex := uint32(accountGrowth[i] / 2)

			path := BIP32Path{
				KeyScope: scopes[0],
				DerivationPath: waddrmgr.DerivationPath{
					InternalAccount: accountIndex,
					Branch:          0,
					Index:           0,
				},
			}

			b.ReportAllocs()
			b.ResetTimer()

			for b.Loop() {
				privKey, err := w.DerivePrivKey(
					b.Context(), path,
				)
				require.NoError(b, err)
				require.NotNil(b, privKey)
				privKey.Zero()
			}
		})
	}
}

// BenchmarkGetPrivKeyForAddress benchmarks the GetPrivKeyForAddress method
// (UnsafeSigner) across different wallet sizes and address counts.
func BenchmarkGetPrivKeyForAddress(b *testing.B) {
	const (
		startGrowthIteration = 0
		maxGrowthIteration   = 10
	)

	var (
		// accountGrowth uses linearGrowth since the account is part of
		// the address search space.
		accountGrowth = mapRange(
			startGrowthIteration, maxGrowthIteration,
			linearGrowth,
		)

		// addressGrowth uses linearGrowth to test how address lookup
		// performance scales. GetPrivKeyForAddress searches through
		// the address manager to find the matching address, so
		// performance scales with total address count.
		addressGrowth = mapRange(
			startGrowthIteration, maxGrowthIteration,
			linearGrowth,
		)

		// utxoGrowth uses constantGrowth since UTXO count doesn't
		// affect the address lookup's time complexity.
		utxoGrowth = mapRange(
			startGrowthIteration, maxGrowthIteration,
			constantGrowth,
		)

		accountGrowthPadding = decimalWidth(
			accountGrowth[len(accountGrowth)-1],
		)

		addressGrowthPadding = decimalWidth(
			addressGrowth[len(addressGrowth)-1],
		)

		scopes = []waddrmgr.KeyScope{waddrmgr.KeyScopeBIP0084}
	)

	for i := 0; i <= maxGrowthIteration; i++ {
		name := fmt.Sprintf("Accounts-%0*d/Addresses-%0*d",
			accountGrowthPadding, accountGrowth[i],
			addressGrowthPadding, addressGrowth[i])

		b.Run(name, func(b *testing.B) {
			bw := setupBenchmarkWallet(
				b, benchmarkWalletConfig{
					scopes:       scopes,
					numAccounts:  accountGrowth[i],
					numAddresses: addressGrowth[i],
					numWalletTxs: utxoGrowth[i],
				},
			)

			testAddr := getTestAddress(
				b, bw.Wallet, accountGrowth[i],
			)

			b.ReportAllocs()
			b.ResetTimer()

			for b.Loop() {
				privKey, err := bw.GetPrivKeyForAddress(
					b.Context(), testAddr,
				)
				require.NoError(b, err)
				require.NotNil(b, privKey)
				privKey.Zero()
			}
		})
	}
}

// BenchmarkSignDigestComparisonECDSAvsSchnorr compares ECDSA and Schnorr
// signature performance side-by-side. This benchmark helps understand the
// performance characteristics of different signature algorithms.
func BenchmarkSignDigestComparisonECDSAvsSchnorr(b *testing.B) {
	const numAccounts = 5

	scopes := []waddrmgr.KeyScope{
		waddrmgr.KeyScopeBIP0084, // For ECDSA
		waddrmgr.KeyScopeBIP0086, // For Schnorr
	}

	ecdsaDigest := chainhash.HashB([]byte("test message"))
	schnorrDigest := chainhash.TaggedHash(
		[]byte("BIP0340/challenge"), []byte("test message"),
	)

	b.Run("ECDSA", func(b *testing.B) {
		w := setupBenchmarkWallet(
			b, benchmarkWalletConfig{
				scopes:       []waddrmgr.KeyScope{scopes[0]},
				numAccounts:  numAccounts,
				numAddresses: 5,
				numWalletTxs: 0,
			},
		)

		path := BIP32Path{
			KeyScope: scopes[0],
			DerivationPath: waddrmgr.DerivationPath{
				InternalAccount: 0,
				Branch:          0,
				Index:           0,
			},
		}

		intent := &SignDigestIntent{
			Digest:  ecdsaDigest,
			SigType: SigTypeECDSA,
		}

		b.ReportAllocs()
		b.ResetTimer()

		for b.Loop() {
			sig, err := w.SignDigest(b.Context(), path, intent)
			require.NoError(b, err)
			require.NotNil(b, sig)
		}
	})

	b.Run("Schnorr", func(b *testing.B) {
		w := setupBenchmarkWallet(
			b, benchmarkWalletConfig{
				scopes:       []waddrmgr.KeyScope{scopes[1]},
				numAccounts:  numAccounts,
				numAddresses: 5,
				numWalletTxs: 0,
			},
		)

		path := BIP32Path{
			KeyScope: scopes[1],
			DerivationPath: waddrmgr.DerivationPath{
				InternalAccount: 0,
				Branch:          0,
				Index:           0,
			},
		}

		intent := &SignDigestIntent{
			Digest:  schnorrDigest[:],
			SigType: SigTypeSchnorr,
		}

		b.ReportAllocs()
		b.ResetTimer()

		for b.Loop() {
			sig, err := w.SignDigest(b.Context(), path, intent)
			require.NoError(b, err)
			require.NotNil(b, sig)
		}
	})
}

// BenchmarkMultiInputTransaction benchmarks signing a transaction with
// multiple inputs.
func BenchmarkMultiInputTransaction(b *testing.B) {
	const (
		startGrowthIteration = 0
		maxGrowthIteration   = 5
	)

	var (
		accountGrowth = mapRange(
			startGrowthIteration, maxGrowthIteration,
			constantGrowth,
		)

		addressGrowth = mapRange(
			startGrowthIteration, maxGrowthIteration,
			constantGrowth,
		)

		utxoGrowth = mapRange(
			startGrowthIteration, maxGrowthIteration,
			constantGrowth,
		)

		// Test with growing number of inputs using linear growth.
		inputGrowth = mapRange(
			startGrowthIteration, maxGrowthIteration,
			linearGrowth,
		)

		inputGrowthPadding = decimalWidth(
			inputGrowth[len(inputGrowth)-1],
		)

		scopes = []waddrmgr.KeyScope{waddrmgr.KeyScopeBIP0084}
	)

	for i := 0; i <= maxGrowthIteration; i++ {
		numInputs := inputGrowth[i]

		name := fmt.Sprintf("Inputs-%0*d", inputGrowthPadding,
			numInputs)

		b.Run(name, func(b *testing.B) {
			bw := setupBenchmarkWallet(
				b, benchmarkWalletConfig{
					scopes:       scopes,
					numAccounts:  accountGrowth[i],
					numAddresses: addressGrowth[i],
					numWalletTxs: utxoGrowth[i],
				},
			)

			// Get test addresses for outputs.
			testAddr := getTestAddress(
				b, bw.Wallet, accountGrowth[i],
			)
			pkScript, err := txscript.PayToAddrScript(testAddr)
			require.NoError(b, err)

			tx := wire.NewMsgTx(2)

			// Create previous outputs for each input.
			prevOuts := make([]*wire.TxOut, numInputs)
			for j := range numInputs {
				prevOuts[j] = &wire.TxOut{
					Value:    100000,
					PkScript: pkScript,
				}

				tx.AddTxIn(&wire.TxIn{
					PreviousOutPoint: wire.OutPoint{
						Hash:  chainhash.Hash{byte(j)},
						Index: 0,
					},
				})
			}

			// Add a single output.
			tx.AddTxOut(&wire.TxOut{
				Value:    int64(numInputs) * 100000,
				PkScript: pkScript,
			})

			// Pre-compute sigHashes.
			fetcher := txscript.NewMultiPrevOutFetcher(nil)
			for j, prevOut := range prevOuts {
				fetcher.AddPrevOut(wire.OutPoint{
					Hash:  chainhash.Hash{byte(j)},
					Index: 0,
				}, prevOut)
			}

			sigHashes := txscript.NewTxSigHashes(tx, fetcher)

			b.ReportAllocs()
			b.ResetTimer()

			for b.Loop() {
				signMultipleInputs(
					b, bw.Wallet, tx, prevOuts, sigHashes,
					txscript.SigHashAll,
				)
			}
		})
	}
}
