package wallet

import (
	"errors"
	"fmt"
	"math"
	"runtime"
	"testing"

	"github.com/btcsuite/btcd/address/v2"
	"github.com/btcsuite/btcd/btcjson"
	"github.com/btcsuite/btcd/btcutil/v2"
	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/btcsuite/btcwallet/wallet/internal/bwtest"
	"github.com/stretchr/testify/require"
)

// BenchmarkListAddressesAPI benchmarks ListAddresses API and a deprecated
// variant of it using same key scope and identical test data across multiple
// dataset sizes. Test names start with dataset size to group API comparisons
// for benchstat analysis.
func BenchmarkListAddressesAPI(b *testing.B) {
	const (
		// startGrowthIteration is the starting iteration index for the
		// growth sequence.
		startGrowthIteration = 0

		// maxGrowthIteration is the maximum iteration index for the
		// growth sequence.
		maxGrowthIteration = 14
	)

	var (
		accountGrowth = mapRange(
			startGrowthIteration, maxGrowthIteration,
			linearGrowth,
		)

		addressGrowth = mapRange(
			startGrowthIteration, maxGrowthIteration,
			exponentialGrowth,
		)

		utxoGrowth = mapRange(
			startGrowthIteration, maxGrowthIteration,
			exponentialGrowth,
		)

		accountGrowthPadding = decimalWidth(
			accountGrowth[len(accountGrowth)-1],
		)

		addressGrowthPadding = decimalWidth(
			addressGrowth[len(addressGrowth)-1],
		)

		utxoGrowthPadding = decimalWidth(
			utxoGrowth[len(utxoGrowth)-1],
		)

		scopes = []waddrmgr.KeyScope{waddrmgr.KeyScopeBIP0044}

		addrType = waddrmgr.PubKeyHash
	)

	for i := 0; i <= maxGrowthIteration; i++ {
		accountName, accountNumber := generateAccountName(
			accountGrowth[i], scopes,
		)

		name := fmt.Sprintf("%0*d-Accounts-%0*d-Addresses-%0*d-UTXOs",
			accountGrowthPadding, accountGrowth[i],
			addressGrowthPadding, addressGrowth[i],
			utxoGrowthPadding, utxoGrowth[i])

		b.Run(name+"/0-Before", func(b *testing.B) {
			bw := setupBenchmarkWallet(
				b, benchmarkWalletConfig{
					scopes:       scopes,
					numAccounts:  accountGrowth[i],
					numAddresses: addressGrowth[i],
					numWalletTxs: utxoGrowth[i],
				},
			)

			b.ReportAllocs()
			b.ResetTimer()

			for b.Loop() {
				_, err := listAddressesDeprecated(
					bw.Wallet, accountNumber,
				)
				require.NoError(b, err)
			}
		})

		b.Run(name+"/1-After", func(b *testing.B) {
			w := setupBenchmarkWallet(
				b, benchmarkWalletConfig{
					scopes:       scopes,
					numAccounts:  accountGrowth[i],
					numAddresses: addressGrowth[i],
					numWalletTxs: utxoGrowth[i],
				},
			)

			b.ReportAllocs()
			b.ResetTimer()

			for b.Loop() {
				_, err := w.ListAddresses(
					b.Context(), accountName, addrType,
				)
				require.NoError(b, err)
			}
		})
	}

	// Use shared node data alongside the original growth matrix.
	// Preserve native workflows; the report states scope/balance differences.
	b.Run("matched", func(b *testing.B) {
		RunKVDBBenchmark(b,
			func(b *testing.B, w *Wallet,
				workload bwtest.NodeBenchmarkWorkload) func() error {

				b.Helper()

				// Include the original caller's address and receipt reads.
				return func() error {
					result, err := listAddressesDeprecated(
						w, waddrmgr.DefaultAccountNum,
					)

					// Retain the result without inspecting its contents.
					runtime.KeepAlive(result)

					return err
				}
			},
			func(b *testing.B, w *Wallet,
				workload bwtest.NodeBenchmarkWorkload) func() error {

				b.Helper()

				// Resolve request inputs before timing;
				// repeat only the native API operation.
				ctx := b.Context()

				return func() error {
					_, err := w.ListAddresses(
						ctx, "default", waddrmgr.TaprootPubKey,
					)

					return err
				}
			},
		)
	})
}

// BenchmarkGetAddressInfoAPI benchmarks GetAddressInfo API and its deprecated
// variant using same key scope and identical test data across multiple
// dataset sizes. Test names start with dataset size to group API comparisons
// for benchstat analysis.
func BenchmarkGetAddressInfoAPI(b *testing.B) {
	const (
		// startGrowthIteration is the starting iteration index for the
		// growth sequence.
		startGrowthIteration = 0

		// maxGrowthIteration is the maximum iteration index for the
		// growth sequence.
		maxGrowthIteration = 14
	)

	var (
		accountGrowth = mapRange(
			startGrowthIteration, maxGrowthIteration,
			linearGrowth,
		)

		addressGrowth = mapRange(
			startGrowthIteration, maxGrowthIteration,
			exponentialGrowth,
		)

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
		name := fmt.Sprintf("%0*d-Accounts-%0*d-Addresses",
			accountGrowthPadding, accountGrowth[i],
			addressGrowthPadding, addressGrowth[i])

		b.Run(name+"/0-Before", func(b *testing.B) {
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
				_, err := bw.AddressInfoDeprecated(testAddr)
				require.NoError(b, err)
			}
		})

		b.Run(name+"/1-After", func(b *testing.B) {
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
				_, err := bw.GetAddressInfo(b.Context(), testAddr)
				require.NoError(b, err)
			}
		})
	}

	// Use shared node data alongside the original growth matrix.
	b.Run("matched", func(b *testing.B) {
		RunKVDBBenchmark(b,
			func(b *testing.B, w *Wallet,
				workload bwtest.NodeBenchmarkWorkload) func() error {

				b.Helper()

				// Resolve request inputs before timing;
				// repeat only the native API operation.
				addr := KVDBBenchmarkTarget(b, w, true).Address

				return func() error {
					_, err := w.AddressInfoDeprecated(addr)

					return err
				}
			},
			func(b *testing.B, w *Wallet,
				workload bwtest.NodeBenchmarkWorkload) func() error {

				b.Helper()

				// Resolve request inputs before timing;
				// repeat only the native API operation.
				addr := KVDBBenchmarkTarget(b, w, false).Address
				ctx := b.Context()

				return func() error {
					_, err := w.GetAddressInfo(ctx, addr)

					return err
				}
			},
		)
	})
}

// BenchmarkNewAddressUsedRotationAPI benchmarks NewAddress, marking each
// returned address used so the next call must rotate, against its deprecated
// variant NewAddressDeprecated using same key scope and identical address
// datasets across multiple dataset sizes. Test names start with dataset
// size to group API comparisons for benchstat analysis. The benchmark
// demonstrates the trade-off between performance (O(1) vs O(n)) and safety
// (preventing address reuse and BIP44 gap limit violations).
func BenchmarkNewAddressUsedRotationAPI(b *testing.B) {
	const (
		// startGrowthIteration is the starting iteration index for the
		// growth sequence.
		startGrowthIteration = 0

		// maxGrowthIteration is the maximum iteration index for the
		// growth sequence.
		maxGrowthIteration = 14
	)

	var (
		accountGrowth = mapRange(
			startGrowthIteration, maxGrowthIteration,
			linearGrowth,
		)

		addressGrowth = mapRange(
			startGrowthIteration, maxGrowthIteration,
			exponentialGrowth,
		)

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

		scopes = []waddrmgr.KeyScope{waddrmgr.KeyScopeBIP0044}
	)

	for i := 0; i <= maxGrowthIteration; i++ {
		accountName, accountNumber := generateAccountName(
			accountGrowth[i], scopes,
		)

		name := fmt.Sprintf("%0*d-Accounts-%0*d-Addresses",
			accountGrowthPadding, accountGrowth[i],
			addressGrowthPadding, addressGrowth[i])

		b.Run(name+"/0-Before", func(b *testing.B) {
			bw := setupBenchmarkWallet(
				b, benchmarkWalletConfig{
					scopes:       scopes,
					numAccounts:  accountGrowth[i],
					numAddresses: addressGrowth[i],
					numWalletTxs: utxoGrowth[i],
				},
			)

			b.ReportAllocs()
			b.ResetTimer()

			for b.Loop() {
				addr, err := bw.NewAddressDeprecated(
					accountNumber, scopes[0],
				)
				require.NoError(b, err)

				// Mark the address as used to make the
				// benchmark iteration idempotent.
				markAddressAsUsed(b, bw.Wallet, addr)
			}
		})

		b.Run(name+"/1-After", func(b *testing.B) {
			bw := setupBenchmarkWallet(
				b, benchmarkWalletConfig{
					scopes:       scopes,
					numAccounts:  accountGrowth[i],
					numAddresses: addressGrowth[i],
					numWalletTxs: utxoGrowth[i],
				},
			)

			b.ReportAllocs()
			b.ResetTimer()

			for b.Loop() {
				info, err := bw.NewAddress(
					b.Context(), NewAccountSelectorByName(
						scopes[0], accountName,
					), false,
				)
				require.NoError(b, err)

				// Mark the address as used to make the
				// benchmark iteration idempotent.
				markAddressAsUsed(b, bw.Wallet, info.Addr)
			}
		})
	}
}

// BenchmarkNewAddressAPI benchmarks NewAddress API and its deprecated variant
// NewAddressDeprecated using same key scope and identical address datasets
// across multiple dataset sizes. Test names start with dataset size to group
// API comparisons for benchstat analysis. The benchmark demonstrates that the
// new API maintains performance parity with the deprecated API.
func BenchmarkNewAddressAPI(b *testing.B) {
	const (
		// startGrowthIteration is the starting iteration index for the
		// growth sequence.
		startGrowthIteration = 0

		// maxGrowthIteration is the maximum iteration index for the
		// growth sequence.
		maxGrowthIteration = 14
	)

	var (
		accountGrowth = mapRange(
			startGrowthIteration, maxGrowthIteration,
			linearGrowth,
		)

		addressGrowth = mapRange(
			startGrowthIteration, maxGrowthIteration,
			exponentialGrowth,
		)

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

		scopes = []waddrmgr.KeyScope{waddrmgr.KeyScopeBIP0044}
	)

	for i := 0; i <= maxGrowthIteration; i++ {
		accountName, accountNumber := generateAccountName(
			accountGrowth[i], scopes,
		)

		name := fmt.Sprintf("%0*d-Accounts-%0*d-Addresses",
			accountGrowthPadding, accountGrowth[i],
			addressGrowthPadding, addressGrowth[i])

		b.Run(name+"/0-Before", func(b *testing.B) {
			bw := setupBenchmarkWallet(
				b, benchmarkWalletConfig{
					scopes:       scopes,
					numAccounts:  accountGrowth[i],
					numAddresses: addressGrowth[i],
					numWalletTxs: utxoGrowth[i],
				},
			)

			b.ReportAllocs()
			b.ResetTimer()

			for b.Loop() {
				_, err := bw.NewAddressDeprecated(
					accountNumber, scopes[0],
				)
				require.NoError(b, err)
			}
		})

		b.Run(name+"/1-After", func(b *testing.B) {
			w := setupBenchmarkWallet(
				b, benchmarkWalletConfig{
					scopes:       scopes,
					numAccounts:  accountGrowth[i],
					numAddresses: addressGrowth[i],
					numWalletTxs: utxoGrowth[i],
				},
			)

			b.ReportAllocs()
			b.ResetTimer()

			for b.Loop() {
				_, err := w.NewAddress(
					b.Context(), NewAccountSelectorByName(
						scopes[0], accountName,
					), false,
				)
				require.NoError(b, err)
			}
		})
	}
}

// BenchmarkImportPublicKeyAPI benchmarks ImportPublicKey API and its deprecated
// variant ImportPublicKeyDeprecated using identical public key datasets across
// multiple dataset sizes. Test names start with dataset size to group API
// comparisons for benchstat analysis. The benchmark demonstrates that the new
// API maintains performance parity with the deprecated API.
func BenchmarkImportPublicKeyAPI(b *testing.B) {
	const (
		// startGrowthIteration is the starting iteration index for the
		// growth sequence.
		startGrowthIteration = 0

		// maxGrowthIteration is the maximum iteration index for the
		// growth sequence.
		maxGrowthIteration = 14
	)

	var (
		accountGrowth = mapRange(
			startGrowthIteration, maxGrowthIteration,
			linearGrowth,
		)

		addressGrowth = mapRange(
			startGrowthIteration, maxGrowthIteration,
			linearGrowth,
		)

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

		addrType = waddrmgr.WitnessPubKey
	)

	for i := 0; i <= maxGrowthIteration; i++ {
		name := fmt.Sprintf("%0*d-Accounts-%0*d-Addresses",
			accountGrowthPadding, accountGrowth[i],
			addressGrowthPadding, addressGrowth[i])

		b.Run(name+"/0-Before", func(b *testing.B) {
			w := setupBenchmarkWallet(
				b, benchmarkWalletConfig{
					scopes:       scopes,
					numAccounts:  accountGrowth[i],
					numAddresses: addressGrowth[i],
					numWalletTxs: utxoGrowth[i],
				},
			)

			b.ReportAllocs()
			b.ResetTimer()

			iterCount := 0
			for b.Loop() {
				// Generate a unique key for each iteration to
				// avoid in-memory cache collision and for an
				// idempotent benchmark iteration test.
				seedIndex := accountGrowth[i] + iterCount
				key, _, _ := generateTestExtendedKey(
					b, seedIndex,
				)
				pubKey, err := key.ECPubKey()
				require.NoError(b, err)

				err = w.ImportPublicKeyDeprecated(
					pubKey, addrType,
				)
				require.NoError(b, err)

				iterCount++
			}
		})

		b.Run(name+"/1-After", func(b *testing.B) {
			w := setupBenchmarkWallet(
				b, benchmarkWalletConfig{
					scopes:       scopes,
					numAccounts:  accountGrowth[i],
					numAddresses: addressGrowth[i],
					numWalletTxs: utxoGrowth[i],
				},
			)

			b.ReportAllocs()
			b.ResetTimer()

			iterCount := 0
			for b.Loop() {
				// Generate a unique key for each iteration to
				// avoid in-memory cache collision and for an
				// idempotent benchmark iteration test.
				seedIndex := accountGrowth[i] + iterCount
				key, _, _ := generateTestExtendedKey(
					b, seedIndex,
				)
				pubKey, err := key.ECPubKey()
				require.NoError(b, err)

				err = w.ImportPublicKey(
					b.Context(), pubKey, addrType,
				)
				require.NoError(b, err)

				iterCount++
			}
		})
	}
}

// BenchmarkImportTaprootScriptAPI benchmarks ImportTaprootScript API and its
// deprecated variant ImportTaprootScriptDeprecated using identical tapscript
// datasets across multiple dataset sizes. Test names start with dataset size
// to group API comparisons for benchstat analysis. The benchmark demonstrates
// that the new API maintains performance parity with the deprecated API.
func BenchmarkImportTaprootScriptAPI(b *testing.B) {
	const (
		// startGrowthIteration is the starting iteration index for the
		// growth sequence.
		startGrowthIteration = 0

		// maxGrowthIteration is the maximum iteration index for the
		// growth sequence.
		maxGrowthIteration = 10
	)

	var (
		accountGrowth = mapRange(
			startGrowthIteration, maxGrowthIteration,
			linearGrowth,
		)

		addressGrowth = mapRange(
			startGrowthIteration, maxGrowthIteration,
			linearGrowth,
		)

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

		scopes = []waddrmgr.KeyScope{waddrmgr.KeyScopeBIP0086}

		witnessVersion = 1

		isSecretScript = false
	)

	for i := 0; i <= maxGrowthIteration; i++ {
		name := fmt.Sprintf("%0*d-Accounts-%0*d-Addresses",
			accountGrowthPadding, accountGrowth[i],
			addressGrowthPadding, addressGrowth[i])

		b.Run(name+"/0-Before", func(b *testing.B) {
			w := setupBenchmarkWallet(
				b, benchmarkWalletConfig{
					scopes:       scopes,
					numAccounts:  accountGrowth[i],
					numAddresses: addressGrowth[i],
					numWalletTxs: utxoGrowth[i],
				},
			)

			b.ReportAllocs()
			b.ResetTimer()

			iterCount := 0
			for b.Loop() {
				// Generate a unique tapscript for each
				// iteration to avoid in-memory cache collision
				// and for an idempotent benchmark iteration
				// test.
				seedIndex := accountGrowth[i] + iterCount
				key, _, _ := generateTestExtendedKey(
					b, seedIndex,
				)
				pubKey, err := key.ECPubKey()
				require.NoError(b, err)

				tapscript := generateTestTapscript(b, pubKey)

				syncedTo := w.addrStore.SyncedTo()
				_, err = w.ImportTaprootScriptDeprecated(
					scopes[0], &tapscript, &syncedTo,
					byte(witnessVersion), isSecretScript,
				)
				require.NoError(b, err)

				iterCount++
			}
		})

		b.Run(name+"/1-After", func(b *testing.B) {
			w := setupBenchmarkWallet(
				b, benchmarkWalletConfig{
					scopes:       scopes,
					numAccounts:  accountGrowth[i],
					numAddresses: addressGrowth[i],
					numWalletTxs: utxoGrowth[i],
				},
			)

			b.ReportAllocs()
			b.ResetTimer()

			iterCount := 0
			for b.Loop() {
				// Generate a unique tapscript for each
				// iteration to avoid in-memory cache collision
				// and for an idempotent benchmark iteration
				// test.
				seedIndex := accountGrowth[i] + iterCount
				key, _, _ := generateTestExtendedKey(
					b, seedIndex,
				)
				pubKey, err := key.ECPubKey()
				require.NoError(b, err)

				tapscript := generateTestTapscript(b, pubKey)

				_, err = w.ImportTaprootScript(
					b.Context(), tapscript,
				)
				require.NoError(b, err)

				iterCount++
			}
		})
	}
}

// BenchmarkScriptForOutputAPI benchmarks ScriptForOutput API and its deprecated
// variant ScriptForOutputDeprecated using identical TxOut datasets across
// multiple dataset sizes. Test names start with dataset size to group API
// comparisons for benchstat analysis. The benchmark demonstrates that the new
// API maintains performance parity with the deprecated API.
func BenchmarkScriptForOutputAPI(b *testing.B) {
	const (
		// startGrowthIteration is the starting iteration index for the
		// growth sequence.
		startGrowthIteration = 0

		// maxGrowthIteration is the maximum iteration index for the
		// growth sequence.
		maxGrowthIteration = 10
	)

	var (
		accountGrowth = mapRange(
			startGrowthIteration, maxGrowthIteration,
			constantGrowth,
		)

		addressGrowth = mapRange(
			startGrowthIteration, maxGrowthIteration,
			exponentialGrowth,
		)

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

		utxoGrowthPadding = decimalWidth(
			utxoGrowth[len(utxoGrowth)-1],
		)

		scopes = []waddrmgr.KeyScope{waddrmgr.KeyScopeBIP0084}
	)

	for i := 0; i <= maxGrowthIteration; i++ {
		name := fmt.Sprintf("%0*d-Accounts-%0*d-Addresses-%0*d-UTXOs",
			accountGrowthPadding, accountGrowth[i],
			addressGrowthPadding, addressGrowth[i],
			utxoGrowthPadding, utxoGrowth[i])

		b.Run(name+"/0-Before", func(b *testing.B) {
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
			testTxOut := generateTestTxOut(b, testAddr)

			b.ReportAllocs()
			b.ResetTimer()

			for b.Loop() {
				_, _, _, err := bw.ScriptForOutputDeprecated(
					&testTxOut,
				)
				require.NoError(b, err)
			}
		})

		b.Run(name+"/1-After", func(b *testing.B) {
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
			testTxOut := generateTestTxOut(b, testAddr)

			b.ReportAllocs()
			b.ResetTimer()

			for b.Loop() {
				_, err := bw.ScriptForOutput(
					b.Context(), testTxOut,
				)
				require.NoError(b, err)
			}
		})
	}
}

// BenchmarkGetAddressInfoDifferentAPI reads a different existing item
// on each call.
func BenchmarkGetAddressInfoDifferentAPI(b *testing.B) {
	b.Run("matched", func(b *testing.B) {
		RunKVDBBenchmark(b,
			func(b *testing.B, w *Wallet,
				workload bwtest.NodeBenchmarkWorkload) func() error {

				b.Helper()

				return benchmarkGetAddressInfoRequests(b, w, true, false)
			},
			func(b *testing.B, w *Wallet,
				workload bwtest.NodeBenchmarkWorkload) func() error {

				b.Helper()

				return benchmarkGetAddressInfoRequests(b, w, false, false)
			},
		)
	})
}

// BenchmarkGetAddressInfoNotFoundAPI reads a different missing item
// on each call.
func BenchmarkGetAddressInfoNotFoundAPI(b *testing.B) {
	b.Run("matched", func(b *testing.B) {
		RunKVDBBenchmark(b,
			func(b *testing.B, w *Wallet,
				workload bwtest.NodeBenchmarkWorkload) func() error {

				b.Helper()

				return benchmarkGetAddressInfoRequests(b, w, true, true)
			},
			func(b *testing.B, w *Wallet,
				workload bwtest.NodeBenchmarkWorkload) func() error {

				b.Helper()

				return benchmarkGetAddressInfoRequests(b, w, false, true)
			},
		)
	})
}

// benchmarkGetAddressInfoRequests prepares different inputs before timing.
// BenchmarkRead uses the first input for its separate untimed call.
func benchmarkGetAddressInfoRequests(b *testing.B, w *Wallet, legacy,
	missing bool) func() error {

	b.Helper()

	// Keep native enumeration outside measurement; canonical keys match SQL.
	// Reserve a different item for BenchmarkRead's untimed first call.
	count := bwtest.BenchmarkReadCount(b) + 1

	var targets []*Utxo
	if missing {
		targets = benchmarkMissingReadTargets(b, count)
	} else {
		targets = benchmarkPointReadTargets(b, w, legacy, count)
	}

	ctx := b.Context()
	// The first item is for warmup; measured calls read the rest once.
	index := 0

	// Resolve the native operation inside each call, without request data
	// generation, result validation or interaction-recording mocks.
	read := func() error {
		target := targets[index]
		index++
		// Keep native result types so benchmark bookkeeping does not
		// box the modern value into an interface and add allocations.
		var err error
		if legacy {
			result, readErr := w.AddressInfoDeprecated(target.Address)
			runtime.KeepAlive(result)

			err = readErr
		} else {
			result, readErr := w.GetAddressInfo(ctx, target.Address)
			runtime.KeepAlive(result)

			err = readErr
		}

		if !missing {
			return err
		}

		// Different native APIs expose different miss identities. Only
		// that expected response completes this request successfully.
		if (legacy && isAddrMgrErr(err, waddrmgr.ErrAddressNotFound)) ||
			(!legacy && errors.Is(err, ErrAddressNotFound)) {

			return nil
		}

		return errors.Join(
			errors.New("expected not-found response"), err,
		)
	}

	return read
}

// benchmarkPointReadTargets normalizes request keys from native kvdb listings.
// Shared selection keeps the output order equal to the SQL suite.
func benchmarkPointReadTargets(tb testing.TB, w *Wallet,
	legacy bool, count int) []*Utxo {

	tb.Helper()

	if legacy {
		utxos, err := w.ListUnspentDeprecated(0, math.MaxInt32, "")
		require.NoError(tb, err)

		// Select native JSON results by shared policy before decoding only
		// the request fields needed by the legacy point reads.
		selected := bwtest.SelectNodeBenchmarkTargets(
			tb, utxos, count,
			func(utxo *btcjson.ListUnspentResult) (btcutil.Amount,
				string, uint32) {

				amount, err := btcutil.NewAmount(utxo.Amount)
				require.NoError(tb, err)

				return amount, utxo.TxID, utxo.Vout
			},
		)
		targets := make([]*Utxo, len(selected))

		for i, utxo := range selected {
			hash, err := chainhash.NewHashFromStr(utxo.TxID)
			require.NoError(tb, err)
			addr, err := address.DecodeAddress(utxo.Address, &chainParams)
			require.NoError(tb, err)

			targets[i] = &Utxo{
				OutPoint: wire.OutPoint{
					Hash:  *hash,
					Index: utxo.Vout,
				},
				Address: addr,
			}
		}

		return targets
	}

	utxos, err := w.ListUnspent(tb.Context(), UtxoQuery{
		MaxConfs: math.MaxInt32,
	})
	require.NoError(tb, err)

	// Maintained kvdb keeps its native result type through selection.
	return bwtest.SelectNodeBenchmarkTargets(
		tb, utxos, count, func(utxo *Utxo) (btcutil.Amount, string, uint32) {
			return utxo.Amount, utxo.OutPoint.Hash.String(),
				utxo.OutPoint.Index
		},
	)
}

// benchmarkMissingReadTargets prepares the same absent keys as the SQL suite.
// Deterministic public keys keep address requests valid without fixture writes.
func benchmarkMissingReadTargets(tb testing.TB, count int) []*Utxo {
	tb.Helper()

	// The shared generator owns keys and order; this adapter retains the
	// native request shape used by the three point APIs in this suite.
	return bwtest.NodeBenchmarkMissingReadTargets(
		tb, count, func(point wire.OutPoint, addr address.Address) *Utxo {
			return &Utxo{
				OutPoint: point,
				Address:  addr,
			}
		},
	)
}
