package wallet

import (
	"errors"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcwallet/pkg/btcunit"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/btcsuite/btcwallet/wallet/internal/db"
	"github.com/btcsuite/btcwallet/wallet/txrules"
	"github.com/btcsuite/btcwallet/walletdb"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

var (
	// errStrategy is used to simulate failures in coin selection
	// strategies within tests.
	errStrategy = errors.New("strategy error")

	// errDB is used to simulate database operation failures within tests.
	errDB = errors.New("db error")

	// defaultAccountName is the name of the default account.
	defaultAccountName = "default"
)

// TestValidateTxIntent ensures that the validateTxIntent function returns
// errors for all expected invalid transaction intents, and that it returns nil
// for valid intents. The test covers a range of scenarios, including missing
// inputs or outputs, dust outputs, duplicate UTXOs, and invalid account or
// change source configurations.
func TestValidateTxIntent(t *testing.T) {
	t.Parallel()

	const defaultAccountName = "default"

	// Define a set of valid outputs and inputs to be reused across test
	// cases.
	validOutput := wire.TxOut{Value: 10000, PkScript: []byte{}}
	validUTXO := wire.OutPoint{Hash: [32]byte{1}, Index: 0}
	validAccountName := defaultAccountName
	validScopedAccount := &ScopedAccount{
		AccountName: validAccountName,
		KeyScope:    waddrmgr.KeyScopeBIP0086,
	}
	defaultFeeRate := btcunit.NewSatPerKVByte(1000)

	// Define the test cases, each representing a different scenario for
	// validating a TxIntent.
	testCases := []struct {
		name        string
		intent      *TxIntent
		expectedErr error
	}{
		{
			name: "valid intent with manual inputs",
			intent: &TxIntent{
				Outputs: []wire.TxOut{validOutput},
				Inputs: &InputsManual{
					UTXOs: []wire.OutPoint{validUTXO},
				},
				ChangeSource: &ScopedAccount{
					AccountName: defaultAccountName,
				},
				FeeRate: defaultFeeRate,
			},
			expectedErr: nil,
		},
		{
			name: "valid intent with policy inputs " +
				"(scoped account)",
			intent: &TxIntent{
				Outputs: []wire.TxOut{validOutput},
				Inputs: &InputsPolicy{
					Source: validScopedAccount,
				},
				ChangeSource: &ScopedAccount{
					AccountName: defaultAccountName,
				},
				FeeRate: defaultFeeRate,
			},
			expectedErr: nil,
		},
		{
			name: "valid intent with policy inputs (utxo source)",
			intent: &TxIntent{
				Outputs: []wire.TxOut{validOutput},
				Inputs: &InputsPolicy{
					Source: &CoinSourceUTXOs{
						UTXOs: []wire.OutPoint{
							validUTXO,
						},
					},
				},
				ChangeSource: &ScopedAccount{
					AccountName: defaultAccountName,
				},
				FeeRate: defaultFeeRate,
			},
			expectedErr: nil,
		},
		{
			name: "valid intent with nil source in policy",
			intent: &TxIntent{
				Outputs: []wire.TxOut{validOutput},
				Inputs:  &InputsPolicy{Source: nil},
				ChangeSource: &ScopedAccount{
					AccountName: defaultAccountName,
				},
				FeeRate: defaultFeeRate,
			},
			expectedErr: nil,
		},
		{
			name: "invalid intent - nil inputs",
			intent: &TxIntent{
				Outputs: []wire.TxOut{validOutput},
				Inputs:  nil,
				ChangeSource: &ScopedAccount{
					AccountName: defaultAccountName,
				},
				FeeRate: defaultFeeRate,
			},
			expectedErr: ErrMissingInputs,
		},
		{
			name: "invalid intent - no outputs",
			intent: &TxIntent{
				Outputs: []wire.TxOut{},
				Inputs: &InputsManual{
					UTXOs: []wire.OutPoint{validUTXO},
				},
				ChangeSource: &ScopedAccount{
					AccountName: defaultAccountName,
				},
				FeeRate: defaultFeeRate,
			},
			expectedErr: ErrNoTxOutputs,
		},
		{
			name: "invalid intent - dust output",
			intent: &TxIntent{
				Outputs: []wire.TxOut{{Value: 1}},
				Inputs: &InputsManual{
					UTXOs: []wire.OutPoint{validUTXO},
				},
				ChangeSource: &ScopedAccount{
					AccountName: defaultAccountName,
				},
				FeeRate: defaultFeeRate,
			},
			expectedErr: txrules.ErrOutputIsDust,
		},
		{
			name: "invalid intent - empty manual inputs",
			intent: &TxIntent{
				Outputs: []wire.TxOut{validOutput},
				Inputs: &InputsManual{
					UTXOs: []wire.OutPoint{},
				},
				ChangeSource: &ScopedAccount{
					AccountName: defaultAccountName,
				},
				FeeRate: defaultFeeRate,
			},
			expectedErr: ErrManualInputsEmpty,
		},
		{
			name: "invalid intent - duplicate manual inputs",
			intent: &TxIntent{
				Outputs: []wire.TxOut{validOutput},
				Inputs: &InputsManual{
					UTXOs: []wire.OutPoint{
						validUTXO, validUTXO,
					},
				},
				ChangeSource: &ScopedAccount{
					AccountName: defaultAccountName,
				},
				FeeRate: defaultFeeRate,
			},
			expectedErr: ErrDuplicatedUtxo,
		},
		{
			name: "invalid intent - empty account name in source",
			intent: &TxIntent{
				Outputs: []wire.TxOut{validOutput},
				Inputs: &InputsPolicy{
					Source: &ScopedAccount{AccountName: ""},
				},
				ChangeSource: &ScopedAccount{
					AccountName: defaultAccountName,
				},
				FeeRate: defaultFeeRate,
			},
			expectedErr: ErrMissingAccountName,
		},
		{
			name: "invalid intent - empty utxo list in source",
			intent: &TxIntent{
				Outputs: []wire.TxOut{validOutput},
				Inputs: &InputsPolicy{
					Source: &CoinSourceUTXOs{
						UTXOs: []wire.OutPoint{},
					},
				},
				ChangeSource: &ScopedAccount{
					AccountName: defaultAccountName,
				},
				FeeRate: defaultFeeRate,
			},
			expectedErr: ErrManualInputsEmpty,
		},
		{
			name: "invalid intent - duplicate utxos in policy",
			intent: &TxIntent{
				Outputs: []wire.TxOut{validOutput},
				Inputs: &InputsPolicy{
					Source: &CoinSourceUTXOs{
						UTXOs: []wire.OutPoint{
							validUTXO, validUTXO,
						},
					},
				},
				ChangeSource: &ScopedAccount{
					AccountName: defaultAccountName,
				},
				FeeRate: defaultFeeRate,
			},
			expectedErr: ErrDuplicatedUtxo,
		},
		{
			name: "invalid intent - unsupported coin source",
			intent: &TxIntent{
				Outputs: []wire.TxOut{validOutput},
				Inputs: &InputsPolicy{
					Source: &unsupportedCoinSource{},
				},
				ChangeSource: &ScopedAccount{
					AccountName: defaultAccountName,
				},
				FeeRate: defaultFeeRate,
			},
			expectedErr: ErrUnsupportedCoinSource,
		},
		{
			name: "invalid intent - unsupported inputs type",
			intent: &TxIntent{
				Outputs: []wire.TxOut{validOutput},
				Inputs:  &unsupportedInputs{},
				ChangeSource: &ScopedAccount{
					AccountName: defaultAccountName,
				},
				FeeRate: defaultFeeRate,
			},
			expectedErr: nil,
		},
		{
			name: "invalid intent - empty account name in change",
			intent: &TxIntent{
				Outputs: []wire.TxOut{validOutput},
				Inputs: &InputsManual{
					UTXOs: []wire.OutPoint{validUTXO},
				},
				ChangeSource: &ScopedAccount{
					AccountName: "",
					KeyScope:    waddrmgr.KeyScopeBIP0086,
				},
				FeeRate: defaultFeeRate,
			},
			expectedErr: ErrMissingAccountName,
		},
		{
			name: "invalid intent - zero fee rate",
			intent: &TxIntent{
				Outputs: []wire.TxOut{validOutput},
				Inputs: &InputsManual{
					UTXOs: []wire.OutPoint{validUTXO},
				},
				ChangeSource: &ScopedAccount{
					AccountName: defaultAccountName,
					KeyScope:    waddrmgr.KeyScopeBIP0086,
				},
				FeeRate: btcunit.ZeroSatPerKVByte,
			},
			expectedErr: ErrMissingFeeRate,
		},
		{
			name: "invalid intent - insane fee rate",
			intent: &TxIntent{
				Outputs: []wire.TxOut{validOutput},
				Inputs: &InputsManual{
					UTXOs: []wire.OutPoint{validUTXO},
				},
				ChangeSource: &ScopedAccount{
					AccountName: defaultAccountName,
					KeyScope:    waddrmgr.KeyScopeBIP0086,
				},
				FeeRate: btcunit.NewSatPerKVByte(2_000_000),
			},
			expectedErr: ErrFeeRateTooLarge,
		},
	}

	// Iterate through all test cases and run them.
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			// Call the validate function and check that the error
			// matches the expected error.
			err := validateTxIntent(tc.intent)
			require.ErrorIs(t, err, tc.expectedErr)
		})
	}
}

// unsupportedInputs is a mock implementation of the Inputs interface used for
// testing purposes.
type unsupportedInputs struct{}

// isInputs marks unsupportedInputs as an Inputs implementation.
func (u *unsupportedInputs) isInputs() {}

// validate returns nil so tests can exercise unsupported input dispatch.
func (u *unsupportedInputs) validate() error { return nil }

// unsupportedCoinSource is a mock implementation of the CoinSource interface
// used for testing purposes.
type unsupportedCoinSource struct{}

// isCoinSource marks unsupportedCoinSource as a CoinSource implementation.
func (u *unsupportedCoinSource) isCoinSource() {}

// TestDetermineChangeSource tests the behavior of the determineChangeSource
// method, ensuring that it correctly selects a change source based on the
// transaction intent. It covers scenarios where the change source is
// explicitly provided, derived from the input policy, or falls back to the
// default P2TR account.
func TestDetermineChangeSource(t *testing.T) {
	t.Parallel()

	w, _ := createStartedWalletWithMocks(t)

	// Define a set of accounts to be reused across test cases.
	explicitChangeSource := &ScopedAccount{
		AccountName: "explicit",
		KeyScope:    waddrmgr.KeyScopeBIP0044,
	}
	policyAccountSource := &ScopedAccount{
		AccountName: "policy",
		KeyScope:    waddrmgr.KeyScopeBIP0049Plus,
	}
	defaultAccountSource := &ScopedAccount{
		AccountName: waddrmgr.DefaultAccountName,
		KeyScope:    waddrmgr.KeyScopeBIP0086,
	}

	testCases := []struct {
		name           string
		intent         *TxIntent
		expectedSource *ScopedAccount
	}{
		{
			name: "explicit change source",
			intent: &TxIntent{
				ChangeSource: explicitChangeSource,
			},
			expectedSource: explicitChangeSource,
		},
		{
			name: "nil change source with policy account",
			intent: &TxIntent{
				Inputs: &InputsPolicy{
					Source: policyAccountSource,
				},
				ChangeSource: nil,
			},
			expectedSource: policyAccountSource,
		},
		{
			name: "nil change source with manual inputs",
			intent: &TxIntent{
				Inputs:       &InputsManual{},
				ChangeSource: nil,
			},
			expectedSource: defaultAccountSource,
		},
		{
			name: "nil change source with non-account policy",
			intent: &TxIntent{
				Inputs: &InputsPolicy{
					Source: &CoinSourceUTXOs{},
				},
				ChangeSource: nil,
			},
			expectedSource: defaultAccountSource,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			source := w.determineChangeSource(tc.intent)
			require.Equal(t, tc.expectedSource, source)
		})
	}
}

type mockReadBucket struct {
	walletdb.ReadBucket
}

type mockReadTx struct {
	walletdb.ReadTx
}

// ReadBucket returns a stub read bucket for UTXO tests.
func (m *mockReadTx) ReadBucket(key []byte) walletdb.ReadBucket {
	return &mockReadBucket{}
}

// TestCreateTransactionInvalidIntent tests that an error is returned when an
// invalid transaction intent is provided.
func TestCreateTransactionInvalidIntent(t *testing.T) {
	t.Parallel()

	// Arrange.
	w, mocks := createStartedWalletWithMocks(t)
	mocks.syncer.On("syncState").Return(syncStateSynced).Once()

	intent := &TxIntent{
		Outputs: []wire.TxOut{}, // No outputs
	}

	// Act.
	tx, err := w.CreateTransaction(t.Context(), intent)

	// Assert.
	require.ErrorIs(t, err, ErrNoTxOutputs)
	require.Nil(t, tx)
}

// TestCreateTransactionAccountNotFound tests that an error is returned when
// the specified account is not found.
func TestCreateTransactionAccountNotFound(t *testing.T) {
	t.Parallel()

	// Arrange.
	w, mocks := createStartedWalletWithMocks(t)
	mocks.syncer.On("syncState").Return(syncStateSynced).Once()

	privKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	p2wkhAddr, err := btcutil.NewAddressWitnessPubKeyHash(
		btcutil.Hash160(privKey.PubKey().SerializeCompressed()),
		&chainParams,
	)
	require.NoError(t, err)
	validPkScript, err := txscript.PayToAddrScript(p2wkhAddr)
	require.NoError(t, err)

	validOutput := wire.TxOut{Value: 10000, PkScript: validPkScript}
	validUTXO := wire.OutPoint{Hash: [32]byte{1}, Index: 0}

	intent := &TxIntent{
		Outputs: []wire.TxOut{validOutput},
		Inputs: &InputsManual{
			UTXOs: []wire.OutPoint{validUTXO},
		},
		ChangeSource: &ScopedAccount{
			AccountName: "unknown",
			KeyScope:    waddrmgr.KeyScopeBIP0086,
		},
		FeeRate: btcunit.NewSatPerKVByte(1000),
	}

	// createChangeSource now goes through w.store.GetAccount instead
	// of the legacy waddrmgr FetchScopedKeyManager + LookupAccount
	// path. The wrapped ErrAccountNotFound bubbles up through
	// prepareTxAuthSources.
	mocks.store.On("GetAccount", mock.Anything,
		mock.MatchedBy(func(q db.GetAccountQuery) bool {
			return q.Name != nil && *q.Name == "unknown"
		}),
	).Return(nil, db.ErrAccountNotFound)

	// Act.
	tx, err := w.CreateTransaction(t.Context(), intent)

	// Assert.
	require.ErrorIs(t, err, ErrAccountNotFound)
	require.Nil(t, tx)
}

// TestCreateChangeSourceOnlyRedirectsImportedCatchAll verifies that imported
// xpub-style accounts keep their own change destination.
func TestCreateChangeSourceOnlyRedirectsImportedCatchAll(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name                  string
		accountName           string
		expectedChangeAccount string
	}{
		{
			name:                  "imported xpub account",
			accountName:           "cold",
			expectedChangeAccount: "cold",
		},
		{
			name:                  "imported catch all account",
			accountName:           db.DefaultImportedAccountName,
			expectedChangeAccount: waddrmgr.DefaultAccountName,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			w, mocks := createTestWalletWithMocks(t)
			scope := waddrmgr.KeyScopeBIP0084
			changeScript := []byte{0x00, 0x04}

			mocks.store.On("GetAccount", mock.Anything,
				db.GetAccountQuery{
					WalletID: w.id,
					Scope:    db.KeyScope(scope),
					Name:     &tc.accountName,
				},
			).Return(&db.AccountInfo{
				AccountName: tc.accountName,
				Origin:      db.ImportedAccount,
				AddrSchema:  db.ScopeAddrMap[db.KeyScope(scope)],
			}, nil).Once()
			mocks.store.On("NewDerivedAddress", mock.Anything,
				db.NewDerivedAddressParams{
					WalletID:    w.id,
					AccountName: tc.expectedChangeAccount,
					Scope:       db.KeyScope(scope),
					Change:      true,
				},
			).Return(&db.AddressInfo{
				ScriptPubKey: changeScript,
			}, nil).Once()

			changeSource, err := w.createChangeSource(
				t.Context(), &ScopedAccount{
					AccountName: tc.accountName,
					KeyScope:    scope,
				},
			)
			require.NoError(t, err)

			script, err := changeSource.NewScript()
			require.NoError(t, err)
			require.Equal(t, changeScript, script)
		})
	}
}

// TestFilterEligibleOutputsIncludesWatchOnlyOutputs verifies that tx authoring
// does not reject wallet-owned watch-only UTXOs before signing.
func TestFilterEligibleOutputsIncludesWatchOnlyOutputs(t *testing.T) {
	t.Parallel()

	w, mocks := createTestWalletWithMocks(t)

	accountName := "watch"
	account := uint32(9)
	targetScope := waddrmgr.KeyScopeBIP0084
	currentBlock := &waddrmgr.BlockStamp{Height: 100}
	script := singleAddrPkScript(t)
	outPoint := wire.OutPoint{Hash: [32]byte{3}, Index: 0}
	unspent := []db.UtxoInfo{
		{
			OutPoint: outPoint,
			Amount:   btcutil.Amount(10000),
			PkScript: script,
			Height:   100,
		},
	}

	// The store enriches each UTXO with its account, scope and lock
	// state and ListUTXOs is already narrowed to (Scope, AccountName), so
	// filtering no longer issues a per-UTXO GetAddress lookup. A
	// wallet-owned watch-only output surfaced by the store must therefore
	// survive filtering.
	scope := db.KeyScope(targetScope)
	mocks.store.On("ListUTXOs", mock.Anything, db.ListUtxosQuery{
		WalletID:    w.id,
		Scope:       &scope,
		AccountName: &accountName,
	}).Return(unspent, nil).Once()

	eligible, err := w.filterEligibleOutputs(
		t.Context(), &targetScope, accountName, account, 1,
		currentBlock,
	)

	require.NoError(t, err)
	require.Len(t, eligible, 1)
	require.Equal(t, outPoint, eligible[0].OutPoint)
}

// TestFilterEligibleOutputsTrustsStoreScopeFilter verifies that UTXO filtering
// trusts the store's (Scope, AccountName) narrowing and the authoritative
// per-UTXO KeyScope, rather than re-deriving a scope from the script type or
// issuing a per-UTXO GetAddress re-check.
func TestFilterEligibleOutputsTrustsStoreScopeFilter(t *testing.T) {
	t.Parallel()

	w, mocks := createTestWalletWithMocks(t)

	accountName := "mixed"
	account := uint32(7)
	targetScope := waddrmgr.KeyScopeBIP0049Plus
	currentBlock := &waddrmgr.BlockStamp{Height: 100}

	bip49Script := singleAddrPkScript(t)
	bip49OutPoint := wire.OutPoint{Hash: [32]byte{1}, Index: 0}

	// ListUTXOs is queried with the target scope, so the store only
	// returns UTXOs that belong to it, each enriched with its
	// authoritative persisted KeyScope. A BIP0084 UTXO under the same
	// account would never be returned for a BIP0049Plus query.
	unspent := []db.UtxoInfo{
		{
			OutPoint: bip49OutPoint,
			Amount:   btcutil.Amount(10000),
			PkScript: bip49Script,
			Height:   100,
			KeyScope: db.KeyScopeBIP0049Plus,
		},
	}

	scope := db.KeyScope(targetScope)
	mocks.store.On("ListUTXOs", mock.Anything, db.ListUtxosQuery{
		WalletID:    w.id,
		Scope:       &scope,
		AccountName: &accountName,
	}).Return(unspent, nil).Once()

	eligible, err := w.filterEligibleOutputs(
		t.Context(), &targetScope, accountName, account, 1,
		currentBlock,
	)

	require.NoError(t, err)
	require.Len(t, eligible, 1)
	require.Equal(t, bip49OutPoint, eligible[0].OutPoint)
}

// singleAddrPkScript builds a standard single-address P2WPKH pkScript that
// ExtractPkScriptAddrs resolves to exactly one address. Coin-selection
// filtering treats such scripts as spendable, so eligible-output tests use it
// for UTXOs that must survive the single-address spendability gate.
func singleAddrPkScript(t *testing.T) []byte {
	t.Helper()

	privKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)

	addr, err := btcutil.NewAddressWitnessPubKeyHash(
		btcutil.Hash160(privKey.PubKey().SerializeCompressed()),
		&chainParams,
	)
	require.NoError(t, err)

	pkScript, err := txscript.PayToAddrScript(addr)
	require.NoError(t, err)

	return pkScript
}

// bareMultisigPkScript builds a bare 1-of-2 multisig pkScript. Even when the
// wallet owns one of the two member pubkeys, ExtractPkScriptAddrs resolves it
// to two addresses, so the single-address spendability gate excludes it from
// automatic coin selection.
func bareMultisigPkScript(t *testing.T) []byte {
	t.Helper()

	walletKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	otherKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)

	walletMember, err := btcutil.NewAddressPubKey(
		walletKey.PubKey().SerializeCompressed(), &chainParams,
	)
	require.NoError(t, err)
	otherMember, err := btcutil.NewAddressPubKey(
		otherKey.PubKey().SerializeCompressed(), &chainParams,
	)
	require.NoError(t, err)

	pkScript, err := txscript.MultiSigScript(
		[]*btcutil.AddressPubKey{walletMember, otherMember}, 1,
	)
	require.NoError(t, err)

	return pkScript
}

// TestFilterEligibleOutputsExcludesBareMultisig verifies that automatic coin
// selection distinguishes wallet *ownership* from wallet *spendability*. The
// store's ListUTXOs surfaces an output the moment one of its member pubkeys
// belongs to the wallet, but a bare multisig output may require keys the
// wallet does not hold. The single-address spendability gate must therefore
// drop the bare-multisig UTXO while letting an ordinary single-address UTXO
// through.
func TestFilterEligibleOutputsExcludesBareMultisig(t *testing.T) {
	t.Parallel()

	// Arrange.
	w, mocks := createTestWalletWithMocks(t)

	accountName := "mixed"
	account := uint32(5)
	targetScope := waddrmgr.KeyScopeBIP0084
	currentBlock := &waddrmgr.BlockStamp{Height: 100}

	// One UTXO is a normal single-address P2WPKH output (spendable); the
	// other is a bare multisig the wallet only partly owns (not spendable
	// on its own).
	singleOutPoint := wire.OutPoint{Hash: [32]byte{1}, Index: 0}
	multisigOutPoint := wire.OutPoint{Hash: [32]byte{2}, Index: 0}
	unspent := []db.UtxoInfo{
		{
			OutPoint: singleOutPoint,
			Amount:   btcutil.Amount(10000),
			PkScript: singleAddrPkScript(t),
			Height:   100,
		},
		{
			OutPoint: multisigOutPoint,
			Amount:   btcutil.Amount(20000),
			PkScript: bareMultisigPkScript(t),
			Height:   100,
		},
	}

	scope := db.KeyScope(targetScope)
	mocks.store.On("ListUTXOs", mock.Anything, db.ListUtxosQuery{
		WalletID:    w.id,
		Scope:       &scope,
		AccountName: &accountName,
	}).Return(unspent, nil).Once()

	// Act.
	eligible, err := w.filterEligibleOutputs(
		t.Context(), &targetScope, accountName, account, 1,
		currentBlock,
	)

	// Assert: only the single-address output survives filtering; the
	// bare-multisig output is excluded despite being wallet-owned.
	require.NoError(t, err)
	require.Len(t, eligible, 1)
	require.Equal(t, singleOutPoint, eligible[0].OutPoint)
}
