package wallet

import (
	"testing"

	"github.com/btcsuite/btcd/address/v2"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil/v2"
	"github.com/btcsuite/btcd/txscript/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/btcsuite/btcwallet/pkg/btcunit"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/btcsuite/btcwallet/wallet/internal/db"
	"github.com/btcsuite/btcwallet/wallet/txrules"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

var (
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
	p2wkhAddr, err := address.NewAddressWitnessPubKeyHash(
		address.Hash160(privKey.PubKey().SerializeCompressed()),
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

// TestCreateChangeSourceRedirectsDefaultImported verifies how change is routed
// for imported accounts: a non-default imported xpub account keeps its own
// change destination, while the default imported bucket redirects change to
// derived account 0 resolved by number (so it follows a renamed account 0
// rather than assuming the literal "default" name).
func TestCreateChangeSourceRedirectsDefaultImported(t *testing.T) {
	t.Parallel()

	defaultAccountNum := uint32(waddrmgr.DefaultAccountNum)

	testCases := []struct {
		name string

		// accountName is the change account requested by the caller.
		accountName string

		// derivedName, when non-empty, is the current name of derived
		// account 0 returned by the by-number resolution. It is only
		// looked up for the default imported bucket.
		derivedName string

		// expectedChangeAccount is the account name the change script
		// is finally derived under.
		expectedChangeAccount string
	}{
		{
			name:                  "imported xpub account",
			accountName:           "cold",
			expectedChangeAccount: "cold",
		},
		{
			name:                  "default imported redirects to account 0",
			accountName:           db.DefaultImportedAccountName,
			derivedName:           waddrmgr.DefaultAccountName,
			expectedChangeAccount: waddrmgr.DefaultAccountName,
		},
		{
			name:                  "default imported follows renamed account 0",
			accountName:           db.DefaultImportedAccountName,
			derivedName:           "renamed-default",
			expectedChangeAccount: "renamed-default",
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

			// The default imported bucket resolves derived account 0
			// by number to follow a possible rename.
			if tc.derivedName != "" {
				mocks.store.On("GetAccount", mock.Anything,
					db.GetAccountQuery{
						WalletID:      w.id,
						Scope:         db.KeyScope(scope),
						AccountNumber: &defaultAccountNum,
					},
				).Return(&db.AccountInfo{
					AccountNumber: waddrmgr.DefaultAccountNum,
					AccountName:   tc.derivedName,
					Origin:        db.DerivedAccount,
				}, nil).Once()
			}

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

// TestCreateChangeSourceDefaultImportedMissingAccountZero verifies that a
// not-found error while resolving derived account 0 for default-imported
// change surfaces as the wallet-level ErrAccountNotFound.
func TestCreateChangeSourceDefaultImportedMissingAccountZero(t *testing.T) {
	t.Parallel()

	w, mocks := createTestWalletWithMocks(t)
	scope := waddrmgr.KeyScopeBIP0084
	accountName := db.DefaultImportedAccountName

	mocks.store.On("GetAccount", mock.Anything,
		db.GetAccountQuery{
			WalletID: w.id,
			Scope:    db.KeyScope(scope),
			Name:     &accountName,
		},
	).Return(&db.AccountInfo{
		AccountName: accountName,
		Origin:      db.ImportedAccount,
		AddrSchema:  db.ScopeAddrMap[db.KeyScope(scope)],
	}, nil).Once()

	// Resolving derived account 0 by number reports not found.
	mocks.store.On("GetAccount", mock.Anything,
		mock.MatchedBy(func(q db.GetAccountQuery) bool {
			return q.AccountNumber != nil &&
				*q.AccountNumber == waddrmgr.DefaultAccountNum
		}),
	).Return(nil, db.ErrAccountNotFound).Once()

	_, err := w.createChangeSource(
		t.Context(), &ScopedAccount{
			AccountName: accountName,
			KeyScope:    scope,
		},
	)
	require.ErrorIs(t, err, ErrAccountNotFound)
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

	addr, err := address.NewAddressWitnessPubKeyHash(
		address.Hash160(privKey.PubKey().SerializeCompressed()),
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

	walletMember, err := address.NewAddressPubKey(
		walletKey.PubKey().SerializeCompressed(), &chainParams,
	)
	require.NoError(t, err)
	otherMember, err := address.NewAddressPubKey(
		otherKey.PubKey().SerializeCompressed(), &chainParams,
	)
	require.NoError(t, err)

	pkScript, err := txscript.MultiSigScript(
		[]*address.AddressPubKey{walletMember, otherMember}, 1,
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

// TestGetEligibleUTXOsNilSourceResolvesDefaultAccount verifies that implicit
// coin selection (a nil InputsPolicy.Source) resolves the BIP86 default
// account by number 0 to its current name before listing UTXOs, and that a
// renamed default account still contributes its spendable UTXOs. Filtering
// ListUTXOs by the literal "default" name would miss account-0 UTXOs after a
// rename, so the listing must be narrowed to the resolved name instead.
func TestGetEligibleUTXOsNilSourceResolvesDefaultAccount(t *testing.T) {
	t.Parallel()

	// Arrange.
	w, mocks := createTestWalletWithMocks(t)

	// The default account (number 0) has been renamed away from "default".
	renamedName := "renamed-default"
	scope := db.KeyScope(waddrmgr.KeyScopeBIP0086)

	mocks.chain.On("BlockStamp").Return(
		&waddrmgr.BlockStamp{Height: 100}, nil,
	).Once()

	// The default account must be resolved by number 0, never by the
	// literal "default" name.
	mocks.store.On("GetAccount", mock.Anything,
		mock.MatchedBy(func(q db.GetAccountQuery) bool {
			return q.WalletID == w.id && q.Scope == scope &&
				q.Name == nil && q.AccountNumber != nil &&
				*q.AccountNumber == waddrmgr.DefaultAccountNum
		}),
	).Return(&db.AccountInfo{
		AccountNumber: waddrmgr.DefaultAccountNum,
		AccountName:   renamedName,
		Origin:        db.DerivedAccount,
	}, nil).Once()

	// UTXOs must be listed under the resolved (renamed) account name.
	outPoint := wire.OutPoint{Hash: [32]byte{4}, Index: 0}
	unspent := []db.UtxoInfo{
		{
			OutPoint: outPoint,
			Amount:   btcutil.Amount(10000),
			PkScript: singleAddrPkScript(t),
			Height:   100,
		},
	}
	mocks.store.On("ListUTXOs", mock.Anything, db.ListUtxosQuery{
		WalletID:    w.id,
		Scope:       &scope,
		AccountName: &renamedName,
	}).Return(unspent, nil).Once()

	// Act: a nil coin source selects the default account implicitly.
	eligible, err := w.getEligibleUTXOs(t.Context(), nil, 1)

	// Assert: the renamed default account still yields its spendable UTXO.
	require.NoError(t, err)
	require.Len(t, eligible, 1)
	require.Equal(t, outPoint, eligible[0].OutPoint)
}

// TestGetEligibleUTXOsNilSourceAccountNotFound verifies that a not-found error
// from resolving the default account by number surfaces as the wallet-level
// ErrAccountNotFound, matching the explicit scoped-account path.
func TestGetEligibleUTXOsNilSourceAccountNotFound(t *testing.T) {
	t.Parallel()

	// Arrange.
	w, mocks := createTestWalletWithMocks(t)

	mocks.chain.On("BlockStamp").Return(
		&waddrmgr.BlockStamp{Height: 100}, nil,
	).Once()

	// The default-account resolution by number 0 reports not found.
	mocks.store.On("GetAccount", mock.Anything,
		mock.MatchedBy(func(q db.GetAccountQuery) bool {
			return q.AccountNumber != nil &&
				*q.AccountNumber == waddrmgr.DefaultAccountNum
		}),
	).Return(nil, db.ErrAccountNotFound).Once()

	// Act.
	eligible, err := w.getEligibleUTXOs(t.Context(), nil, 1)

	// Assert: the store-level not-found is wrapped as the wallet error.
	require.ErrorIs(t, err, ErrAccountNotFound)
	require.Nil(t, eligible)
}

// TestCreateManualInputSource verifies the coinbase-maturity gate on manually
// selected inputs. A manual UTXO that is an immature coinbase must be rejected
// with ErrUtxoNotEligible, matching account-based selection, while a mature
// coinbase must be accepted and surfaced by the resulting input source.
func TestCreateManualInputSource(t *testing.T) {
	t.Parallel()

	// The wallet treats an output as a mature coinbase only once it has
	// reached CoinbaseMaturity confirmations against the chain tip. With
	// the tip at height 100 and regtest maturity of 100, a coinbase mined
	// at height 1 has exactly 100 confirmations (mature) while one mined at
	// height 100 has a single confirmation (immature).
	const tipHeight = 100

	matureCoinbase := wire.OutPoint{Hash: [32]byte{1}, Index: 0}
	immatureCoinbase := wire.OutPoint{Hash: [32]byte{2}, Index: 0}

	tests := []struct {
		name       string
		outPoint   wire.OutPoint
		height     uint32
		wantErr    bool
		wantAmount btcutil.Amount
	}{
		{
			name:     "immature coinbase rejected",
			outPoint: immatureCoinbase,
			height:   tipHeight,
			wantErr:  true,
		},
		{
			name:       "mature coinbase accepted",
			outPoint:   matureCoinbase,
			height:     1,
			wantErr:    false,
			wantAmount: btcutil.Amount(10000),
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			// Arrange.
			w, mocks := createTestWalletWithMocks(t)

			mocks.chain.On("BlockStamp").Return(
				&waddrmgr.BlockStamp{Height: tipHeight}, nil,
			).Once()

			credit := &db.UtxoInfo{
				OutPoint:     tc.outPoint,
				Amount:       btcutil.Amount(10000),
				PkScript:     singleAddrPkScript(t),
				Height:       tc.height,
				FromCoinBase: true,
			}
			mocks.store.On("GetUtxo", mock.Anything, db.GetUtxoQuery{
				WalletID: w.id,
				OutPoint: tc.outPoint,
			}).Return(credit, nil).Once()

			// Act.
			source, err := w.createManualInputSource(
				t.Context(), &InputsManual{
					UTXOs: []wire.OutPoint{tc.outPoint},
				},
			)

			// Assert: an immature coinbase is rejected, a mature one
			// is dispensed by the resulting input source.
			if tc.wantErr {
				require.ErrorIs(t, err, ErrUtxoNotEligible)
				require.Nil(t, source)

				return
			}

			require.NoError(t, err)
			require.NotNil(t, source)

			total, inputs, _, _, err := source(0)
			require.NoError(t, err)
			require.Len(t, inputs, 1)
			require.Equal(t, tc.outPoint, inputs[0].PreviousOutPoint)
			require.Equal(t, tc.wantAmount, total)
		})
	}
}

// TestGetEligibleUTXOsFromList verifies that policy-selected CoinSourceUTXOs
// excludes an immature coinbase output even when the requested confirmation
// target is met, while a mature coinbase survives. This keeps explicit UTXO
// selection consistent with account-based selection's coinbase-maturity gate.
func TestGetEligibleUTXOsFromList(t *testing.T) {
	t.Parallel()

	// With the tip at height 100 and regtest maturity of 100, a coinbase
	// mined at height 1 is mature (100 confirmations) while one mined at
	// height 100 is immature (1 confirmation). A minconf of 1 is satisfied
	// in both cases, so only the maturity gate can exclude the immature
	// output.
	const tipHeight = 100

	matureCoinbase := wire.OutPoint{Hash: [32]byte{1}, Index: 0}
	immatureCoinbase := wire.OutPoint{Hash: [32]byte{2}, Index: 0}

	tests := []struct {
		name        string
		height      uint32
		wantInclude bool
	}{
		{
			name:        "immature coinbase excluded",
			height:      tipHeight,
			wantInclude: false,
		},
		{
			name:        "mature coinbase included",
			height:      1,
			wantInclude: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			// Arrange.
			w, mocks := createTestWalletWithMocks(t)

			outPoint := matureCoinbase
			if !tc.wantInclude {
				outPoint = immatureCoinbase
			}

			source := &CoinSourceUTXOs{
				UTXOs: []wire.OutPoint{outPoint},
			}
			bs := &waddrmgr.BlockStamp{Height: tipHeight}

			credit := &db.UtxoInfo{
				OutPoint:     outPoint,
				Amount:       btcutil.Amount(10000),
				PkScript:     singleAddrPkScript(t),
				Height:       tc.height,
				FromCoinBase: true,
			}
			mocks.store.On("GetUtxo", mock.Anything, db.GetUtxoQuery{
				WalletID: w.id,
				OutPoint: outPoint,
			}).Return(credit, nil).Once()

			// Act: minconf of 1 is satisfied for both outputs.
			eligible, err := w.getEligibleUTXOsFromList(
				t.Context(), source, 1, bs,
			)

			// Assert.
			require.NoError(t, err)

			if tc.wantInclude {
				require.Len(t, eligible, 1)
				require.Equal(t, outPoint, eligible[0].OutPoint)
			} else {
				require.Empty(t, eligible)
			}
		})
	}
}

// TestFilterEligibleOutputsExcludesImmatureCoinbase verifies that account-based
// selection is unchanged by the shared coinbase-maturity helper: an immature
// coinbase output is filtered out while a mature one is retained, even though
// both satisfy the requested confirmation target.
func TestFilterEligibleOutputsExcludesImmatureCoinbase(t *testing.T) {
	t.Parallel()

	const tipHeight = 100

	accountName := "default"
	account := uint32(0)
	targetScope := waddrmgr.KeyScopeBIP0086

	matureCoinbase := wire.OutPoint{Hash: [32]byte{1}, Index: 0}
	immatureCoinbase := wire.OutPoint{Hash: [32]byte{2}, Index: 0}

	tests := []struct {
		name        string
		outPoint    wire.OutPoint
		height      uint32
		wantInclude bool
	}{
		{
			name:        "immature coinbase excluded",
			outPoint:    immatureCoinbase,
			height:      tipHeight,
			wantInclude: false,
		},
		{
			name:        "mature coinbase included",
			outPoint:    matureCoinbase,
			height:      1,
			wantInclude: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			// Arrange.
			w, mocks := createTestWalletWithMocks(t)

			currentBlock := &waddrmgr.BlockStamp{Height: tipHeight}
			unspent := []db.UtxoInfo{
				{
					OutPoint:     tc.outPoint,
					Amount:       btcutil.Amount(10000),
					PkScript:     singleAddrPkScript(t),
					Height:       tc.height,
					FromCoinBase: true,
				},
			}

			scope := db.KeyScope(targetScope)
			mocks.store.On("ListUTXOs", mock.Anything,
				db.ListUtxosQuery{
					WalletID:    w.id,
					Scope:       &scope,
					AccountName: &accountName,
				},
			).Return(unspent, nil).Once()

			// Act: minconf of 1 is satisfied for both outputs.
			eligible, err := w.filterEligibleOutputs(
				t.Context(), &targetScope, accountName, account,
				1, currentBlock,
			)

			// Assert.
			require.NoError(t, err)

			if tc.wantInclude {
				require.Len(t, eligible, 1)
				require.Equal(t, tc.outPoint,
					eligible[0].OutPoint)
			} else {
				require.Empty(t, eligible)
			}
		})
	}
}
