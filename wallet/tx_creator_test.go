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
