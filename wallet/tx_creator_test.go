package wallet

import (
	"testing"

	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/btcsuite/btcwallet/wallet/txrules"
	"github.com/btcsuite/btcwallet/walletdb"
	"github.com/btcsuite/btcwallet/wtxmgr"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// TestValidateTxIntent ensures that the validateTxIntent function returns
// errors for all expected invalid transaction intents, and that it returns nil
// for valid intents. The test covers a range of scenarios, including missing
// inputs or outputs, dust outputs, duplicate UTXOs, and invalid account or
// change source configurations.
func TestValidateTxIntent(t *testing.T) {
	t.Parallel()

	// Define a set of valid outputs and inputs to be reused across test
	// cases.
	validOutput := wire.TxOut{Value: 10000, PkScript: []byte{}}
	validUTXO := wire.OutPoint{Hash: [32]byte{1}, Index: 0}
	validAccountName := "default"
	validScopedAccount := &ScopedAccount{
		AccountName: validAccountName,
		KeyScope:    waddrmgr.KeyScopeBIP0086,
	}

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
					AccountName: "default",
				},
			},
			expectedErr: nil,
		},
		{
			name: "valid intent with policy inputs (scoped account)",
			intent: &TxIntent{
				Outputs: []wire.TxOut{validOutput},
				Inputs: &InputsPolicy{
					Source: validScopedAccount,
				},
				ChangeSource: &ScopedAccount{
					AccountName: "default",
				},
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
					AccountName: "default",
				},
			},
			expectedErr: nil,
		},
		{
			name: "valid intent with nil source in policy",
			intent: &TxIntent{
				Outputs: []wire.TxOut{validOutput},
				Inputs:  &InputsPolicy{Source: nil},
				ChangeSource: &ScopedAccount{
					AccountName: "default",
				},
			},
			expectedErr: nil,
		},
		{
			name: "invalid intent - nil inputs",
			intent: &TxIntent{
				Outputs: []wire.TxOut{validOutput},
				Inputs:  nil,
				ChangeSource: &ScopedAccount{
					AccountName: "default",
				},
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
					AccountName: "default",
				},
			},
			expectedErr: ErrNoOutputs,
		},
		{
			name: "invalid intent - dust output",
			intent: &TxIntent{
				Outputs: []wire.TxOut{{Value: 1}},
				Inputs: &InputsManual{
					UTXOs: []wire.OutPoint{validUTXO},
				},
				ChangeSource: &ScopedAccount{
					AccountName: "default",
				},
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
					AccountName: "default",
				},
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
					AccountName: "default",
				},
			},
			expectedErr: ErrDuplicateUtxo,
		},
		{
			name: "invalid intent - empty account name in source",
			intent: &TxIntent{
				Outputs: []wire.TxOut{validOutput},
				Inputs: &InputsPolicy{
					Source: &ScopedAccount{AccountName: ""},
				},
				ChangeSource: &ScopedAccount{
					AccountName: "default",
				},
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
					AccountName: "default",
				},
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
					AccountName: "default",
				},
			},
			expectedErr: ErrDuplicateUtxo,
		},
		{
			name: "invalid intent - unsupported coin source",
			intent: &TxIntent{
				Outputs: []wire.TxOut{validOutput},
				Inputs: &InputsPolicy{
					Source: &unsupportedCoinSource{},
				},
				ChangeSource: &ScopedAccount{
					AccountName: "default",
				},
			},
			expectedErr: ErrUnsupportedCoinSource,
		},
		{
			name: "invalid intent - unsupported inputs type",
			intent: &TxIntent{
				Outputs: []wire.TxOut{validOutput},
				Inputs:  &unsupportedInputs{},
				ChangeSource: &ScopedAccount{
					AccountName: "default",
				},
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
			},
			expectedErr: ErrMissingAccountName,
		},
	}

	// Iterate through all test cases and run them.
	for _, tc := range testCases {
		tc := tc
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

func (u *unsupportedInputs) isInputs()       {}
func (u *unsupportedInputs) validate() error { return nil }

// unsupportedCoinSource is a mock implementation of the CoinSource interface
// used for testing purposes.
type unsupportedCoinSource struct{}

func (u *unsupportedCoinSource) isCoinSource() {}

type mockReadBucket struct {
	walletdb.ReadBucket
}

type mockReadTx struct {
	walletdb.ReadTx
}

func (m *mockReadTx) ReadBucket(key []byte) walletdb.ReadBucket {
	return &mockReadBucket{}
}

// TestGetEligibleUTXOsFromList tests that the getEligibleUTXOsFromList method
// correctly filters a list of UTXOs based on their confirmation status. It
// ensures that UTXOs with sufficient confirmations are included, while those
// that are unconfirmed or do not meet the minimum confirmation requirement are
// excluded. The test also verifies that an error is returned if a specified
// UTXO is not found in the wallet.
func TestGetEligibleUTXOsFromList(t *testing.T) {
	t.Parallel()

	w, mocks := testWalletWithMocks(t)

	// Define a block stamp for the current chain height.
	currentHeight := int32(100)
	blockStamp := &waddrmgr.BlockStamp{
		Height: currentHeight,
	}

	// Define some UTXOs.
	// This UTXO has 1 confirmation.
	utxo1 := wire.OutPoint{Hash: [32]byte{1}, Index: 0}

	// This UTXO has 6 confirmations.
	utxo2 := wire.OutPoint{Hash: [32]byte{2}, Index: 0}

	// This UTXO is unconfirmed.
	utxo3 := wire.OutPoint{Hash: [32]byte{3}, Index: 0}

	// This UTXO is not found.
	utxo4 := wire.OutPoint{Hash: [32]byte{4}, Index: 0}

	// Define the corresponding credits.
	credit1 := &wtxmgr.Credit{
		OutPoint: utxo1,
		BlockMeta: wtxmgr.BlockMeta{
			Block: wtxmgr.Block{
				// 1 conf = 100 - 100 + 1.
				Height: currentHeight,
			},
		},
	}
	credit2 := &wtxmgr.Credit{
		OutPoint: utxo2,
		BlockMeta: wtxmgr.BlockMeta{
			Block: wtxmgr.Block{
				// 6 confs = 100 - 95 + 1.
				Height: currentHeight - 5,
			},
		},
	}
	credit3 := &wtxmgr.Credit{
		OutPoint: utxo3,
		BlockMeta: wtxmgr.BlockMeta{
			Block: wtxmgr.Block{
				// Unconfirmed.
				Height: -1,
			},
		},
	}

	// Set up mock calls for txStore.GetUtxo.
	mocks.txStore.On("GetUtxo", mock.Anything, utxo1).Return(credit1, nil)
	mocks.txStore.On("GetUtxo", mock.Anything, utxo2).Return(credit2, nil)
	mocks.txStore.On("GetUtxo", mock.Anything, utxo3).Return(credit3, nil)
	mocks.txStore.On("GetUtxo", mock.Anything, utxo4).Return(
		nil, wtxmgr.ErrUtxoNotFound,
	)

	testCases := []struct {
		name          string
		source        *CoinSourceUTXOs
		minconf       uint32
		expectedUtxos []wtxmgr.Credit
		expectedErr   error
	}{
		{
			name: "all utxos with minconf 0",
			source: &CoinSourceUTXOs{
				UTXOs: []wire.OutPoint{utxo1, utxo2, utxo3},
			},
			minconf: 0,
			expectedUtxos: []wtxmgr.Credit{
				*credit1, *credit2, *credit3,
			},
		},
		{
			name: "1 conf required",
			source: &CoinSourceUTXOs{
				UTXOs: []wire.OutPoint{utxo1, utxo2, utxo3},
			},
			minconf:       1,
			expectedUtxos: []wtxmgr.Credit{*credit1, *credit2},
		},
		{
			name: "6 confs required",
			source: &CoinSourceUTXOs{
				UTXOs: []wire.OutPoint{utxo1, utxo2, utxo3},
			},
			minconf:       6,
			expectedUtxos: []wtxmgr.Credit{*credit2},
		},
		{
			name: "7 confs required",
			source: &CoinSourceUTXOs{
				UTXOs: []wire.OutPoint{utxo1, utxo2, utxo3},
			},
			minconf:       7,
			expectedUtxos: []wtxmgr.Credit{},
		},
		{
			name: "utxo not found",
			source: &CoinSourceUTXOs{
				UTXOs: []wire.OutPoint{utxo1, utxo4},
			},
			minconf:     1,
			expectedErr: ErrUtxoNotEligible,
		},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			dbtx := &mockReadTx{}
			utxos, err := w.getEligibleUTXOsFromList(
				dbtx, tc.source, tc.minconf, blockStamp,
			)

			require.ErrorIs(t, err, tc.expectedErr)
			if err == nil {
				require.ElementsMatch(t, tc.expectedUtxos, utxos)
			}
		})
	}
}

// TestGetEligibleUTXOsFromAccount tests that the getEligibleUTXOsFromAccount
// method correctly returns an ErrAccountNotFound when the specified account
// does not exist. This ensures that the function properly handles cases where
// UTXOs are requested from a non-existent account.
func TestGetEligibleUTXOsFromAccount(t *testing.T) {
	t.Parallel()

	// Define a block stamp for the current chain height.
	blockStamp := &waddrmgr.BlockStamp{
		Height: 100,
	}

	keyScope := waddrmgr.KeyScopeBIP0086
	minconf := uint32(1)

	w, mocks := testWalletWithMocks(t)
	accountStore := &mockAccountStore{}
	mocks.addrStore.On("FetchScopedKeyManager", keyScope).
		Return(accountStore, nil)

	// We need to define the error type explicitly to avoid mock panics.
	errNotFound := waddrmgr.ManagerError{
		ErrorCode: waddrmgr.ErrAccountNotFound,
	}
	accountStore.On("LookupAccount", mock.Anything, "unknown").
		Return(uint32(0), errNotFound)

	_, err := w.getEligibleUTXOsFromAccount(
		&mockReadTx{},
		&ScopedAccount{
			AccountName: "unknown",
			KeyScope:    keyScope,
		},
		minconf, blockStamp,
	)
	require.ErrorIs(t, err, ErrAccountNotFound)
}

// TestGetEligibleUTXOs serves as a comprehensive test suite for the
// getEligibleUTXOs method, which acts as a dispatcher based on the provided
// CoinSource type. This test ensures that the method correctly delegates to the
// appropriate sub-handler for each source type (scoped account, UTXO list, or
// nil for default) and that it properly returns an error for unsupported
// source types.
func TestGetEligibleUTXOs(t *testing.T) {
	t.Parallel()

	minconf := uint32(1)
	utxo := wire.OutPoint{}
	credit := &wtxmgr.Credit{}
	scopedAccount := &ScopedAccount{
		AccountName: "default",
		KeyScope:    waddrmgr.KeyScopeBIP0086,
	}

	testCases := []struct {
		name        string
		source      CoinSource
		setupMocks  func(m *mockers, source CoinSource)
		expectedErr error
	}{
		{
			name:   "scoped account",
			source: scopedAccount,
			setupMocks: func(
				m *mockers, source CoinSource,
			) {
				scopedSrc := source.(*ScopedAccount)
				accountStore := &mockAccountStore{}

				m.addrStore.On("FetchScopedKeyManager",
					scopedSrc.KeyScope,
				).Return(accountStore, nil)

				accountStore.On("LookupAccount",
					mock.Anything, scopedSrc.AccountName,
				).Return(uint32(0), nil)

				m.txStore.On("UnspentOutputs",
					mock.Anything,
				).Return([]wtxmgr.Credit{}, nil)
			},
		},
		{
			name: "utxo source",
			source: &CoinSourceUTXOs{
				UTXOs: []wire.OutPoint{utxo},
			},
			setupMocks: func(m *mockers, source CoinSource) {
				m.txStore.On("GetUtxo", mock.Anything, utxo).
					Return(credit, nil)
			},
		},
		{
			name:   "nil source",
			source: nil,
			setupMocks: func(m *mockers, source CoinSource) {
				m.txStore.On("UnspentOutputs",
					mock.Anything,
				).Return([]wtxmgr.Credit{}, nil)
			},
		},
		{
			name:        "unsupported source",
			source:      &unsupportedCoinSource{},
			setupMocks:  func(m *mockers, source CoinSource) {},
			expectedErr: ErrUnsupportedCoinSource,
		},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			w, mocks := testWalletWithMocks(t)
			tc.setupMocks(mocks, tc.source)

			_, err := w.getEligibleUTXOs(
				&mockReadTx{}, tc.source, minconf,
			)

			require.ErrorIs(t, err, tc.expectedErr)
		})
	}
}
