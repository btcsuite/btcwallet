package wallet

import (
	"errors"
	"testing"

	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/btcsuite/btcwallet/wallet/txrules"
	"github.com/stretchr/testify/require"
)

var (
	// errStrategy is used to simulate failures in coin selection
	// strategies within tests.
	errStrategy = errors.New("strategy error")

	// errDB is used to simulate database operation failures within tests.
	errDB = errors.New("db error")
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
				FeeRate: 1000,
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
					AccountName: "default",
				},
				FeeRate: 1000,
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
				FeeRate: 1000,
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
				FeeRate: 1000,
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
				FeeRate: 1000,
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
				FeeRate: 1000,
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
					AccountName: "default",
				},
				FeeRate: 1000,
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
				FeeRate: 1000,
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
				FeeRate: 1000,
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
					AccountName: "default",
				},
				FeeRate: 1000,
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
				FeeRate: 1000,
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
				FeeRate: 1000,
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
					AccountName: "default",
				},
				FeeRate: 1000,
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
				FeeRate: 1000,
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
				FeeRate: 1000,
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
					AccountName: "default",
					KeyScope:    waddrmgr.KeyScopeBIP0086,
				},
				FeeRate: 0,
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
					AccountName: "default",
					KeyScope:    waddrmgr.KeyScopeBIP0086,
				},
				FeeRate: DefaultMaxFeeRate + 1,
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

func (u *unsupportedInputs) isInputs()       {}
func (u *unsupportedInputs) validate() error { return nil }

// unsupportedCoinSource is a mock implementation of the CoinSource interface
// used for testing purposes.
type unsupportedCoinSource struct{}

func (u *unsupportedCoinSource) isCoinSource() {}
