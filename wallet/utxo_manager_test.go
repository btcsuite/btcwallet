// Copyright (c) 2025 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wallet

import (
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/btcsuite/btcwallet/wtxmgr"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// TestListUnspent tests the ListUnspent method with various filters.
func TestListUnspent(t *testing.T) {
	t.Parallel()

	// Create a new test wallet with mocks.
	w, mocks := testWalletWithMocks(t)

	// Define account names.
	account1 := "default"
	account2 := "test"

	// Create the addresses that our mocks will return.
	privKeyDefault, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	addrDefault, err := btcutil.NewAddressPubKey(
		privKeyDefault.PubKey().SerializeCompressed(), &chainParams,
	)
	require.NoError(t, err)

	privKeyTest, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	addrTest, err := btcutil.NewAddressPubKey(
		privKeyTest.PubKey().SerializeCompressed(), &chainParams,
	)
	require.NoError(t, err)

	// Set the current block height to be 100.
	currentHeight := int32(100)
	mocks.addrStore.On("SyncedTo").Return(waddrmgr.BlockStamp{
		Height: currentHeight,
	})

	mocks.addrStore.On("AddressDetails", mock.Anything, addrDefault).Return(
		false, account1, waddrmgr.WitnessPubKey,
	)
	mocks.addrStore.On("AddressDetails", mock.Anything, addrTest).Return(
		false, account2, waddrmgr.NestedWitnessPubKey,
	)

	// Now that the mocks are set up, we can create the pkScripts.
	pkScriptDefault, err := txscript.PayToAddrScript(addrDefault)
	require.NoError(t, err)
	pkScriptTest, err := txscript.PayToAddrScript(addrTest)
	require.NoError(t, err)

	const (
		minConf = 2
		maxConf = 6
	)

	// Create two UTXOs, one for each address.
	utxo1 := wtxmgr.Credit{
		OutPoint: wire.OutPoint{
			Hash:  [32]byte{1},
			Index: 0,
		},
		Amount:   100000,
		PkScript: pkScriptDefault,
		BlockMeta: wtxmgr.BlockMeta{
			Block: wtxmgr.Block{
				Height: currentHeight - minConf,
			},
		},
	}
	utxo2 := wtxmgr.Credit{
		OutPoint: wire.OutPoint{
			Hash:  [32]byte{2},
			Index: 0,
		},
		Amount:   200000,
		PkScript: pkScriptTest,
		BlockMeta: wtxmgr.BlockMeta{
			Block: wtxmgr.Block{
				Height: currentHeight - maxConf,
			},
		},
	}

	// Mock the UnspentOutputs method to return the two UTXOs.
	mocks.txStore.On("UnspentOutputs", mock.Anything).Return(
		[]wtxmgr.Credit{utxo1, utxo2}, nil,
	)

	testCases := []struct {
		name          string
		query         UtxoQuery
		expectedCount int
		expectedAddrs map[string]bool
	}{
		{
			name:          "no filter",
			query:         UtxoQuery{MinConfs: 0, MaxConfs: 999999},
			expectedCount: 2,
			expectedAddrs: map[string]bool{
				addrDefault.String(): true,
				addrTest.String():    true,
			},
		},
		{
			name: "filter by default account",
			query: UtxoQuery{
				Account:  account1,
				MinConfs: 0,
				MaxConfs: 999999,
			},
			expectedCount: 1,
			expectedAddrs: map[string]bool{
				addrDefault.String(): true,
			},
		},
		{
			name: "filter by test account",
			query: UtxoQuery{
				Account:  account2,
				MinConfs: 0,
				MaxConfs: 999999,
			},
			expectedCount: 1,
			expectedAddrs: map[string]bool{
				addrTest.String(): true,
			},
		},
		{
			name: "filter by min confs",
			query: UtxoQuery{
				MinConfs: minConf + 1,
				MaxConfs: 999999,
			},
			expectedCount: 1,
			expectedAddrs: map[string]bool{
				addrTest.String(): true,
			},
		},
		{
			name: "filter by max confs",
			query: UtxoQuery{
				MinConfs: 0,
				MaxConfs: maxConf - 1,
			},
			expectedCount: 1,
			expectedAddrs: map[string]bool{
				addrDefault.String(): true,
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			utxos, err := w.ListUnspent(t.Context(), tc.query)
			require.NoError(t, err)
			require.Len(t, utxos, tc.expectedCount)

			// Check that the correct addresses are returned. We do
			// this by creating a map of the returned addresses and
			// comparing it to the expected map. This ensures that
			// all expected addresses are present and there are no
			// duplicates.
			returnedAddrs := make(map[string]bool)
			for _, utxo := range utxos {
				returnedAddrs[utxo.Address.String()] = true
			}

			require.Equal(t, tc.expectedAddrs, returnedAddrs)

			// Check that the UTXOs are sorted by amount in
			// ascending order.
			for i := range len(utxos) - 1 {
				require.LessOrEqual(
					t, utxos[i].Amount, utxos[i+1].Amount,
				)
			}
		})
	}
}

