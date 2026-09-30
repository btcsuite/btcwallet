package wallet

import (
	"testing"
	"time"

	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/btcsuite/btcwallet/walletdb"
	"github.com/btcsuite/btcwallet/wtxmgr"
	"github.com/stretchr/testify/require"
)

// TestNotifyUnminedTransactionMissingDetails ensures a notification is not
// created when an unmined transaction is missing from the transaction store.
func TestNotifyUnminedTransactionMissingDetails(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		coalescing bool
	}{
		{name: "without mined notification"},
		{name: "with mined notification", coalescing: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			w, cleanup := testWallet(t)
			defer cleanup()

			server := w.NtfnServer
			client := make(chan *TransactionNotifications, 1)
			server.transactions = append(
				server.transactions, client,
			)
			if test.coalescing {
				server.currentTxNtfn =
					&TransactionNotifications{}
			}

			var err error
			require.NotPanics(t, func() {
				notify := func(tx walletdb.ReadTx) error {
					ns := tx.ReadBucket(wtxmgrNamespaceKey)
					server.notifyUnminedTransaction(
						tx, ns, chainhash.Hash{1},
					)

					return nil
				}
				err = walletdb.View(w.db, notify)
			})
			require.NoError(t, err)
			require.Empty(t, client)
		})
	}
}

// TestNotifyMinedTransactionMissingDetails ensures a notification is not
// created when a mined transaction is missing from the transaction store.
func TestNotifyMinedTransactionMissingDetails(t *testing.T) {
	t.Parallel()

	w, cleanup := testWallet(t)
	defer cleanup()

	server := w.NtfnServer
	client := make(chan *TransactionNotifications, 1)
	server.transactions = append(server.transactions, client)

	block := &wtxmgr.BlockMeta{
		Block: wtxmgr.Block{
			Hash:   chainhash.Hash{2},
			Height: 1,
		},
		Time: time.Unix(1, 0),
	}

	var err error
	require.NotPanics(t, func() {
		err = walletdb.View(w.db, func(tx walletdb.ReadTx) error {
			ns := tx.ReadBucket(wtxmgrNamespaceKey)
			server.notifyMinedTransaction(
				tx, ns, chainhash.Hash{1}, block,
			)

			return nil
		})
	})
	require.NoError(t, err)
	require.Empty(t, client)
	require.Nil(t, server.currentTxNtfn)
}
