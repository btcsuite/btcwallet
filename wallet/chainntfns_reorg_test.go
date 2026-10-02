package wallet

import (
	"fmt"
	"testing"
	"time"

	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcwallet/walletdb"
	"github.com/btcsuite/btcwallet/wtxmgr"
	"github.com/stretchr/testify/require"
)

// reorgRecord creates a synthetic transaction for notification-handler tests.
func reorgRecord(t *testing.T, n byte) *wtxmgr.TxRecord {
	t.Helper()

	msg := wire.NewMsgTx(2)
	msg.AddTxIn(wire.NewTxIn(
		&wire.OutPoint{Hash: chainhash.Hash{n}}, nil, nil,
	))
	msg.AddTxOut(wire.NewTxOut(1000, []byte{0x51}))

	rec, err := wtxmgr.NewTxRecordFromMsgTx(msg, time.Unix(1, 0))
	require.NoError(t, err)

	return rec
}

// TestDisconnectBlockDuringSync verifies disconnects remove matching history
// with a matching, lagging, or already replaced address-manager tip.
func TestDisconnectBlockDuringSync(t *testing.T) {
	t.Parallel()

	for _, synced := range []bool{false, true} {
		for _, tip := range []struct {
			name       string
			height     int32
			hash       chainhash.Hash
			wantHeight int32
			wantHash   chainhash.Hash
		}{
			{"behind", 0, *chaincfg.TestNet3Params.GenesisHash,
				0, *chaincfg.TestNet3Params.GenesisHash},
			{"matching", 1, chainhash.Hash{1},
				0, *chaincfg.TestNet3Params.GenesisHash},
			{"replacement", 1, chainhash.Hash{2},
				1, chainhash.Hash{2}},
		} {
			t.Run(fmt.Sprintf("synced=%v/tip=%s", synced, tip.name),
				func(t *testing.T) {
					t.Parallel()

					w, cleanup := testWalletWatchingOnly(t)
					t.Cleanup(cleanup)
					t.Cleanup(func() {
						require.NoError(t, w.db.Close())
					})
					w.SetChainSynced(synced)
					w.chainClient = &mockChainClient{
						getBlockHeader: &wire.BlockHeader{
							Timestamp: time.Unix(1, 0),
						},
					}

					old := &wtxmgr.BlockMeta{
						Block: wtxmgr.Block{
							Height: 1,
							Hash:   chainhash.Hash{1},
						},
						Time: time.Unix(1, 0),
					}
					replacement := *old
					replacement.Hash = chainhash.Hash{2}
					a, b := reorgRecord(t, 3), reorgRecord(t, 4)

					err := walletdb.Update(w.db,
						func(tx walletdb.ReadWriteTx) error {
							require.NoError(t, w.addRelevantTx(tx, a, old))

							return w.connectBlock(tx, wtxmgr.BlockMeta{
								Block: wtxmgr.Block{
									Height: tip.height,
									Hash:   tip.hash,
								},
								Time: time.Unix(1, 0),
							})
						})
					require.NoError(t, err)

					err = walletdb.Update(w.db,
						func(tx walletdb.ReadWriteTx) error {
							return w.disconnectBlock(tx, *old)
						})
					require.NoError(t, err)

					require.Equal(
						t, tip.wantHeight, w.Manager.SyncedTo().Height,
					)
					require.Equal(t, tip.wantHash, w.Manager.SyncedTo().Hash)

					err = walletdb.Update(w.db,
						func(tx walletdb.ReadWriteTx) error {
							return w.addRelevantTx(tx, b, &replacement)
						})
					require.NoError(t, err)

					// A replayed disconnect must not remove the replacement.
					err = walletdb.Update(w.db,
						func(tx walletdb.ReadWriteTx) error {
							return w.disconnectBlock(tx, *old)
						})
					require.NoError(t, err)

					// A delayed connection from the other notification
					// producer can leave the manager on the old block.
					err = walletdb.Update(w.db,
						func(tx walletdb.ReadWriteTx) error {
							return w.connectBlock(tx, *old)
						})
					require.NoError(t, err)

					before := w.Manager.SyncedTo()
					err = walletdb.Update(w.db,
						func(tx walletdb.ReadWriteTx) error {
							return w.disconnectBlock(tx, *old)
						})
					require.NoError(t, err)
					require.Equal(t, before, w.Manager.SyncedTo())

					for _, account := range []string{"", "default"} {
						result, err := w.GetTransactions(nil, nil, account, nil)
						require.NoError(t, err)
						require.Len(t, result.MinedTransactions, 1)
						require.Len(t, result.UnminedTransactions, 1)
					}

					oldTx, err := w.GetTransaction(a.Hash)
					require.NoError(t, err)
					require.EqualValues(t, -1, oldTx.Height)
					require.Nil(t, oldTx.BlockHash)

					newTx, err := w.GetTransaction(b.Hash)
					require.NoError(t, err)
					require.Equal(t, replacement.Height, newTx.Height)
					require.Equal(t, &replacement.Hash, newTx.BlockHash)
				})
		}
	}
}

// TestDisconnectEmptyBlock verifies a known block with no wallet transactions
// still rolls back descendant transactions and their credits while syncing.
func TestDisconnectEmptyBlock(t *testing.T) {
	t.Parallel()

	w, cleanup := testWalletWatchingOnly(t)
	t.Cleanup(cleanup)
	t.Cleanup(func() { require.NoError(t, w.db.Close()) })

	w.SetChainSynced(false)
	w.chainClient = &mockChainClient{
		getBlockHeader: &wire.BlockHeader{Timestamp: time.Unix(1, 0)},
	}
	block := wtxmgr.BlockMeta{
		Block: wtxmgr.Block{Height: 1, Hash: chainhash.Hash{1}},
		Time:  time.Unix(1, 0),
	}
	descendant := block
	descendant.Height++
	descendant.Hash = chainhash.Hash{2}
	rec := reorgRecord(t, 3)

	err := walletdb.Update(w.db, func(tx walletdb.ReadWriteTx) error {
		require.NoError(t, w.connectBlock(tx, block))
		require.NoError(t, w.addRelevantTx(tx, rec, &descendant))

		return w.TxStore.AddCredit(
			tx.ReadWriteBucket(wtxmgrNamespaceKey), rec, &descendant,
			0, false,
		)
	})
	require.NoError(t, err)

	err = walletdb.Update(w.db, func(tx walletdb.ReadWriteTx) error {
		return w.disconnectBlock(tx, block)
	})
	require.NoError(t, err)

	err = walletdb.View(w.db, func(tx walletdb.ReadTx) error {
		ns := tx.ReadBucket(wtxmgrNamespaceKey)
		details, err := w.TxStore.TxDetails(ns, &rec.Hash)
		require.NoError(t, err)
		require.NotNil(t, details)
		require.EqualValues(t, -1, details.Block.Height)
		require.Len(t, details.Credits, 1)
		require.EqualValues(t, 1000, details.Credits[0].Amount)

		confirmed, err := w.TxStore.Balance(ns, 1, 2)
		require.NoError(t, err)
		require.Zero(t, confirmed)

		balance, err := w.TxStore.Balance(ns, 0, 2)
		require.NoError(t, err)
		require.EqualValues(t, 1000, balance)

		return nil
	})
	require.NoError(t, err)
}
