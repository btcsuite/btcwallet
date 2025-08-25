package wallet

import (
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/btcsuite/btcd/chaincfg/v2"
	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/btcsuite/btcwallet/waddrmgr"
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
// with a matching, lagging, sparse, or already replaced address-manager tip.
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
			{"sparse", 2, chainhash.Hash{5},
				2, chainhash.Hash{5}},
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
						t, tip.wantHeight, w.addrStore.SyncedTo().Height,
					)
					require.Equal(t, tip.wantHash, w.addrStore.SyncedTo().Hash)

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

					notifications := w.NtfnServer.TransactionNotifications()
					t.Cleanup(notifications.Done)

					err = walletdb.Update(w.db,
						func(tx walletdb.ReadWriteTx) error {
							return w.disconnectBlock(tx, *old)
						})
					require.NoError(t, err)
					require.Equal(t, waddrmgr.BlockStamp{
						Height:    0,
						Hash:      *chaincfg.TestNet3Params.GenesisHash,
						Timestamp: time.Unix(1, 0),
					}, w.addrStore.SyncedTo())
					require.NotNil(t, w.NtfnServer.currentTxNtfn)
					require.Equal(t, []*chainhash.Hash{&old.Hash},
						w.NtfnServer.currentTxNtfn.DetachedBlocks)

					result, err := w.GetTransactions(nil, nil, "", nil)
					require.NoError(t, err)
					require.Len(t, result.MinedTransactions, 1)
					require.Len(t, result.UnminedTransactions, 1)

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

var errReorgBackend = errors.New("reorg backend unavailable")

// reorgChainClient supplies canonical block hashes, including lookup failures.
type reorgChainClient struct {
	*mockChainClient

	blockHashes map[int64]chainhash.Hash
	bestErr     error
}

func (c *reorgChainClient) GetBestBlock() (*chainhash.Hash, int32, error) {
	if c.bestErr != nil {
		return nil, 0, c.bestErr
	}

	return c.mockChainClient.GetBestBlock()
}

func (c *reorgChainClient) GetBlockHash(height int64) (*chainhash.Hash, error) {
	hash, ok := c.blockHashes[height]
	if !ok {
		return nil, fmt.Errorf("block hash at height %d: %w",
			height, errReorgBackend)
	}

	return &hash, nil
}

type mixedHistoryCase struct {
	name    string
	mask    uint8
	tip     int32
	missing int64
	bestErr bool
}

// TestDisconnectMixedHistory covers every canonical/orphan arrangement across
// three stored heights, with and without a record at the disconnected height.
// The all-orphan case also covers disconnects of empty blocks.
func TestDisconnectMixedHistory(t *testing.T) {
	t.Parallel()

	tests := []mixedHistoryCase{
		{"all orphaned", 0, 4, 0, false},
		{"canonical prefix", 1, 4, 0, false},
		{"canonical middle", 2, 4, 0, false},
		{"orphan suffix", 3, 4, 0, false},
		{"orphan prefix", 4, 4, 0, false},
		{"orphan middle", 5, 4, 0, false},
		{"canonical suffix", 6, 4, 0, false},
		{"all canonical", 7, 4, 0, false},
		{"above backend tip", 7, 3, 0, false},
		{"early lookup failure", 7, 4, 2, false},
		{"late lookup failure", 0, 4, 4, false},
		{"best block failure", 0, 4, 0, true},
	}
	for _, stored := range []bool{false, true} {
		for _, test := range tests {
			t.Run(fmt.Sprintf("stored=%v/%s", stored, test.name),
				func(t *testing.T) {
					t.Parallel()

					w, cleanup := testWalletWatchingOnly(t)
					t.Cleanup(cleanup)
					t.Cleanup(func() { require.NoError(t, w.db.Close()) })

					client := &reorgChainClient{
						mockChainClient: &mockChainClient{
							getBestBlockHeight: test.tip,
							getBlockHeader: &wire.BlockHeader{
								Timestamp: time.Unix(1, 0),
							},
						},
						blockHashes: map[int64]chainhash.Hash{1: {9}},
					}
					if test.bestErr {
						client.bestErr = errReorgBackend
					}

					w.chainClient = client

					old := reorgBlock(1)
					replacement := old
					replacement.Hash = chainhash.Hash{9}
					records, heights, wantHeights := mixedHistoryRecords(
						t, stored, test, client,
					)

					delete(client.blockHashes, test.missing)

					wantErr := test.bestErr || test.missing != 0
					if wantErr {
						wantHeights = heights
					}

					require.NoError(t, walletdb.Update(w.db,
						func(tx walletdb.ReadWriteTx) error {
							require.NoError(t, w.connectBlock(tx, replacement))
							// Higher records arrive before the old block.
							for i := len(records) - 1; i >= 0; i-- {
								block := reorgBlock(heights[i])
								addReorgCredit(
									t, w, tx, records[i], &block, i%2 != 0,
								)
							}

							return w.connectBlock(tx, old)
						}))

					err := walletdb.Update(w.db,
						func(tx walletdb.ReadWriteTx) error {
							return w.disconnectBlock(tx, old)
						})
					if wantErr {
						require.ErrorIs(t, err, errReorgBackend)
						require.Equal(t, old.Hash, w.addrStore.SyncedTo().Hash)
					} else {
						require.NoError(t, err)
						require.Zero(t, w.addrStore.SyncedTo().Height)
					}

					assertReorgHistory(t, w, records, wantHeights)

					if !wantErr {
						// A duplicate detach must not change the result.
						require.NoError(t, walletdb.Update(w.db,
							func(tx walletdb.ReadWriteTx) error {
								return w.disconnectBlock(tx, old)
							}))
						assertReorgHistory(t, w, records, wantHeights)
					}
				})
		}
	}
}

func mixedHistoryRecords(t *testing.T, stored bool, test mixedHistoryCase,
	client *reorgChainClient) ([]*wtxmgr.TxRecord, []int32, []int32) {

	t.Helper()

	records := make([]*wtxmgr.TxRecord, 0, 4)
	heights := make([]int32, 0, 4)
	wantHeights := make([]int32, 0, 4)

	if stored {
		records = append(records, reorgRecord(t, 10))
		heights = append(heights, 1)
		wantHeights = append(wantHeights, -1)
	}

	for i := range 3 {
		height := int32(i + 2)
		records = append(records, reorgRecord(t, byte(i+11)))
		heights = append(heights, height)
		want := int32(-1)

		hash := chainhash.Hash{byte(height + 10)}
		if test.mask&(1<<i) != 0 {
			hash = chainhash.Hash{byte(height)}
			if height <= test.tip {
				want = height
			}
		}

		client.blockHashes[int64(height)] = hash

		wantHeights = append(wantHeights, want)
	}

	return records, heights, wantHeights
}

func reorgBlock(height int32) wtxmgr.BlockMeta {
	return wtxmgr.BlockMeta{
		Block: wtxmgr.Block{Height: height, Hash: chainhash.Hash{byte(height)}},
		Time:  time.Unix(int64(height), 0),
	}
}

func addReorgCredit(t *testing.T, w *Wallet, tx walletdb.ReadWriteTx,
	record *wtxmgr.TxRecord, block *wtxmgr.BlockMeta, change bool) {

	t.Helper()
	require.NoError(t, w.addRelevantTx(tx, record, block))
	require.NoError(t, w.TxStore.AddCredit(
		tx.ReadWriteBucket(wtxmgrNamespaceKey), record, block, 0, change,
	))
}

func assertReorgHistory(t *testing.T, w *Wallet,
	records []*wtxmgr.TxRecord, heights []int32) {

	t.Helper()
	require.NoError(t, walletdb.View(w.db, func(tx walletdb.ReadTx) error {
		ns := tx.ReadBucket(wtxmgrNamespaceKey)

		var wantConfirmed int64
		for i, record := range records {
			detail, err := w.TxStore.TxDetails(ns, &record.Hash)
			require.NoError(t, err)
			require.NotNil(t, detail)
			require.Equal(t, heights[i], detail.Block.Height)
			require.Equal(t, record.Received, detail.Received)
			require.Len(t, detail.Credits, 1)
			require.EqualValues(t, 1000, detail.Credits[0].Amount)
			require.Equal(t, i%2 != 0, detail.Credits[0].Change)

			if heights[i] >= 0 {
				block := reorgBlock(heights[i])
				require.Equal(t, block, detail.Block)

				wantConfirmed += 1000
			}
		}

		confirmed, err := w.TxStore.Balance(ns, 1, 4)
		require.NoError(t, err)
		require.EqualValues(t, wantConfirmed, confirmed)

		total, err := w.TxStore.Balance(ns, 0, 4)
		require.NoError(t, err)
		require.EqualValues(t, len(records)*1000, total)

		return nil
	}))
}
