//go:build itest

package itest

import (
	"bytes"

	"github.com/btcsuite/btcd/btcutil/v2"
	"github.com/btcsuite/btcwallet/bwtest"
	"github.com/btcsuite/btcwallet/wallet"
	"github.com/stretchr/testify/require"
)

// testWalletSyncRollback verifies that the public tip, transaction and UTXO
// views agree after a real shallow reorg, reconfirmation and Manager reload.
// Each stable state is read once after the exact synchronization boundary;
// retrying a wallet read here would conceal incomplete rollback publication.
func testWalletSyncRollback(h *bwtest.HarnessTest) {
	// Arrange: isolate a second miner before the payment exists, so its
	// winning branch cannot accidentally confirm the payment being detached.
	w, _ := h.NewWallet(bwtest.WalletFixture{})
	h.AssertWalletSynced(w)
	_, forkHeight := h.GetBestBlock()
	competitor := h.SpawnTempMiner()

	funding := h.FundWallet(w, oneBTC)
	require.Len(h, funding.WalletOutpoints, 1)
	outpoint := funding.WalletOutpoints[0]
	txid := funding.Tx.TxHash()
	losingHash := funding.Block.BlockHash()
	require.Equal(h, forkHeight+1, funding.BlockHeight)

	var rawTx bytes.Buffer
	require.NoError(h, funding.Tx.Serialize(&rawTx))

	allCoins := wallet.UtxoQuery{MaxConfs: maxConfsLimit}
	confirmedCoins := wallet.UtxoQuery{MinConfs: 1, MaxConfs: maxConfsLimit}

	// The funding helper has crossed the Wallet boundary. Establish a
	// non-empty baseline tied to the actual payment, rather than comparing
	// snapshots that could all agree while omitting it.
	info, err := w.Info(h.Context())
	require.NoError(h, err)
	require.True(h, info.Synced)
	require.Equal(h, losingHash, info.SyncedTo.Hash)
	require.Equal(h, funding.BlockHeight, info.SyncedTo.Height)

	mined, err := w.GetTx(h.Context(), txid)
	require.NoError(h, err)
	require.Equal(h, txid, mined.Hash)
	require.Equal(h, rawTx.Bytes(), mined.RawTx)
	require.Equal(h, btcutil.Amount(oneBTC), mined.Value)
	require.Equal(h, wallet.TxStatusPublished, mined.Status)
	require.Equal(h, &wallet.BlockDetails{
		Hash:      losingHash,
		Height:    funding.BlockHeight,
		Timestamp: funding.Block.Header.Timestamp.Unix(),
	}, mined.Block)
	require.Equal(h, int32(1), mined.Confirmations)

	history, err := w.ListTxns(h.Context(), 0, unminedHeight)
	require.NoError(h, err)
	require.Equal(h, []*wallet.TxDetail{mined}, history)

	coin, err := w.GetUtxo(h.Context(), outpoint)
	require.NoError(h, err)
	require.Equal(h, outpoint, coin.OutPoint)
	require.Equal(h, btcutil.Amount(oneBTC), coin.Amount)
	require.Equal(h, funding.Tx.TxOut[outpoint.Index].PkScript, coin.PkScript)
	require.Equal(h, int32(1), coin.Confirmations)

	coins, err := w.ListUnspent(h.Context(), allCoins)
	require.NoError(h, err)
	require.Equal(h, []*wallet.Utxo{coin}, coins)

	confirmed, err := w.ListUnspent(h.Context(), confirmedCoins)
	require.NoError(h, err)
	require.Equal(h, coins, confirmed)

	// Act: two empty blocks beat the one-block payment branch. Wait for the
	// miner's known winning hash before asking the Wallet to catch up;
	// otherwise synchronization could still succeed at the losing tip.
	winningBlocks := competitor.MineEmptyBlocks(2)
	winningTip := winningBlocks[len(winningBlocks)-1].BlockHash()

	h.ConnectToMiner(competitor)
	h.WaitForMinerTip(winningTip, forkHeight+2)
	h.AssertWalletSynced(w)

	// Assert: rollback detaches an ordinary payment without invalidating it.
	// Its output remains unconfirmed, but must disappear from confirmed-only
	// queries. No mempool delivery to the Wallet is required, including SPV.
	info, err = w.Info(h.Context())
	require.NoError(h, err)
	require.True(h, info.Synced)
	require.Equal(h, winningTip, info.SyncedTo.Hash)
	require.Equal(h, forkHeight+2, info.SyncedTo.Height)

	unmined, err := w.GetTx(h.Context(), txid)
	require.NoError(h, err)
	require.Equal(h, wallet.TxStatusPublished, unmined.Status)
	require.Nil(h, unmined.Block)
	require.Zero(h, unmined.Confirmations)

	wantUnmined := *mined
	wantUnmined.Block = nil
	wantUnmined.Confirmations = 0
	require.Equal(h, &wantUnmined, unmined)

	history, err = w.ListTxns(h.Context(), 0, unminedHeight)
	require.NoError(h, err)
	require.Equal(h, []*wallet.TxDetail{unmined}, history)

	unconfirmedCoin, err := w.GetUtxo(h.Context(), outpoint)
	require.NoError(h, err)

	wantUnconfirmedCoin := *coin
	wantUnconfirmedCoin.Confirmations = 0
	require.Equal(h, &wantUnconfirmedCoin, unconfirmedCoin)

	coins, err = w.ListUnspent(h.Context(), allCoins)
	require.NoError(h, err)
	require.Equal(h, []*wallet.Utxo{unconfirmedCoin}, coins)

	confirmed, err = w.ListUnspent(h.Context(), confirmedCoins)
	require.NoError(h, err)
	require.Empty(h, confirmed)

	// Act: extend the winning branch with the same payment. The miner's
	// mempool wait is an external event; MineBlockWithTx then supplies the
	// exact Wallet synchronization boundary and empties the miner mempool.
	newBlock := h.MineBlockWithTx(funding.Tx)
	newHash := newBlock.BlockHash()

	// Assert: the new block, never the losing block at the same transaction
	// hash, owns confirmation. Transaction receipt times can be refreshed on
	// confirmation by kvdb, so only that transition allows a changed time.
	require.NotEqual(h, losingHash, newHash)
	require.Equal(h, winningTip, newBlock.Header.PrevBlock)
	info, err = w.Info(h.Context())
	require.NoError(h, err)
	require.True(h, info.Synced)
	require.Equal(h, newHash, info.SyncedTo.Hash)
	require.Equal(h, forkHeight+3, info.SyncedTo.Height)

	reconfirmed, err := w.GetTx(h.Context(), txid)
	require.NoError(h, err)
	require.Equal(h, &wallet.BlockDetails{
		Hash:      newHash,
		Height:    forkHeight + 3,
		Timestamp: newBlock.Header.Timestamp.Unix(),
	}, reconfirmed.Block)
	require.Equal(h, int32(1), reconfirmed.Confirmations)
	require.False(h, reconfirmed.ReceivedTime.IsZero())

	wantReconfirmed := *mined
	wantReconfirmed.Block = reconfirmed.Block
	wantReconfirmed.ReceivedTime = reconfirmed.ReceivedTime
	require.Equal(h, &wantReconfirmed, reconfirmed)

	history, err = w.ListTxns(h.Context(), 0, unminedHeight)
	require.NoError(h, err)
	require.Equal(h, []*wallet.TxDetail{reconfirmed}, history)

	reconfirmedCoin, err := w.GetUtxo(h.Context(), outpoint)
	require.NoError(h, err)
	require.Equal(h, coin, reconfirmedCoin)

	coins, err = w.ListUnspent(h.Context(), allCoins)
	require.NoError(h, err)
	require.Equal(h, []*wallet.Utxo{reconfirmedCoin}, coins)

	confirmed, err = w.ListUnspent(h.Context(), confirmedCoins)
	require.NoError(h, err)
	require.Equal(h, coins, confirmed)

	// Act: ReloadWallet stops the old Manager and starts a fresh one over
	// the same database. Only the returned Wallet may serve the final reads.
	id := w.ID()
	w = h.ReloadWallet(w)
	h.AssertWalletSynced(w)

	// Assert: every final public view survives the full durable lifecycle,
	// including metadata that was not allowed to change across reload.
	require.Equal(h, id, w.ID())
	reopenedInfo, err := w.Info(h.Context())
	require.NoError(h, err)
	require.True(h, reopenedInfo.Synced)
	require.Equal(h, info.SyncedTo, reopenedInfo.SyncedTo)

	reopenedTx, err := w.GetTx(h.Context(), txid)
	require.NoError(h, err)
	require.Equal(h, reconfirmed, reopenedTx)

	reopenedHistory, err := w.ListTxns(h.Context(), 0, unminedHeight)
	require.NoError(h, err)
	require.Equal(h, history, reopenedHistory)

	reopenedCoin, err := w.GetUtxo(h.Context(), outpoint)
	require.NoError(h, err)
	require.Equal(h, reconfirmedCoin, reopenedCoin)

	reopenedCoins, err := w.ListUnspent(h.Context(), allCoins)
	require.NoError(h, err)
	require.Equal(h, coins, reopenedCoins)

	reopenedConfirmed, err := w.ListUnspent(h.Context(), confirmedCoins)
	require.NoError(h, err)
	require.Equal(h, confirmed, reopenedConfirmed)
}
