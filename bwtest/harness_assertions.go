package bwtest

import (
	"errors"
	"fmt"
	"time"

	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/btcsuite/btcwallet/bwtest/wait"
	"github.com/btcsuite/btcwallet/wallet"
	"github.com/stretchr/testify/require"
)

var (
	// ErrWalletNotSynced is returned when a wallet has not reached the chain
	// tip.
	ErrWalletNotSynced = errors.New("wallet not synced")
)

// AssertWalletSynced polls until the wallet reports it is synced to the
// miner's exact best block. Once this returns, wallet reads for that block may
// be asserted without another retry.
func (h *HarnessTest) AssertWalletSynced(w *wallet.Wallet) {
	h.Helper()

	if w == nil {
		h.Fatalf("nil wallet")
	}

	err := wait.NoError(func() error {
		info, err := w.Info(h.Context())
		if err != nil {
			return fmt.Errorf("get wallet info: %w", err)
		}

		bestHash, bestHeight, err := h.miner.Client.GetBestBlock()
		if err != nil {
			return fmt.Errorf("get best block: %w", err)
		}

		if !info.Synced || info.SyncedTo.Height != bestHeight ||
			!info.SyncedTo.Hash.IsEqual(bestHash) {

			return fmt.Errorf("%w: synced=%v wallet=%v:%d "+
				"chain=%v:%d", ErrWalletNotSynced, info.Synced,
				info.SyncedTo.Hash, info.SyncedTo.Height, bestHash,
				bestHeight)
		}

		return nil
	}, defaultTestTimeout)
	if err != nil {
		h.Fatalf("wallet sync timeout: %v", err)
	}
}

// ReceiveTxEvent waits for the requested transaction and confirmation
// state. Other observations may repeat or arrive out of order, so one harness
// timeout bounds the whole search rather than restarting for every event.
func (h *HarnessTest) ReceiveTxEvent(events <-chan *wallet.TxEvent,
	txHash chainhash.Hash, confirmed bool) *wallet.TxEvent {

	h.Helper()

	timer := time.NewTimer(defaultTestTimeout)
	defer timer.Stop()

	for {
		select {
		case notification, open := <-events:
			require.True(h, open, "subscription ended")

			// Match only the requested observation; the scenario retains
			// responsibility for checking the returned Wallet payload.
			detail := notification.Detail
			if detail.Hash == txHash && (detail.Block != nil) == confirmed {
				return notification
			}

		case <-timer.C:
			h.Fatalf("transaction subscription did not deliver %v", txHash)

			return nil
		}
	}
}
