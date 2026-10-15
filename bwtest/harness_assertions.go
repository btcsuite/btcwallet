package bwtest

import (
	"errors"
	"fmt"
	"time"

	"github.com/btcsuite/btcwallet/bwtest/wait"
	"github.com/btcsuite/btcwallet/wallet"
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

// ReceiveTxEvent returns the next event sub delivers. It fails the test if the
// subscription ends or delivers nothing within the default timeout.
func (h *HarnessTest) ReceiveTxEvent(
	sub *wallet.TxSubscription) *wallet.TxDetail {

	h.Helper()

	select {
	case detail, ok := <-sub.Events():
		if !ok {
			h.Fatalf("transaction subscription ended: %v", sub.Err())
		}

		return detail

	case <-time.After(defaultTestTimeout):
		h.Fatalf("no transaction event within %v", defaultTestTimeout)

		return nil
	}
}
