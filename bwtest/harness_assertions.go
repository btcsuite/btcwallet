package bwtest

import (
	"errors"
	"fmt"

	"github.com/btcsuite/btcwallet/bwtest/wait"
	"github.com/btcsuite/btcwallet/wallet"
)

var (
	// ErrWalletNotSynced is returned when a wallet has not reached the chain
	// tip.
	ErrWalletNotSynced = errors.New("wallet not synced")
)

// AssertWalletSynced polls until the wallet reports it is synced to the
// miner's best known height.
func (h *HarnessTest) AssertWalletSynced(w *wallet.Wallet) {
	h.Helper()

	if w == nil {
		h.Fatalf("nil wallet")
	}

	err := wait.NoError(func() error {
		syncedTo := w.SyncedTo()

		_, bestHeight, err := h.miner.Client.GetBestBlock()
		if err != nil {
			return fmt.Errorf("get best block: %w", err)
		}

		if syncedTo.Height != bestHeight {
			return fmt.Errorf("%w: wallet=%d chain=%d", ErrWalletNotSynced,
				syncedTo.Height, bestHeight)
		}

		return nil
	}, defaultTestTimeout)
	if err != nil {
		h.Fatalf("wallet sync timeout: %v", err)
	}
}
