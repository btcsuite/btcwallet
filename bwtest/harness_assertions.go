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
