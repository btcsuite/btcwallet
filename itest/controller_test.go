//go:build itest

package itest

import (
	"context"
	"math"

	"github.com/btcsuite/btcd/btcutil/v2"
	"github.com/btcsuite/btcwallet/bwtest"
	"github.com/btcsuite/btcwallet/bwtest/wait"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/btcsuite/btcwallet/wallet"
	"github.com/stretchr/testify/require"
)

// testControllerUnlockLock verifies unlock/lock behavior: a failed unlock
// leaves the wallet locked, and Lock is idempotent after an explicit lock.
func testControllerUnlockLock(h *bwtest.HarnessTest) {
	const wrongPassphrase = "wrong-private-passphrase"

	w, _ := h.NewWallet(bwtest.WalletFixture{})

	// A freshly started wallet is locked.
	requireLocked(h, w, true)

	err := w.Unlock(h.Context(), wallet.UnlockRequest{
		Passphrase: []byte(bwtest.TestWalletPrivatePassphrase),
		Timeout:    -1,
	})
	require.NoError(h, err, "failed to unlock wallet")
	requireLocked(h, w, false)

	// Lock the wallet so the next Unlock validates the passphrase.
	require.NoError(
		h, w.Lock(h.Context()), "failed to lock wallet before wrong passphrase",
	)
	requireLocked(h, w, true)

	// A wrong passphrase leaves the wallet locked after validation fails.
	err = w.Unlock(h.Context(), wallet.UnlockRequest{
		Passphrase: []byte(wrongPassphrase),
		Timeout:    -1,
	})
	require.ErrorIs(
		h, err, wallet.ErrInvalidPassphrase,
		"wrong passphrase did not return invalid-passphrase error",
	)
	requireLocked(h, w, true)

	// Restore the unlocked state so the explicit Lock transition is
	// unambiguous.
	err = w.Unlock(h.Context(), wallet.UnlockRequest{
		Passphrase: []byte(bwtest.TestWalletPrivatePassphrase),
		Timeout:    -1,
	})
	require.NoError(h, err, "failed to unlock wallet after failed unlock")
	requireLocked(h, w, false)

	// Lock transitions the wallet to locked state; a second Lock is a no-op.
	require.NoError(h, w.Lock(h.Context()), "failed to lock wallet")
	requireLocked(h, w, true)
	require.NoError(h, w.Lock(h.Context()), "second lock should be a no-op")
	requireLocked(h, w, true)
}

// testControllerInfo verifies the Info snapshot reports the configured backend
// and chain params, and tracks synchronization as a block is mined.
func testControllerInfo(h *bwtest.HarnessTest) {
	w, _ := h.NewWallet(bwtest.WalletFixture{})
	h.AssertWalletSynced(w)

	// Capture the baseline at the current chain tip so the next block measures
	// only post-start mining, not startup catch-up.
	before, err := w.Info(h.Context())
	require.NoError(h, err, "failed to query wallet info")
	require.Equal(
		h, h.ChainClient.BackEnd(), before.Backend, "info backend mismatch",
	)
	require.Equal(
		h, h.NetParams(), before.ChainParams, "info chain params mismatch",
	)
	require.True(h, before.Locked, "freshly started wallet should be locked")

	// Mining advances the synced height.
	h.MineBlocks(1)

	after, err := w.Info(h.Context())
	require.NoError(h, err, "failed to query wallet info after mining")
	require.True(h, after.Synced, "wallet should be synced after mining")
	require.Greater(
		h, after.SyncedTo.Height, before.SyncedTo.Height,
		"synced height did not advance after mining",
	)
}

// testControllerResyncHistory verifies Resync rescans history from the
// requested height, recovering a payment the Wallet missed, and that the
// recovered records survive a reload.
func testControllerResyncHistory(h *bwtest.HarnessTest) {
	w, _ := h.NewWallet(bwtest.WalletFixture{WatchOnly: true})
	_, funding := h.FundUnimportedAccount(w, oneBTC)
	payment := funding.WalletOutpoints[0]

	err := w.Resync(h.Context(), uint32(funding.BlockHeight-1))
	require.NoError(h, err)

	// Resync returns once the request is accepted, so wait for the scan to
	// recover the payment.
	err = wait.NoError(func() error {
		_, err := w.GetTx(h.Context(), payment.Hash)

		return err
	}, pollTimeout)
	require.NoError(h, err, "resync did not recover the payment")
	h.AssertWalletSynced(w)

	detail, err := w.GetTx(h.Context(), payment.Hash)
	require.NoError(h, err)
	require.Equal(h, funding.BlockHeight, detail.Block.Height)
	require.Equal(h, funding.Block.BlockHash(), detail.Block.Hash)
	utxo, err := w.GetUtxo(h.Context(), payment)
	require.NoError(h, err)
	require.Equal(h, btcutil.Amount(oneBTC), utxo.Amount)

	w = h.ReloadWallet(w)
	h.AssertWalletSynced(w)

	reloadedDetail, err := w.GetTx(h.Context(), payment.Hash)
	require.NoError(h, err)
	require.Equal(h, detail, reloadedDetail)
	reloadedUtxo, err := w.GetUtxo(h.Context(), payment)
	require.NoError(h, err)
	require.Equal(h, utxo, reloadedUtxo)
}

// testControllerRescanHistory verifies a targeted Rescan recovers a payment the
// Wallet missed without moving its live tip, keeps running after the caller
// cancels, and that the recovered records survive a reload.
func testControllerRescanHistory(h *bwtest.HarnessTest) {
	w, _ := h.NewWallet(bwtest.WalletFixture{WatchOnly: true})
	target, funding := h.FundUnimportedAccount(w, oneBTC)
	payment := funding.WalletOutpoints[0]
	before, err := w.Info(h.Context())
	require.NoError(h, err)

	ctx, cancel := context.WithCancel(h.Context())
	err = w.Rescan(
		ctx, uint32(funding.BlockHeight-1), []waddrmgr.AccountScope{target},
	)
	require.NoError(h, err)

	// The Wallet owns an accepted scan, so canceling the caller must not
	// stop the recovery.
	cancel()

	err = wait.NoError(func() error {
		_, err := w.GetTx(h.Context(), payment.Hash)

		return err
	}, pollTimeout)
	require.NoError(h, err, "rescan did not recover the payment")

	// The payment commits before the scan restores live readiness, so join
	// that boundary before checking the tip the scan must not move.
	h.AssertWalletSynced(w)

	after, err := w.Info(h.Context())
	require.NoError(h, err)
	require.Equal(h, before.SyncedTo, after.SyncedTo)

	detail, err := w.GetTx(h.Context(), payment.Hash)
	require.NoError(h, err)
	require.Equal(h, funding.BlockHeight, detail.Block.Height)
	require.Equal(h, funding.Block.BlockHash(), detail.Block.Hash)
	utxo, err := w.GetUtxo(h.Context(), payment)
	require.NoError(h, err)
	require.Equal(h, btcutil.Amount(oneBTC), utxo.Amount)

	w = h.ReloadWallet(w)
	h.AssertWalletSynced(w)

	reloadedDetail, err := w.GetTx(h.Context(), payment.Hash)
	require.NoError(h, err)
	require.Equal(h, detail, reloadedDetail)
	reloadedUtxo, err := w.GetUtxo(h.Context(), payment)
	require.NoError(h, err)
	require.Equal(h, utxo, reloadedUtxo)
}

// testControllerRescanTip verifies a Rescan starting at the current tip still
// scans that block, since the start height is inclusive.
func testControllerRescanTip(h *bwtest.HarnessTest) {
	w, _ := h.NewWallet(bwtest.WalletFixture{WatchOnly: true})
	target, funding := h.FundUnimportedAccount(w, oneBTC)
	payment := funding.WalletOutpoints[0]

	err := w.Rescan(
		h.Context(), uint32(funding.BlockHeight),
		[]waddrmgr.AccountScope{target},
	)
	require.NoError(h, err)

	err = wait.NoError(func() error {
		_, err := w.GetTx(h.Context(), payment.Hash)

		return err
	}, pollTimeout)
	require.NoError(h, err, "rescan did not recover the payment")
}

// testControllerResyncBounds verifies Resync rejects start heights above the
// tip or outside the block height range, and an already canceled caller,
// without changing Wallet state. The current tip is accepted as a no-op.
func testControllerResyncBounds(h *bwtest.HarnessTest) {
	w, _ := h.NewWallet(bwtest.WalletFixture{WatchOnly: true})
	_, funding := h.FundUnimportedAccount(w, oneBTC)
	payment := funding.WalletOutpoints[0]
	before, err := w.Info(h.Context())
	require.NoError(h, err)

	tip := uint32(funding.BlockHeight)
	tests := []struct {
		name        string
		startHeight uint32
		wantErr     error
	}{
		{"above tip", tip + 1, wallet.ErrStartHeightTooHigh},
		{"max int32", math.MaxInt32, wallet.ErrStartHeightTooHigh},
		{"int32+1", math.MaxInt32 + 1, wallet.ErrStartHeightTooLarge},
		{"max uint32", math.MaxUint32, wallet.ErrStartHeightTooLarge},
		{"current tip", tip, nil},
	}

	for _, tc := range tests {
		err := w.Resync(h.Context(), tc.startHeight)
		require.ErrorIs(h, err, tc.wantErr, tc.name)
	}

	// A valid height shows the cancellation alone rejects the request.
	ctx, cancel := context.WithCancel(h.Context())
	cancel()

	err = w.Resync(ctx, tip-1)
	require.ErrorIs(h, err, context.Canceled)

	after, err := w.Info(h.Context())
	require.NoError(h, err)
	require.Equal(h, before, after)
	_, err = w.GetTx(h.Context(), payment.Hash)
	require.ErrorIs(h, err, wallet.ErrTxNotFound)
}

// testControllerRescanBounds verifies Rescan rejects invalid start heights,
// missing targets, and an already canceled caller without starting a scan or
// changing Wallet state.
func testControllerRescanBounds(h *bwtest.HarnessTest) {
	w, _ := h.NewWallet(bwtest.WalletFixture{WatchOnly: true})
	target, funding := h.FundUnimportedAccount(w, oneBTC)
	payment := funding.WalletOutpoints[0]
	before, err := w.Info(h.Context())
	require.NoError(h, err)

	tip := uint32(funding.BlockHeight)
	targets := []waddrmgr.AccountScope{target}
	tests := []struct {
		name        string
		startHeight uint32
		targets     []waddrmgr.AccountScope
		wantErr     error
	}{
		{"above tip", tip + 1, targets, wallet.ErrStartHeightTooHigh},
		{"max int32", math.MaxInt32, targets, wallet.ErrStartHeightTooHigh},
		{"int32+1", math.MaxInt32 + 1, targets, wallet.ErrStartHeightTooLarge},
		{"max uint32", math.MaxUint32, targets, wallet.ErrStartHeightTooLarge},
		{"nil", tip, nil, wallet.ErrNoScanTargets},
		{"empty", tip, []waddrmgr.AccountScope{}, wallet.ErrNoScanTargets},
	}

	for _, tc := range tests {
		err := w.Rescan(h.Context(), tc.startHeight, tc.targets)
		require.ErrorIs(h, err, tc.wantErr, tc.name)
	}

	// A valid request shows the cancellation alone rejects it.
	ctx, cancel := context.WithCancel(h.Context())
	cancel()

	err = w.Rescan(ctx, tip, targets)
	require.ErrorIs(h, err, context.Canceled)

	after, err := w.Info(h.Context())
	require.NoError(h, err)
	require.Equal(h, before, after)
	_, err = w.GetTx(h.Context(), payment.Hash)
	require.ErrorIs(h, err, wallet.ErrTxNotFound)
}

// requireLocked asserts the wallet's Info reports the expected locked state.
func requireLocked(h *bwtest.HarnessTest, w *wallet.Wallet, locked bool) {
	h.Helper()

	info, err := w.Info(h.Context())
	require.NoError(h, err, "failed to query wallet info")
	require.Equal(h, locked, info.Locked, "unexpected locked state")
}
