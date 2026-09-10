//go:build itest

package itest

import (
	"github.com/btcsuite/btcwallet/bwtest"
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

// requireLocked asserts the wallet's Info reports the expected locked state.
func requireLocked(h *bwtest.HarnessTest, w *wallet.Wallet, locked bool) {
	h.Helper()

	info, err := w.Info(h.Context())
	require.NoError(h, err, "failed to query wallet info")
	require.Equal(h, locked, info.Locked, "unexpected locked state")
}
