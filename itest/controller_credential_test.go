//go:build itest

package itest

import (
	"errors"
	"time"

	"github.com/btcsuite/btcwallet/bwtest"
	"github.com/btcsuite/btcwallet/bwtest/wait"
	"github.com/btcsuite/btcwallet/wallet"
	"github.com/stretchr/testify/require"
)

// testControllerChangePassphraseLocked verifies private passphrase rotation
// while locked and durable credential enforcement after reload.
func testControllerChangePassphraseLocked(h *bwtest.HarnessTest) {
	const (
		oldPassphrase = bwtest.TestWalletPrivatePassphrase
		newPassphrase = "controller-new-private-passphrase"
	)

	w, _ := h.NewWallet(bwtest.WalletFixture{})
	requireLocked(h, w, true)

	err := w.ChangePassphrase(h.Context(), wallet.ChangePassphraseRequest{
		ChangePrivate: true,
		PrivateOld:    []byte(oldPassphrase),
		PrivateNew:    []byte(newPassphrase),
	})
	require.NoError(h, err, "failed to change private passphrase")
	requireLocked(h, w, true)

	err = w.Unlock(h.Context(), wallet.UnlockRequest{
		Passphrase: []byte(oldPassphrase),
		Timeout:    -1,
	})
	require.ErrorIs(
		h, err, wallet.ErrInvalidPassphrase,
		"old passphrase should be rejected after change",
	)
	requireLocked(h, w, true)

	// A zero timeout uses the default auto-lock duration; -1 keeps the wallet
	// unlocked until Lock so credential assertions cannot race a timer.
	err = w.Unlock(h.Context(), wallet.UnlockRequest{
		Passphrase: []byte(newPassphrase),
		Timeout:    -1,
	})
	require.NoError(h, err, "new passphrase should unlock wallet")
	requireLocked(h, w, false)

	// ReloadWallet crosses the durable close-and-reopen boundary and returns
	// a fresh started wallet that must require the rotated credential.
	w = h.ReloadWallet(w)
	requireLocked(h, w, true)

	err = w.Unlock(h.Context(), wallet.UnlockRequest{
		Passphrase: []byte(oldPassphrase),
		Timeout:    -1,
	})
	require.ErrorIs(
		h, err, wallet.ErrInvalidPassphrase,
		"old passphrase should stay rejected after reload",
	)
	requireLocked(h, w, true)

	err = w.Unlock(h.Context(), wallet.UnlockRequest{
		Passphrase: []byte(newPassphrase),
		Timeout:    -1,
	})
	require.NoError(h, err, "new passphrase should unlock reloaded wallet")
	requireLocked(h, w, false)
}

// testControllerChangePassphraseUnlocked verifies private passphrase rotation
// while unlocked preserves the public unlocked state.
func testControllerChangePassphraseUnlocked(h *bwtest.HarnessTest) {
	const (
		oldPassphrase = bwtest.TestWalletPrivatePassphrase
		newPassphrase = "controller-unlocked-private-passphrase"
	)

	w, _ := h.NewWallet(bwtest.WalletFixture{Unlocked: true})
	requireLocked(h, w, false)

	err := w.ChangePassphrase(h.Context(), wallet.ChangePassphraseRequest{
		ChangePrivate: true,
		PrivateOld:    []byte(oldPassphrase),
		PrivateNew:    []byte(newPassphrase),
	})
	require.NoError(
		h, err, "failed to change private passphrase while unlocked",
	)
	requireLocked(h, w, false)

	require.NoError(h, w.Lock(h.Context()), "failed to lock wallet")
	requireLocked(h, w, true)

	err = w.Unlock(h.Context(), wallet.UnlockRequest{
		Passphrase: []byte(oldPassphrase),
		Timeout:    -1,
	})
	require.ErrorIs(
		h, err, wallet.ErrInvalidPassphrase,
		"previous passphrase should be rejected after unlocked change",
	)
	requireLocked(h, w, true)

	err = w.Unlock(h.Context(), wallet.UnlockRequest{
		Passphrase: []byte(newPassphrase),
		Timeout:    -1,
	})
	require.NoError(
		h, err, "unlocked change passphrase should unlock wallet",
	)
	requireLocked(h, w, false)
}

// testControllerChangePassphraseLifecycle verifies lifecycle state gates for
// passphrase rotation.
func testControllerChangePassphraseLifecycle(h *bwtest.HarnessTest) {
	const (
		oldPassphrase  = bwtest.TestWalletPrivatePassphrase
		nextPassphrase = "controller-next-private-passphrase"
	)

	w, _ := h.NewWallet(bwtest.WalletFixture{Unstarted: true})

	err := w.ChangePassphrase(h.Context(), wallet.ChangePassphraseRequest{
		ChangePrivate: true,
		PrivateOld:    []byte(oldPassphrase),
		PrivateNew:    []byte(nextPassphrase),
	})
	require.ErrorIs(
		h, err, wallet.ErrStateForbidden,
		"change passphrase before start not rejected",
	)

	require.NoError(h, w.Start(h.Context()), "failed to start wallet")
	requireLocked(h, w, true)

	err = w.Unlock(h.Context(), wallet.UnlockRequest{
		Passphrase: []byte(nextPassphrase),
		Timeout:    -1,
	})
	require.ErrorIs(
		h, err, wallet.ErrInvalidPassphrase,
		"pre-start rejection should not install new passphrase",
	)
	requireLocked(h, w, true)

	err = w.Unlock(h.Context(), wallet.UnlockRequest{
		Passphrase: []byte(oldPassphrase),
		Timeout:    -1,
	})
	require.NoError(
		h, err, "old passphrase should survive pre-start rejection",
	)
	requireLocked(h, w, false)

	require.NoError(h, w.Lock(h.Context()), "failed to lock wallet")
	requireLocked(h, w, true)

	require.NoError(h, w.Stop(h.Context()), "failed to stop wallet")

	err = w.ChangePassphrase(h.Context(), wallet.ChangePassphraseRequest{
		ChangePrivate: true,
		PrivateOld:    []byte(oldPassphrase),
		PrivateNew:    []byte(nextPassphrase),
	})
	require.ErrorIs(
		h, err, wallet.ErrStateForbidden,
		"change passphrase after stop not rejected",
	)

	require.NoError(h, w.Start(h.Context()), "failed to restart wallet")
	requireLocked(h, w, true)

	err = w.Unlock(h.Context(), wallet.UnlockRequest{
		Passphrase: []byte(nextPassphrase),
		Timeout:    -1,
	})
	require.ErrorIs(
		h, err, wallet.ErrInvalidPassphrase,
		"post-stop rejection should not install new passphrase",
	)
	requireLocked(h, w, true)

	err = w.Unlock(h.Context(), wallet.UnlockRequest{
		Passphrase: []byte(oldPassphrase),
		Timeout:    -1,
	})
	require.NoError(
		h, err, "old passphrase should survive post-stop rejection",
	)
	requireLocked(h, w, false)
}

// testControllerChangePassphraseRejectLocked verifies a wrong current
// passphrase is rejected while the Wallet is locked.
func testControllerChangePassphraseRejectLocked(h *bwtest.HarnessTest) {
	const (
		wrongPassphrase = "wrong-private-passphrase"
		nextPassphrase  = "controller-next-private-passphrase"
	)

	w, _ := h.NewWallet(bwtest.WalletFixture{})
	requireLocked(h, w, true)

	err := w.ChangePassphrase(h.Context(), wallet.ChangePassphraseRequest{
		ChangePrivate: true,
		PrivateOld:    []byte(wrongPassphrase),
		PrivateNew:    []byte(nextPassphrase),
	})
	require.ErrorIs(
		h, err, wallet.ErrInvalidPassphrase,
		"wrong current passphrase did not return invalid-passphrase error",
	)
	requireLocked(h, w, true)

	err = w.Unlock(h.Context(), wallet.UnlockRequest{
		Passphrase: []byte(bwtest.TestWalletPrivatePassphrase),
		Timeout:    -1,
	})
	require.NoError(
		h, err, "old passphrase should survive locked rejection",
	)
	requireLocked(h, w, false)
}

// testControllerChangePassphraseRejectEmpty verifies that a missing selection
// and incomplete private passphrase pairs are rejected without changing the
// credential state.
func testControllerChangePassphraseRejectEmpty(h *bwtest.HarnessTest) {
	const (
		oldPassphrase   = bwtest.TestWalletPrivatePassphrase
		wrongPassphrase = "wrong-private-passphrase"
		newPassphrase   = "controller-new-private-passphrase"
	)

	w, _ := h.NewWallet(bwtest.WalletFixture{})
	requireLocked(h, w, true)

	tests := []struct {
		name        string
		req         wallet.ChangePassphraseRequest
		wantContext string
	}{
		{
			name:        "no selection",
			wantContext: "no passphrase selected",
		},
		{
			name: "empty private pair",
			req: wallet.ChangePassphraseRequest{
				ChangePrivate: true,
			},
			wantContext: "private old passphrase",
		},
		{
			name: "private old without new",
			req: wallet.ChangePassphraseRequest{
				ChangePrivate: true,
				PrivateOld:    []byte(wrongPassphrase),
			},
			wantContext: "private new passphrase",
		},
		{
			name: "private new without old",
			req: wallet.ChangePassphraseRequest{
				ChangePrivate: true,
				PrivateNew:    []byte(newPassphrase),
			},
			wantContext: "private old passphrase",
		},
	}

	for _, test := range tests {
		err := w.ChangePassphrase(h.Context(), test.req)
		require.ErrorIs(
			h, err, wallet.ErrEmptyPassphrase,
			"%s should return empty-passphrase error", test.name,
		)
		require.ErrorContains(h, err, test.wantContext)
	}

	requireLocked(h, w, true)

	err := w.Unlock(h.Context(), wallet.UnlockRequest{
		Passphrase: []byte(oldPassphrase),
		Timeout:    -1,
	})
	require.NoError(
		h, err, "old passphrase should survive empty-passphrase rejections",
	)
	requireLocked(h, w, false)
}

// testControllerChangePassphraseRejectUnlocked verifies a wrong current
// passphrase is rejected while the Wallet is unlocked.
func testControllerChangePassphraseRejectUnlocked(h *bwtest.HarnessTest) {
	const (
		wrongPassphrase = "wrong-private-passphrase"
		nextPassphrase  = "controller-next-private-passphrase"
	)

	w, _ := h.NewWallet(bwtest.WalletFixture{Unlocked: true})
	requireLocked(h, w, false)

	err := w.ChangePassphrase(h.Context(), wallet.ChangePassphraseRequest{
		ChangePrivate: true,
		PrivateOld:    []byte(wrongPassphrase),
		PrivateNew:    []byte(nextPassphrase),
	})
	require.ErrorIs(
		h, err, wallet.ErrInvalidPassphrase,
		"wrong current passphrase should be rejected while unlocked",
	)
	requireLocked(h, w, false)

	require.NoError(h, w.Lock(h.Context()), "failed to lock wallet")
	requireLocked(h, w, true)

	err = w.Unlock(h.Context(), wallet.UnlockRequest{
		Passphrase: []byte(bwtest.TestWalletPrivatePassphrase),
		Timeout:    -1,
	})
	require.NoError(
		h, err, "old passphrase should survive unlocked rejection",
	)
	requireLocked(h, w, false)
}

// testControllerUnlockTimeout verifies that a positive Unlock timeout returns
// the Wallet to its public locked state.
func testControllerUnlockTimeout(h *bwtest.HarnessTest) {
	w, _ := h.NewWallet(bwtest.WalletFixture{})
	requireLocked(h, w, true)

	// Use a positive timeout long enough that the immediate unlocked
	// assertion observes the post-Unlock state before the timer can fire.
	err := w.Unlock(h.Context(), wallet.UnlockRequest{
		Passphrase: []byte(bwtest.TestWalletPrivatePassphrase),
		Timeout:    5 * time.Second,
	})
	require.NoError(h, err, "failed to unlock wallet")
	requireLocked(h, w, false)

	err = wait.NoError(
		func() error {
			info, err := w.Info(h.Context())
			if err != nil {
				return err
			}

			if !info.Locked {
				return errors.New("wallet still unlocked")
			}

			return nil
		},
		pollTimeout,
	)
	require.NoError(h, err, "wallet did not lock after unlock timeout")
}
