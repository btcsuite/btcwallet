//go:build itest

package itest

import (
	"fmt"
	"math"
	"time"

	"github.com/btcsuite/btcd/btcutil/v2"
	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/btcsuite/btcwallet/bwtest"
	"github.com/btcsuite/btcwallet/bwtest/wait"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/btcsuite/btcwallet/wallet"
	"github.com/stretchr/testify/require"
)

const (
	// maxConfsLimit is used as the MaxConfs bound when a test does not want
	// to constrain the upper confirmation range.
	maxConfsLimit = math.MaxInt32

	// leaseDuration is the standard lease length for tests. It is long
	// enough that the lease never expires mid-test.
	leaseDuration = 10 * time.Minute

	// pollTimeout bounds waits for asynchronous wallet state changes, such
	// as unconfirmed transaction notifications and lease expiry.
	pollTimeout = 30 * time.Second

	// The funding amounts shared by the UtxoManager cases.
	oneBTC   = 1 * btcutil.SatoshiPerBitcoin
	twoBTC   = 2 * btcutil.SatoshiPerBitcoin
	threeBTC = 3 * btcutil.SatoshiPerBitcoin
)

// createWallet creates and registers a wallet without starting it so tests can
// exercise the pre-start state gates before bringing the wallet up.
func createWallet(h *bwtest.HarnessTest) *wallet.Wallet {
	h.Helper()

	cfg, params := h.TestWalletConfig()

	manager := h.NewWalletManager()
	w, err := manager.Create(cfg, params)
	require.NoError(h, err, "failed to create wallet")

	// Register before Start so teardown owns the wallet even if Start fails.
	h.RegisterWallet(w)

	return w
}

// unknownOutpoint returns an outpoint that was never mined and is therefore
// unknown to any wallet.
func unknownOutpoint() wire.OutPoint {
	return wire.OutPoint{Hash: chainhash.Hash{0xaa}, Index: 0}
}

// testListUnspent verifies ListUnspent field enrichment, amount ordering,
// account and confirmation filters, and the pre-start state gate.
func testListUnspent(h *bwtest.HarnessTest) {
	w := createWallet(h)

	// ListUnspent is forbidden before Start.
	_, err := w.ListUnspent(h.Context(), wallet.UtxoQuery{})
	require.ErrorIs(
		h, err, wallet.ErrStateForbidden,
		"list unspent before start not rejected",
	)

	require.NoError(h, w.Start(h.Context()), "failed to start wallet")

	// A fresh wallet has no UTXOs.
	utxos, err := w.ListUnspent(h.Context(), wallet.UtxoQuery{
		MinConfs: 0,
		MaxConfs: maxConfsLimit,
	})
	require.NoError(h, err, "failed to list unspent for empty wallet")
	require.Empty(h, utxos, "fresh wallet reported UTXOs")

	// Unlock before funding, the Spendable assertions below require it.
	h.UnlockWallet(w)

	// Fund out of order so the ascending amount sort is observable.
	amounts := []btcutil.Amount{threeBTC, oneBTC, twoBTC}

	outpoints := h.FundWallet(w, amounts...)
	require.Len(h, outpoints, 3, "unexpected funded outpoint count")

	funded := make(map[wire.OutPoint]btcutil.Amount, len(outpoints))
	for i, op := range outpoints {
		funded[op] = amounts[i]
	}

	// The funding transaction is confirmed, so every output reports one
	// confirmation. FundWallet waits on GetUtxo, but ListUnspent is a
	// separate query whose confirmation filter tracks the synced height, so
	// poll until it reports the full set.
	err = wait.NoError(func() error {
		utxos, err = w.ListUnspent(h.Context(), wallet.UtxoQuery{
			MinConfs: 0,
			MaxConfs: maxConfsLimit,
		})
		if err != nil {
			return fmt.Errorf("list unspent: %w", err)
		}

		if len(utxos) != 3 {
			return fmt.Errorf("want 3 utxos, got %d", len(utxos))
		}

		return nil
	}, pollTimeout)
	require.NoError(h, err, "unexpected UTXO count")

	// Results are sorted by amount in ascending order.
	require.Equal(h, btcutil.Amount(oneBTC), utxos[0].Amount)
	require.Equal(h, btcutil.Amount(twoBTC), utxos[1].Amount)
	require.Equal(h, btcutil.Amount(threeBTC), utxos[2].Amount)

	for _, utxo := range utxos {
		amount, ok := funded[utxo.OutPoint]
		require.True(h, ok, "listed unexpected outpoint %v", utxo.OutPoint)
		require.Equal(h, amount, utxo.Amount, "amount mismatch")
		require.Equal(
			h, int32(1), utxo.Confirmations, "confirmation mismatch",
		)
		require.True(h, utxo.Spendable, "funded output not spendable")
		require.False(h, utxo.Locked, "funded output locked")
		require.NotNil(h, utxo.Address, "missing address")
		require.NotEmpty(h, utxo.PkScript, "missing pkScript")
		require.Equal(
			h, waddrmgr.DefaultAccountName, utxo.Account,
			"account mismatch",
		)
		require.Equal(
			h, waddrmgr.WitnessPubKey, utxo.AddressType,
			"address type mismatch",
		)
	}

	// The account filter matches only the default account.
	utxos, err = w.ListUnspent(h.Context(), wallet.UtxoQuery{
		Account:  waddrmgr.DefaultAccountName,
		MinConfs: 0,
		MaxConfs: maxConfsLimit,
	})
	require.NoError(h, err, "failed to list unspent by account")
	require.Len(h, utxos, 3, "default account filter hid UTXOs")

	utxos, err = w.ListUnspent(h.Context(), wallet.UtxoQuery{
		Account:  "no-such-account",
		MinConfs: 0,
		MaxConfs: maxConfsLimit,
	})
	require.NoError(h, err, "failed to list unspent by unknown account")
	require.Empty(h, utxos, "unknown account filter returned UTXOs")

	// Advance the chain so every funded output reaches two confirmations
	// and the confirmation bounds become selective. Mining only waits for
	// the wallet's synced height, so wait for the confirmation count the
	// bounds below depend on.
	h.MineBlocks(1)
	h.AssertUtxoConfirmations(w, outpoints[0], 2)

	utxos, err = w.ListUnspent(h.Context(), wallet.UtxoQuery{
		MinConfs: 3,
		MaxConfs: maxConfsLimit,
	})
	require.NoError(h, err, "failed to list unspent with min confs")
	require.Empty(h, utxos, "min confs bound ignored")

	utxos, err = w.ListUnspent(h.Context(), wallet.UtxoQuery{
		MinConfs: 0,
		MaxConfs: 1,
	})
	require.NoError(h, err, "failed to list unspent with max confs")
	require.Empty(h, utxos, "max confs bound ignored")

	utxos, err = w.ListUnspent(h.Context(), wallet.UtxoQuery{
		MinConfs: 2,
		MaxConfs: maxConfsLimit,
	})
	require.NoError(h, err, "failed to list unspent within conf range")
	require.Len(h, utxos, 3, "conf range excluded confirmed UTXOs")
}
