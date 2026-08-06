//go:build itest

package itest

import (
	"fmt"
	"math"
	"time"

	"github.com/btcsuite/btcd/btcutil/v2"
	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/btcsuite/btcd/txscript/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/btcsuite/btcwallet/bwtest"
	"github.com/btcsuite/btcwallet/bwtest/wait"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/btcsuite/btcwallet/wallet"
	"github.com/btcsuite/btcwallet/wtxmgr"
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

// testListUnspentUnconfirmed verifies that an unconfirmed payment to a wallet
// address is listed with zero confirmations under MinConfs=0 and excluded
// under MinConfs=1.
//
// The case is skipped under the neutrino backend: a light client has no
// mempool and only emits block-derived notifications (chain/neutrino.go), so
// the wallet can never learn about a transaction while it is unconfirmed.
func testListUnspentUnconfirmed(h *bwtest.HarnessTest) {
	if h.Backend.Name() == "neutrino" {
		h.Skip("neutrino cannot deliver unconfirmed transactions")
	}

	w := createWallet(h)
	require.NoError(h, w.Start(h.Context()), "failed to start wallet")

	h.FundWallet(w, oneBTC)

	addr, err := w.NewAddress(
		h.Context(), waddrmgr.DefaultAccountName,
		waddrmgr.WitnessPubKey, false,
	)
	require.NoError(h, err, "failed to create address")

	pkScript, err := txscript.PayToAddrScript(addr)
	require.NoError(h, err, "failed to create pkscript")

	output := &wire.TxOut{Value: int64(oneBTC), PkScript: pkScript}
	txid := h.SendOutput(output, bwtest.MinerFeeRate)

	// The wallet learns about the unconfirmed transaction asynchronously, so
	// poll until it appears in the listing. The returned error names the real
	// cause when the wait times out.
	err = wait.NoError(func() error {
		utxos, err := w.ListUnspent(h.Context(), wallet.UtxoQuery{
			MinConfs: 0,
			MaxConfs: maxConfsLimit,
		})
		if err != nil {
			return fmt.Errorf("list unspent: %w", err)
		}

		for _, utxo := range utxos {
			if utxo.OutPoint.Hash == *txid {
				return nil
			}
		}

		return fmt.Errorf("unconfirmed output %v not listed", *txid)
	}, pollTimeout)
	require.NoError(h, err, "unconfirmed output did not appear")

	// Re-read for the field assertions now that the output is known to be
	// present.
	utxos, err := w.ListUnspent(h.Context(), wallet.UtxoQuery{
		MinConfs: 0,
		MaxConfs: maxConfsLimit,
	})
	require.NoError(h, err, "failed to list unspent with unconfirmed")

	var unconfirmed *wallet.Utxo
	for _, utxo := range utxos {
		if utxo.OutPoint.Hash == *txid {
			unconfirmed = utxo
		}
	}

	require.NotNil(h, unconfirmed, "unconfirmed output missing")
	require.Equal(
		h, int32(0), unconfirmed.Confirmations,
		"unconfirmed output reported confirmations",
	)

	utxos, err = w.ListUnspent(h.Context(), wallet.UtxoQuery{
		MinConfs: 1,
		MaxConfs: maxConfsLimit,
	})
	require.NoError(h, err, "failed to list unspent excluding unconfirmed")
	require.Len(h, utxos, 1, "unconfirmed output not filtered")

	// Confirm the payment so teardown finds an empty mempool.
	tx := h.AssertTxInMempool(*txid)
	h.MineBlockWithTx(tx)
}

// testGetUtxo verifies GetUtxo returns wallet-facing metadata for owned
// outpoints, rejects unknown and foreign outpoints, and is forbidden before
// Start.
func testGetUtxo(h *bwtest.HarnessTest) {
	w := createWallet(h)

	// GetUtxo is forbidden before Start.
	_, err := w.GetUtxo(h.Context(), unknownOutpoint())
	require.ErrorIs(
		h, err, wallet.ErrStateForbidden,
		"get utxo before start not rejected",
	)

	require.NoError(h, w.Start(h.Context()), "failed to start wallet")

	// The Spendable assertion below required unlocking the wallet.
	h.UnlockWallet(w)

	outpoints := h.FundWallet(w, oneBTC, twoBTC)

	// Iterate a slice rather than a map so the assertions run in a
	// deterministic order and a duplicated outpoint can never collapse
	// coverage.
	funded := []struct {
		op     wire.OutPoint
		amount btcutil.Amount
	}{
		{outpoints[0], oneBTC},
		{outpoints[1], twoBTC},
	}

	// Every funded outpoint resolves with its funding metadata.
	for _, f := range funded {
		utxo, err := w.GetUtxo(h.Context(), f.op)
		require.NoError(h, err, "failed to get funded utxo")
		require.Equal(h, f.op, utxo.OutPoint, "outpoint mismatch")
		require.Equal(h, f.amount, utxo.Amount, "amount mismatch")
		require.Equal(
			h, int32(1), utxo.Confirmations, "confirmation mismatch",
		)
		require.True(h, utxo.Spendable, "funded output not spendable")
		require.False(h, utxo.Locked, "funded output locked")
		require.Equal(
			h, waddrmgr.DefaultAccountName, utxo.Account,
			"account mismatch",
		)
	}

	// An outpoint that was never mined is unknown to the wallet.
	_, err = w.GetUtxo(h.Context(), unknownOutpoint())
	require.ErrorIs(
		h, err, wallet.ErrUnknownOutput,
		"unknown outpoint not rejected",
	)

	// The funding transaction contains one change output back to the miner
	// in addition to the wallet outputs, so exactly one index in
	// [0, len(outpoints)] is not wallet-owned. That output exists on chain
	// but belongs to the miner, so the wallet must reject it as unknown.
	owned := make(map[uint32]bool, len(outpoints))
	for _, op := range outpoints {
		owned[op.Index] = true
	}

	changeIndex := -1
	for i := range len(outpoints) + 1 {
		if !owned[uint32(i)] {
			changeIndex = i

			break
		}
	}

	require.NotEqual(
		h, -1, changeIndex, "funding transaction has no change output",
	)

	foreign := wire.OutPoint{
		Hash:  outpoints[0].Hash,
		Index: uint32(changeIndex),
	}

	_, err = w.GetUtxo(h.Context(), foreign)
	require.ErrorIs(
		h, err, wallet.ErrUnknownOutput,
		"foreign outpoint not rejected",
	)
}

// testLeaseOutput verifies LeaseOutput marks an output as locked, renews a
// lease under the same lock ID, rejects double leases under a different lock
// ID, unknown outpoints, and non-positive durations, and is forbidden before
// Start.
func testLeaseOutput(h *bwtest.HarnessTest) {
	w := createWallet(h)

	lockID1 := wtxmgr.LockID{1}
	lockID2 := wtxmgr.LockID{2}

	// LeaseOutput is forbidden before Start.
	_, err := w.LeaseOutput(
		h.Context(), lockID1, unknownOutpoint(), leaseDuration,
	)
	require.ErrorIs(
		h, err, wallet.ErrStateForbidden,
		"lease output before start not rejected",
	)

	require.NoError(h, w.Start(h.Context()), "failed to start wallet")

	outpoints := h.FundWallet(w, oneBTC, twoBTC)

	// Lease the first output; the expiration tracks the requested duration.
	expiration, err := w.LeaseOutput(
		h.Context(), lockID1, outpoints[0], leaseDuration,
	)
	require.NoError(h, err, "failed to lease output")
	require.WithinDuration(
		h, time.Now().Add(leaseDuration), expiration, time.Minute,
		"lease expiration mismatch",
	)

	// The leased output reports Locked while the other remains unlocked.
	utxo, err := w.GetUtxo(h.Context(), outpoints[0])
	require.NoError(h, err, "failed to get leased utxo")
	require.True(h, utxo.Locked, "leased output not locked")

	utxo, err = w.GetUtxo(h.Context(), outpoints[1])
	require.NoError(h, err, "failed to get unleased utxo")
	require.False(h, utxo.Locked, "unleased output locked")

	utxos, err := w.ListUnspent(h.Context(), wallet.UtxoQuery{
		MinConfs: 0,
		MaxConfs: maxConfsLimit,
	})
	require.NoError(h, err, "failed to list unspent after lease")

	locked := make(map[wire.OutPoint]bool, len(utxos))
	for _, u := range utxos {
		locked[u.OutPoint] = u.Locked
	}

	require.True(
		h, locked[outpoints[0]], "list unspent did not report the lease",
	)
	require.False(
		h, locked[outpoints[1]], "list unspent reported a phantom lease",
	)

	// A second lease under a different lock ID is rejected.
	_, err = w.LeaseOutput(
		h.Context(), lockID2, outpoints[0], leaseDuration,
	)
	require.ErrorIs(
		h, err, wallet.ErrOutputAlreadyLocked,
		"double lease under different lock ID not rejected",
	)

	// Re-leasing under the same lock ID renews the lease with a later
	// expiration. The kvdb and SQL backends implement renewal through
	// separate code paths, so exercise the documented renewal behavior
	// explicitly.
	renewed, err := w.LeaseOutput(
		h.Context(), lockID1, outpoints[0], 2*leaseDuration,
	)
	require.NoError(h, err, "failed to renew lease under same lock ID")
	require.True(
		h, renewed.After(expiration),
		"lease renewal did not extend the expiration",
	)

	leases, err := w.ListLeasedOutputs(h.Context())
	require.NoError(h, err, "failed to list leased outputs after renewal")
	require.Len(h, leases, 1, "lease renewal created a second lease")
	require.Equal(h, lockID1, leases[0].LockID, "renewed lock ID mismatch")

	// Leasing an unknown outpoint is rejected.
	_, err = w.LeaseOutput(
		h.Context(), lockID1, unknownOutpoint(), leaseDuration,
	)
	require.ErrorIs(
		h, err, wallet.ErrUnknownOutput,
		"lease of unknown outpoint not rejected",
	)

	// A non-positive lease duration is rejected. Both store backends return
	// the internal db.ErrInvalidParam sentinel, which Wallet.LeaseOutput
	// passes through unmapped, so an external caller cannot match it with
	// errors.Is. require.Error is the strongest available assertion until
	// the wallet exports a public sentinel for invalid lease durations.
	_, err = w.LeaseOutput(h.Context(), lockID2, outpoints[1], 0)
	require.Error(h, err, "non-positive lease duration not rejected")
}
