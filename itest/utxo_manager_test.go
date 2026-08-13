//go:build itest

package itest

import (
	"fmt"
	"time"

	"github.com/btcsuite/btcd/btcutil/v2"
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
	// pollTimeout bounds waits for asynchronous wallet state changes, such
	// as unconfirmed transaction notifications and lease expiry.
	pollTimeout = 30 * time.Second
)

// testListUnspent verifies ListUnspent field enrichment, amount ordering,
// account and confirmation filters, and the pre-start state gate.
func testListUnspent(h *bwtest.HarnessTest) {
	w, _ := h.NewWallet(bwtest.WalletFixture{Unstarted: true})

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

	// FundWallet waits for the block's exact committed wallet tip, so the
	// confirmed outputs are ready for one direct ListUnspent assertion.
	utxos, err = w.ListUnspent(h.Context(), wallet.UtxoQuery{
		MinConfs: 0,
		MaxConfs: maxConfsLimit,
	})
	require.NoError(h, err, "failed to list funded outputs")
	require.Len(h, utxos, 3, "unexpected UTXO count")

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

	// Advance the chain so every funded output reaches two confirmations and
	// the confirmation bounds become selective.
	h.MineBlocks(1)

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

// testListUnspentImmatureCoinbase verifies that a freshly mined coinbase output
// paying the wallet is reported as not spendable, because it has not reached
// coinbase maturity.
func testListUnspentImmatureCoinbase(h *bwtest.HarnessTest) {
	w, _ := h.NewWallet(bwtest.WalletFixture{Unstarted: true})
	require.NoError(h, w.Start(h.Context()), "failed to start wallet")

	// The Spendable assertion below requires unlocking the wallet.
	h.UnlockWallet(w)

	addr := h.NewWalletAddress(w)

	// Pay a single coinbase to the wallet. It is immature by construction:
	// one confirmation is far below the coinbase maturity requirement.
	h.MineBlockToAddress(addr)

	// Fund an ordinary confirmed output as the spendable control.
	funded := h.FundWallet(w, oneBTC)
	require.Len(h, funded, 1, "unexpected funded outpoint count")

	// Both mining helpers wait for the exact committed wallet tip, so the
	// coinbase and ordinary output are ready for one direct read.
	utxos, err := w.ListUnspent(h.Context(), wallet.UtxoQuery{
		MinConfs: 0,
		MaxConfs: maxConfsLimit,
	})
	require.NoError(h, err, "failed to list coinbase and funded outputs")
	require.Len(h, utxos, 2, "coinbase and funded outputs not listed")

	var coinbase, control *wallet.Utxo

	for _, utxo := range utxos {
		if utxo.OutPoint == funded[0] {
			control = utxo

			continue
		}

		coinbase = utxo
	}

	require.NotNil(h, coinbase, "coinbase output not listed")
	require.NotNil(h, control, "control output not listed")

	// The control proves the wallet reports spendable outputs at all, so the
	// coinbase assertion below cannot pass vacuously.
	require.True(h, control.Spendable, "funded output not spendable")

	require.Less(
		h, coinbase.Confirmations,
		int32(h.NetParams().CoinbaseMaturity),
		"coinbase already mature",
	)
	require.False(
		h, coinbase.Spendable, "immature coinbase reported spendable",
	)

	// GetUtxo reports the same spendability for the same output.
	utxo, err := w.GetUtxo(h.Context(), coinbase.OutPoint)
	require.NoError(h, err, "failed to get coinbase utxo")
	require.False(
		h, utxo.Spendable, "immature coinbase reported spendable",
	)
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

	w, _ := h.NewWallet(bwtest.WalletFixture{Unstarted: true})
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
	w, _ := h.NewWallet(bwtest.WalletFixture{Unstarted: true})

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

	// The funding transaction also pays one change output back to the
	// miner. That output exists on chain but belongs to the miner, so the
	// wallet must reject it as unknown.
	_, err = w.GetUtxo(h.Context(), h.ForeignOutpoint(outpoints))
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
	w, _ := h.NewWallet(bwtest.WalletFixture{Unstarted: true})

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

// testReleaseOutput verifies ReleaseOutput unlocks a leased output, rejects
// mismatched lock IDs and unknown outpoints, treats releasing an unleased
// output as a no-op, and is forbidden before Start.
func testReleaseOutput(h *bwtest.HarnessTest) {
	w, _ := h.NewWallet(bwtest.WalletFixture{Unstarted: true})

	lockID1 := wtxmgr.LockID{1}
	lockID2 := wtxmgr.LockID{2}

	// ReleaseOutput is forbidden before Start.
	err := w.ReleaseOutput(h.Context(), lockID1, unknownOutpoint())
	require.ErrorIs(
		h, err, wallet.ErrStateForbidden,
		"release output before start not rejected",
	)

	require.NoError(h, w.Start(h.Context()), "failed to start wallet")

	outpoints := h.FundWallet(w, oneBTC)

	// Releasing an output with no active lease is a no-op.
	require.NoError(
		h, w.ReleaseOutput(h.Context(), lockID1, outpoints[0]),
		"release of unleased output not a no-op",
	)

	_, err = w.LeaseOutput(
		h.Context(), lockID1, outpoints[0], leaseDuration,
	)
	require.NoError(h, err, "failed to lease output")

	// Releasing under a different lock ID is rejected and the lease
	// survives.
	err = w.ReleaseOutput(h.Context(), lockID2, outpoints[0])
	require.ErrorIs(
		h, err, wallet.ErrOutputUnlockNotAllowed,
		"release under wrong lock ID not rejected",
	)

	utxo, err := w.GetUtxo(h.Context(), outpoints[0])
	require.NoError(h, err, "failed to get utxo after rejected release")
	require.True(h, utxo.Locked, "rejected release cleared the lease")

	// Releasing an unknown outpoint is rejected.
	err = w.ReleaseOutput(h.Context(), lockID1, unknownOutpoint())
	require.ErrorIs(
		h, err, wallet.ErrUnknownOutput,
		"release of unknown outpoint not rejected",
	)

	// Releasing under the owning lock ID unlocks the output.
	require.NoError(
		h, w.ReleaseOutput(h.Context(), lockID1, outpoints[0]),
		"failed to release output",
	)

	utxo, err = w.GetUtxo(h.Context(), outpoints[0])
	require.NoError(h, err, "failed to get released utxo")
	require.False(h, utxo.Locked, "released output still locked")

	leases, err := w.ListLeasedOutputs(h.Context())
	require.NoError(h, err, "failed to list leased outputs")
	require.Empty(h, leases, "released output still leased")

	// Releasing an already-released output is a no-op.
	require.NoError(
		h, w.ReleaseOutput(h.Context(), lockID1, outpoints[0]),
		"second release not a no-op",
	)
}

// testListLeasedOutputs verifies ListLeasedOutputs tracks active leases with
// their lock IDs and expirations, drops released leases, excludes expired
// leases, and is forbidden before Start.
func testListLeasedOutputs(h *bwtest.HarnessTest) {
	w, _ := h.NewWallet(bwtest.WalletFixture{Unstarted: true})

	// ListLeasedOutputs is forbidden before Start.
	_, err := w.ListLeasedOutputs(h.Context())
	require.ErrorIs(
		h, err, wallet.ErrStateForbidden,
		"list leased outputs before start not rejected",
	)

	require.NoError(h, w.Start(h.Context()), "failed to start wallet")

	outpoints := h.FundWallet(w, oneBTC, twoBTC)

	// A funded wallet starts with no leases.
	leases, err := w.ListLeasedOutputs(h.Context())
	require.NoError(h, err, "failed to list leased outputs")
	require.Empty(h, leases, "funded wallet reported leases")

	lockID1 := wtxmgr.LockID{1}
	lockID2 := wtxmgr.LockID{2}

	_, err = w.LeaseOutput(
		h.Context(), lockID1, outpoints[0], leaseDuration,
	)
	require.NoError(h, err, "failed to lease first output")

	_, err = w.LeaseOutput(
		h.Context(), lockID2, outpoints[1], leaseDuration,
	)
	require.NoError(h, err, "failed to lease second output")

	// Both active leases are listed with their lock IDs and expirations.
	leases, err = w.ListLeasedOutputs(h.Context())
	require.NoError(h, err, "failed to list leased outputs")
	require.Len(h, leases, 2, "unexpected lease count")

	active := make(map[wire.OutPoint]*wallet.LeasedOutput, len(leases))
	for _, lease := range leases {
		active[lease.OutPoint] = lease
	}

	require.Contains(h, active, outpoints[0], "first lease missing")
	require.Equal(
		h, lockID1, active[outpoints[0]].LockID, "first lock ID mismatch",
	)
	require.WithinDuration(
		h, time.Now().Add(leaseDuration),
		active[outpoints[0]].Expiration, time.Minute,
		"first lease expiration mismatch",
	)

	require.Contains(h, active, outpoints[1], "second lease missing")
	require.Equal(
		h, lockID2, active[outpoints[1]].LockID,
		"second lock ID mismatch",
	)

	// Releasing the first lease leaves only the second.
	require.NoError(
		h, w.ReleaseOutput(h.Context(), lockID1, outpoints[0]),
		"failed to release first output",
	)

	leases, err = w.ListLeasedOutputs(h.Context())
	require.NoError(h, err, "failed to list leased outputs")
	require.Len(h, leases, 1, "released lease still listed")
	require.Equal(
		h, outpoints[1], leases[0].OutPoint, "wrong lease remained",
	)

	// An expired lease is excluded from the listing. Lease the first output
	// again with a short duration and poll until it lapses.
	shortLease := wtxmgr.LockID{3}

	_, err = w.LeaseOutput(
		h.Context(), shortLease, outpoints[0], time.Second,
	)
	require.NoError(h, err, "failed to lease output with short duration")

	err = wait.NoError(func() error {
		leases, err := w.ListLeasedOutputs(h.Context())
		if err != nil {
			return fmt.Errorf("list leased outputs: %w", err)
		}

		if len(leases) != 1 {
			return fmt.Errorf("want 1 lease, got %d", len(leases))
		}

		if leases[0].OutPoint != outpoints[1] {
			return fmt.Errorf("want lease on %v, got %v",
				outpoints[1], leases[0].OutPoint)
		}

		return nil
	}, pollTimeout)
	require.NoError(h, err, "expired lease still listed")
}
